//! Mesh workload metadata plugin.
//!
//! Adds Istio/GAMMA-style identity labels into transaction metadata. The
//! existing logging and metrics sinks then pick them up without plugin-trait
//! changes.

use crate::fips::backend::rand::{SecureRandom, SystemRandom};
use async_trait::async_trait;
use serde_json::Value;
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::MeshTrafficDirection;
use crate::modes::mesh::config::{MeshMetricsConfig, MeshTracingConfig, TracingProvider};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::modes::mesh::metric_tag_cel::{
    METRIC_TAG_CEL_DESTINATION_PORT_METADATA, METRIC_TAG_CEL_REQUEST_HOST_METADATA,
    METRIC_TAG_CEL_REQUEST_METHOD_METADATA, MetricTagCelExpr, MetricTagCelStampNeeds,
    parse_metric_tag_cel_expression, split_metric_tag_cel_plan,
    validate_metric_tag_cel_for_families,
};
use crate::plugins::mesh::CUSTOM_TRACE_ATTRIBUTES_METADATA;
use crate::plugins::mesh::authz::{
    HboneBaggageHonor, IGNORED_UDP_SOURCE_SCOPE_METADATA, TrustedAssertorIndex,
    hbone_baggage_honor, hbone_baggage_identity, hbone_wire_folded_baggage,
    merge_hbone_baggage_honor, mesh_authz_destination_port, mesh_stream_authz_destination_port,
    parse_trust_domain_aliases, parse_trusted_hbone_assertors,
};
use crate::plugins::mesh::prometheus_helpers::{
    MESH_METRICS_DISABLED_METADATA, MESH_WORKLOAD_METRICS_OBSERVED_METADATA, MeshMetricFamily,
    MeshMetricLabel, MeshTracingProvider, increment_mesh_tracing_span_dropped,
};
use crate::plugins::mesh::telemetry_facts::{
    LocalWorkloadFacts, MeshLabel, MeshLabelShadow, RemoteSourceFacts, SpiffeLabels,
};
use crate::plugins::otel_tracing::{
    OtelTracing, SpanData, SpanKind, TraceExporter, build_traceparent, ensure_trace_metadata,
    trace_export_drop_reason, trace_exporters_from_providers, trace_is_sampled,
    validate_trace_provider_endpoints, validate_trace_provider_secret_refs,
};
use crate::plugins::utils::PluginHttpClient;
use crate::plugins::utils::metadata_redaction::{
    REDACTED_PLACEHOLDER, is_credential_class_metadata_key, is_operator_sensitive_metadata_key,
    is_sensitive_header_name, is_sensitive_metadata_key,
};
use crate::plugins::{
    ALL_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, StreamConnectionContext,
    StreamTransactionSummary, TransactionSummary, priority,
};

const MESH_SOURCE_PRINCIPAL: &str = "mesh.source.principal";
const MESH_SOURCE_TRUST_DOMAIN: &str = "mesh.source.trust_domain";
const MESH_SOURCE_NAMESPACE: &str = "mesh.source.namespace";
const MESH_SOURCE_SERVICE_ACCOUNT: &str = "mesh.source.service_account";
const MESH_DIRECTION_METADATA: &str = "mesh.direction";
const MESH_DIRECTION_INBOUND: &str = "inbound";
const MESH_DIRECTION_OUTBOUND: &str = "outbound";
const TRACEPARENT_HEADER: &str = "traceparent";
const TRACESTATE_HEADER: &str = "tracestate";
const CAPTURED_TRACEPARENT_METADATA: &str = "workload_metrics.captured_traceparent";
const CAPTURED_TRACESTATE_METADATA: &str = "workload_metrics.captured_tracestate";
const CAPTURED_B3_METADATA: &str = "workload_metrics.captured_b3";
const B3_TRACE_HEADERS: [&str; 6] = [
    "b3",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
    "x-b3-sampled",
    "x-b3-flags",
];
const MAX_CUSTOM_TAGS: usize = 32;
const MAX_CUSTOM_TAG_NAME_BYTES: usize = 128;
const MAX_CUSTOM_TAG_VALUE_BYTES: usize = 1024;
const MAX_CUSTOM_ENV_VAR_NAME_BYTES: usize = 256;
const MAX_METRIC_TAG_VALUE_BYTES: usize = 256;
const MAX_METRIC_TAG_OVERRIDES: usize = 128;
const MAX_METRIC_TAG_OVERRIDE_PLAN_BYTES: usize = 16 * 1024;

fn mesh_direction_str(direction: MeshTrafficDirection) -> &'static str {
    match direction {
        MeshTrafficDirection::Inbound => MESH_DIRECTION_INBOUND,
        MeshTrafficDirection::Outbound => MESH_DIRECTION_OUTBOUND,
    }
}

/// Parse a `mesh.direction` metadata value emitted by this plugin. `None`
/// when the metadata is absent or unrecognized so callers fall back to the
/// pre-GAP-3F SERVER-only behaviour.
fn parse_mesh_direction_metadata(value: &str) -> Option<MeshTrafficDirection> {
    match value {
        MESH_DIRECTION_INBOUND => Some(MeshTrafficDirection::Inbound),
        MESH_DIRECTION_OUTBOUND => Some(MeshTrafficDirection::Outbound),
        _ => None,
    }
}

/// Which directions of a mesh hop should produce tracing spans.
///
/// Mirrors Istio `Telemetry.tracing[].match.mode`:
///
/// - `{ server: true, client: false }` — SERVER (default, back-compat)
/// - `{ server: false, client: true }` — CLIENT-only
/// - `{ server: true, client: true }` — CLIENT_AND_SERVER
///
/// The Istio translator pre-computes this from the merged `tracing[]`
/// entries; operator-supplied direct configurations can also set it
/// explicitly via the `direction_emit` JSON object. Default preserves the
/// pre-GAP-3F behaviour where every workload_metrics instance emits SERVER
/// spans only. Closed: a misspelled `client` must not silently keep the
/// server-only default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectionEmit {
    #[serde(default = "DirectionEmit::default_server")]
    pub(crate) server: bool,
    #[serde(default)]
    pub(crate) client: bool,
}

impl DirectionEmit {
    fn default_server() -> bool {
        true
    }

    /// Back-compat default: emit SERVER spans only. Matches the behaviour of
    /// every workload_metrics instance before GAP-3F shipped.
    pub(crate) fn server_only() -> Self {
        Self {
            server: true,
            client: false,
        }
    }

    /// Both CLIENT and SERVER spans — emitted on any mesh listener.
    #[allow(dead_code)]
    pub(crate) fn both() -> Self {
        Self {
            server: true,
            client: true,
        }
    }

    /// Whether this plugin instance should emit a span for the given listener
    /// direction. An unstamped `direction` (`None`) preserves SERVER-emit
    /// behaviour so non-mesh modes and pre-stamping listeners keep working.
    pub(crate) fn emits_for(self, direction: Option<MeshTrafficDirection>) -> bool {
        match direction {
            Some(MeshTrafficDirection::Inbound) => self.server,
            Some(MeshTrafficDirection::Outbound) => self.client,
            None => self.server,
        }
    }
}

impl Default for DirectionEmit {
    fn default() -> Self {
        Self::server_only()
    }
}

/// Internal injection field: exact copy of every enabled global `mesh_authz`
/// baggage gate PluginCache will execute. Absent = the plugin's own
/// single-gate `trusted_hbone_assertors` / `trust_domain_aliases` config
/// (direct / user-created instances). Present = fail-closed conjunction of
/// those compiled gates. Not an operator-facing schema field.
pub const EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY: &str = "_effective_mesh_authz_baggage_gates";

/// Hard cap on injected/configured effective authz gates. Construction fails
/// closed above this; request-time evaluation scales only with this bound,
/// never with unrelated assertor inventory.
pub const MAX_EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES: usize = 16;

const EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATE_KEYS: &[&str] =
    &["trusted_hbone_assertors", "trust_domain_aliases"];

/// Every root `config` key `workload_metrics` reads, and the exact set mesh
/// slice injection writes (`inject_workload_metrics_plugin`). Unknown root
/// keys fail closed at construction: a misspelled `trusted_hbone_assertors`
/// would otherwise silently restore the built-in assertor defaults and undo
/// an operator's `trusted_hbone_assertors: []` baggage lockdown.
///
/// The last block is read by
/// [`crate::plugins::otel_tracing::TraceExporterOptions::from_config`] off
/// this same root object via `trace_exporters_from_providers`, so those keys
/// are part of this plugin's schema even though no `config.get` for them
/// appears in this file.
pub const WORKLOAD_METRICS_CONFIG_KEYS: &[&str] = &[
    "node_id",
    "topology",
    "namespace",
    "workload_spiffe_id",
    "labels",
    "trust_domain_aliases",
    "trusted_hbone_assertors",
    EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY,
    "sampling_percentage",
    "custom_tags",
    "custom_header_tags",
    "custom_env_tags",
    "safe_tag_sources",
    "metrics",
    "tracing_provider",
    "tracing_providers",
    "direction_emit",
    "span_reporting_disabled",
    "disable_span_reporting",
    "disableSpanReporting",
    "service_name",
    "deployment_environment",
    "batch_size",
    "flush_interval_ms",
    "buffer_capacity",
    "buffer_max_bytes",
    "max_retries",
    "retry_delay_ms",
    "allow_plaintext",
];

/// One compiled `mesh_authz` baggage gate: the same
/// [`TrustedAssertorIndex`] + alias list authorization uses.
#[derive(Default)]
struct BaggageTrustGate {
    trusted_hbone_assertors: TrustedAssertorIndex,
    trust_domain_aliases: Vec<TrustDomain>,
}

impl BaggageTrustGate {
    fn from_config(config: &Value, effective_gate_index: Option<usize>) -> Result<Self, String> {
        Ok(Self {
            trusted_hbone_assertors: parse_trusted_hbone_assertors(
                config,
                "workload_metrics",
                effective_gate_index,
            )?,
            trust_domain_aliases: parse_trust_domain_aliases(config)?,
        })
    }

    fn honor(&self, peer: &SpiffeId, asserted: &SpiffeId) -> HboneBaggageHonor {
        hbone_baggage_honor(
            &self.trusted_hbone_assertors,
            &self.trust_domain_aliases,
            peer,
            asserted,
        )
    }
}

/// Compiled telemetry baggage policy. `Single` is the backward-compatible
/// direct-plugin path. `Conjunctive` mirrors every enabled global mesh_authz
/// gate; honor requires every gate to honor.
enum BaggageTrustPolicy {
    Single(BaggageTrustGate),
    Conjunctive(Box<[BaggageTrustGate]>),
}

impl Default for BaggageTrustPolicy {
    fn default() -> Self {
        Self::Single(BaggageTrustGate::default())
    }
}

impl BaggageTrustPolicy {
    fn from_config(config: &Value) -> Result<Self, String> {
        match config.get(EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY) {
            None => Ok(Self::Single(BaggageTrustGate::from_config(config, None)?)),
            Some(Value::Array(gates)) => {
                if gates.is_empty() {
                    return Err(format!(
                        "`{EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY}` must contain at least one gate"
                    ));
                }
                if gates.len() > MAX_EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES {
                    return Err(format!(
                        "`{EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY}` exceeds \
                         {MAX_EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES} gates"
                    ));
                }
                let compiled: Result<Vec<BaggageTrustGate>, String> = gates
                    .iter()
                    .enumerate()
                    .map(|(idx, gate)| parse_effective_authz_baggage_gate(idx, gate))
                    .collect();
                Ok(Self::Conjunctive(compiled?.into_boxed_slice()))
            }
            Some(_) => Err(format!(
                "`{EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY}` must be an array of objects"
            )),
        }
    }

    fn honor(&self, peer: &SpiffeId, asserted: &SpiffeId) -> HboneBaggageHonor {
        match self {
            Self::Single(gate) => gate.honor(peer, asserted),
            Self::Conjunctive(gates) => {
                let mut outcome = HboneBaggageHonor::Honored;
                for gate in gates.iter() {
                    outcome = merge_hbone_baggage_honor(outcome, gate.honor(peer, asserted));
                }
                if gates.is_empty() {
                    HboneBaggageHonor::UntrustedAssertor
                } else {
                    outcome
                }
            }
        }
    }
}

fn parse_effective_authz_baggage_gate(
    idx: usize,
    gate: &Value,
) -> Result<BaggageTrustGate, String> {
    let Some(object) = gate.as_object() else {
        return Err(format!(
            "`{EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY}[{idx}]` must be an object"
        ));
    };
    crate::util::unknown_keys::reject_unknown_keys(
        object,
        &format!("{EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY}[{idx}]"),
        EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATE_KEYS,
        &format!("workload_metrics: `{EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY}[{idx}]`: "),
    )?;
    BaggageTrustGate::from_config(gate, Some(idx)).map_err(|e| {
        format!("workload_metrics: `{EFFECTIVE_MESH_AUTHZ_BAGGAGE_GATES_KEY}[{idx}]`: {e}")
    })
}

/// Resolve the local workload's `workload` / `app` / `service` metric labels.
///
/// Precedence (first non-empty wins): workload =
/// `service.istio.io/canonical-name`, `app.kubernetes.io/name`, `app`,
/// `k8s-app`, `workload`, then the SPIFFE service account, then `unknown`;
/// app = `app.kubernetes.io/name`, `app`, `k8s-app`, then workload; service =
/// `service.istio.io/canonical-name`, `service`, `app`, then workload.
fn resolve_local_workload_facts(
    labels: &HashMap<String, String>,
    workload_spiffe_id: Option<&SpiffeId>,
    namespace: Option<&str>,
) -> LocalWorkloadFacts {
    let workload = first_label(
        labels,
        &[
            "service.istio.io/canonical-name",
            "app.kubernetes.io/name",
            "app",
            "k8s-app",
            "workload",
        ],
    )
    .or_else(|| workload_spiffe_id.and_then(SpiffeId::service_account))
    .unwrap_or("unknown");
    let app =
        first_label(labels, &["app.kubernetes.io/name", "app", "k8s-app"]).unwrap_or(workload);
    let service = first_label(
        labels,
        &["service.istio.io/canonical-name", "service", "app"],
    )
    .unwrap_or(workload);
    LocalWorkloadFacts::new(workload_spiffe_id, namespace, workload, app, service)
}

/// The source identity a stamp attributes, without cloning the verified peer.
enum ResolvedSourceIdentity {
    /// The authenticated peer (`ctx.peer_spiffe_id`).
    Peer,
    /// A baggage principal every effective trust gate honored.
    Asserted(SpiffeId),
    /// No source identity.
    Absent,
}

pub struct WorkloadMetrics {
    node_id: Option<String>,
    topology: Option<String>,
    namespace: Option<String>,
    workload_spiffe_id: Option<SpiffeId>,
    /// This workload's metric labels, resolved once from `labels`,
    /// `namespace` and `workload_spiffe_id` at construction (one
    /// config/identity generation) instead of probing the label map on every
    /// stamp (issue #6793). Shared by every request this instance stamps.
    local_facts: LocalWorkloadFacts,
    /// Compiled HBONE baggage trust policy. Direct instances use a single
    /// gate from this plugin's own config; mesh injection supplies a
    /// conjunctive set mirroring every enabled global `mesh_authz`.
    baggage_trust: BaggageTrustPolicy,
    /// Tracing sampling percentage 0.0–100.0 (from Telemetry CRD).
    sampling_percentage: Option<f64>,
    /// Custom tags injected into every transaction's metadata.
    custom_tags: HashMap<String, String>,
    /// Custom tags populated from request headers.
    custom_header_tags: HashMap<String, String>,
    /// Header-backed tags whose source header is not declared in
    /// `safe_tag_sources`: their values are emitted as `[REDACTED]`.
    redacted_header_tags: HashSet<String>,
    /// Per-family self-contained compact tag-override plans. Each plan carries
    /// its immutable CEL input requirements in a fixed header.
    tag_override_plans: Vec<(MeshMetricFamily, String)>,
    disabled_metrics_marker: Option<String>,
    custom_trace_attributes_marker: Option<String>,
    /// Provider-specific tracing backends surfaced from Istio Telemetry CRD
    /// via the mesh slice. These also enable trace-context propagation when
    /// span reporting is disabled.
    tracing_providers: Vec<TracingProvider>,
    /// Inject the active span as B3 headers toward the backend for every
    /// traced request, not only for requests that arrived with B3 context.
    /// True when a Zipkin provider is configured (B3 is Zipkin's native
    /// propagation format), including while span reporting is disabled.
    b3_propagation: bool,
    trace_exporters: Vec<Arc<dyn TraceExporter>>,
    export_drop_log_limiter: Mutex<crate::util::accept_backoff::LogRateLimiter>,
    span_reporting_disabled: bool,
    service_name: String,
    /// Which directions of a mesh hop this plugin instance should emit spans
    /// for. Defaults to SERVER-only.
    direction_emit: DirectionEmit,
}

/// An unconfigured instance, as the former `#[derive(Default)]` produced. Its
/// local facts are resolved from no labels, no namespace and no SPIFFE
/// identity, exactly what a stamp derived from that empty config before the
/// facts were precomputed (issue #6793).
impl Default for WorkloadMetrics {
    fn default() -> Self {
        Self {
            node_id: None,
            topology: None,
            namespace: None,
            workload_spiffe_id: None,
            local_facts: resolve_local_workload_facts(&HashMap::new(), None, None),
            baggage_trust: BaggageTrustPolicy::default(),
            sampling_percentage: None,
            custom_tags: HashMap::new(),
            custom_header_tags: HashMap::new(),
            redacted_header_tags: HashSet::new(),
            tag_override_plans: Vec::new(),
            disabled_metrics_marker: None,
            custom_trace_attributes_marker: None,
            tracing_providers: Vec::new(),
            b3_propagation: false,
            trace_exporters: Vec::new(),
            export_drop_log_limiter: Mutex::default(),
            span_reporting_disabled: false,
            service_name: String::new(),
            direction_emit: DirectionEmit::default(),
        }
    }
}

impl WorkloadMetrics {
    #[allow(dead_code)]
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_http_client(config, PluginHttpClient::default())
    }

    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        // Production resolves custom env tags through the real process
        // environment at construction/reload only.
        Self::new_with_http_client_and_env_lookup(config, http_client, |key| std::env::var(key))
    }

    /// Test seam: inject environment lookup outcomes without mutating the
    /// process environment (Rust 2024 forbids unsynchronized `set_var` under
    /// the parallel test harness).
    #[allow(dead_code)]
    pub(crate) fn new_with_env_lookup_for_test<F>(
        config: &Value,
        env_lookup: F,
    ) -> Result<Self, String>
    where
        F: FnMut(&str) -> Result<String, std::env::VarError>,
    {
        Self::new_with_http_client_and_env_lookup(config, PluginHttpClient::default(), env_lookup)
    }

    fn new_with_http_client_and_env_lookup<F>(
        config: &Value,
        http_client: PluginHttpClient,
        env_lookup: F,
    ) -> Result<Self, String>
    where
        F: FnMut(&str) -> Result<String, std::env::VarError>,
    {
        let object = config
            .as_object()
            .ok_or_else(|| "workload_metrics: `config` must be an object".to_string())?;
        crate::util::unknown_keys::reject_unknown_keys(
            object,
            "config",
            WORKLOAD_METRICS_CONFIG_KEYS,
            "workload_metrics: `config`: ",
        )?;
        for key in [
            "node_id",
            "topology",
            "namespace",
            "workload_spiffe_id",
            "service_name",
            "deployment_environment",
        ] {
            if config.get(key).is_some_and(|value| !value.is_string()) {
                return Err(format!("workload_metrics: `{key}` must be a string"));
            }
        }
        for key in [
            "span_reporting_disabled",
            "disable_span_reporting",
            "disableSpanReporting",
        ] {
            if config.get(key).is_some_and(|value| !value.is_boolean()) {
                return Err(format!("workload_metrics: `{key}` must be a boolean"));
            }
        }
        for key in [
            "batch_size",
            "flush_interval_ms",
            "buffer_capacity",
            "buffer_max_bytes",
            "max_retries",
            "retry_delay_ms",
        ] {
            if config
                .get(key)
                .is_some_and(|value| value.as_u64().is_none())
            {
                return Err(format!(
                    "workload_metrics: `{key}` must be a non-negative integer"
                ));
            }
        }

        let workload_spiffe_id = config
            .get("workload_spiffe_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(SpiffeId::new)
            .transpose()
            .map_err(|_| {
                "workload_metrics: `workload_spiffe_id` is not a valid SPIFFE id".to_string()
            })?;
        let labels = string_map_config(config, "labels")?;
        let namespace = string_config(config, "namespace");
        let local_facts = resolve_local_workload_facts(
            &labels,
            workload_spiffe_id.as_ref(),
            namespace.as_deref(),
        );
        let baggage_trust = BaggageTrustPolicy::from_config(config).map_err(|e| {
            if e.starts_with("workload_metrics:") {
                e
            } else {
                format!("workload_metrics: {e}")
            }
        })?;
        let sampling_percentage = match config.get("sampling_percentage") {
            Some(value) => {
                let Some(percentage) = value.as_f64() else {
                    return Err(
                        "workload_metrics: `sampling_percentage` must be a number".to_string()
                    );
                };
                if !percentage.is_finite() || !(0.0..=100.0).contains(&percentage) {
                    return Err(format!(
                        "workload_metrics: `sampling_percentage` must be between 0.0 and 100.0 (got \"{percentage}\")"
                    ));
                }
                Some(percentage)
            }
            None => None,
        };
        let custom_tags = string_map_config(config, "custom_tags")?;
        let custom_header_tags = string_map_config(config, "custom_header_tags")?;
        let custom_env_tags = string_map_config(config, "custom_env_tags")?;
        let safe_tag_sources = safe_tag_sources_config(config)?;
        let ValidatedCustomTags {
            mut custom_tags,
            custom_header_tags,
            custom_env_tags,
            custom_trace_attributes_marker,
            redacted_header_tags,
            redacted_env_tags,
        } = validate_custom_tags(
            custom_tags,
            custom_header_tags,
            custom_env_tags,
            &safe_tag_sources,
        )?;
        // Resolve Istio environment custom tags from *this* data-plane process
        // environment at construction/reload — never on the request hot path
        // and never from a controller-host translation.
        resolve_custom_env_tags_with(
            &mut custom_tags,
            &custom_env_tags,
            &redacted_env_tags,
            env_lookup,
        )?;
        let ParsedMetricConfig {
            tag_override_plans,
            disabled_metrics_marker,
        } = parse_metric_config(config.get("metrics"))?;
        let tracing_providers = parse_tracing_providers(config)?;
        validate_trace_provider_secret_refs(&tracing_providers)
            .map_err(|error| format!("workload_metrics: {error}"))?;
        // Typed whenever supplied, even when no exporter is built (no
        // providers, or span reporting disabled), so a stored value cannot
        // become a latent admission failure.
        if config
            .get("allow_plaintext")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err("workload_metrics: `allow_plaintext` must be a boolean".to_string());
        }
        let span_reporting_disabled = config
            .get("span_reporting_disabled")
            .or_else(|| config.get("disable_span_reporting"))
            .or_else(|| config.get("disableSpanReporting"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let service_name = string_config(config, "service_name").unwrap_or_else(|| {
            config
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(|namespace| format!("ferrum-edge-mesh-{namespace}"))
                .unwrap_or_else(|| "ferrum-edge-mesh".to_string())
        });
        let trace_exporters = if span_reporting_disabled {
            Vec::new()
        } else {
            trace_exporters_from_providers(&tracing_providers, &service_name, config, http_client)
                .map_err(|error| format!("workload_metrics: {error}"))?
        };
        let direction_emit = parse_direction_emit(config)?;
        let b3_propagation = tracing_providers
            .iter()
            .any(|provider| matches!(provider, TracingProvider::Zipkin { .. }));

        Ok(Self {
            node_id: string_config(config, "node_id"),
            topology: string_config(config, "topology"),
            namespace,
            workload_spiffe_id,
            local_facts,
            baggage_trust,
            sampling_percentage,
            custom_tags,
            custom_header_tags,
            redacted_header_tags,
            tag_override_plans,
            disabled_metrics_marker,
            custom_trace_attributes_marker,
            tracing_providers,
            b3_propagation,
            trace_exporters,
            export_drop_log_limiter: Mutex::new(crate::util::accept_backoff::LogRateLimiter::new()),
            span_reporting_disabled,
            service_name,
            direction_emit,
        })
    }

    /// Test/introspection helper — returns the currently configured tracing
    /// backends. Kept `pub(crate)` so tests can assert the config without
    /// exposing internal struct shape.
    #[cfg(test)]
    pub(crate) fn tracing_providers(&self) -> &[TracingProvider] {
        &self.tracing_providers
    }

    #[cfg(test)]
    pub(crate) fn span_reporting_disabled(&self) -> bool {
        self.span_reporting_disabled
    }

    fn trace_context_enabled(&self) -> bool {
        // Span export can be disabled while propagation stays enabled; Telemetry
        // provider config and sampling still require trace metadata on the request.
        self.span_reporting_disabled
            || self.sampling_percentage.is_some()
            || !self.tracing_providers.is_empty()
    }

    /// Stamp from `headers`, the request's own header map (`ctx.headers`):
    /// its folded `baggage` value is the one `mesh_authz` evaluates.
    fn annotate_http_context(&self, ctx: &mut RequestContext, headers: &HashMap<String, String>) {
        let probe = TraceHeaderProbe::scan(headers);
        let folded_baggage = headers.get(BAGGAGE_HEADER).map(String::as_str);
        self.annotate_http_context_with_probe(ctx, headers, &probe, folded_baggage);
    }

    /// Stamp from the `before_proxy` backend-visible map. Request transforms
    /// have already run, after authorization, so its `baggage` is NOT what
    /// `mesh_authz` evaluated: a transformer-added assertion must not be
    /// honored, and one a transformer stripped before forwarding must not be
    /// lost. While the pristine wire block is held, the folded value is
    /// rebuilt from it with materialization's own UTF-8 rule
    /// ([`hbone_wire_folded_baggage`]), so an obs-text field-line the ASCII
    /// raw accessor skips still counts exactly as it did for authorization;
    /// without a wire block the map's value is the only evidence.
    fn annotate_backend_http_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
    ) {
        let probe = TraceHeaderProbe::scan(headers);
        let wire_folded = (ctx.has_raw_headers() && is_hbone_request(ctx))
            .then(|| hbone_wire_folded_baggage(ctx))
            .flatten();
        let folded_baggage = if ctx.has_raw_headers() {
            wire_folded.as_deref()
        } else {
            headers.get(BAGGAGE_HEADER).map(String::as_str)
        };
        self.annotate_http_context_with_probe(ctx, headers, &probe, folded_baggage);
    }

    /// Stamp the request's mesh telemetry metadata and labels.
    ///
    /// The label keys are written through [`Self::stamp_http_labels`]; every
    /// other key is written to `ctx.metadata` exactly as before. `probe` must
    /// describe `headers`. `folded_baggage` is the folded `baggage` value read
    /// beside the pristine wire field-lines (see [`hbone_baggage_identity`]).
    fn annotate_http_context_with_probe(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        probe: &TraceHeaderProbe<'_>,
        folded_baggage: Option<&str>,
    ) {
        self.insert_common_metadata(&mut ctx.metadata);
        self.apply_telemetry_metadata_with_probe(&mut ctx.metadata, headers, probe);
        let cel_stamp_needs = effective_metric_tag_cel_stamp_needs(&ctx.metadata);
        // When `otel_tracing` established the gateway SERVER span it owns the
        // request's trace identity and its trust decision: re-deriving here
        // would re-parent that span, and importing the wire `tracestate`
        // would resurrect state `otel_tracing` dropped as untrusted.
        if self.should_ensure_http_trace_context(&ctx.metadata, probe)
            && !trace_owned_by_otel_tracing(ctx)
        {
            if !probe.has_valid_traceparent() {
                import_b3_trace_metadata(&mut ctx.metadata, probe);
            }
            ensure_trace_metadata(&mut ctx.metadata, headers);
            ctx.claim_gateway_trace_owner(
                crate::plugins::otel_tracing::GatewayTraceOwner::WorkloadMetrics,
            );
            // W3C Trace Context: an invalid `tracestate` list is dropped,
            // never propagated, while its parent is still honored.
            if let Some(tracestate) = probe
                .tracestate
                .filter(|value| crate::plugins::otel_tracing::is_valid_tracestate(value))
            {
                ctx.metadata
                    .insert(TRACESTATE_HEADER.to_string(), tracestate.to_string());
            }
        }
        let hbone_identity = hbone_identity_for_request(ctx, folded_baggage);
        let resolved_source = self.resolve_peer_source_identity(ctx, hbone_identity.as_ref());
        insert_metadata_if_changed(
            &mut ctx.metadata,
            "mesh.connection_security_policy",
            if ctx.peer_spiffe_id.is_some() || ctx.tls_client_cert_der.is_some() {
                "mutual_tls"
            } else {
                "none"
            },
        );
        let protocol = request_protocol(ctx, probe);
        insert_metadata_if_changed(&mut ctx.metadata, "mesh.request_protocol", protocol);
        // Stamp only attributes required by the active COMPOSED family plans.
        // Several effective instances may contribute different families or
        // replace the same family, so one instance's private requirements are
        // insufficient. Always clear unused HTTP-only keys so a reused metadata
        // bag cannot leak stale values into a later metric emission.
        if cel_stamp_needs.request_host {
            if let Some(authority) = ctx.request_authority.as_ref() {
                if authority.len() <= MAX_METRIC_TAG_VALUE_BYTES {
                    ctx.metadata.insert(
                        METRIC_TAG_CEL_REQUEST_HOST_METADATA.to_string(),
                        authority.clone(),
                    );
                } else {
                    ctx.metadata.remove(METRIC_TAG_CEL_REQUEST_HOST_METADATA);
                }
            } else if let Some(host) = header_value(headers, "host") {
                if host.len() <= MAX_METRIC_TAG_VALUE_BYTES {
                    ctx.metadata.insert(
                        METRIC_TAG_CEL_REQUEST_HOST_METADATA.to_string(),
                        host.to_string(),
                    );
                } else {
                    ctx.metadata.remove(METRIC_TAG_CEL_REQUEST_HOST_METADATA);
                }
            } else {
                ctx.metadata.remove(METRIC_TAG_CEL_REQUEST_HOST_METADATA);
            }
        } else {
            ctx.metadata.remove(METRIC_TAG_CEL_REQUEST_HOST_METADATA);
        }
        if cel_stamp_needs.request_method {
            if !ctx.method.is_empty() && ctx.method.len() <= MAX_METRIC_TAG_VALUE_BYTES {
                ctx.metadata.insert(
                    METRIC_TAG_CEL_REQUEST_METHOD_METADATA.to_string(),
                    ctx.method.clone(),
                );
            } else {
                ctx.metadata.remove(METRIC_TAG_CEL_REQUEST_METHOD_METADATA);
            }
        } else {
            ctx.metadata.remove(METRIC_TAG_CEL_REQUEST_METHOD_METADATA);
        }
        if cel_stamp_needs.destination_port {
            if let Some(port) = mesh_metric_destination_port(ctx) {
                ctx.metadata.insert(
                    METRIC_TAG_CEL_DESTINATION_PORT_METADATA.to_string(),
                    port.to_string(),
                );
            } else {
                ctx.metadata
                    .remove(METRIC_TAG_CEL_DESTINATION_PORT_METADATA);
            }
        } else {
            ctx.metadata
                .remove(METRIC_TAG_CEL_DESTINATION_PORT_METADATA);
        }
        if let Some(direction) = ctx.mesh_direction {
            insert_metadata_if_changed(
                &mut ctx.metadata,
                MESH_DIRECTION_METADATA,
                mesh_direction_str(direction),
            );
        }
        self.stamp_http_labels(ctx, resolved_source);
    }

    /// Project the request's source and destination workload labels.
    ///
    /// Every label key goes through one [`LabelWriter`]: into `ctx.metadata`
    /// exactly as it always has (unless the request's plugin view deferred the
    /// string projection because nothing can observe it), and always into the
    /// request's typed [`MeshLabelShadow`], from values resolved once per
    /// instance or per connection (issue #6793).
    ///
    /// This runs before authorization and again after request-header
    /// transforms. The SPIFFE-derived source labels are rebuilt as one atomic
    /// view, so a final peer with fewer path segments cannot retain namespace
    /// or service-account labels from early trusted baggage. The clear is
    /// skipped only when the identity this call stamps already matches the
    /// stamped labels exactly, which is the common repeat-annotate case; any
    /// identity change — including to or from `None` — still clears first.
    fn stamp_http_labels(&self, ctx: &mut RequestContext, resolved_source: ResolvedSourceIdentity) {
        let peer_source_identity: Option<&SpiffeId> = match &resolved_source {
            ResolvedSourceIdentity::Peer => ctx.peer_spiffe_id.as_ref(),
            ResolvedSourceIdentity::Asserted(identity) => Some(identity),
            ResolvedSourceIdentity::Absent => None,
        };
        let local = &self.local_facts;
        // Resolve every remote fact before borrowing the label sinks.
        let (source_identity, remote_source) = match ctx.mesh_direction {
            Some(MeshTrafficDirection::Inbound) => (
                peer_source_identity,
                Some(remote_source_facts(ctx, peer_source_identity)),
            ),
            // A NodeWaypoint outbound listener serves many captured pods. Its
            // accept path authenticates the originating pod and stamps both
            // fields together; use that asserted identity directly so request
            // baggage cannot spoof it and the shared waypoint is never
            // reported as the application source. Other outbound topologies
            // continue to attribute the local workload.
            Some(MeshTrafficDirection::Outbound) if ctx.node_waypoint_pod_uid.is_some() => (
                ctx.peer_spiffe_id.as_ref(),
                ctx.peer_spiffe_id
                    .as_ref()
                    .map(|identity| remote_source_facts(ctx, Some(identity))),
            ),
            Some(MeshTrafficDirection::Outbound) => (self.workload_spiffe_id.as_ref(), None),
            None => {
                let identity = peer_source_identity.or(self.workload_spiffe_id.as_ref());
                let remote = (identity != self.workload_spiffe_id.as_ref())
                    .then(|| remote_source_facts(ctx, identity));
                (identity, remote)
            }
        };
        // Remote facts carry their own SPIFFE labels; otherwise the stamped
        // identity is this workload's own.
        let source_spiffe: Option<&SpiffeLabels> = match remote_source.as_ref() {
            Some(remote) => remote.spiffe(),
            None => local.spiffe(),
        };
        let route = match ctx.mesh_direction {
            Some(MeshTrafficDirection::Inbound) => None,
            _ => ctx.matched_proxy.as_deref().map(|proxy| {
                (
                    proxy.namespace.as_str(),
                    proxy.name.as_deref().unwrap_or(&proxy.id),
                )
            }),
        };
        let shadow = ctx.mesh_labels.get_or_insert_with(Default::default);
        let mut labels = LabelWriter {
            metadata: (!ctx.mesh_label_projection_deferred).then_some(&mut ctx.metadata),
            shadow,
        };
        labels.source_spiffe(source_identity, source_spiffe);
        match ctx.mesh_direction {
            Some(MeshTrafficDirection::Inbound) => {
                labels.remote_source_workload(remote_source.as_deref());
                labels.local_destination(local);
            }
            Some(MeshTrafficDirection::Outbound) | None => {
                match remote_source.as_deref() {
                    // NodeWaypoint outbound attributes the captured pod.
                    Some(remote) if ctx.mesh_direction.is_some() => {
                        labels.remote_source_workload(Some(remote));
                    }
                    _ => labels.local_source_workload(local),
                }
                if let Some((namespace, destination)) = route {
                    labels.route_destination(namespace, destination);
                }
            }
        }
    }

    fn reconcile_captured_trace_headers(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> bool {
        // Metrics-only instances compose labels and custom tags without owning
        // trace context. Clearing a sibling's trace IDs here would suppress all
        // of its span exporters because this instance cannot rebuild the IDs.
        if !self.trace_context_enabled() {
            return false;
        }
        // `otel_tracing` owns this request's SERVER span: the backend map's
        // `traceparent` is that span, not a replacement parent, and no early
        // provenance markers were recorded for it.
        if trace_owned_by_otel_tracing(ctx) {
            ctx.metadata.remove(CAPTURED_TRACEPARENT_METADATA);
            ctx.metadata.remove(CAPTURED_B3_METADATA);
            ctx.metadata.remove(CAPTURED_TRACESTATE_METADATA);
            return false;
        }
        // `on_request_received` imports inbound context early so authorization
        // rejects remain observable. For accepted requests, request_transformer
        // runs before this hook and its final header policy is authoritative.
        // A valid final W3C or B3 value replaces every early-derived trace
        // field, including locally generated context when the transformer adds
        // traceparent. When an inbound W3C parent was captured, only a valid
        // final W3C parent may retain tracestate; a final B3 context can rebuild
        // its own trace identity but must not inherit orphan W3C state.
        let captured_traceparent = ctx.metadata.remove(CAPTURED_TRACEPARENT_METADATA).is_some();
        let captured_b3 = ctx.metadata.remove(CAPTURED_B3_METADATA).is_some();
        let captured_tracestate = ctx.metadata.remove(CAPTURED_TRACESTATE_METADATA).is_some();
        let final_traceparent = has_valid_traceparent(headers);
        let final_b3_context = !final_traceparent && has_b3_trace_context(headers);
        let final_b3_sampling = !final_traceparent && b3_sampling_decision(headers).is_some();
        let final_trace_signal = final_traceparent || final_b3_context || final_b3_sampling;
        // A final `traceparent` that is exactly the gateway SERVER span this
        // request already established (a sibling tracing plugin, or an earlier
        // instance, injected it) is this gateway's own context, not a new
        // parent. Re-deriving from it would mint a second SERVER span
        // parented under the first, which no exporter reports.
        let final_is_gateway_context = final_traceparent
            && header_value(headers, TRACEPARENT_HEADER).is_some_and(|value| {
                ctx.metadata
                    .get(TRACEPARENT_HEADER)
                    .is_some_and(|own| own == value)
            });

        if final_trace_signal && !final_is_gateway_context {
            clear_http_trace_metadata(&mut ctx.metadata);
        }

        if captured_traceparent && !final_traceparent {
            ctx.metadata.remove(TRACEPARENT_HEADER);
            ctx.metadata.remove(TRACESTATE_HEADER);
            // A transformer may remove the captured parent, replace it with
            // malformed hostile input, or leave/add tracestate independently.
            // Remove every casing of both W3C headers so neither the cached
            // parent nor an orphan tracestate can cross the proxy boundary.
            headers.retain(|name, _| {
                !name.eq_ignore_ascii_case(TRACEPARENT_HEADER)
                    && !name.eq_ignore_ascii_case(TRACESTATE_HEADER)
            });
        }

        if captured_b3 && !final_traceparent && !final_b3_context && !final_b3_sampling {
            ctx.metadata.remove(TRACEPARENT_HEADER);
            headers.retain(|name, _| {
                !B3_TRACE_HEADERS
                    .iter()
                    .any(|header| name.eq_ignore_ascii_case(header))
            });
        }

        if captured_tracestate && header_value(headers, TRACESTATE_HEADER).is_none() {
            ctx.metadata.remove(TRACESTATE_HEADER);
        }

        let suppress_local_trace = (captured_traceparent || captured_b3) && !final_trace_signal;
        if suppress_local_trace {
            clear_http_trace_metadata(&mut ctx.metadata);
        }
        suppress_local_trace
    }

    fn resolve_peer_source_identity(
        &self,
        ctx: &mut RequestContext,
        hbone_identity: Option<&HboneIdentity>,
    ) -> ResolvedSourceIdentity {
        // Resolve the source identity using the SAME baggage trust relation as
        // `mesh_authz` (shared `hbone_baggage_honor`) so the telemetry
        // attribution can never diverge from the authorization decision. When
        // mesh injection supplied `_effective_mesh_authz_baggage_gates`, every
        // enabled global mesh_authz gate is evaluated conjunctively: telemetry
        // honors baggage only if every effective authorization gate would.
        // Direct / user-created instances keep a single gate from this
        // plugin's own config. The forged identity is never echoed.
        let rejected_udp_source_scope =
            ctx.metadata.get(IGNORED_UDP_SOURCE_SCOPE_METADATA).cloned();
        if let Some(reason) = rejected_udp_source_scope.as_ref() {
            ctx.metadata
                .insert("mesh.ignored_baggage".to_string(), reason.clone());
        }
        let baggage_source_principal = if rejected_udp_source_scope.is_some() {
            None
        } else {
            hbone_identity.and_then(|identity| identity.source_principal.clone())
        };
        match (ctx.peer_spiffe_id.as_ref(), baggage_source_principal) {
            (Some(peer), Some(baggage)) => match self.baggage_trust.honor(peer, &baggage) {
                HboneBaggageHonor::UntrustedAssertor => {
                    ctx.metadata.insert(
                        "mesh.ignored_baggage".to_string(),
                        "untrusted_assertor".to_string(),
                    );
                    ResolvedSourceIdentity::Peer
                }
                HboneBaggageHonor::TrustDomainMismatch => {
                    ctx.metadata.insert(
                        "mesh.ignored_baggage".to_string(),
                        "trust_domain_mismatch".to_string(),
                    );
                    ResolvedSourceIdentity::Peer
                }
                HboneBaggageHonor::AssertionOutOfScope => {
                    ctx.metadata.insert(
                        "mesh.ignored_baggage".to_string(),
                        "assertion_out_of_scope".to_string(),
                    );
                    ResolvedSourceIdentity::Peer
                }
                HboneBaggageHonor::Honored => ResolvedSourceIdentity::Asserted(baggage),
            },
            // An unauthenticated request must never have its source identity
            // rewritten by baggage; fall back to the workload hint below.
            (None, Some(_)) => {
                ctx.metadata.insert(
                    "mesh.ignored_baggage".to_string(),
                    "unauthenticated_hbone".to_string(),
                );
                ResolvedSourceIdentity::Absent
            }
            // No baggage principal: use the authenticated peer identity if any.
            (Some(_), None) => ResolvedSourceIdentity::Peer,
            (None, None) => ResolvedSourceIdentity::Absent,
        }
    }

    fn should_ensure_http_trace_context<MS: std::hash::BuildHasher>(
        &self,
        metadata: &HashMap<String, String, MS>,
        probe: &TraceHeaderProbe<'_>,
    ) -> bool {
        self.trace_context_enabled()
            && (trace_is_sampled(metadata)
                || probe.has_valid_traceparent()
                || probe.has_b3_trace_context())
    }

    fn insert_common_metadata<MS: std::hash::BuildHasher>(
        &self,
        metadata: &mut HashMap<String, String, MS>,
    ) {
        if let Some(node_id) = self.node_id.as_ref() {
            insert_metadata_if_changed(metadata, "mesh.node_id", node_id);
        }
        if let Some(topology) = self.topology.as_ref() {
            insert_metadata_if_changed(metadata, "mesh.topology", topology);
        }
    }

    fn apply_telemetry_metadata<MS: std::hash::BuildHasher>(
        &self,
        metadata: &mut HashMap<String, String, MS>,
        headers: &HashMap<String, String>,
    ) {
        self.apply_telemetry_metadata_with_probe(
            metadata,
            headers,
            &TraceHeaderProbe::scan(headers),
        );
    }

    /// [`Self::apply_telemetry_metadata`] with the trace-header probe the
    /// caller already took over `headers`.
    fn apply_telemetry_metadata_with_probe<MS: std::hash::BuildHasher>(
        &self,
        metadata: &mut HashMap<String, String, MS>,
        headers: &HashMap<String, String>,
        probe: &TraceHeaderProbe<'_>,
    ) {
        if let Some(sampled) = existing_sampling_decision(metadata, probe) {
            metadata.insert(
                "trace_sampled".to_string(),
                if sampled { "true" } else { "false" }.to_string(),
            );
        } else if let Some(sampling_percentage) = self.sampling_percentage {
            let sampled = trace_sampled(sampling_percentage);
            metadata.insert(
                "trace_sampled".to_string(),
                if sampled { "true" } else { "false" }.to_string(),
            );
        }
        // This method runs both before authorization and after request
        // transformers. Clear header-backed values before rebuilding the final
        // view so a removed or over-limit header cannot leave stale metadata.
        // Literal values are then reapplied as the documented fallback before a
        // present valid header takes precedence.
        for key in self.custom_header_tags.keys() {
            metadata.remove(key);
        }
        for (key, value) in &self.custom_tags {
            insert_metadata_if_changed(metadata, key, value);
        }
        for (key, header_name) in &self.custom_header_tags {
            if let Some(value) = header_value(headers, header_name)
                && value.len() <= MAX_CUSTOM_TAG_VALUE_BYTES
            {
                // Fail closed: a header the operator has not declared safe is
                // copied as the redaction marker, never verbatim.
                let value = if self.redacted_header_tags.contains(key) {
                    REDACTED_PLACEHOLDER.to_string()
                } else {
                    value.to_string()
                };
                metadata.insert(key.clone(), value);
            }
        }
        if let Some(marker) = self.custom_trace_attributes_marker.as_ref() {
            let composed = metadata
                .entry(CUSTOM_TRACE_ATTRIBUTES_METADATA.to_string())
                .or_default();
            if composed != marker {
                // Cache admission bounds the union across the effective chain.
                // Repeated early/final hooks must not duplicate names.
                for name in marker.split(',') {
                    if !composed.split(',').any(|existing| existing == name) {
                        if !composed.is_empty() {
                            composed.push(',');
                        }
                        composed.push_str(name);
                    }
                }
            }
        }
        // Instance-immutable values: the repeat stamp (request-received, then
        // before-proxy) is one borrowed comparison, not a fresh key and up to
        // 16 KiB of plan bytes copied again per family.
        if let Some(marker) = self.disabled_metrics_marker.as_ref() {
            insert_metadata_if_changed(metadata, MESH_METRICS_DISABLED_METADATA, marker);
        }
        for (family, plan) in &self.tag_override_plans {
            insert_metadata_if_changed(metadata, family.override_metadata_key(), plan);
        }
    }

    fn should_export_metadata<MS: std::hash::BuildHasher>(
        &self,
        metadata: &HashMap<String, String, MS>,
    ) -> bool {
        if trace_is_sampled(metadata) {
            return true;
        }
        if metadata_has_sampling_decision(metadata) {
            return false;
        }
        if self.sampling_percentage.is_some() {
            tracing::debug!(
                plugin = "workload_metrics",
                "missing trace sampling decision; skipping span export"
            );
        }
        false
    }

    fn local_workload_labels(&self) -> (&str, &str, &str) {
        (
            self.local_facts.workload(),
            self.local_facts.app(),
            self.local_facts.service(),
        )
    }

    fn insert_local_source_workload_labels<MS: std::hash::BuildHasher>(
        &self,
        metadata: &mut HashMap<String, String, MS>,
    ) {
        if let Some(namespace) = self.namespace.as_ref() {
            insert_metadata_if_changed(metadata, "mesh.source.namespace", namespace);
        }
        let (workload, app, service) = self.local_workload_labels();
        insert_metadata_if_changed(metadata, "mesh.source.workload", workload);
        insert_metadata_if_changed(metadata, "mesh.source.app", app);
        insert_metadata_if_changed(metadata, "mesh.source.service", service);
    }

    fn insert_local_destination_workload_labels<MS: std::hash::BuildHasher>(
        &self,
        metadata: &mut HashMap<String, String, MS>,
    ) {
        if let Some(identity) = self.workload_spiffe_id.as_ref() {
            insert_destination_spiffe_labels(metadata, identity);
        }
        if let Some(namespace) = self.namespace.as_ref() {
            insert_metadata_if_changed(metadata, "mesh.destination.namespace", namespace);
        }
        let (workload, app, service) = self.local_workload_labels();
        insert_metadata_if_changed(metadata, "mesh.destination.workload", workload);
        insert_metadata_if_changed(metadata, "mesh.destination.app", app);
        insert_metadata_if_changed(metadata, "mesh.destination.service", service);
    }

    fn insert_remote_source_workload_labels<MS: std::hash::BuildHasher>(
        &self,
        metadata: &mut HashMap<String, String, MS>,
        identity: Option<&SpiffeId>,
    ) {
        let workload = identity
            .and_then(SpiffeId::service_account)
            .unwrap_or("unknown");
        insert_metadata_if_changed(metadata, "mesh.source.workload", workload);
        insert_metadata_if_changed(metadata, "mesh.source.app", workload);
        insert_metadata_if_changed(metadata, "mesh.source.service", workload);
    }

    fn insert_proxy_destination_labels<MS: std::hash::BuildHasher>(
        &self,
        metadata: &mut HashMap<String, String, MS>,
        namespace: &str,
        destination: &str,
    ) {
        insert_metadata_if_changed(metadata, "mesh.destination.namespace", namespace);
        insert_metadata_if_changed(metadata, "mesh.destination.workload", destination);
        insert_metadata_if_changed(metadata, "mesh.destination.app", destination);
        insert_metadata_if_changed(metadata, "mesh.destination.service", destination);
    }

    /// Whether a finished span can reach any exporter. Callers check this
    /// BEFORE building a [`SpanData`]: propagation-only instances (span
    /// reporting disabled, or no provider) would otherwise build every sampled
    /// span's owned IDs and projected attributes only to drop them.
    fn span_export_active(&self) -> bool {
        !self.span_reporting_disabled && !self.trace_exporters.is_empty()
    }

    fn export_span(&self, span: Option<SpanData>) {
        if !self.span_export_active() {
            return;
        }
        let Some(span) = span else {
            return;
        };
        let Some((last_exporter, earlier_exporters)) = self.trace_exporters.split_last() else {
            return;
        };
        for exporter in earlier_exporters {
            if let Err(error) = exporter.try_export(span.clone()) {
                self.record_export_drop(exporter.provider_name(), &error);
            }
        }
        if let Err(error) = last_exporter.try_export(span) {
            self.record_export_drop(last_exporter.provider_name(), &error);
        }
    }

    /// Count a refused span on `ferrum_mesh_tracing_spans_dropped_total` (fixed
    /// provider/reason labels, never the endpoint or error text) and emit the
    /// rate-limited diagnostic.
    fn record_export_drop(&self, provider: &'static str, error: &str) {
        increment_mesh_tracing_span_dropped(
            MeshTracingProvider::from_exporter_name(provider),
            trace_export_drop_reason(error),
        );
        let now_ms = crate::socket_opts::monotonic_now_ms();
        let suppressed = match self.export_drop_log_limiter.lock() {
            Ok(mut limiter) => limiter.on_event(now_ms),
            Err(poisoned) => poisoned.into_inner().on_event(now_ms),
        };
        if let Some(suppressed) = suppressed {
            tracing::warn!(
                provider = provider,
                suppressed = suppressed,
                error = %error,
                "workload_metrics trace export buffer rejected a span"
            );
        }
    }

    async fn log_span(&self, summary: &TransactionSummary) {
        if summary.mirror || !self.span_export_active() {
            return;
        }
        if !self.should_export_metadata(&summary.metadata) {
            return;
        }
        let direction = summary
            .metadata
            .get(MESH_DIRECTION_METADATA)
            .and_then(|value| parse_mesh_direction_metadata(value));
        if !self.direction_emit.emits_for(direction) {
            return;
        }
        let kind = match direction {
            Some(MeshTrafficDirection::Outbound) => SpanKind::Client,
            _ => SpanKind::Server,
        };
        self.export_span(SpanData::from_transaction_summary_with_kind(
            summary,
            &self.service_name,
            kind,
            true,
            2_048,
        ));
    }
}

/// Enforce the aggregate per-proxy metric tag-override plan budget against the
/// final effective `workload_metrics` chain before a PluginCache generation is
/// published.
///
/// Composition mirrors request/stream stamping: instances run in chain order, a
/// later unconditional plan replaces the same metric family, and untouched
/// family plans survive. For a triggered instance, either the replacement or
/// the earlier plan can survive for a particular request, so admission retains
/// the larger possible family plan. The bound is the sum of these worst-case
/// surviving stamped plan lengths — the same 16,384-byte ceiling documented for
/// per-instance construction — never the sum of every intermediate instance.
/// Diagnostics name the proxy only and never echo plan bytes, expressions,
/// request data, or secrets.
/// The custom trace attribute union is also capped at 32 names, including
/// conditional instances, so composing ownership cannot truncate exports.
pub(crate) fn validate_effective_metric_tag_override_plan_budget(
    plugins: &[Arc<dyn Plugin>],
    proxy_id: &str,
) -> Result<(), String> {
    let mut effective_plan_lengths = [0usize; MeshMetricFamily::ALL.len()];
    let mut custom_tag_names = BTreeSet::new();
    for plugin in plugins {
        // Only the registered plugin stamps these plans. A custom plugin
        // reporting its name must not displace a real instance's family plan
        // from the sum (issue #6022).
        if plugin.name() != "workload_metrics"
            || !crate::plugins::is_builtin_plugin(plugin.as_ref())
        {
            continue;
        }
        if let Some(marker) = plugin.workload_custom_trace_attributes() {
            custom_tag_names.extend(marker.split(','));
            if custom_tag_names.len() > MAX_CUSTOM_TAGS {
                return Err(format!(
                    "proxy_id={proxy_id:?}: workload_metrics effective custom tags exceed {MAX_CUSTOM_TAGS} distinct names"
                ));
            }
        }
        let conditional = plugin.metric_tag_override_plans_are_conditional();
        for (family, plan) in plugin.metric_tag_override_plans() {
            let effective = &mut effective_plan_lengths[family.index()];
            if conditional {
                *effective = (*effective).max(plan.len());
            } else {
                *effective = plan.len();
            }
        }
    }
    let mut total = 0usize;
    for plan_len in effective_plan_lengths {
        total = total.checked_add(plan_len).ok_or_else(|| {
            format!(
                "proxy_id={proxy_id:?}: workload_metrics effective metric tag override plans exceed {MAX_METRIC_TAG_OVERRIDE_PLAN_BYTES} encoded bytes across surviving families"
            )
        })?;
        if total > MAX_METRIC_TAG_OVERRIDE_PLAN_BYTES {
            return Err(format!(
                "proxy_id={proxy_id:?}: workload_metrics effective metric tag override plans exceed {MAX_METRIC_TAG_OVERRIDE_PLAN_BYTES} encoded bytes across surviving families"
            ));
        }
    }
    Ok(())
}

#[async_trait]
impl Plugin for WorkloadMetrics {
    fn name(&self) -> &str {
        "workload_metrics"
    }

    fn records_mesh_service_graph(&self, _summary: &TransactionSummary) -> bool {
        true
    }

    fn workload_custom_trace_attributes(&self) -> Option<&str> {
        self.custom_trace_attributes_marker.as_deref()
    }

    fn metric_tag_override_plans(&self) -> &[(MeshMetricFamily, String)] {
        &self.tag_override_plans
    }

    fn priority(&self) -> u16 {
        priority::WORKLOAD_METRICS
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::ON_REQUEST_RECEIVED
            | crate::plugins::PluginHooks::BEFORE_PROXY
            | crate::plugins::PluginHooks::AFTER_PROXY
            | crate::plugins::PluginHooks::LOG
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.trace_context_enabled()
    }

    /// Reusable (issue #5583): pure observability. Every hook it implements
    /// stamps RED labels, workload attribution, and trace context onto the
    /// transaction and then returns `Continue`. It takes no admission
    /// decision, holds no per-request budget, makes no external
    /// admission call, and never rejects — so nothing an elided CONNECT would
    /// have decided is lost. What reuse costs here is FIDELITY, not
    /// enforcement: one tunnel summary stands for every operation the tunnel
    /// carried, the same trade the relay already makes for the inner requests
    /// it byte-copies without ever parsing them.
    fn allows_hbone_inner_reuse(&self) -> bool {
        true
    }

    /// The labels are this plugin's own projection; it reads them back only
    /// to export spans (`log_span` serializes summary metadata into span
    /// attributes). An instance that can export no span leaves them to the
    /// typed label projection (issue #6793).
    fn observes_mesh_label_metadata(&self) -> bool {
        self.span_export_active()
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // The authorization phase runs after every plugin's request-received
        // phase. Stamp telemetry here so mesh_authz rejects still retain RED
        // labels and trace context; before_proxy refreshes the same metadata
        // after route selection for accepted requests.
        let headers = std::mem::take(&mut ctx.headers);
        let probe = TraceHeaderProbe::scan(&headers);
        let captured_traceparent = probe.has_valid_traceparent();
        let captured_b3 = probe.has_b3_trace_context() || probe.b3_sampling_decision().is_some();
        let captured_tracestate = probe.tracestate.is_some();
        self.annotate_http_context_with_probe(
            ctx,
            &headers,
            &probe,
            headers.get(BAGGAGE_HEADER).map(String::as_str),
        );
        if captured_traceparent && ctx.metadata.contains_key(TRACEPARENT_HEADER) {
            ctx.metadata.insert(
                CAPTURED_TRACEPARENT_METADATA.to_string(),
                "true".to_string(),
            );
        }
        if captured_tracestate && ctx.metadata.contains_key(TRACESTATE_HEADER) {
            ctx.metadata
                .insert(CAPTURED_TRACESTATE_METADATA.to_string(), "true".to_string());
        }
        if captured_b3 {
            ctx.metadata
                .insert(CAPTURED_B3_METADATA.to_string(), "true".to_string());
        }
        ctx.headers = headers;
        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let suppress_local_trace = self.reconcile_captured_trace_headers(ctx, headers);
        self.annotate_backend_http_context(ctx, headers);
        if suppress_local_trace {
            clear_http_trace_metadata(&mut ctx.metadata);
        }
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            set_header_case_insensitive(headers, TRACEPARENT_HEADER, traceparent);
        }
        if let Some(tracestate) = ctx.metadata.get(TRACESTATE_HEADER) {
            set_header_case_insensitive(headers, TRACESTATE_HEADER, tracestate);
        }
        // B3 rides beside W3C: always for a Zipkin provider, and whenever the
        // backend request still carries B3 context, whose stale copy (the
        // caller's span) would otherwise make a B3-only backend continue from
        // the parent instead of this gateway span. Metrics-only instances own
        // no trace context and leave the headers alone.
        if self.trace_context_enabled() {
            let b3 = backend_b3_headers(headers);
            if self.b3_propagation || b3.any {
                inject_b3_trace_headers(&ctx.metadata, headers, b3.single);
            }
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // `on_request_received` stamps source labels before `mesh_authz`
        // evaluates Ambient UDP pod-UID/source-scope evidence. When authz
        // discards that evidence (`mesh_authz.ignored_udp_source_scope`) and
        // rejects, `before_proxy` never runs, so restamp here — this hook runs
        // on the reject path before the rejected transaction summary is built.
        // The stale baggage-derived source keys are cleared first because the
        // attesting-peer fallback identity may not carry every SPIFFE path
        // segment the discarded baggage principal did.
        // A deferred label projection keeps the stamped principal only in the
        // request's typed shadow (issue #6793).
        let stamped_source_principal = if ctx.mesh_label_projection_deferred {
            ctx.mesh_labels
                .as_deref()
                .and_then(|labels| labels.get(MeshLabel::SourcePrincipal))
        } else {
            ctx.metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str)
        };
        if ctx.metadata.contains_key(IGNORED_UDP_SOURCE_SCOPE_METADATA)
            && stamped_source_principal != ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str)
        {
            clear_source_spiffe_labels(&mut ctx.metadata);
            let headers = std::mem::take(&mut ctx.headers);
            self.annotate_http_context(ctx, &headers);
            ctx.headers = headers;
        }
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            response_headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        // Accepted requests consume these markers in `before_proxy`. Rejects
        // intentionally retain the early trace context through this hook, then
        // discard the temporary provenance markers before transaction logging.
        ctx.metadata.remove(CAPTURED_TRACEPARENT_METADATA);
        ctx.metadata.remove(CAPTURED_TRACESTATE_METADATA);
        ctx.metadata.remove(CAPTURED_B3_METADATA);
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        // Always participate in reject-path `after_proxy`: even with tracing
        // disabled, a mesh_authz UDP source-scope reject needs its RED /
        // service-graph source labels restamped (see `after_proxy`).
        true
    }

    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        // When `workload_metrics` is the mesh tracing plugin its `after_proxy`
        // echoes the gateway-authored `traceparent` from `ctx.metadata`, exactly
        // like `otel_tracing`. If the backend already echoed that identical
        // value, mutation tracking sees no change, so declare ownership so a
        // buffered gRPC deadline rebuild preserves the gateway trace context.
        name.eq_ignore_ascii_case(TRACEPARENT_HEADER)
            && ctx.metadata.contains_key(TRACEPARENT_HEADER)
    }

    /// Same contract as `otel_tracing`: the echoed `traceparent` is the
    /// gateway's, an identical backend echo hides the write from
    /// observed-mutation reconciliation, and a backend `traceparent` TRAILER
    /// must not replace it after the fact.
    fn response_trailer_policy(&self) -> crate::plugins::ResponseTrailerPolicy<'_> {
        if self.trace_context_enabled() {
            crate::plugins::ResponseTrailerPolicy::Names(
                &crate::plugins::TRACEPARENT_RESPONSE_POLICY_NAMES,
            )
        } else {
            crate::plugins::ResponseTrailerPolicy::None
        }
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let stamped_direction = ctx.mesh_direction;
        let peer_identity = ctx
            .authenticated_identity
            .as_deref()
            .and_then(|value| SpiffeId::new(value).ok())
            .or_else(|| {
                ctx.metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("peer_spiffe_id"))
                    .and_then(|value| SpiffeId::new(value).ok())
            });
        let proxy_name = ctx
            .proxy_name
            .as_deref()
            .unwrap_or(ctx.proxy_id.as_str())
            .to_string();
        let proxy_namespace = mesh_service_namespace(&proxy_name)
            .map(str::to_owned)
            .or_else(|| self.namespace.clone())
            .unwrap_or_default();
        let request_protocol = if ctx.backend_scheme.is_udp() {
            "udp"
        } else {
            "tcp"
        };
        let metadata = ctx.metadata.get_or_insert_with(Default::default);
        // The stream path, rather than an individual plugin instance, owns the
        // exactly-once TCP opened/closed lifecycle. Prove that at least one
        // workload_metrics instance actually observed this connection before a
        // later finalizer can emit it: mesh routing/security code may have
        // pre-populated other `mesh.*` labels even when an earlier plugin
        // rejects before this hook is reached.
        metadata.insert(
            MESH_WORKLOAD_METRICS_OBSERVED_METADATA.to_string(),
            "1".to_string(),
        );
        self.insert_common_metadata(metadata);
        self.apply_telemetry_metadata(metadata, &HashMap::new());
        let cel_stamp_needs = effective_metric_tag_cel_stamp_needs(metadata);
        if self.trace_context_enabled() && trace_is_sampled(metadata) {
            ensure_trace_metadata(metadata, &HashMap::new());
        }
        if let Some(direction) = stamped_direction {
            metadata.insert(
                MESH_DIRECTION_METADATA.to_string(),
                mesh_direction_str(direction).to_string(),
            );
        }
        metadata.insert(
            "mesh.connection_security_policy".to_string(),
            if ctx.tls_client_cert_der.is_some() || peer_identity.is_some() {
                "mutual_tls"
            } else {
                "none"
            }
            .to_string(),
        );
        metadata.insert(
            "mesh.request_protocol".to_string(),
            request_protocol.to_string(),
        );
        // Clear HTTP-only CEL attributes on the stream path so a reused
        // metadata bag cannot leak request.host/method into TCP metrics.
        metadata.remove(METRIC_TAG_CEL_REQUEST_HOST_METADATA);
        metadata.remove(METRIC_TAG_CEL_REQUEST_METHOD_METADATA);
        if cel_stamp_needs.destination_port {
            let port = mesh_stream_authz_destination_port(
                ctx.connection_destination_port,
                ctx.destination_port,
                ctx.listen_port,
            );
            if port != 0 {
                metadata.insert(
                    METRIC_TAG_CEL_DESTINATION_PORT_METADATA.to_string(),
                    port.to_string(),
                );
            } else {
                metadata.remove(METRIC_TAG_CEL_DESTINATION_PORT_METADATA);
            }
        } else {
            metadata.remove(METRIC_TAG_CEL_DESTINATION_PORT_METADATA);
        }
        match stamped_direction {
            Some(MeshTrafficDirection::Inbound) => {
                if let Some(identity) = peer_identity.as_ref() {
                    insert_source_spiffe_labels(metadata, identity);
                }
                self.insert_remote_source_workload_labels(metadata, peer_identity.as_ref());
                self.insert_local_destination_workload_labels(metadata);
            }
            Some(MeshTrafficDirection::Outbound) => {
                // Captured L4 egress (NodeWaypoint TCP, Ambient UDP) runs on
                // the node data plane but carries the originating pod's
                // verified identity as the authenticated peer. Honor it as
                // the source so CLIENT spans/labels attribute the traffic to
                // the captured workload instead of the waypoint/ztunnel.
                if let Some(identity) = peer_identity.as_ref() {
                    insert_source_spiffe_labels(metadata, identity);
                    self.insert_remote_source_workload_labels(metadata, Some(identity));
                } else {
                    if let Some(identity) = self.workload_spiffe_id.as_ref() {
                        insert_source_spiffe_labels(metadata, identity);
                    }
                    self.insert_local_source_workload_labels(metadata);
                }
                self.insert_proxy_destination_labels(metadata, &proxy_namespace, &proxy_name);
            }
            None => {
                let source_identity = peer_identity.as_ref().or(self.workload_spiffe_id.as_ref());
                if let Some(identity) = source_identity {
                    insert_source_spiffe_labels(metadata, identity);
                }
                self.insert_local_source_workload_labels(metadata);
                self.insert_proxy_destination_labels(metadata, &proxy_namespace, &proxy_name);
            }
        }
        // TCP_OPENED_CONNECTIONS is deliberately NOT emitted here. Several
        // effective `workload_metrics` instances may run this hook for one
        // connection, each over metadata that later instances still modify, and
        // a later plugin may still reject the stream or the client may
        // disconnect during admission. The stream path finalizes the opened
        // counter once after the last hook that actually ran (and, for captured
        // mesh egress TCP, after selected target metadata is stamped) via
        // `prometheus_helpers::finalize_mesh_tcp_opened_stream`.
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if !self.span_export_active() || !self.should_export_metadata(&summary.metadata) {
            return;
        }
        let direction = summary
            .metadata
            .get(MESH_DIRECTION_METADATA)
            .and_then(|value| parse_mesh_direction_metadata(value));
        if !self.direction_emit.emits_for(direction) {
            return;
        }
        let kind = match direction {
            Some(MeshTrafficDirection::Outbound) => SpanKind::Client,
            _ => SpanKind::Server,
        };
        self.export_span(SpanData::from_stream_summary_with_kind(
            summary,
            &self.service_name,
            kind,
            2_048,
        ));
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.log_span(summary).await;
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.trace_exporters
            .iter()
            .filter_map(|exporter| exporter.hostname().map(ToOwned::to_owned))
            .collect()
    }
}

fn string_config(config: &Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn string_map_config(config: &Value, key: &str) -> Result<HashMap<String, String>, String> {
    let Some(value) = config.get(key) else {
        return Ok(HashMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("workload_metrics: `{key}` must be an object"))?;
    object
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_string()))
                .ok_or_else(|| format!("workload_metrics: `{key}` values must be strings"))
        })
        .collect()
}

fn parse_direction_emit(config: &Value) -> Result<DirectionEmit, String> {
    match config.get("direction_emit") {
        None | Some(Value::Null) => Ok(DirectionEmit::server_only()),
        Some(value) => super::diagnostics::from_value::<
            crate::util::json_object::JsonObject<DirectionEmit>,
        >(value.clone(), super::diagnostics::Schema::Direction)
        .map(|object| object.0)
        .map_err(|e| format!("workload_metrics: invalid `direction_emit` config: {e}")),
    }
}

/// Closed direct provider envelope. [`TracingProvider`] is the adjacently
/// tagged mesh-slice type, whose serde derive ignores unknown members, so the
/// direct plugin config closes the envelope and each `config` here.
const TRACING_PROVIDER_ENVELOPE_KEYS: &[&str] = &["kind", "config"];
const ZIPKIN_PROVIDER_CONFIG_KEYS: &[&str] = &["url"];
const DATADOG_PROVIDER_CONFIG_KEYS: &[&str] = &["agent_url", "service"];
const LIGHTSTEP_PROVIDER_CONFIG_KEYS: &[&str] =
    &["collector_url", "access_token_env", "accessTokenEnv"];
const OPENTELEMETRY_PROVIDER_CONFIG_KEYS: &[&str] = &["endpoint"];

fn tracing_provider_config_keys(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "zipkin" => Some(ZIPKIN_PROVIDER_CONFIG_KEYS),
        "datadog" => Some(DATADOG_PROVIDER_CONFIG_KEYS),
        "lightstep" => Some(LIGHTSTEP_PROVIDER_CONFIG_KEYS),
        "opentelemetry" => Some(OPENTELEMETRY_PROVIDER_CONFIG_KEYS),
        // An unknown `kind` is refused by the typed decode below.
        _ => None,
    }
}

/// Reject unknown members of one provider envelope and its `config`. Shape
/// errors (non-object envelope or config, unknown `kind`) are left to the
/// typed decode, which reports them with the provider path.
fn reject_unknown_tracing_provider_keys(provider: &Value, path: &str) -> Result<(), String> {
    let Some(envelope) = provider.as_object() else {
        return Ok(());
    };
    crate::util::unknown_keys::reject_unknown_keys(
        envelope,
        path,
        TRACING_PROVIDER_ENVELOPE_KEYS,
        "workload_metrics: ",
    )?;
    let Some(allowed) = envelope
        .get("kind")
        .and_then(Value::as_str)
        .and_then(tracing_provider_config_keys)
    else {
        return Ok(());
    };
    if let Some(provider_config) = envelope.get("config").and_then(Value::as_object) {
        crate::util::unknown_keys::reject_unknown_keys(
            provider_config,
            &format!("{path}.config"),
            allowed,
            "workload_metrics: ",
        )?;
    }
    Ok(())
}

fn parse_tracing_providers(config: &Value) -> Result<Vec<TracingProvider>, String> {
    if let Some(value) = config.get("tracing_providers") {
        if value.is_null() {
            return Ok(Vec::new());
        }
        if let Some(providers) = value.as_array() {
            for (idx, provider) in providers.iter().enumerate() {
                reject_unknown_tracing_provider_keys(
                    provider,
                    &format!("tracing_providers[{idx}]"),
                )?;
            }
        }
        return super::diagnostics::from_value::<Vec<TracingProvider>>(
            value.clone(),
            super::diagnostics::Schema::Provider,
        )
        .map_err(|e| format!("workload_metrics: invalid `tracing_providers` config: {e}"));
    }

    match config.get("tracing_provider") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(value) => {
            reject_unknown_tracing_provider_keys(value, "tracing_provider")?;
            Ok(vec![
                super::diagnostics::from_value::<TracingProvider>(
                    value.clone(),
                    super::diagnostics::Schema::Provider,
                )
                .map_err(|e| format!("workload_metrics: invalid `tracing_provider` config: {e}"))?,
            ])
        }
    }
}

struct ParsedMetricConfig {
    tag_override_plans: Vec<(MeshMetricFamily, String)>,
    disabled_metrics_marker: Option<String>,
}

#[derive(Clone, Copy)]
enum MetricSelector {
    All,
    Emitted(MeshMetricFamily),
}

fn metric_selector(name: &str) -> Option<MetricSelector> {
    if name.trim().eq_ignore_ascii_case("ALL_METRICS") {
        return Some(MetricSelector::All);
    }
    MeshMetricFamily::from_config_name(name).map(MetricSelector::Emitted)
}

enum ParsedTagOperation<'a> {
    Remove,
    Rename(&'a str),
    Set(&'a str),
    SetExpr(MetricTagCelExpr),
}

fn parse_tag_operation<'a>(
    name: &str,
    operation: &'a serde_json::Map<String, Value>,
) -> Result<ParsedTagOperation<'a>, String> {
    match operation.get("type").and_then(Value::as_str) {
        Some("remove") => Ok(ParsedTagOperation::Remove),
        Some("rename") => operation
            .get("new_name")
            .and_then(Value::as_str)
            .map(ParsedTagOperation::Rename)
            .ok_or_else(|| {
                format!("workload_metrics: `new_name` is required to rename metric tag {name:?}")
            }),
        Some("set") => {
            let value = operation
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!("workload_metrics: `value` is required to set metric tag {name:?}")
                })?;
            if value.len() > MAX_METRIC_TAG_VALUE_BYTES {
                return Err(format!(
                    "workload_metrics: metric tag {name:?} `value` exceeds {MAX_METRIC_TAG_VALUE_BYTES} bytes"
                ));
            }
            Ok(ParsedTagOperation::Set(value))
        }
        Some("set_expr") => {
            if operation.get("expression").is_some() && operation.get("cel").is_some() {
                return Err(format!(
                    "workload_metrics: `set_expr` metric tag {name:?} sets both `cel` and `expression`; set exactly one"
                ));
            }
            if let Some(expression) = operation.get("expression") {
                let expression: MetricTagCelExpr = serde_json::from_value(expression.clone())
                    .map_err(|_| {
                        format!(
                            "workload_metrics: invalid compiled CEL `expression` for metric tag {name:?}"
                        )
                    })?;
                validate_metric_tag_cel_expr_named(name, &expression)?;
                return Ok(ParsedTagOperation::SetExpr(expression));
            }
            let cel = operation.get("cel").and_then(Value::as_str).ok_or_else(|| {
                format!(
                    "workload_metrics: `cel` or `expression` is required for `set_expr` metric tag {name:?}"
                )
            })?;
            let expression = parse_metric_tag_cel_expression(cel).map_err(|error| {
                format!(
                    "workload_metrics: metric tag {name:?} CEL `cel` expression rejected: {error}"
                )
            })?;
            validate_metric_tag_cel_expr_named(name, &expression)?;
            Ok(ParsedTagOperation::SetExpr(expression))
        }
        Some(operation_type) => Err(format!(
            "workload_metrics: unsupported operation `type` {operation_type:?} for metric tag {name:?}"
        )),
        None => Err(format!(
            "workload_metrics: operation `type` is required for metric tag {name:?}"
        )),
    }
}

fn validate_metric_tag_cel_expr_named(
    name: &str,
    expression: &MetricTagCelExpr,
) -> Result<(), String> {
    crate::modes::mesh::metric_tag_cel::validate_metric_tag_cel_expr(expression).map_err(|error| {
        format!("workload_metrics: metric tag {name:?} CEL `expression` rejected: {error}")
    })
}

fn encode_metric_tag_cel_expr(expr: &MetricTagCelExpr, out: &mut String) {
    match expr {
        MetricTagCelExpr::Literal { value } => {
            out.push('L');
            out.push_str(&value.len().to_string());
            out.push(':');
            out.push_str(value);
        }
        MetricTagCelExpr::Attribute { name } => {
            out.push('A');
            out.push_str(&name.plan_id().to_string());
        }
        MetricTagCelExpr::StringOfInt { attribute } => {
            out.push('I');
            out.push_str(&attribute.plan_id().to_string());
        }
        MetricTagCelExpr::HasThenElse {
            attribute,
            then_expr,
            else_expr,
        } => {
            out.push('H');
            out.push_str(&attribute.plan_id().to_string());
            out.push(',');
            let mut then_buf = String::new();
            encode_metric_tag_cel_expr(then_expr, &mut then_buf);
            out.push_str(&then_buf.len().to_string());
            out.push(':');
            out.push_str(&then_buf);
            let mut else_buf = String::new();
            encode_metric_tag_cel_expr(else_expr, &mut else_buf);
            out.push_str(&else_buf.len().to_string());
            out.push(':');
            out.push_str(&else_buf);
        }
    }
}

fn mesh_metric_destination_port(ctx: &RequestContext) -> Option<u16> {
    // Keep metric attribution on the exact transport-derived port used by
    // mesh authorization. In particular, Sidecar ingress and HBONE relay
    // routes must not fall back to their backend dial port when the declared
    // listener/CONNECT authority stamp is absent.
    mesh_authz_destination_port(
        ctx.mesh_direction,
        ctx.matched_proxy.as_deref(),
        ctx.mesh_inbound_listener_authz_port,
        ctx.mesh_outbound_destination_authz_port,
        ctx.orig_dst,
        ctx.frontend_listen_port,
    )
    .filter(|port| *port != 0)
}

/// Union the CEL inputs required by the per-family plans that are actually
/// active in request/stream metadata after effective workload-metrics
/// instances compose. The fixed ten-family scan is bounded and does not parse
/// CEL or allocate. A missing/malformed marker beside an active plan falls
/// back to all inputs so coordination corruption cannot silently evaluate a
/// valid expression against absent authoritative data.
fn effective_metric_tag_cel_stamp_needs<MS: std::hash::BuildHasher>(
    metadata: &HashMap<String, String, MS>,
) -> MetricTagCelStampNeeds {
    let mut effective = MetricTagCelStampNeeds::default();
    for family in MeshMetricFamily::ALL {
        let Some(plan) = metadata.get(family.override_metadata_key()) else {
            continue;
        };
        let family_needs = split_metric_tag_cel_plan(plan)
            .map(|(needs, _)| needs)
            .unwrap_or_else(MetricTagCelStampNeeds::all);
        effective.merge(family_needs);
    }
    effective
}

/// Closed `metrics` object and `metrics.tag_overrides[]` entry key sets.
const METRICS_CONFIG_KEYS: &[&str] = &["disabled_metrics", "tag_overrides"];
const METRIC_TAG_OVERRIDE_KEYS: &[&str] = &["metric", "name", "operation"];

/// Closed `metrics.tag_overrides[].operation` key sets, per operation `type`,
/// so a field another operation reads (`value` on a `rename`) is refused
/// rather than silently ignored.
const REMOVE_TAG_OPERATION_KEYS: &[&str] = &["type"];
const RENAME_TAG_OPERATION_KEYS: &[&str] = &["type", "new_name"];
const SET_TAG_OPERATION_KEYS: &[&str] = &["type", "value"];
const SET_EXPR_TAG_OPERATION_KEYS: &[&str] = &["type", "cel", "expression"];

fn tag_operation_keys(operation_type: &str) -> Option<&'static [&'static str]> {
    match operation_type {
        "remove" => Some(REMOVE_TAG_OPERATION_KEYS),
        "rename" => Some(RENAME_TAG_OPERATION_KEYS),
        "set" => Some(SET_TAG_OPERATION_KEYS),
        "set_expr" => Some(SET_EXPR_TAG_OPERATION_KEYS),
        // An unknown or missing `type` is refused by `parse_tag_operation`.
        _ => None,
    }
}

fn parse_metric_config(value: Option<&Value>) -> Result<ParsedMetricConfig, String> {
    let Some(metrics) = value else {
        return Ok(ParsedMetricConfig {
            tag_override_plans: Vec::new(),
            disabled_metrics_marker: None,
        });
    };
    let object = metrics
        .as_object()
        .ok_or_else(|| "workload_metrics: `metrics` must be an object".to_string())?;
    crate::util::unknown_keys::reject_unknown_keys(
        object,
        "metrics",
        METRICS_CONFIG_KEYS,
        "workload_metrics: ",
    )?;
    let mut disabled = BTreeSet::new();
    if let Some(value) = object.get("disabled_metrics") {
        let entries = value.as_array().ok_or_else(|| {
            "workload_metrics: `metrics.disabled_metrics` must be an array".to_string()
        })?;
        for (idx, metric) in entries.iter().enumerate() {
            let name = metric.as_str().ok_or_else(|| {
                format!("workload_metrics: `metrics.disabled_metrics[{idx}]` must be a string")
            })?;
            match metric_selector(name) {
                Some(MetricSelector::All) => {
                    for family in MeshMetricFamily::ALL {
                        disabled.insert(family.disabled_name());
                    }
                }
                Some(MetricSelector::Emitted(family)) => {
                    disabled.insert(family.disabled_name());
                }
                None => {
                    return Err(format!(
                        "workload_metrics: `metrics.disabled_metrics[{idx}]` unsupported disabled metric {name:?}"
                    ));
                }
            }
        }
    }

    let mut plans: HashMap<MeshMetricFamily, String> = HashMap::new();
    let mut plan_stamp_needs: HashMap<MeshMetricFamily, MetricTagCelStampNeeds> = HashMap::new();
    let mut total_plan_bytes = 0usize;
    if let Some(value) = object.get("tag_overrides") {
        let overrides = value.as_array().ok_or_else(|| {
            "workload_metrics: `metrics.tag_overrides` must be an array".to_string()
        })?;
        if overrides.len() > MAX_METRIC_TAG_OVERRIDES {
            return Err(format!(
                "workload_metrics: `metrics.tag_overrides` exceeds {MAX_METRIC_TAG_OVERRIDES} entries"
            ));
        }
        for (idx, entry) in overrides.iter().enumerate() {
            if let Some(entry_object) = entry.as_object() {
                crate::util::unknown_keys::reject_unknown_keys(
                    entry_object,
                    &format!("metrics.tag_overrides[{idx}]"),
                    METRIC_TAG_OVERRIDE_KEYS,
                    "workload_metrics: ",
                )?;
            }
            let name = entry.get("name").and_then(Value::as_str).ok_or_else(|| {
                format!("workload_metrics: `metrics.tag_overrides[{idx}].name` is required")
            })?;
            let operation = entry
                .get("operation")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    format!(
                        "workload_metrics: `metrics.tag_overrides[{idx}].operation` is required for metric tag {name:?}"
                    )
                })?;
            if let Some(allowed) = operation
                .get("type")
                .and_then(Value::as_str)
                .and_then(tag_operation_keys)
            {
                crate::util::unknown_keys::reject_unknown_keys(
                    operation,
                    &format!("metrics.tag_overrides[{idx}].operation"),
                    allowed,
                    "workload_metrics: ",
                )?;
            }
            let operation = parse_tag_operation(name, operation)
                .map_err(|error| format!("`metrics.tag_overrides[{idx}].operation`: {error}"))?;
            let selector = match entry.get("metric") {
                None | Some(Value::Null) => MetricSelector::All,
                Some(Value::String(metric)) => metric_selector(metric).ok_or_else(|| {
                    format!(
                        "workload_metrics: `metrics.tag_overrides[{idx}].metric` unsupported metric {metric:?} for tag override {name:?}"
                    )
                })?,
                Some(_) => {
                    return Err(format!(
                        "workload_metrics: `metrics.tag_overrides[{idx}].metric` for tag override {name:?} must be a string"
                    ));
                }
            };
            let label = MeshMetricLabel::from_config_name(name).ok_or_else(|| {
                format!(
                    "workload_metrics: `metrics.tag_overrides[{idx}].name` unsupported metric tag {name:?}"
                )
            })?;
            let operation_stamp_needs = match &operation {
                ParsedTagOperation::SetExpr(expression) => expression.stamp_needs(),
                _ => MetricTagCelStampNeeds::default(),
            };
            let encoded = match &operation {
                ParsedTagOperation::Remove => format!("r{};", label.index()),
                ParsedTagOperation::Rename(new_name) => {
                    let new_label =
                        MeshMetricLabel::from_config_name(new_name).ok_or_else(|| {
                            format!(
                                "workload_metrics: `metrics.tag_overrides[{idx}].operation.new_name` unsupported renamed metric tag {new_name:?}"
                            )
                        })?;
                    format!("n{},{};", label.index(), new_label.index())
                }
                ParsedTagOperation::Set(value) => format!(
                    "s{},{value_len}:{value};",
                    label.index(),
                    value_len = value.len()
                ),
                ParsedTagOperation::SetExpr(expression) => {
                    let includes_tcp = match selector {
                        MetricSelector::All => true,
                        MetricSelector::Emitted(family) => family.is_tcp(),
                    };
                    validate_metric_tag_cel_for_families(expression, includes_tcp).map_err(
                        |_| {
                            format!(
                                "workload_metrics: `metrics.tag_overrides[{idx}].operation` metric tag {name:?} CEL expression rejected: HTTP-only attributes are unrepresentable for TCP metric families"
                            )
                        },
                    )?;
                    let mut body = String::new();
                    encode_metric_tag_cel_expr(expression, &mut body);
                    format!(
                        "x{},{body_len}:{body};",
                        label.index(),
                        body_len = body.len()
                    )
                }
            };
            let family_count = match selector {
                MetricSelector::All => MeshMetricFamily::ALL.len(),
                MetricSelector::Emitted(_) => 1,
            };
            let new_plan_headers = match selector {
                MetricSelector::All => MeshMetricFamily::ALL
                    .iter()
                    .filter(|family| !plans.contains_key(family))
                    .count(),
                MetricSelector::Emitted(family) => {
                    if plans.contains_key(&family) {
                        0
                    } else {
                        1
                    }
                }
            };
            total_plan_bytes = encoded
                .len()
                .checked_mul(family_count)
                .and_then(|added| total_plan_bytes.checked_add(added))
                .and_then(|total| total.checked_add(new_plan_headers.checked_mul(3)?))
                .filter(|total| *total <= MAX_METRIC_TAG_OVERRIDE_PLAN_BYTES)
                .ok_or_else(|| {
                    format!(
                        "workload_metrics: encoded metric tag override plans exceed {MAX_METRIC_TAG_OVERRIDE_PLAN_BYTES} bytes"
                    )
                })?;
            match selector {
                MetricSelector::All => {
                    for family in MeshMetricFamily::ALL {
                        plans.entry(family).or_default().push_str(&encoded);
                        plan_stamp_needs
                            .entry(family)
                            .or_default()
                            .merge(operation_stamp_needs);
                    }
                }
                MetricSelector::Emitted(family) => {
                    plans.entry(family).or_default().push_str(&encoded);
                    plan_stamp_needs
                        .entry(family)
                        .or_default()
                        .merge(operation_stamp_needs);
                }
            }
        }
    }

    let disabled_metrics_marker = if disabled.is_empty() {
        None
    } else {
        Some(
            MeshMetricFamily::ALL
                .iter()
                .filter_map(|family| {
                    disabled
                        .contains(family.disabled_name())
                        .then_some(family.disabled_name())
                })
                .collect::<Vec<_>>()
                .join(","),
        )
    };
    let tag_override_plans = MeshMetricFamily::ALL
        .iter()
        .filter_map(|family| {
            plans
                .remove(family)
                .filter(|plan| !plan.is_empty())
                .map(|plan| {
                    let stamp_needs = plan_stamp_needs.remove(family).unwrap_or_default();
                    (*family, format!("m{};{plan}", stamp_needs.marker()))
                })
        })
        .collect();
    Ok(ParsedMetricConfig {
        tag_override_plans,
        disabled_metrics_marker,
    })
}

/// Validate the parts of an Istio Telemetry resource that are projected into
/// the auto-injected `workload_metrics` plugin.
///
/// The Kubernetes translator calls this before reporting the resource as
/// accepted. Direct/native plugin configuration still runs the same validators
/// from [`WorkloadMetrics::new`] and retains its hard-error behavior.
pub(crate) fn validate_istio_telemetry_config(
    tracing: Option<&MeshTracingConfig>,
    metrics: Option<&MeshMetricsConfig>,
) -> Result<(), String> {
    if let Some(tracing) = tracing {
        // Structural validation only — do not resolve environment values here.
        // Controllers and CP translators must not treat host process env as the
        // target data plane.
        validate_custom_tags(
            tracing.custom_tags.clone(),
            tracing.custom_header_tags.clone(),
            tracing.custom_env_tags.clone(),
            &tracing.safe_tag_sources,
        )?;
        // Mesh injection always writes `allow_plaintext: true` beside
        // providers it emits with a cleartext collector URL (see
        // `inject_workload_metrics_plugin`), so translation-time screening
        // admits the same set the injected plugin will.
        validate_trace_provider_endpoints(&tracing.providers, true)
            .map_err(|error| format!("workload_metrics: `tracing.providers`: {error}"))?;
    }
    if let Some(metrics) = metrics {
        let metrics = serde_json::to_value(metrics).map_err(|_| {
            "workload_metrics: could not serialize translated `metrics`".to_string()
        })?;
        parse_metric_config(Some(&metrics))?;
    }
    Ok(())
}

struct ValidatedCustomTags {
    custom_tags: HashMap<String, String>,
    custom_header_tags: HashMap<String, String>,
    custom_env_tags: HashMap<String, String>,
    custom_trace_attributes_marker: Option<String>,
    redacted_header_tags: HashSet<String>,
    redacted_env_tags: HashSet<String>,
}

/// Maximum entries in `safe_tag_sources`.
const MAX_SAFE_TAG_SOURCES: usize = 64;

/// Parse `safe_tag_sources`: the header and environment-variable names whose
/// values custom header / env tags may copy verbatim (issue #6619).
fn safe_tag_sources_config(config: &Value) -> Result<Vec<String>, String> {
    let Some(value) = config.get("safe_tag_sources") else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| "workload_metrics: `safe_tag_sources` must be an array".to_string())?;
    if entries.len() > MAX_SAFE_TAG_SOURCES {
        return Err(format!(
            "workload_metrics: `safe_tag_sources` exceeds {MAX_SAFE_TAG_SOURCES} entries"
        ));
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry
                .as_str()
                .filter(|name| !name.is_empty() && name.len() <= MAX_CUSTOM_ENV_VAR_NAME_BYTES)
                .map(str::to_string)
                .ok_or_else(|| {
                    format!(
                        "workload_metrics: `safe_tag_sources[{index}]` must be a non-empty string of at most {MAX_CUSTOM_ENV_VAR_NAME_BYTES} bytes"
                    )
                })
        })
        .collect()
}

/// Validate `safe_tag_sources` against the deny layer: a credential-shaped
/// header or environment-variable name cannot be declared safe. Diagnostics
/// name the index only, never the (possibly credential-bearing) entry.
fn validate_safe_tag_sources(safe_tag_sources: &[String]) -> Result<(), String> {
    if safe_tag_sources.len() > MAX_SAFE_TAG_SOURCES {
        return Err(format!(
            "workload_metrics: `safe_tag_sources` exceeds {MAX_SAFE_TAG_SOURCES} entries"
        ));
    }
    for (index, source) in safe_tag_sources.iter().enumerate() {
        if source.is_empty()
            || source.len() > MAX_CUSTOM_ENV_VAR_NAME_BYTES
            || is_sensitive_header_name(source)
            || is_sensitive_header_name(&source.to_ascii_lowercase())
            || is_sensitive_environment_variable_name(source)
        {
            return Err(format!(
                "workload_metrics: `safe_tag_sources[{index}]` is empty, oversized, or names a credential-bearing source and cannot be declared safe"
            ));
        }
    }
    Ok(())
}

fn validate_custom_tags(
    custom_tags: HashMap<String, String>,
    custom_header_tags: HashMap<String, String>,
    custom_env_tags: HashMap<String, String>,
    safe_tag_sources: &[String],
) -> Result<ValidatedCustomTags, String> {
    validate_safe_tag_sources(safe_tag_sources)?;
    let mut names: Vec<String> = custom_tags
        .keys()
        .chain(custom_header_tags.keys())
        .chain(custom_env_tags.keys())
        .cloned()
        .collect();
    names.sort();
    names.dedup();
    if names.len() > MAX_CUSTOM_TAGS {
        return Err(format!(
            "workload_metrics: custom tag count exceeds {MAX_CUSTOM_TAGS}"
        ));
    }
    for name in &names {
        validate_custom_tag_name(name)?;
    }
    for (name, value) in &custom_tags {
        if value.len() > MAX_CUSTOM_TAG_VALUE_BYTES {
            return Err(format!(
                "workload_metrics: custom tag {name:?} value exceeds {MAX_CUSTOM_TAG_VALUE_BYTES} bytes"
            ));
        }
    }

    let mut normalized_header_tags = HashMap::with_capacity(custom_header_tags.len());
    let mut redacted_header_tags = HashSet::new();
    for (name, header) in custom_header_tags {
        let header_name =
            http::header::HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                format!("workload_metrics: custom tag {name:?} has invalid header name {header:?}")
            })?;
        // Judge the configured spelling as well as the normalized one:
        // normalization lowercases away camelCase boundaries (`x-projectPin`).
        if is_sensitive_header_name(&header)
            || is_sensitive_header_name(header_name.as_str())
            || names_short_form_credential(&header)
        {
            return Err(format!(
                "workload_metrics: custom tag {name:?} cannot copy sensitive header {header:?}"
            ));
        }
        if !safe_tag_sources
            .iter()
            .any(|safe| safe.eq_ignore_ascii_case(header_name.as_str()))
        {
            redacted_header_tags.insert(name.clone());
        }
        normalized_header_tags.insert(name, header_name.as_str().to_string());
    }

    let mut normalized_env_tags = HashMap::with_capacity(custom_env_tags.len());
    let mut redacted_env_tags = HashSet::new();
    for (name, env_var) in custom_env_tags {
        validate_env_var_name(&name, &env_var)?;
        // Environment variable names are case-sensitive.
        if !safe_tag_sources.contains(&env_var) {
            redacted_env_tags.insert(name.clone());
        }
        normalized_env_tags.insert(name, env_var);
    }

    let marker = (!names.is_empty()).then(|| names.join(","));
    Ok(ValidatedCustomTags {
        custom_tags,
        custom_header_tags: normalized_header_tags,
        custom_env_tags: normalized_env_tags,
        custom_trace_attributes_marker: marker,
        redacted_header_tags,
        redacted_env_tags,
    })
}

/// Resolve `custom_env_tags` against a caller-supplied environment lookup.
///
/// Production passes `std::env::var`. Tests inject deterministic present,
/// missing, empty, oversized, and non-Unicode outcomes without mutating the
/// process environment.
///
/// Istio/Envoy semantics: a present variable overrides any literal default in
/// `custom_tags`; a missing variable keeps the default when one was translated,
/// otherwise the tag is omitted. Resolved values are deliberately emitted as
/// custom telemetry metadata, but diagnostics must never include their values.
fn resolve_custom_env_tags_with<F>(
    custom_tags: &mut HashMap<String, String>,
    custom_env_tags: &HashMap<String, String>,
    redacted_env_tags: &HashSet<String>,
    mut lookup: F,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, std::env::VarError>,
{
    for (tag, env_var) in custom_env_tags {
        match lookup(env_var) {
            Ok(value) => {
                if value.len() > MAX_CUSTOM_TAG_VALUE_BYTES {
                    return Err(format!(
                        "workload_metrics: custom env tag {tag:?} resolved value exceeds {MAX_CUSTOM_TAG_VALUE_BYTES} bytes"
                    ));
                }
                // Fail closed: a variable the operator has not declared in
                // `safe_tag_sources` is emitted as the redaction marker.
                let value = if redacted_env_tags.contains(tag) {
                    REDACTED_PLACEHOLDER.to_string()
                } else {
                    value
                };
                custom_tags.insert(tag.clone(), value);
            }
            Err(std::env::VarError::NotPresent) => {
                // Keep any translated defaultValue already in custom_tags;
                // otherwise omit the tag (Istio/Envoy).
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!(
                    "workload_metrics: custom env tag {tag:?} environment value is not valid UTF-8"
                ));
            }
        }
    }
    Ok(())
}

fn validate_env_var_name(tag: &str, env_var: &str) -> Result<(), String> {
    // O(1) length admission before any walk that could inspect hostile input.
    // Never echo the raw name — it may be credential-bearing.
    if env_var.len() > MAX_CUSTOM_ENV_VAR_NAME_BYTES {
        return Err(format!(
            "workload_metrics: custom tag {tag:?} has invalid environment variable name"
        ));
    }
    if env_var.is_empty() {
        return Err(format!(
            "workload_metrics: custom tag {tag:?} has invalid environment variable name"
        ));
    }
    // Credential classifier before any diagnostic that could contain the raw
    // name, including portable-syntax rejection of credential-shaped spellings
    // such as `AWS_SECRET-KEY` or `myPassword`.
    if is_sensitive_environment_variable_name(env_var) {
        return Err(format!(
            "workload_metrics: custom tag {tag:?} cannot copy a credential-bearing environment variable"
        ));
    }
    let mut chars = env_var.chars();
    let Some(first) = chars.next() else {
        return Err(format!(
            "workload_metrics: custom tag {tag:?} has invalid environment variable name"
        ));
    };
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(format!(
            "workload_metrics: custom tag {tag:?} has invalid environment variable name"
        ));
    }
    Ok(())
}

/// Environment names need a stricter credential boundary than log-metadata
/// keys. In particular, database URLs and access/client identifiers can expose
/// credentials even though their names intentionally do not match the shared
/// metadata redaction classifier's narrower `token` rules.
///
/// Detection is fail-closed across delimiter, camelCase, and concatenated
/// spellings. Most credential names use bounded token / known-compound
/// matching; HTTP credential-state stems (`authorization`, `bearer`, `cookie`,
/// and `csrf`) deliberately retain substring matching so concatenated names
/// cannot bypass the telemetry boundary. Every credential class the metadata
/// redactor recognizes (session identifiers, passphrases and passcodes, PINs
/// and one-time codes, JWTs, signatures, private/access/signing keys, bearer
/// assertions; issue #6619) is also refused here, so `GPG_PASSPHRASE`,
/// `HSM_PIN` or `USER_SESSION_ID` cannot be copied into telemetry. Ordinary
/// names such as `ISTIO_META_CLUSTER_ID` and `FERRUM_REGION` remain allowed.
fn is_sensitive_environment_variable_name(name: &str) -> bool {
    if is_operator_sensitive_metadata_key(name) || is_credential_class_metadata_key(name) {
        return true;
    }

    let fingerprint = environment_name_fingerprint(name);
    if matches!(
        fingerprint.as_str(),
        "cache_request_headers_snapshot"
            | "grpc_web_shadowed_trailers"
            | "claim_header"
            | "last_event_id"
            | "lasteventid"
    ) || fingerprint.starts_with("claim_header_")
    {
        return true;
    }
    let segments: Vec<&str> = fingerprint
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments_name_short_form_credential(&segments) {
        return true;
    }

    let mut has_database_source = false;
    let mut has_location = false;
    let mut has_client = false;
    let mut has_id = false;

    for segment in &segments {
        if is_credential_token(segment) || is_known_credential_compound(segment) {
            return true;
        }
        if segment_embeds_credential_compound(segment) {
            return true;
        }

        has_database_source |= is_database_source_token(segment);
        has_location |= is_location_token(segment);
        has_client |= *segment == "client";
        has_id |= *segment == "id";
    }

    for pair in segments.windows(2) {
        let collapsed = [pair[0], pair[1]].concat();
        if is_known_credential_compound(&collapsed) {
            return true;
        }
        if is_database_source_token(pair[0]) && is_location_token(pair[1]) {
            return true;
        }
        if pair[0] == "client" && pair[1] == "id" {
            return true;
        }
    }

    (has_database_source && has_location) || (has_client && has_id)
}

/// Short credential spellings the shared classifiers do not name: a `pat`
/// segment (personal access token: `GITHUB_PAT`, `AZURE_DEVOPS_PAT`, `x-pat`)
/// and a TERMINAL `auth` segment, which holds the credential itself
/// (`BASIC_AUTH`, `DOCKER_AUTH`, `NPM_AUTH`, `x-basic-auth`). Segment
/// equality keeps `path` / `pattern` / `patch` and a non-terminal `auth`
/// (`AUTH_TYPE`, `AUTH_MODE`) out of the rule.
fn segments_name_short_form_credential(segments: &[&str]) -> bool {
    segments.contains(&"pat") || segments.last() == Some(&"auth")
}

/// [`segments_name_short_form_credential`] over a raw header or environment
/// name, segmented exactly like the environment classifier (delimiters and
/// camelCase boundaries split, so `x-basicAuth` is `x_basic_auth`).
fn names_short_form_credential(name: &str) -> bool {
    let fingerprint = environment_name_fingerprint(name);
    let segments: Vec<&str> = fingerprint
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect();
    segments_name_short_form_credential(&segments)
}

fn is_credential_token(segment: &str) -> bool {
    matches!(
        segment,
        "secret"
            | "password"
            | "passwd"
            | "token"
            | "credential"
            | "credentials"
            | "key"
            | "dsn"
            | "connection"
            | "authorization"
            | "bearer"
            | "cookie"
            | "csrf"
    )
}

fn is_database_source_token(segment: &str) -> bool {
    matches!(
        segment,
        "db" | "database" | "mongo" | "mongodb" | "mysql" | "postgres" | "postgresql" | "redis"
    )
}

fn is_location_token(segment: &str) -> bool {
    matches!(segment, "url" | "uri" | "dsn" | "connection")
}

/// Known compounds for undelimited / concatenated credential spellings.
const KNOWN_CREDENTIAL_COMPOUNDS: &[&str] = &[
    "apikey",
    "accesskey",
    "privatekey",
    "secretkey",
    "sessiontoken",
    "accesstoken",
    "idtoken",
    "refreshtoken",
    "bearertoken",
    "clientid",
    "clientsecret",
    "clientkey",
    "dburl",
    "dburi",
    "dbdsn",
    "databaseurl",
    "databaseuri",
    "databasedsn",
    "databaseconnection",
    "connectionstring",
    "mongodburi",
    "mongouri",
    "mysqlurl",
    "postgresurl",
    "postgresqluri",
    "postgresqlurl",
    "redisurl",
    "redisuri",
];

fn is_known_credential_compound(segment: &str) -> bool {
    KNOWN_CREDENTIAL_COMPOUNDS.contains(&segment)
}

fn contains_known_credential_compound(segment: &str) -> bool {
    KNOWN_CREDENTIAL_COMPOUNDS.iter().any(|compound| {
        segment.match_indices(*compound).any(|(offset, _)| {
            // `clientidentity` is a common non-credential dimension. Do not
            // reinterpret its leading bytes as the `clientid` compound.
            *compound != "clientid" || !segment[offset + compound.len()..].starts_with("entity")
        })
    })
}

/// Bounded embedding detection for concatenated forms such as `mysecret`,
/// `sessiontoken`, or `awssecretkey` without treating short credential words
/// as arbitrary substrings (`secretion`, `authentication`, `keyboard`).
fn segment_embeds_credential_compound(segment: &str) -> bool {
    // Preserve the metadata redactor's fail-closed substring treatment for
    // credential-bearing HTTP state. Environment names commonly concatenate
    // these words (`SESSIONCOOKIE`, `AUTHORIZATIONHEADER`), so exact token
    // matching would allow their values to escape under an innocuous tag name.
    if ["authorization", "bearer", "cookie", "csrf"]
        .iter()
        .any(|stem| segment.contains(stem))
    {
        return true;
    }

    // Exact credential compounds remain sensitive when a provider prefix or
    // qualifier is concatenated around them (`AWSACCESSKEYID`,
    // `AWSSECRETACCESSKEY`, `MYCLIENTSECRETJSON`). These compounds are specific
    // enough to search as bounded literals; bare `key` / `secret` / `token`
    // retain the narrower rules below.
    if contains_known_credential_compound(segment) {
        return true;
    }

    // Long credential stems: accept as a suffix (`mysecret`) or when followed
    // by a known compound trailer (`awssecretkey`). Do not treat an arbitrary
    // mid-word occurrence as sensitive (`secretion`).
    const STEMS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "credentials",
    ];
    const TRAILERS: &[&str] = &[
        "key", "id", "url", "uri", "dsn", "string", "token", "secret", "value", "json", "file",
        "path",
    ];

    for stem in STEMS {
        if segment.len() <= stem.len() {
            continue;
        }
        if segment.ends_with(stem) {
            return true;
        }
        let mut start = 0;
        while let Some(rel) = segment[start..].find(stem) {
            let abs = start + rel;
            let after = abs + stem.len();
            let suffix = &segment[after..];
            if !suffix.is_empty() && TRAILERS.contains(&suffix) {
                return true;
            }
            start = abs + 1;
        }
    }

    // Short `key` is too common for open suffixes (`monkey`, `keyboard`); only
    // known credential prefixes may concatenate with it.
    const KEY_PREFIXES: &[&str] = &[
        "api", "access", "private", "secret", "client", "signing", "crypt", "crypto", "aes", "rsa",
        "ssh", "pgp", "hmac", "jwt",
    ];
    if let Some(prefix) = segment.strip_suffix("key")
        && !prefix.is_empty()
        && KEY_PREFIXES.contains(&prefix)
    {
        return true;
    }

    false
}

/// Lowercase fingerprint with non-alnum delimiters collapsed to `_` and
/// camelCase boundaries split so `AccessToken` / `ClientId` classify.
fn environment_name_fingerprint(name: &str) -> String {
    let mut out = String::with_capacity(name.len().saturating_mul(2));
    let mut prev_kind = FingerprintCharKind::Delimiter;

    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() {
            if prev_kind != FingerprintCharKind::Delimiter && !out.is_empty() {
                out.push('_');
            }
            prev_kind = FingerprintCharKind::Delimiter;
            continue;
        }

        let kind = if ch.is_ascii_uppercase() {
            FingerprintCharKind::Upper
        } else if ch.is_ascii_digit() {
            FingerprintCharKind::Digit
        } else {
            FingerprintCharKind::Lower
        };

        if matches!(
            (prev_kind, kind),
            (FingerprintCharKind::Lower, FingerprintCharKind::Upper)
                | (FingerprintCharKind::Digit, FingerprintCharKind::Upper)
        ) {
            out.push('_');
        }

        out.push(ch.to_ascii_lowercase());
        prev_kind = kind;
    }

    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FingerprintCharKind {
    Delimiter,
    Lower,
    Upper,
    Digit,
}

fn validate_custom_tag_name(name: &str) -> Result<(), String> {
    let allowed = !name.is_empty()
        && name.len() <= MAX_CUSTOM_TAG_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !allowed {
        return Err(format!(
            "workload_metrics: invalid custom tag name {name:?}"
        ));
    }
    let reserved = name.starts_with("mesh.")
        || name.starts_with("mesh_authz.")
        || name.starts_with("workload_metrics.")
        || matches!(
            name,
            "trace_id"
                | "span_id"
                | "parent_span_id"
                | "trace_sampled"
                | "traceparent"
                | "tracestate"
                | "peer_spiffe_id"
                | "request_protocol"
                | "response_flags"
        );
    if reserved || is_sensitive_metadata_key(name) {
        return Err(format!(
            "workload_metrics: custom tag name {name:?} is reserved or sensitive"
        ));
    }
    Ok(())
}

fn first_label<'a>(labels: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        labels
            .get(*key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    })
}

fn mesh_service_namespace(service: &str) -> Option<&str> {
    let service_and_namespace = service.split_once(".svc.")?.0;
    service_and_namespace
        .rsplit_once('.')
        .map(|(_, namespace)| namespace)
}

fn request_protocol(ctx: &RequestContext, probe: &TraceHeaderProbe<'_>) -> &'static str {
    if ctx
        .metadata
        .get("request_protocol")
        .is_some_and(|value| value == "hbone")
    {
        return "hbone";
    }
    let content_type = probe
        .content_type
        .or_else(|| ctx.raw_header_get("content-type"))
        .unwrap_or("");
    if content_type
        .split(',')
        .next()
        .is_some_and(|value| is_grpc_content_type(value.trim()))
    {
        "grpc"
    } else {
        "http"
    }
}

/// Typed facts for a remote source identity: the facts cached on the TLS
/// connection when the identity is that connection's verified certificate
/// identity (resolved once per connection), otherwise built for this request
/// (an honored HBONE assertion or a NodeWaypoint-attested pod).
fn remote_source_facts(
    ctx: &RequestContext,
    identity: Option<&SpiffeId>,
) -> Arc<RemoteSourceFacts> {
    let Some(identity) = identity else {
        return Arc::clone(RemoteSourceFacts::absent());
    };
    ctx.peer_spiffe_extraction_cache
        .as_ref()
        .and_then(|cache| cache.remote_source_facts(identity))
        .unwrap_or_else(|| Arc::new(RemoteSourceFacts::new(Some(identity))))
}

/// The HBONE baggage identity of an HBONE request, read exactly as
/// `mesh_authz` reads it: every pristine wire field-line plus `folded`.
fn hbone_identity_for_request(ctx: &RequestContext, folded: Option<&str>) -> Option<HboneIdentity> {
    is_hbone_request(ctx).then(|| hbone_baggage_identity(ctx, folded))
}

fn is_hbone_request(ctx: &RequestContext) -> bool {
    ctx.metadata
        .get("request_protocol")
        .is_some_and(|value| value == "hbone")
}

/// Which B3 spellings the backend request carries.
#[derive(Debug, Clone, Copy, Default)]
struct BackendB3Headers {
    /// Any B3 header, single or multi.
    any: bool,
    /// The single-header `b3` form.
    single: bool,
}

fn backend_b3_headers(headers: &HashMap<String, String>) -> BackendB3Headers {
    let mut found = BackendB3Headers::default();
    for name in headers.keys() {
        if B3_TRACE_HEADERS
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
        {
            found.any = true;
            found.single |= name.eq_ignore_ascii_case("b3");
        }
    }
    found
}

/// Replace every B3 header on the backend request with the active span from
/// `metadata` (the same trace ID, span ID, parent and sampling decision the
/// injected `traceparent` carries): multi-header `x-b3-traceid` /
/// `x-b3-spanid` / `x-b3-parentspanid` / `x-b3-sampled`, plus the
/// single-header `b3` form when the request used it. Without an active span
/// the headers are left untouched.
fn inject_b3_trace_headers<MS: std::hash::BuildHasher>(
    metadata: &HashMap<String, String, MS>,
    headers: &mut HashMap<String, String>,
    single_header: bool,
) {
    let Some(active) = metadata
        .get(TRACEPARENT_HEADER)
        .and_then(|value| OtelTracing::parse_traceparent(value))
    else {
        return;
    };
    let sampled = if u8::from_str_radix(active.flags, 16).is_ok_and(|flags| flags & 0x01 == 0x01) {
        "1"
    } else {
        "0"
    };
    let parent_span_id = metadata
        .get("parent_span_id")
        .and_then(|value| normalize_b3_span_id(value));
    // `parse_traceparent` names the traceparent span field from the
    // receiver's point of view; for the injected value it is this span.
    let span_id = active.parent_span_id;
    headers.retain(|name, _| {
        !B3_TRACE_HEADERS
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
    });
    headers.insert("x-b3-traceid".to_string(), active.trace_id.to_string());
    headers.insert("x-b3-spanid".to_string(), span_id.to_string());
    headers.insert("x-b3-sampled".to_string(), sampled.to_string());
    if let Some(parent_span_id) = parent_span_id.as_deref() {
        headers.insert("x-b3-parentspanid".to_string(), parent_span_id.to_string());
    }
    if single_header {
        let mut value = format!("{}-{span_id}-{sampled}", active.trace_id);
        if let Some(parent_span_id) = parent_span_id.as_deref() {
            value.push('-');
            value.push_str(parent_span_id);
        }
        headers.insert("b3".to_string(), value);
    }
}

thread_local! {
    static TRACE_SAMPLING_STATE: Cell<u64> = Cell::new(random_sampling_seed());
}

fn trace_sampled(sampling_percentage: f64) -> bool {
    if sampling_percentage <= 0.0 {
        return false;
    }
    if sampling_percentage >= 100.0 {
        return true;
    }

    let random = next_sampling_u64();
    (random as f64 / u64::MAX as f64) * 100.0 < sampling_percentage
}

fn existing_sampling_decision<MS: std::hash::BuildHasher>(
    metadata: &HashMap<String, String, MS>,
    probe: &TraceHeaderProbe<'_>,
) -> Option<bool> {
    if let Some(value) = metadata.get("trace_sampled") {
        return Some(value.eq_ignore_ascii_case("true"));
    }
    metadata
        .get(TRACEPARENT_HEADER)
        .and_then(|value| traceparent_sampling_decision(value))
        .or_else(|| probe.traceparent.and_then(traceparent_sampling_decision))
        .or_else(|| probe.b3_sampling_decision())
}

/// Whether the standalone `otel_tracing` plugin established this request's
/// gateway SERVER span (see [`crate::plugins::otel_tracing::GatewayTraceOwner`]).
fn trace_owned_by_otel_tracing(ctx: &RequestContext) -> bool {
    ctx.gateway_trace_owner() == Some(crate::plugins::otel_tracing::GatewayTraceOwner::OtelTracing)
}

fn clear_http_trace_metadata<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
) {
    for key in [
        "trace_id",
        "span_id",
        "parent_span_id",
        "trace_sampled",
        TRACEPARENT_HEADER,
        TRACESTATE_HEADER,
    ] {
        metadata.remove(key);
    }
}

fn metadata_has_sampling_decision<MS: std::hash::BuildHasher>(
    metadata: &HashMap<String, String, MS>,
) -> bool {
    metadata.contains_key("trace_sampled")
        || metadata
            .get(TRACEPARENT_HEADER)
            .and_then(|value| traceparent_sampling_decision(value))
            .is_some()
}

fn traceparent_sampling_decision(value: &str) -> Option<bool> {
    OtelTracing::parse_traceparent(value)
        .and_then(|parsed| u8::from_str_radix(parsed.flags, 16).ok())
        .map(|flags| flags & 0x01 == 0x01)
}

fn b3_sampling_decision(headers: &HashMap<String, String>) -> Option<bool> {
    TraceHeaderProbe::scan(headers).b3_sampling_decision()
}

fn has_b3_trace_context(headers: &HashMap<String, String>) -> bool {
    TraceHeaderProbe::scan(headers).has_b3_trace_context()
}

/// Every trace-context header (plus `content-type`) a stamp consults, found in
/// ONE pass over the request headers.
///
/// Each field is exactly what `header_value(headers, name)` returns: the
/// byte-exact key when present, otherwise the first ASCII-case-insensitive
/// match in the map's iteration order. A stamp used to look each name up
/// separately, and every miss — the common case, a request with no trace
/// headers — rescanned the whole map. `scan` must be re-run after the headers
/// change.
#[derive(Debug, Clone, Copy, Default)]
struct TraceHeaderProbe<'a> {
    traceparent: Option<&'a str>,
    tracestate: Option<&'a str>,
    b3: Option<&'a str>,
    x_b3_traceid: Option<&'a str>,
    x_b3_spanid: Option<&'a str>,
    x_b3_flags: Option<&'a str>,
    x_b3_sampled: Option<&'a str>,
    content_type: Option<&'a str>,
}

impl<'a> TraceHeaderProbe<'a> {
    const NAMES: [&'static str; 8] = [
        TRACEPARENT_HEADER,
        TRACESTATE_HEADER,
        "b3",
        "x-b3-traceid",
        "x-b3-spanid",
        "x-b3-flags",
        "x-b3-sampled",
        "content-type",
    ];

    fn scan(headers: &'a HashMap<String, String>) -> Self {
        let mut exact: [Option<&'a str>; 8] = [None; 8];
        let mut folded: [Option<&'a str>; 8] = [None; 8];
        for (name, value) in headers {
            for (index, probed) in Self::NAMES.iter().enumerate() {
                if name.len() != probed.len() {
                    continue;
                }
                if name == probed {
                    exact[index] = Some(value.as_str());
                } else if folded[index].is_none() && name.eq_ignore_ascii_case(probed) {
                    folded[index] = Some(value.as_str());
                }
            }
        }
        let [
            traceparent,
            tracestate,
            b3,
            x_b3_traceid,
            x_b3_spanid,
            x_b3_flags,
            x_b3_sampled,
            content_type,
        ] = std::array::from_fn(|index| exact[index].or(folded[index]));
        Self {
            traceparent,
            tracestate,
            b3,
            x_b3_traceid,
            x_b3_spanid,
            x_b3_flags,
            x_b3_sampled,
            content_type,
        }
    }

    fn has_valid_traceparent(&self) -> bool {
        self.traceparent
            .and_then(OtelTracing::parse_traceparent)
            .is_some()
    }

    fn b3_sampling_decision(&self) -> Option<bool> {
        if let Some(value) = self.b3 {
            return b3_single_sampling_decision(value);
        }
        if let Some(flags) = self.x_b3_flags
            && flags.trim() == "1"
        {
            return Some(true);
        }
        self.x_b3_sampled.and_then(|value| match value.trim() {
            "1" => Some(true),
            "0" => Some(false),
            value if value.eq_ignore_ascii_case("true") => Some(true),
            value if value.eq_ignore_ascii_case("false") => Some(false),
            _ => None,
        })
    }

    fn has_b3_trace_context(&self) -> bool {
        if let Some(value) = self.b3 {
            return parse_b3_single_trace_context(value).is_some();
        }

        self.x_b3_traceid.and_then(normalize_b3_trace_id).is_some()
            && self.x_b3_spanid.and_then(normalize_b3_span_id).is_some()
    }
}

#[derive(Debug, Clone)]
struct B3SingleTraceContext {
    trace_id: String,
    span_id: String,
    sampled: Option<bool>,
}

fn b3_single_sampling_decision(value: &str) -> Option<bool> {
    let trimmed = value.trim();
    if !trimmed.contains('-') {
        return b3_sampling_state(trimmed);
    }

    parse_b3_single_trace_context(trimmed).and_then(|context| context.sampled)
}

fn parse_b3_single_trace_context(value: &str) -> Option<B3SingleTraceContext> {
    let mut parts = value.trim().split('-');
    let trace_id = normalize_b3_trace_id(parts.next()?)?;
    let span_id = normalize_b3_span_id(parts.next()?)?;
    let sampled = match parts.next() {
        Some(state) => Some(b3_sampling_state(state)?),
        None => None,
    };
    if let Some(parent_span_id) = parts.next() {
        normalize_b3_span_id(parent_span_id)?;
    }
    if parts.next().is_some() {
        return None;
    }

    Some(B3SingleTraceContext {
        trace_id,
        span_id,
        sampled,
    })
}

fn b3_sampling_state(value: &str) -> Option<bool> {
    match value.trim() {
        "1" => Some(true),
        "0" => Some(false),
        value if value.eq_ignore_ascii_case("d") => Some(true),
        value if value.eq_ignore_ascii_case("true") => Some(true),
        value if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn import_b3_trace_metadata<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
    probe: &TraceHeaderProbe<'_>,
) {
    if metadata.contains_key(TRACEPARENT_HEADER) {
        return;
    }
    if let Some(value) = probe.b3 {
        if let Some(context) = parse_b3_single_trace_context(value) {
            import_b3_trace_context(metadata, context.trace_id, context.span_id);
        }
        return;
    }
    let Some(trace_id) = probe.x_b3_traceid.and_then(normalize_b3_trace_id) else {
        return;
    };
    let Some(parent_span_id) = probe.x_b3_spanid.and_then(normalize_b3_span_id) else {
        return;
    };

    import_b3_trace_context(metadata, trace_id, parent_span_id);
}

fn import_b3_trace_context<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
    trace_id: String,
    parent_span_id: String,
) {
    let span_id = OtelTracing::generate_span_id();
    let flags = if trace_is_sampled(metadata) {
        "01"
    } else {
        "00"
    };
    metadata.insert("trace_id".to_string(), trace_id.clone());
    metadata.insert("parent_span_id".to_string(), parent_span_id);
    metadata.insert("span_id".to_string(), span_id.clone());
    metadata.insert(
        TRACEPARENT_HEADER.to_string(),
        build_traceparent("00", &trace_id, &span_id, flags),
    );
}

fn normalize_b3_trace_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let is_valid = matches!(trimmed.len(), 16 | 32)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        && !trimmed.chars().all(|c| c == '0');
    is_valid.then(|| {
        if trimmed.len() == 16 {
            format!("0000000000000000{}", trimmed.to_ascii_lowercase())
        } else {
            trimmed.to_ascii_lowercase()
        }
    })
}

fn normalize_b3_span_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (trimmed.len() == 16
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        && !trimmed.chars().all(|c| c == '0'))
    .then(|| trimmed.to_ascii_lowercase())
}

fn next_sampling_u64() -> u64 {
    TRACE_SAMPLING_STATE.with(|state| {
        let next = state.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
        state.set(next);
        splitmix64(next)
    })
}

fn random_sampling_seed() -> u64 {
    let mut bytes = [0u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_ok() {
        return u64::from_ne_bytes(bytes);
    }

    let time_seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let stack_marker = 0u8;
    let stack_entropy = (&stack_marker as *const u8 as usize) as u64;
    fallback_sampling_seed(time_seed, stack_entropy)
}

fn fallback_sampling_seed(time_seed: u64, stack_entropy: u64) -> u64 {
    splitmix64(
        0xA5A5_5A5A_D3C1_B2A0
            ^ time_seed
            ^ stack_entropy.rotate_left(17)
            ^ (std::process::id() as u64).rotate_left(32),
    )
}

fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn is_grpc_content_type(value: &str) -> bool {
    value
        .as_bytes()
        .get(..b"application/grpc".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"application/grpc"))
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn set_header_case_insensitive(headers: &mut HashMap<String, String>, name: &str, value: &str) {
    headers.retain(|header_name, _| !header_name.eq_ignore_ascii_case(name));
    headers.insert(name.to_string(), value.to_string());
}

fn has_valid_traceparent(headers: &HashMap<String, String>) -> bool {
    TraceHeaderProbe::scan(headers).has_valid_traceparent()
}

/// Insert `key -> value` only when the current value differs.
///
/// `annotate_http_context` runs twice per request (request-received and
/// before-proxy) and most stamped values are identical across both calls;
/// the plain `insert` form paid a key hash plus two `String` allocations
/// per key per call to rewrite the same value. The borrowed `get` first
/// keeps the repeat stamp allocation-free while preserving the final map
/// exactly (a changed value still takes the insert path).
fn insert_metadata_if_changed<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
    key: &str,
    value: &str,
) {
    match metadata.get(key) {
        Some(existing) if existing == value => {}
        _ => {
            metadata.insert(key.to_string(), value.to_string());
        }
    }
}

/// Writes one stamp's `mesh.source.*` / `mesh.destination.*` labels.
///
/// `metadata` is the request's string projection, present unless the
/// request's plugin view deferred it; every write there is exactly the
/// historical `insert_metadata_if_changed` / clear sequence. `shadow` is the
/// request's typed copy, which receives the same value as a shared `Arc` and
/// skips a write whose value is unchanged (issue #6793).
struct LabelWriter<'a, MS: std::hash::BuildHasher> {
    metadata: Option<&'a mut HashMap<String, String, MS>>,
    shadow: &'a mut MeshLabelShadow,
}

impl<MS: std::hash::BuildHasher> LabelWriter<'_, MS> {
    fn set(&mut self, label: MeshLabel, value: &Arc<str>) {
        if let Some(metadata) = self.metadata.as_deref_mut() {
            insert_metadata_if_changed(metadata, label.key(), value);
        }
        self.shadow.set_arc(label, value);
    }

    fn set_str(&mut self, label: MeshLabel, value: &str) {
        if let Some(metadata) = self.metadata.as_deref_mut() {
            insert_metadata_if_changed(metadata, label.key(), value);
        }
        self.shadow.set_str(label, value);
    }

    /// Rebuild the SPIFFE-derived source labels as one atomic view.
    ///
    /// The metadata half keeps its historical decision on `identity` exactly
    /// (clear unless the stamped labels already equal its projection); the
    /// shadow half decides on `labels`. Both then hold exactly `labels`'
    /// projection.
    fn source_spiffe(&mut self, identity: Option<&SpiffeId>, labels: Option<&SpiffeLabels>) {
        if let Some(metadata) = self.metadata.as_deref_mut()
            && !source_spiffe_labels_match(metadata, identity)
        {
            clear_source_spiffe_labels(metadata);
        }
        if !self.shadow.source_spiffe_matches(labels) {
            for label in [
                MeshLabel::SourcePrincipal,
                MeshLabel::SourceTrustDomain,
                MeshLabel::SourceNamespace,
                MeshLabel::SourceServiceAccount,
            ] {
                self.shadow.remove(label);
            }
        }
        if let Some(labels) = labels {
            self.set(MeshLabel::SourcePrincipal, labels.principal());
            self.set(MeshLabel::SourceTrustDomain, labels.trust_domain());
            if let Some(namespace) = labels.namespace() {
                self.set(MeshLabel::SourceNamespace, namespace);
            }
            if let Some(service_account) = labels.service_account() {
                self.set(MeshLabel::SourceServiceAccount, service_account);
            }
        }
    }

    /// A remote source's workload, app and service: its service account, or
    /// `unknown` without a source identity.
    fn remote_source_workload(&mut self, remote: Option<&RemoteSourceFacts>) {
        let workload = remote.map_or_else(
            || crate::plugins::mesh::telemetry_facts::unknown_label(),
            RemoteSourceFacts::workload,
        );
        self.set(MeshLabel::SourceWorkload, workload);
        self.set(MeshLabel::SourceApp, workload);
        self.set(MeshLabel::SourceService, workload);
    }

    /// The local workload as the source: its configured namespace (over any
    /// SPIFFE namespace) and its workload, app and service labels.
    fn local_source_workload(&mut self, local: &LocalWorkloadFacts) {
        if let Some(namespace) = local.namespace() {
            self.set(MeshLabel::SourceNamespace, namespace);
        }
        self.set(MeshLabel::SourceWorkload, local.workload());
        self.set(MeshLabel::SourceApp, local.app());
        self.set(MeshLabel::SourceService, local.service());
    }

    /// The local workload as the destination of inbound traffic: its SPIFFE
    /// principal and namespace, then its configured namespace, then its
    /// workload, app and service labels. Destination labels are never cleared.
    fn local_destination(&mut self, local: &LocalWorkloadFacts) {
        if let Some(spiffe) = local.spiffe() {
            self.set(MeshLabel::DestinationPrincipal, spiffe.principal());
            if let Some(namespace) = spiffe.namespace() {
                self.set(MeshLabel::DestinationNamespace, namespace);
            }
        }
        if let Some(namespace) = local.namespace() {
            self.set(MeshLabel::DestinationNamespace, namespace);
        }
        self.set(MeshLabel::DestinationWorkload, local.workload());
        self.set(MeshLabel::DestinationApp, local.app());
        self.set(MeshLabel::DestinationService, local.service());
    }

    /// A matched route as the destination of outbound traffic: its namespace
    /// and its name (or id) for workload, app and service.
    fn route_destination(&mut self, namespace: &str, destination: &str) {
        self.set_str(MeshLabel::DestinationNamespace, namespace);
        // One shared value for the three labels, reused from the shadow when
        // an earlier stamp already holds it.
        let destination = match self.shadow.get_arc(MeshLabel::DestinationWorkload) {
            Some(existing) if &**existing == destination => Arc::clone(existing),
            _ => Arc::from(destination),
        };
        self.set(MeshLabel::DestinationWorkload, &destination);
        self.set(MeshLabel::DestinationApp, &destination);
        self.set(MeshLabel::DestinationService, &destination);
    }
}

/// Whether the SPIFFE-derived source labels already in `metadata` are
/// exactly the labels `identity` would stamp (including key absence for
/// a missing namespace / service account, and all-absent for `None`).
fn source_spiffe_labels_match<MS: std::hash::BuildHasher>(
    metadata: &HashMap<String, String, MS>,
    identity: Option<&SpiffeId>,
) -> bool {
    let principal = metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str);
    let trust_domain = metadata.get(MESH_SOURCE_TRUST_DOMAIN).map(String::as_str);
    let namespace = metadata.get(MESH_SOURCE_NAMESPACE).map(String::as_str);
    let service_account = metadata
        .get(MESH_SOURCE_SERVICE_ACCOUNT)
        .map(String::as_str);
    match identity {
        None => {
            principal.is_none()
                && trust_domain.is_none()
                && namespace.is_none()
                && service_account.is_none()
        }
        Some(identity) => {
            principal == Some(identity.as_str())
                && trust_domain == Some(identity.trust_domain().as_str())
                && namespace == identity.namespace()
                && service_account == identity.service_account()
        }
    }
}

fn clear_source_spiffe_labels<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
) {
    for key in [
        MESH_SOURCE_PRINCIPAL,
        MESH_SOURCE_TRUST_DOMAIN,
        MESH_SOURCE_NAMESPACE,
        MESH_SOURCE_SERVICE_ACCOUNT,
    ] {
        metadata.remove(key);
    }
}

fn insert_source_spiffe_labels<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
    identity: &SpiffeId,
) {
    insert_metadata_if_changed(metadata, MESH_SOURCE_PRINCIPAL, identity.as_str());
    insert_metadata_if_changed(
        metadata,
        MESH_SOURCE_TRUST_DOMAIN,
        identity.trust_domain().as_str(),
    );
    if let Some(namespace) = identity.namespace() {
        insert_metadata_if_changed(metadata, MESH_SOURCE_NAMESPACE, namespace);
    }
    if let Some(service_account) = identity.service_account() {
        insert_metadata_if_changed(metadata, MESH_SOURCE_SERVICE_ACCOUNT, service_account);
    }
}

fn insert_destination_spiffe_labels<MS: std::hash::BuildHasher>(
    metadata: &mut HashMap<String, String, MS>,
    identity: &SpiffeId,
) {
    insert_metadata_if_changed(metadata, "mesh.destination.principal", identity.as_str());
    if let Some(namespace) = identity.namespace() {
        insert_metadata_if_changed(metadata, "mesh.destination.namespace", namespace);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    struct CapturingExporter {
        spans: Arc<Mutex<Vec<SpanData>>>,
    }

    impl TraceExporter for CapturingExporter {
        fn provider_name(&self) -> &'static str {
            "test"
        }

        fn hostname(&self) -> Option<&str> {
            None
        }

        fn try_export(&self, span: SpanData) -> Result<(), String> {
            self.spans
                .lock()
                .map_err(|_| "test span mutex poisoned".to_string())?
                .push(span);
            Ok(())
        }
    }

    fn stream_context(
        direction: MeshTrafficDirection,
        authenticated_identity: Option<&str>,
        proxy_name: &str,
    ) -> StreamConnectionContext {
        let mut ctx = StreamConnectionContext::new(
            "10.0.0.2".to_string(),
            "10.0.0.2".to_string(),
            "mesh-stream".to_string(),
            Some(proxy_name.to_string()),
            5432,
            crate::config::types::BackendScheme::Tcp,
            Arc::new(crate::consumer_index::ConsumerIndex::new(&[])),
        );
        ctx.authenticated_identity = authenticated_identity.map(str::to_owned);
        ctx.mesh_direction = Some(direction);
        ctx
    }

    #[test]
    fn source_spiffe_labels_match_gates_clear_and_restamp() {
        // The repeat-annotate fast path must preserve clear-then-restamp
        // semantics exactly: identical identity = labels already current
        // (clear may be skipped); any identity change — including loss of
        // namespace/service-account segments or to `None` — must not match,
        // so stale segments can never survive.
        let full = SpiffeId::new("spiffe://cluster.local/ns/payments/sa/api")
            .expect("valid workload SPIFFE ID");
        let no_segments =
            SpiffeId::new("spiffe://cluster.local/workload/api").expect("valid SPIFFE ID");
        let other = SpiffeId::new("spiffe://cluster.local/ns/orders/sa/web")
            .expect("valid workload SPIFFE ID");

        let mut metadata = HashMap::new();
        assert!(source_spiffe_labels_match(&metadata, None));
        assert!(!source_spiffe_labels_match(&metadata, Some(&full)));

        insert_source_spiffe_labels(&mut metadata, &full);
        assert!(source_spiffe_labels_match(&metadata, Some(&full)));
        assert!(!source_spiffe_labels_match(&metadata, Some(&other)));
        assert!(!source_spiffe_labels_match(&metadata, Some(&no_segments)));
        assert!(!source_spiffe_labels_match(&metadata, None));

        // Re-stamping the same identity is a no-op on the final map.
        let before = metadata.clone();
        insert_source_spiffe_labels(&mut metadata, &full);
        assert_eq!(metadata, before);

        // Identity change still clears the segments the new identity lacks.
        clear_source_spiffe_labels(&mut metadata);
        insert_source_spiffe_labels(&mut metadata, &no_segments);
        assert!(source_spiffe_labels_match(&metadata, Some(&no_segments)));
        assert!(!metadata.contains_key(MESH_SOURCE_NAMESPACE));
        assert!(!metadata.contains_key(MESH_SOURCE_SERVICE_ACCOUNT));

        // insert-if-changed overwrites differing values and keeps equal ones.
        insert_metadata_if_changed(&mut metadata, "mesh.test", "alpha");
        assert_eq!(metadata.get("mesh.test").map(String::as_str), Some("alpha"));
        insert_metadata_if_changed(&mut metadata, "mesh.test", "beta");
        assert_eq!(metadata.get("mesh.test").map(String::as_str), Some("beta"));
    }

    #[test]
    fn custom_header_tags_resolve_request_header_values() {
        let metrics = WorkloadMetrics::new(&json!({
            "custom_tags": {
                "literal": "constant"
            },
            "custom_header_tags": {
                "tenant": "x-tenant"
            },
            "safe_tag_sources": ["X-Tenant"]
        }))
        .expect("metrics config");
        let headers = HashMap::from([("X-Tenant".to_string(), "acme".to_string())]);
        let mut metadata = HashMap::new();

        metrics.apply_telemetry_metadata(&mut metadata, &headers);

        assert_eq!(
            metadata.get("literal").map(String::as_str),
            Some("constant")
        );
        assert_eq!(metadata.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(
            metadata
                .get(CUSTOM_TRACE_ATTRIBUTES_METADATA)
                .map(String::as_str),
            Some("literal,tenant")
        );
    }

    #[test]
    fn response_trailer_policy_only_claims_traceparent_when_tracing_can_author_it() {
        let metrics_only = WorkloadMetrics::new(&json!({})).expect("metrics-only config");
        assert!(matches!(
            metrics_only.response_trailer_policy(),
            crate::plugins::ResponseTrailerPolicy::None
        ));

        let tracing = WorkloadMetrics::new(&json!({
            "sampling_percentage": 100.0
        }))
        .expect("tracing config");
        assert!(matches!(
            tracing.response_trailer_policy(),
            crate::plugins::ResponseTrailerPolicy::Names(names)
                if names.len() == 1 && names[0] == "traceparent"
        ));
    }

    #[test]
    fn custom_env_tags_resolve_at_construction_with_istio_missing_semantics() {
        const ENV_VAR: &str = "FERRUM_TEST_WORKLOAD_METRICS_ENV_TAG";

        let missing = WorkloadMetrics::new_with_env_lookup_for_test(
            &json!({
                "custom_tags": {"cluster": "fallback"},
                "custom_env_tags": {
                    "cluster": ENV_VAR,
                    "region": "FERRUM_TEST_WORKLOAD_METRICS_ENV_TAG_ABSENT"
                }
            }),
            |_| Err(std::env::VarError::NotPresent),
        )
        .expect("missing env keeps default / omits tag");
        let mut metadata = HashMap::new();
        missing.apply_telemetry_metadata(&mut metadata, &HashMap::new());
        assert_eq!(
            metadata.get("cluster").map(String::as_str),
            Some("fallback")
        );
        assert!(!metadata.contains_key("region"));

        let present = WorkloadMetrics::new_with_env_lookup_for_test(
            &json!({
                "custom_tags": {"cluster": "fallback"},
                "custom_env_tags": {"cluster": ENV_VAR},
                "safe_tag_sources": [ENV_VAR]
            }),
            |name| {
                if name == ENV_VAR {
                    Ok("live".to_string())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            },
        )
        .expect("present env overrides default");
        let mut metadata = HashMap::new();
        present.apply_telemetry_metadata(&mut metadata, &HashMap::new());
        assert_eq!(metadata.get("cluster").map(String::as_str), Some("live"));

        let invalid = WorkloadMetrics::new_with_env_lookup_for_test(
            &json!({
                "custom_env_tags": {"cluster": "BAD-NAME"}
            }),
            |_| Err(std::env::VarError::NotPresent),
        );
        assert!(
            invalid
                .err()
                .expect("invalid env var name")
                .contains("invalid environment variable name")
        );

        for env_var in [
            "FERRUM_ADMIN_JWT_SECRET",
            "AWS_SESSION_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AZURE_CLIENT_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "FERRUM_DB_URL",
            "DATABASE_URL",
            "MONGODB_URI",
            "DATABASE_DSN",
            "DATABASE_CONNECTION_STRING",
            "AWS_SECRET-KEY",
            "myPassword",
            "AccessToken",
            "sessiontoken",
            "ClientId",
        ] {
            let sensitive = WorkloadMetrics::new_with_env_lookup_for_test(
                &json!({
                    "custom_env_tags": {"dimension": env_var}
                }),
                |_| Err(std::env::VarError::NotPresent),
            );
            let error = sensitive.err().expect("sensitive env var name");
            assert!(
                error.contains("cannot copy a credential-bearing environment variable"),
                "expected credential-bearing env rejection, got {error}"
            );
            assert!(
                !error.contains(env_var),
                "sensitive environment variable name must not be echoed"
            );
        }

        for env_var in ["ISTIO_META_CLUSTER_ID", "ISTIO_META_ZONE", "FERRUM_REGION"] {
            assert!(
                validate_env_var_name("dimension", env_var).is_ok(),
                "ordinary telemetry dimension {env_var} must remain allowed"
            );
        }

        for invalid in [
            json!(null),
            json!([]),
            json!("ISTIO_META_CLUSTER_ID"),
            json!({"cluster": 42}),
        ] {
            let error = WorkloadMetrics::new_with_env_lookup_for_test(
                &json!({
                    "custom_env_tags": invalid
                }),
                |_| Err(std::env::VarError::NotPresent),
            )
            .err()
            .expect("invalid custom_env_tags shape must fail closed");
            assert!(
                error.contains("custom_env_tags"),
                "expected field-specific custom_env_tags error, got {error}"
            );
        }
    }

    #[test]
    fn custom_header_tags_reject_credentials_and_trace_control_collisions() {
        let credential_error = WorkloadMetrics::new(&json!({
            "custom_header_tags": {"tenant": "authorization"}
        }))
        .err()
        .expect("credential header must be rejected");
        assert!(credential_error.contains("sensitive header"));

        let reserved_error = WorkloadMetrics::new(&json!({
            "custom_header_tags": {"trace_sampled": "x-debug"}
        }))
        .err()
        .expect("trace control collision must be rejected");
        assert!(reserved_error.contains("reserved or sensitive"));
    }

    /// Issue #6619: a header or environment source the operator has not
    /// declared in `safe_tag_sources` is copied as the redaction marker, and
    /// a credential-shaped source cannot be declared safe.
    #[test]
    fn undeclared_tag_sources_are_redacted_and_credential_sources_cannot_be_declared() {
        let metrics = WorkloadMetrics::new_with_env_lookup_for_test(
            &json!({
                "custom_header_tags": {"tenant": "x-tenant", "zone": "x-zone"},
                "custom_env_tags": {"cluster": "ISTIO_META_CLUSTER_ID", "region": "FERRUM_REGION"},
                "safe_tag_sources": ["x-zone", "FERRUM_REGION"]
            }),
            |name| Ok(format!("{name}-value")),
        )
        .expect("metrics config");
        let headers = HashMap::from([
            ("x-tenant".to_string(), "tenant-sentinel".to_string()),
            ("x-zone".to_string(), "zone-a".to_string()),
        ]);
        let mut metadata = HashMap::new();
        metrics.apply_telemetry_metadata(&mut metadata, &headers);
        assert_eq!(
            metadata.get("tenant").map(String::as_str),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_eq!(metadata.get("zone").map(String::as_str), Some("zone-a"));
        assert_eq!(
            metadata.get("cluster").map(String::as_str),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_eq!(
            metadata.get("region").map(String::as_str),
            Some("FERRUM_REGION-value")
        );

        for source in [
            "x-key-private",
            "GPGPASS_PHRASE",
            "x-hsm-pin",
            "AWS_SESSION_TOKEN",
        ] {
            let error = WorkloadMetrics::new(&json!({ "safe_tag_sources": [source] }))
                .err()
                .expect("credential-shaped source rejected");
            assert!(error.contains("safe_tag_sources[0]"), "{error}");
            assert!(!error.contains(source), "{error}");
        }
    }

    #[test]
    fn custom_header_tag_values_are_bounded() {
        let metrics = WorkloadMetrics::new(&json!({
            "custom_header_tags": {"tenant": "x-tenant"}
        }))
        .expect("metrics config");
        let headers = HashMap::from([(
            "x-tenant".to_string(),
            "x".repeat(MAX_CUSTOM_TAG_VALUE_BYTES + 1),
        )]);
        let mut metadata = HashMap::new();

        metrics.apply_telemetry_metadata(&mut metadata, &headers);

        assert!(!metadata.contains_key("tenant"));
    }

    #[tokio::test]
    async fn configured_custom_tags_reach_spans_without_promoting_other_metadata() {
        let spans = Arc::new(Mutex::new(Vec::new()));
        let mut metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 100.0,
            "custom_tags": {"region": "east"},
            "custom_header_tags": {"tenant": "x-tenant"},
            "safe_tag_sources": ["x-tenant"]
        }))
        .expect("metrics config");
        metrics.trace_exporters = vec![Arc::new(CapturingExporter {
            spans: Arc::clone(&spans),
        })];
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
        ctx.headers
            .insert("x-tenant".to_string(), "acme".to_string());
        metrics.on_request_received(&mut ctx).await;
        ctx.metadata
            .insert("unrelated".to_string(), "must-not-export".to_string());
        let summary = TransactionSummary {
            metadata: ctx.metadata,
            ..TransactionSummary::default()
        };

        metrics.log(&summary).await;

        let spans = spans.lock().expect("span mutex");
        let span = spans.first().expect("exported span");
        assert!(
            span.mesh_attributes
                .contains(&("region".to_string(), "east".to_string()))
        );
        assert!(
            span.mesh_attributes
                .contains(&("tenant".to_string(), "acme".to_string()))
        );
        assert!(
            span.mesh_attributes
                .iter()
                .all(|(key, _)| key != "unrelated")
        );
    }

    #[tokio::test]
    async fn request_received_stamps_directional_metadata_before_authorization() {
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "payments",
            "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
            "labels": {"app": "checkout"}
        }))
        .expect("metrics config");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);

        let result = metrics.on_request_received(&mut ctx).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(!ctx.metadata.contains_key(MESH_SOURCE_PRINCIPAL));
        assert_eq!(
            ctx.metadata.get("mesh.source.workload").map(String::as_str),
            Some("unknown")
        );
        assert_eq!(
            ctx.metadata
                .get("mesh.destination.workload")
                .map(String::as_str),
            Some("checkout")
        );
        assert_eq!(
            ctx.metadata
                .get("mesh.destination.principal")
                .map(String::as_str),
            Some("spiffe://cluster.local/ns/payments/sa/checkout")
        );
        assert_eq!(
            ctx.metadata
                .get(MESH_DIRECTION_METADATA)
                .map(String::as_str),
            Some(MESH_DIRECTION_INBOUND)
        );
        let summary = TransactionSummary {
            response_status_code: 403,
            metadata: ctx.metadata.clone(),
            ..TransactionSummary::default()
        };
        let key = crate::plugins::mesh::prometheus_helpers::mesh_request_key(&summary)
            .expect("mesh request key before authorization rejection");
        assert_eq!(key.source_workload.as_ref(), "unknown");
        assert_eq!(key.destination_workload.as_ref(), "checkout");
        assert_eq!(key.response_code, 403);
    }

    #[test]
    fn inbound_peer_is_source_while_local_workload_is_destination() {
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "payments",
            "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
            "labels": {"app": "checkout"}
        }))
        .expect("metrics config");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
        ctx.peer_spiffe_id = Some(
            SpiffeId::new("spiffe://cluster.local/ns/storefront/sa/frontend")
                .expect("peer SPIFFE ID"),
        );

        metrics.annotate_http_context(&mut ctx, &HashMap::new());

        assert_eq!(
            ctx.metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str),
            Some("spiffe://cluster.local/ns/storefront/sa/frontend")
        );
        assert_eq!(
            ctx.metadata.get("mesh.source.workload").map(String::as_str),
            Some("frontend")
        );
        assert_eq!(
            ctx.metadata
                .get("mesh.destination.workload")
                .map(String::as_str),
            Some("checkout")
        );
    }

    #[test]
    fn trusted_hbone_baggage_is_the_inbound_source() {
        // Bare exact SPIFFE pins grant SameNamespace only (issue #4274). This
        // test is about honoring trusted baggage, so pin the storefront
        // identity with an exact-inventory object rather than relying on the
        // pre-fix namespace-blind reading of a ztunnel SVID in istio-system.
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "payments",
            "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
            "labels": {"app": "checkout"},
            "trusted_hbone_assertors": [{
                "assertor": "spiffe://cluster.local/ns/istio-system/sa/ztunnel",
                "asserts": ["spiffe://cluster.local/ns/storefront/sa/frontend"]
            }]
        }))
        .expect("metrics config");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
        ctx.peer_spiffe_id = Some(
            SpiffeId::new("spiffe://cluster.local/ns/istio-system/sa/ztunnel")
                .expect("assertor SPIFFE ID"),
        );
        ctx.metadata
            .insert("request_protocol".to_string(), "hbone".to_string());
        let headers = HashMap::from([(
            BAGGAGE_HEADER.to_string(),
            "source.principal=spiffe%3A%2F%2Fcluster.local%2Fns%2Fstorefront%2Fsa%2Ffrontend"
                .to_string(),
        )]);

        metrics.annotate_http_context(&mut ctx, &headers);

        assert_eq!(
            ctx.metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str),
            Some("spiffe://cluster.local/ns/storefront/sa/frontend")
        );
        assert!(
            !ctx.metadata.contains_key("mesh.ignored_baggage"),
            "trusted inventory must honor baggage rather than dropping it out of scope"
        );
        assert_eq!(
            ctx.metadata.get("mesh.source.workload").map(String::as_str),
            Some("frontend")
        );
        assert_eq!(
            ctx.metadata
                .get("mesh.destination.workload")
                .map(String::as_str),
            Some("checkout")
        );
    }

    #[tokio::test]
    async fn udp_source_scope_reject_restamps_source_to_attesting_peer() {
        // Exact inventory so request-received attribution honors the baggage
        // (the intended starting state). A bare ztunnel pin would fail closed
        // as assertion_out_of_scope first and never exercise the UDP
        // pod-UID/source-scope restamp this test is about.
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "payments",
            "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
            "labels": {"app": "checkout"},
            "trusted_hbone_assertors": [{
                "assertor": "spiffe://cluster.local/ns/istio-system/sa/ztunnel",
                "asserts": ["spiffe://cluster.local/ns/storefront/sa/frontend"]
            }]
        }))
        .expect("metrics config");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
        ctx.peer_spiffe_id = Some(
            SpiffeId::new("spiffe://cluster.local/ns/istio-system/sa/ztunnel")
                .expect("assertor SPIFFE ID"),
        );
        ctx.metadata
            .insert("request_protocol".to_string(), "hbone".to_string());
        ctx.headers.insert(
            BAGGAGE_HEADER.to_string(),
            "source.principal=spiffe%3A%2F%2Fcluster.local%2Fns%2Fstorefront%2Fsa%2Ffrontend"
                .to_string(),
        );

        // Request-received attribution runs before authorization and honors
        // the trusted-assertor baggage.
        metrics.on_request_received(&mut ctx).await;
        assert_eq!(
            ctx.metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str),
            Some("spiffe://cluster.local/ns/storefront/sa/frontend")
        );
        assert!(
            !ctx.metadata.contains_key("mesh.ignored_baggage"),
            "UDP restamp coverage must start from honored baggage, not assertion_out_of_scope"
        );

        // mesh_authz then discards the UDP pod-UID/source-scope evidence
        // bundle, falls back to the attesting peer, and rejects before
        // before_proxy can refresh the labels.
        ctx.metadata.insert(
            IGNORED_UDP_SOURCE_SCOPE_METADATA.to_string(),
            "pod_uid_not_bound".to_string(),
        );

        let mut response_headers = HashMap::new();
        metrics
            .after_proxy(&mut ctx, 403, &mut response_headers)
            .await;

        assert_eq!(
            ctx.metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str),
            Some("spiffe://cluster.local/ns/istio-system/sa/ztunnel")
        );
        assert_eq!(
            ctx.metadata.get("mesh.source.workload").map(String::as_str),
            Some("ztunnel")
        );
        assert_eq!(
            ctx.metadata.get(MESH_SOURCE_NAMESPACE).map(String::as_str),
            Some("istio-system")
        );
        assert_eq!(
            ctx.metadata.get("mesh.ignored_baggage").map(String::as_str),
            Some("pod_uid_not_bound"),
            "restamp must be the UDP source-scope refusal, not assertion_out_of_scope"
        );
    }

    #[test]
    fn outbound_local_workload_remains_the_source() {
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "storefront",
            "workload_spiffe_id": "spiffe://cluster.local/ns/storefront/sa/frontend",
            "labels": {"app": "frontend"}
        }))
        .expect("metrics config");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);

        metrics.annotate_http_context(&mut ctx, &HashMap::new());

        assert_eq!(
            ctx.metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str),
            Some("spiffe://cluster.local/ns/storefront/sa/frontend")
        );
        assert_eq!(
            ctx.metadata.get("mesh.source.workload").map(String::as_str),
            Some("frontend")
        );
        assert!(!ctx.metadata.contains_key("mesh.destination.principal"));
    }

    #[tokio::test]
    async fn stream_attribution_uses_directional_source_and_destination_roles() {
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "payments",
            "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
            "labels": {"app": "checkout"}
        }))
        .expect("metrics config");
        let mut inbound = stream_context(
            MeshTrafficDirection::Inbound,
            Some("spiffe://cluster.local/ns/storefront/sa/frontend"),
            "checkout.payments.svc.cluster.local",
        );
        metrics.on_stream_connect(&mut inbound).await;
        let inbound_summary = TransactionSummary {
            metadata: inbound.take_metadata(),
            ..TransactionSummary::default()
        };
        let inbound_key =
            crate::plugins::mesh::prometheus_helpers::mesh_request_key(&inbound_summary)
                .expect("inbound mesh key");
        assert_eq!(inbound_key.source_workload.as_ref(), "frontend");
        assert_eq!(inbound_key.destination_workload.as_ref(), "checkout");
        assert_eq!(inbound_key.destination_namespace.as_ref(), "payments");

        let mut outbound = stream_context(
            MeshTrafficDirection::Outbound,
            None,
            "reviews.catalog.svc.cluster.local",
        );
        metrics.on_stream_connect(&mut outbound).await;
        let outbound_summary = TransactionSummary {
            metadata: outbound.take_metadata(),
            ..TransactionSummary::default()
        };
        let outbound_key =
            crate::plugins::mesh::prometheus_helpers::mesh_request_key(&outbound_summary)
                .expect("outbound mesh key");
        assert_eq!(outbound_key.source_workload.as_ref(), "checkout");
        assert_eq!(
            outbound_key.destination_workload.as_ref(),
            "reviews.catalog.svc.cluster.local"
        );
        assert_eq!(outbound_key.destination_namespace.as_ref(), "catalog");
    }

    #[tokio::test]
    async fn captured_outbound_stream_attributes_asserted_source_workload() {
        // NodeWaypoint TCP / Ambient UDP capture runs on the node data plane
        // (ztunnel/waypoint identity) but asserts the originating pod as the
        // authenticated peer; the CLIENT-side labels must name that pod, not
        // the capturing data plane.
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "istio-system",
            "workload_spiffe_id": "spiffe://cluster.local/ns/istio-system/sa/ztunnel",
            "labels": {"app": "ztunnel"}
        }))
        .expect("metrics config");
        let mut outbound = stream_context(
            MeshTrafficDirection::Outbound,
            Some("spiffe://cluster.local/ns/storefront/sa/frontend"),
            "reviews.catalog.svc.cluster.local",
        );
        metrics.on_stream_connect(&mut outbound).await;
        let metadata = outbound.take_metadata();

        assert_eq!(
            metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str),
            Some("spiffe://cluster.local/ns/storefront/sa/frontend")
        );
        assert_eq!(
            metadata.get("mesh.source.workload").map(String::as_str),
            Some("frontend")
        );
        assert_eq!(
            metadata.get(MESH_SOURCE_NAMESPACE).map(String::as_str),
            Some("storefront")
        );
        assert_eq!(
            metadata
                .get("mesh.destination.workload")
                .map(String::as_str),
            Some("reviews.catalog.svc.cluster.local")
        );
    }

    #[test]
    fn metric_configuration_preserves_family_scope_and_istio_label_names() {
        let metrics = WorkloadMetrics::new(&json!({
            "metrics": {
                "disabled_metrics": ["REQUEST_DURATION"],
                "tag_overrides": [
                    {
                        "metric": "REQUEST_COUNT",
                        "name": "source_workload",
                        "operation": {"type": "set", "value": "edge"}
                    },
                    {
                        "metric": "REQUEST_DURATION",
                        "name": "response_flags",
                        "operation": {"type": "remove"}
                    }
                ]
            }
        }))
        .expect("metric config");

        assert_eq!(
            metrics
                .tag_override_plans
                .iter()
                .find(|(family, _)| *family
                    == crate::plugins::mesh::prometheus_helpers::MeshMetricFamily::RequestCount)
                .map(|(_, plan)| plan.as_str()),
            Some("m0;s0,4:edge;")
        );
        assert_eq!(
            metrics
                .tag_override_plans
                .iter()
                .find(|(family, _)| *family
                    == crate::plugins::mesh::prometheus_helpers::MeshMetricFamily::RequestDuration)
                .map(|(_, plan)| plan.as_str()),
            Some("m0;r11;")
        );
        assert_eq!(
            metrics.disabled_metrics_marker.as_deref(),
            Some("request_duration")
        );
    }

    #[tokio::test]
    async fn mirror_summary_does_not_duplicate_primary_span_identity() {
        let spans = Arc::new(Mutex::new(Vec::new()));
        let mut metrics = WorkloadMetrics::new(&json!({})).expect("metrics config");
        metrics.trace_exporters = vec![Arc::new(CapturingExporter {
            spans: Arc::clone(&spans),
        })];
        let summary = TransactionSummary {
            metadata: crate::plugins::MetadataMap::from_iter([
                ("trace_sampled".to_string(), "true".to_string()),
                (
                    "trace_id".to_string(),
                    "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
                ),
                ("span_id".to_string(), "00f067aa0ba902b7".to_string()),
            ]),
            ..TransactionSummary::default()
        };

        metrics.log(&summary).await;
        metrics
            .log(
                &summary.as_mirror_entry(crate::plugins::MirrorResponseMeta {
                    mirror_plugin_id: Some("request-mirror-test".to_string()),
                    mirror_target_url: "https://mirror.example".to_string(),
                    mirror_response_status_code: Some(200),
                    mirror_response_size_bytes: Some(0),
                    mirror_response_advertised_size_bytes: None,
                    mirror_latency_ms: 1.0,
                    mirror_error: None,
                }),
            )
            .await;

        let spans = spans.lock().expect("span mutex");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(spans[0].span_id, "00f067aa0ba902b7");
    }

    #[test]
    fn sampling_config_without_recorded_decision_does_not_resample_on_export() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 100.0
        }))
        .expect("sampling-only metrics config");
        let metadata = HashMap::from([
            (
                "trace_id".to_string(),
                "abcdef1234567890abcdef1234567890".to_string(),
            ),
            ("span_id".to_string(), "1234567890abcdef".to_string()),
        ]);

        assert!(
            !metrics.should_export_metadata(&metadata),
            "export should rely on the request-time sampling decision"
        );
    }

    #[test]
    fn invalid_sampling_percentage_is_rejected() {
        let err = WorkloadMetrics::new(&json!({
            "sampling_percentage": 150.0
        }))
        .err()
        .expect("out-of-range sampling should fail");
        assert!(
            err.contains("`sampling_percentage` must be between 0.0 and 100.0"),
            "{err}"
        );

        let err = WorkloadMetrics::new(&json!({
            "sampling_percentage": "100"
        }))
        .err()
        .expect("non-numeric sampling should fail");
        assert!(
            err.contains("`sampling_percentage` must be a number"),
            "{err}"
        );
    }

    #[test]
    fn fallback_sampling_seed_mixes_stack_entropy() {
        assert_ne!(
            fallback_sampling_seed(0, 0x1111),
            fallback_sampling_seed(0, 0x2222)
        );
    }

    #[tokio::test]
    async fn tracing_provider_zipkin_round_trips_through_config() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "tracing_provider": {
                "kind": "zipkin",
                "config": {
                    "url": "http://zipkin:9411/api/v2/spans"
                }
            }
        }))
        .expect("zipkin provider accepted");
        match metrics
            .tracing_providers()
            .first()
            .expect("provider stored")
        {
            TracingProvider::Zipkin { url } => {
                assert_eq!(url, "http://zipkin:9411/api/v2/spans");
            }
            other => panic!("expected Zipkin, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tracing_provider_datadog_optional_service_round_trips() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "tracing_provider": {
                "kind": "datadog",
                "config": {
                    "agent_url": "http://datadog-agent:8126",
                    "service": "checkout"
                }
            }
        }))
        .expect("datadog provider accepted");
        match metrics
            .tracing_providers()
            .first()
            .expect("provider stored")
        {
            TracingProvider::Datadog { agent_url, service } => {
                assert_eq!(agent_url, "http://datadog-agent:8126");
                assert_eq!(service.as_deref(), Some("checkout"));
            }
            other => panic!("expected Datadog, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tracing_provider_lightstep_requires_collector_and_token_env() {
        let metrics = WorkloadMetrics::new(&json!({
            "span_reporting_disabled": true,
            "tracing_provider": {
                "kind": "lightstep",
                "config": {
                    "collector_url": "https://ingest.lightstep.com:443",
                    "access_token_env": "FERRUM_PLUGIN_SECRET_LIGHTSTEP"
                }
            }
        }))
        .expect("lightstep provider accepted");
        match metrics
            .tracing_providers()
            .first()
            .expect("provider stored")
        {
            TracingProvider::Lightstep {
                collector_url,
                access_token_env,
            } => {
                assert_eq!(collector_url, "https://ingest.lightstep.com:443");
                assert_eq!(access_token_env, "FERRUM_PLUGIN_SECRET_LIGHTSTEP");
            }
            other => panic!("expected Lightstep, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tracing_provider_opentelemetry_round_trips() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "tracing_provider": {
                "kind": "opentelemetry",
                "config": {
                    "endpoint": "http://otel-collector:4317"
                }
            }
        }))
        .expect("opentelemetry provider accepted");
        match metrics
            .tracing_providers()
            .first()
            .expect("provider stored")
        {
            TracingProvider::OpenTelemetry { endpoint } => {
                assert_eq!(endpoint, "http://otel-collector:4317");
            }
            other => panic!("expected OpenTelemetry, got {other:?}"),
        }
    }

    #[test]
    fn missing_tracing_provider_remains_none() {
        let metrics = WorkloadMetrics::new(&json!({
            "custom_tags": {"literal": "constant"}
        }))
        .expect("config without provider accepted");
        assert!(metrics.tracing_providers().is_empty());
    }

    #[test]
    fn invalid_tracing_provider_kind_is_rejected() {
        let err = WorkloadMetrics::new(&json!({
            "tracing_provider": {
                "kind": "stackdriver",
                "config": {"endpoint": "x"}
            }
        }))
        .err()
        .expect("unknown provider kind should fail");
        assert!(err.contains("invalid `tracing_provider` config"), "{err}");
    }

    #[test]
    fn tracing_provider_config_is_safe_without_tokio_runtime() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "tracing_provider": {
                "kind": "zipkin",
                "config": {
                    "url": "http://zipkin:9411/api/v2/spans"
                }
            }
        }))
        .expect("validation-time construction should not require a Tokio runtime");

        assert_eq!(metrics.tracing_providers().len(), 1);
        assert_eq!(metrics.warmup_hostnames(), vec!["zipkin".to_string()]);
    }

    #[tokio::test]
    async fn tracing_providers_array_round_trips() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "tracing_providers": [
                {
                    "kind": "zipkin",
                    "config": {
                        "url": "http://zipkin:9411/api/v2/spans"
                    }
                },
                {
                    "kind": "datadog",
                    "config": {
                        "agent_url": "http://datadog-agent:8126"
                    }
                }
            ]
        }))
        .expect("provider array accepted");
        assert_eq!(metrics.tracing_providers().len(), 2);
    }

    #[tokio::test]
    async fn before_proxy_propagates_trace_context_from_header_parameter() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "tracing_providers": [{
                "kind": "zipkin",
                "config": {
                    "url": "http://zipkin:9411/api/v2/spans"
                }
            }]
        }))
        .expect("zipkin provider accepted");
        assert!(metrics.modifies_request_headers());

        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let incoming_traceparent = format!("00-{trace_id}-{parent_span_id}-01");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::from([
            (TRACEPARENT_HEADER.to_string(), incoming_traceparent),
            (TRACESTATE_HEADER.to_string(), "dd=s:1".to_string()),
        ]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_id").map(String::as_str),
            Some(trace_id)
        );
        assert_eq!(
            ctx.metadata.get("parent_span_id").map(String::as_str),
            Some(parent_span_id)
        );
        let outgoing_traceparent = headers
            .get(TRACEPARENT_HEADER)
            .expect("traceparent propagated");
        assert!(outgoing_traceparent.starts_with(&format!("00-{trace_id}-")));
        assert!(outgoing_traceparent.ends_with("-01"));
        assert_ne!(
            outgoing_traceparent,
            &format!("00-{trace_id}-{parent_span_id}-01")
        );
        assert_eq!(
            headers.get(TRACESTATE_HEADER).map(String::as_str),
            Some("dd=s:1")
        );

        let mut response_headers = HashMap::new();
        metrics
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        assert_eq!(
            response_headers.get(TRACEPARENT_HEADER),
            headers.get(TRACEPARENT_HEADER)
        );
    }

    #[tokio::test]
    async fn before_proxy_keeps_incoming_sampled_trace_context_when_locally_unsampled() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "sampling_percentage": 0.0,
            "tracing_providers": [{
                "kind": "zipkin",
                "config": {
                    "url": "http://zipkin:9411/api/v2/spans"
                }
            }]
        }))
        .expect("zipkin provider accepted");

        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let incoming_traceparent = format!("00-{trace_id}-{parent_span_id}-01");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::from([(TRACEPARENT_HEADER.to_string(), incoming_traceparent)]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ctx.metadata.get("trace_id").map(String::as_str),
            Some(trace_id)
        );
        assert_eq!(
            ctx.metadata.get("parent_span_id").map(String::as_str),
            Some(parent_span_id)
        );
        let outgoing_traceparent = headers
            .get(TRACEPARENT_HEADER)
            .expect("traceparent propagated despite local sampling");
        assert!(outgoing_traceparent.starts_with(&format!("00-{trace_id}-")));
        assert!(outgoing_traceparent.ends_with("-01"));
        assert_ne!(
            outgoing_traceparent,
            &format!("00-{trace_id}-{parent_span_id}-01")
        );
    }

    #[tokio::test]
    async fn before_proxy_keeps_incoming_unsampled_trace_context_when_locally_sampled() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "sampling_percentage": 100.0,
            "tracing_providers": [{
                "kind": "zipkin",
                "config": {
                    "url": "http://zipkin:9411/api/v2/spans"
                }
            }]
        }))
        .expect("zipkin provider accepted");

        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let incoming_traceparent = format!("00-{trace_id}-{parent_span_id}-00");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::from([(TRACEPARENT_HEADER.to_string(), incoming_traceparent)]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("false")
        );
        let outgoing_traceparent = headers
            .get(TRACEPARENT_HEADER)
            .expect("traceparent propagated despite local sampling");
        assert!(outgoing_traceparent.starts_with(&format!("00-{trace_id}-")));
        assert!(outgoing_traceparent.ends_with("-00"));
        assert_ne!(
            outgoing_traceparent,
            &format!("00-{trace_id}-{parent_span_id}-00")
        );
    }

    #[tokio::test]
    async fn before_proxy_keeps_b3_sampling_decision_when_local_sampling_configured() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 0.0
        }))
        .expect("sampling-only workload metrics accepted");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::from([("x-b3-sampled".to_string(), "1".to_string())]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn before_proxy_imports_b3_trace_ids_when_honoring_b3_sampling() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 0.0
        }))
        .expect("sampling-only workload metrics accepted");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let mut headers = HashMap::from([
            ("x-b3-sampled".to_string(), "1".to_string()),
            ("x-b3-traceid".to_string(), trace_id.to_string()),
            ("x-b3-spanid".to_string(), parent_span_id.to_string()),
        ]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ctx.metadata.get("trace_id").map(String::as_str),
            Some(trace_id)
        );
        assert_eq!(
            ctx.metadata.get("parent_span_id").map(String::as_str),
            Some(parent_span_id)
        );
        let outgoing_traceparent = headers
            .get(TRACEPARENT_HEADER)
            .expect("traceparent propagated from B3 context");
        assert!(outgoing_traceparent.starts_with(&format!("00-{trace_id}-")));
        assert!(outgoing_traceparent.ends_with("-01"));
        assert_ne!(
            outgoing_traceparent,
            &format!("00-{trace_id}-{parent_span_id}-01")
        );
    }

    #[tokio::test]
    async fn before_proxy_imports_unsampled_b3_trace_ids() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 100.0
        }))
        .expect("sampling-only workload metrics accepted");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let mut headers = HashMap::from([
            ("x-b3-sampled".to_string(), "0".to_string()),
            ("x-b3-traceid".to_string(), trace_id.to_string()),
            ("x-b3-spanid".to_string(), parent_span_id.to_string()),
        ]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            ctx.metadata.get("trace_id").map(String::as_str),
            Some(trace_id)
        );
        assert_eq!(
            ctx.metadata.get("parent_span_id").map(String::as_str),
            Some(parent_span_id)
        );
        let outgoing_traceparent = headers
            .get(TRACEPARENT_HEADER)
            .expect("traceparent propagated from unsampled B3 context");
        assert!(outgoing_traceparent.starts_with(&format!("00-{trace_id}-")));
        assert!(outgoing_traceparent.ends_with("-00"));
        assert_ne!(
            outgoing_traceparent,
            &format!("00-{trace_id}-{parent_span_id}-00")
        );
    }

    #[tokio::test]
    async fn before_proxy_keeps_b3_single_sampling_decision_when_local_sampling_configured() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 0.0
        }))
        .expect("sampling-only workload metrics accepted");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::from([("b3".to_string(), "1".to_string())]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn before_proxy_prefers_b3_single_sampling_over_multi_headers() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 100.0
        }))
        .expect("sampling-only workload metrics accepted");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::from([
            ("b3".to_string(), "0".to_string()),
            ("x-b3-flags".to_string(), "1".to_string()),
            ("x-b3-sampled".to_string(), "1".to_string()),
        ]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("false")
        );
    }

    #[tokio::test]
    async fn before_proxy_imports_b3_single_trace_ids_when_honoring_b3_sampling() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 0.0
        }))
        .expect("sampling-only workload metrics accepted");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let mut headers =
            HashMap::from([("b3".to_string(), format!("{trace_id}-{parent_span_id}-1"))]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ctx.metadata.get("trace_id").map(String::as_str),
            Some(trace_id)
        );
        assert_eq!(
            ctx.metadata.get("parent_span_id").map(String::as_str),
            Some(parent_span_id)
        );
        let outgoing_traceparent = headers
            .get(TRACEPARENT_HEADER)
            .expect("traceparent propagated from B3 single context");
        assert!(outgoing_traceparent.starts_with(&format!("00-{trace_id}-")));
        assert!(outgoing_traceparent.ends_with("-01"));
        assert_ne!(
            outgoing_traceparent,
            &format!("00-{trace_id}-{parent_span_id}-01")
        );
    }

    #[tokio::test]
    async fn before_proxy_imports_unsampled_b3_single_trace_ids() {
        let metrics = WorkloadMetrics::new(&json!({
            "sampling_percentage": 100.0
        }))
        .expect("sampling-only workload metrics accepted");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let mut headers =
            HashMap::from([("b3".to_string(), format!("{trace_id}-{parent_span_id}-0"))]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_sampled").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            ctx.metadata.get("trace_id").map(String::as_str),
            Some(trace_id)
        );
        assert_eq!(
            ctx.metadata.get("parent_span_id").map(String::as_str),
            Some(parent_span_id)
        );
        let outgoing_traceparent = headers
            .get(TRACEPARENT_HEADER)
            .expect("traceparent propagated from unsampled B3 single context");
        assert!(outgoing_traceparent.starts_with(&format!("00-{trace_id}-")));
        assert!(outgoing_traceparent.ends_with("-00"));
        assert_ne!(
            outgoing_traceparent,
            &format!("00-{trace_id}-{parent_span_id}-00")
        );
    }

    #[tokio::test]
    async fn disable_span_reporting_keeps_provider_config_but_builds_no_exporters() {
        let metrics = WorkloadMetrics::new(&json!({
            "allow_plaintext": true,
            "span_reporting_disabled": true,
            "sampling_percentage": 100.0,
            "tracing_providers": [{
                "kind": "zipkin",
                "config": {
                    "url": "http://zipkin:9411/api/v2/spans"
                }
            }]
        }))
        .expect("disabled tracing accepted");
        assert!(metrics.span_reporting_disabled());
        assert_eq!(metrics.tracing_providers().len(), 1);
        assert!(metrics.warmup_hostnames().is_empty());
        assert!(metrics.modifies_request_headers());

        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::new();

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.metadata.contains_key("trace_id"));
        assert!(ctx.metadata.contains_key("span_id"));
        assert!(ctx.metadata.contains_key(TRACEPARENT_HEADER));
        assert!(headers.contains_key(TRACEPARENT_HEADER));
    }

    #[tokio::test]
    async fn disable_span_reporting_without_providers_propagates_incoming_trace_context() {
        let metrics = WorkloadMetrics::new(&json!({
            "span_reporting_disabled": true
        }))
        .expect("disabled tracing without providers accepted");
        assert!(metrics.span_reporting_disabled());
        assert!(metrics.tracing_providers().is_empty());
        assert!(metrics.modifies_request_headers());

        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_span_id = "00f067aa0ba902b7";
        let incoming_traceparent = format!("00-{trace_id}-{parent_span_id}-01");
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let mut headers = HashMap::from([(TRACEPARENT_HEADER.to_string(), incoming_traceparent)]);

        let result = metrics.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.metadata.get("trace_id").map(String::as_str),
            Some(trace_id)
        );
        assert!(headers.contains_key(TRACEPARENT_HEADER));
    }
}
