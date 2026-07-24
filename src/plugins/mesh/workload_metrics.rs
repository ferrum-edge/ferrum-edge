//! Mesh workload metadata plugin.
//!
//! Adds Istio/GAMMA-style identity labels into transaction metadata. The
//! existing logging and metrics sinks then pick them up without plugin-trait
//! changes.

use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::MeshTrafficDirection;
use crate::modes::mesh::config::{MeshMetricsConfig, MeshTracingConfig, TracingProvider};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::plugins::mesh::CUSTOM_TRACE_ATTRIBUTES_METADATA;
use crate::plugins::mesh::authz::{
    IGNORED_UDP_SOURCE_SCOPE_METADATA, TrustedAssertor, is_trusted_hbone_assertor,
    parse_trust_domain_aliases, parse_trusted_hbone_assertors,
};
use crate::plugins::mesh::prometheus_helpers::{
    MESH_METRICS_DISABLED_METADATA, MESH_REQUEST_COUNT_OVERRIDES_METADATA,
    MESH_REQUEST_DURATION_OVERRIDES_METADATA, MeshMetricFamily, MeshMetricLabel,
};
use crate::plugins::otel_tracing::{
    OtelTracing, SpanData, SpanKind, TraceExporter, build_traceparent, ensure_trace_metadata,
    trace_exporters_from_providers, trace_is_sampled, validate_trace_provider_endpoints,
};
use crate::plugins::utils::PluginHttpClient;
use crate::plugins::utils::metadata_redaction::is_sensitive_metadata_key;
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
const MAX_METRIC_TAG_VALUE_BYTES: usize = 256;

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
/// spans only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
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

#[derive(Default)]
pub struct WorkloadMetrics {
    node_id: Option<String>,
    topology: Option<String>,
    namespace: Option<String>,
    workload_spiffe_id: Option<SpiffeId>,
    labels: HashMap<String, String>,
    trust_domain_aliases: Vec<TrustDomain>,
    /// HBONE trusted-assertor allow-list. Baggage `source.principal` is honored
    /// only when the authenticated peer matches this list (default
    /// ztunnel/waypoint), mirroring `mesh_authz` so telemetry attribution can
    /// never diverge from the authorization decision. Empty = no peer may
    /// assert baggage (fail closed).
    trusted_hbone_assertors: Vec<TrustedAssertor>,
    /// Tracing sampling percentage 0.0–100.0 (from Telemetry CRD).
    sampling_percentage: Option<f64>,
    /// Custom tags injected into every transaction's metadata.
    custom_tags: HashMap<String, String>,
    /// Custom tags populated from request headers.
    custom_header_tags: HashMap<String, String>,
    request_count_tag_overrides: Option<String>,
    request_duration_tag_overrides: Option<String>,
    disabled_metrics_marker: Option<String>,
    custom_trace_attributes_marker: Option<String>,
    /// Provider-specific tracing backends surfaced from Istio Telemetry CRD
    /// via the mesh slice. These also enable trace-context propagation when
    /// span reporting is disabled.
    tracing_providers: Vec<TracingProvider>,
    trace_exporters: Vec<Arc<dyn TraceExporter>>,
    export_drop_log_limiter: Mutex<crate::util::accept_backoff::LogRateLimiter>,
    span_reporting_disabled: bool,
    service_name: String,
    /// Which directions of a mesh hop this plugin instance should emit spans
    /// for. Defaults to SERVER-only.
    direction_emit: DirectionEmit,
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
        let workload_spiffe_id = config
            .get("workload_spiffe_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(SpiffeId::new)
            .transpose()
            .map_err(|e| format!("workload_metrics: invalid workload_spiffe_id: {e}"))?;
        let labels = config
            .get("labels")
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let trust_domain_aliases =
            parse_trust_domain_aliases(config).map_err(|e| format!("workload_metrics: {e}"))?;
        let trusted_hbone_assertors =
            parse_trusted_hbone_assertors(config).map_err(|e| format!("workload_metrics: {e}"))?;
        let sampling_percentage = match config.get("sampling_percentage") {
            Some(value) => {
                let Some(percentage) = value.as_f64() else {
                    return Err(
                        "workload_metrics: sampling_percentage must be a number".to_string()
                    );
                };
                if !percentage.is_finite() || !(0.0..=100.0).contains(&percentage) {
                    return Err(format!(
                        "workload_metrics: sampling_percentage must be between 0.0 and 100.0 (got {percentage})"
                    ));
                }
                Some(percentage)
            }
            None => None,
        };
        let custom_tags: HashMap<String, String> = config
            .get("custom_tags")
            .and_then(Value::as_object)
            .map(|tags| {
                tags.iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let custom_header_tags: HashMap<String, String> = config
            .get("custom_header_tags")
            .and_then(Value::as_object)
            .map(|tags| {
                tags.iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ValidatedCustomTags {
            custom_tags,
            custom_header_tags,
            custom_trace_attributes_marker,
        } = validate_custom_tags(custom_tags, custom_header_tags)?;
        let ParsedMetricConfig {
            request_count_tag_overrides,
            request_duration_tag_overrides,
            disabled_metrics_marker,
        } = parse_metric_config(config.get("metrics"), true)?;
        let tracing_providers = parse_tracing_providers(config)?;
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
                .map_err(|e| format!("workload_metrics: invalid tracing exporter config: {e}"))?
        };
        let direction_emit = parse_direction_emit(config)?;

        Ok(Self {
            node_id: string_config(config, "node_id"),
            topology: string_config(config, "topology"),
            namespace: string_config(config, "namespace"),
            workload_spiffe_id,
            labels,
            trust_domain_aliases,
            trusted_hbone_assertors,
            sampling_percentage,
            custom_tags,
            custom_header_tags,
            request_count_tag_overrides,
            request_duration_tag_overrides,
            disabled_metrics_marker,
            custom_trace_attributes_marker,
            tracing_providers,
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

    fn annotate_http_context(&self, ctx: &mut RequestContext, headers: &HashMap<String, String>) {
        self.insert_common_metadata(&mut ctx.metadata);
        self.apply_telemetry_metadata(&mut ctx.metadata, headers);
        if self.should_ensure_http_trace_context(&ctx.metadata, headers) {
            if !has_valid_traceparent(headers) {
                import_b3_trace_metadata(&mut ctx.metadata, headers);
            }
            ensure_trace_metadata(&mut ctx.metadata, headers);
            if let Some(tracestate) = header_value(headers, TRACESTATE_HEADER) {
                ctx.metadata
                    .insert(TRACESTATE_HEADER.to_string(), tracestate.to_string());
            }
        }
        let hbone_identity = hbone_identity_from_headers(ctx, headers);
        let peer_source_identity = self.resolve_peer_source_identity(ctx, hbone_identity.as_ref());
        // This method runs before authorization and again after request-header
        // transforms. Rebuild the SPIFFE-derived source identity as one atomic
        // view so a final peer with fewer path segments cannot retain namespace
        // or service-account labels from early trusted baggage.
        clear_source_spiffe_labels(&mut ctx.metadata);
        ctx.metadata.insert(
            "mesh.connection_security_policy".to_string(),
            if ctx.peer_spiffe_id.is_some() || ctx.tls_client_cert_der.is_some() {
                "mutual_tls"
            } else {
                "none"
            }
            .to_string(),
        );
        ctx.metadata.insert(
            "mesh.request_protocol".to_string(),
            request_protocol(ctx, headers).to_string(),
        );
        if let Some(direction) = ctx.mesh_direction {
            ctx.metadata.insert(
                MESH_DIRECTION_METADATA.to_string(),
                mesh_direction_str(direction).to_string(),
            );
        }

        match ctx.mesh_direction {
            Some(MeshTrafficDirection::Inbound) => {
                if let Some(identity) = peer_source_identity.as_ref() {
                    insert_source_spiffe_labels(&mut ctx.metadata, identity);
                }
                self.insert_remote_source_workload_labels(
                    &mut ctx.metadata,
                    peer_source_identity.as_ref(),
                );
                self.insert_local_destination_workload_labels(&mut ctx.metadata);
            }
            Some(MeshTrafficDirection::Outbound) => {
                // A NodeWaypoint outbound listener serves many captured pods.
                // Its accept path authenticates the originating pod and stamps
                // both fields together; use that asserted identity directly so
                // request baggage cannot spoof it and the shared waypoint is
                // never reported as the application source. Other outbound
                // topologies continue to attribute the local workload.
                let node_waypoint_source_identity = if ctx.node_waypoint_pod_uid.is_some() {
                    ctx.peer_spiffe_id.as_ref()
                } else {
                    None
                };
                if let Some(identity) = node_waypoint_source_identity {
                    insert_source_spiffe_labels(&mut ctx.metadata, identity);
                    self.insert_remote_source_workload_labels(&mut ctx.metadata, Some(identity));
                } else {
                    if let Some(identity) = self.workload_spiffe_id.as_ref() {
                        insert_source_spiffe_labels(&mut ctx.metadata, identity);
                    }
                    self.insert_local_source_workload_labels(&mut ctx.metadata);
                }
                if let Some(proxy) = ctx.matched_proxy.as_ref() {
                    self.insert_proxy_destination_labels(
                        &mut ctx.metadata,
                        &proxy.namespace,
                        proxy.name.as_deref().unwrap_or(&proxy.id),
                    );
                }
            }
            None => {
                let source_identity = peer_source_identity
                    .as_ref()
                    .or(self.workload_spiffe_id.as_ref());
                if let Some(identity) = source_identity {
                    insert_source_spiffe_labels(&mut ctx.metadata, identity);
                }
                self.insert_local_source_workload_labels(&mut ctx.metadata);
                if let Some(proxy) = ctx.matched_proxy.as_ref() {
                    self.insert_proxy_destination_labels(
                        &mut ctx.metadata,
                        &proxy.namespace,
                        proxy.name.as_deref().unwrap_or(&proxy.id),
                    );
                }
            }
        }
    }

    fn reconcile_captured_trace_headers(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> bool {
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

        if final_trace_signal {
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
    ) -> Option<SpiffeId> {
        // Resolve the source identity using the SAME baggage trust gate as
        // `mesh_authz` (shared `is_trusted_hbone_assertor` predicate) so the
        // telemetry attribution can never diverge from the authorization
        // decision. On authenticated ambient HBONE the peer cert identifies the
        // assertor (ztunnel/waypoint, by default) while baggage carries the
        // originating workload. Baggage `source.principal` is honored ONLY when
        // the peer is a trusted assertor AND the baggage trust domain matches
        // the peer's (or an alias). Otherwise the baggage is dropped, we fall
        // back to the peer-cert identity, and we stamp `mesh.ignored_baggage`
        // with the reason (mirroring `mesh_authz.ignored_baggage.*`). Without
        // the assertor gate any authenticated workload pod could forge a baggage
        // `source.principal` and mis-attribute its own traffic to a victim
        // workload across metrics, the service graph, spans, and access logs.
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
            (Some(peer), Some(baggage)) => {
                if !is_trusted_hbone_assertor(&self.trusted_hbone_assertors, peer) {
                    ctx.metadata.insert(
                        "mesh.ignored_baggage".to_string(),
                        "untrusted_assertor".to_string(),
                    );
                    Some(peer.clone())
                } else if !self.trust_domain_allowed(peer.trust_domain(), baggage.trust_domain()) {
                    ctx.metadata.insert(
                        "mesh.ignored_baggage".to_string(),
                        "trust_domain_mismatch".to_string(),
                    );
                    Some(peer.clone())
                } else {
                    Some(baggage)
                }
            }
            // An unauthenticated request must never have its source identity
            // rewritten by baggage; fall back to the workload hint below.
            (None, Some(_)) => {
                ctx.metadata.insert(
                    "mesh.ignored_baggage".to_string(),
                    "unauthenticated_hbone".to_string(),
                );
                None
            }
            // No baggage principal: use the authenticated peer identity if any.
            (peer, None) => peer.cloned(),
        }
    }

    fn should_ensure_http_trace_context(
        &self,
        metadata: &HashMap<String, String>,
        headers: &HashMap<String, String>,
    ) -> bool {
        self.trace_context_enabled()
            && (trace_is_sampled(metadata)
                || has_valid_traceparent(headers)
                || has_b3_trace_context(headers))
    }

    fn trust_domain_allowed(&self, peer_td: &TrustDomain, baggage_td: &TrustDomain) -> bool {
        peer_td == baggage_td
            || self
                .trust_domain_aliases
                .iter()
                .any(|alias| alias == baggage_td)
    }

    fn insert_common_metadata(&self, metadata: &mut HashMap<String, String>) {
        if let Some(node_id) = self.node_id.as_ref() {
            metadata.insert("mesh.node_id".to_string(), node_id.clone());
        }
        if let Some(topology) = self.topology.as_ref() {
            metadata.insert("mesh.topology".to_string(), topology.clone());
        }
    }

    fn apply_telemetry_metadata(
        &self,
        metadata: &mut HashMap<String, String>,
        headers: &HashMap<String, String>,
    ) {
        if let Some(sampled) = existing_sampling_decision(metadata, headers) {
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
            metadata.insert(key.clone(), value.clone());
        }
        for (key, header_name) in &self.custom_header_tags {
            if let Some(value) = header_value(headers, header_name)
                && value.len() <= MAX_CUSTOM_TAG_VALUE_BYTES
            {
                metadata.insert(key.clone(), value.to_string());
            }
        }
        if let Some(marker) = self.custom_trace_attributes_marker.as_ref() {
            metadata.insert(CUSTOM_TRACE_ATTRIBUTES_METADATA.to_string(), marker.clone());
        }
        if let Some(marker) = self.disabled_metrics_marker.as_ref() {
            metadata.insert(MESH_METRICS_DISABLED_METADATA.to_string(), marker.clone());
        }
        if let Some(plan) = self.request_count_tag_overrides.as_ref() {
            metadata.insert(
                MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
                plan.clone(),
            );
        }
        if let Some(plan) = self.request_duration_tag_overrides.as_ref() {
            metadata.insert(
                MESH_REQUEST_DURATION_OVERRIDES_METADATA.to_string(),
                plan.clone(),
            );
        }
    }

    fn should_export_metadata(&self, metadata: &HashMap<String, String>) -> bool {
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
        let workload = first_label(
            &self.labels,
            &[
                "service.istio.io/canonical-name",
                "app.kubernetes.io/name",
                "app",
                "k8s-app",
                "workload",
            ],
        )
        .or_else(|| {
            self.workload_spiffe_id
                .as_ref()
                .and_then(|identity| spiffe_path_value(identity, "sa"))
        })
        .unwrap_or("unknown");
        let app = first_label(&self.labels, &["app.kubernetes.io/name", "app", "k8s-app"])
            .unwrap_or(workload);
        let service = first_label(
            &self.labels,
            &["service.istio.io/canonical-name", "service", "app"],
        )
        .unwrap_or(workload);

        (workload, app, service)
    }

    fn insert_local_source_workload_labels(&self, metadata: &mut HashMap<String, String>) {
        if let Some(namespace) = self.namespace.as_ref() {
            metadata.insert("mesh.source.namespace".to_string(), namespace.clone());
        }
        let (workload, app, service) = self.local_workload_labels();
        metadata.insert("mesh.source.workload".to_string(), workload.to_string());
        metadata.insert("mesh.source.app".to_string(), app.to_string());
        metadata.insert("mesh.source.service".to_string(), service.to_string());
    }

    fn insert_local_destination_workload_labels(&self, metadata: &mut HashMap<String, String>) {
        if let Some(identity) = self.workload_spiffe_id.as_ref() {
            insert_destination_spiffe_labels(metadata, identity);
        }
        if let Some(namespace) = self.namespace.as_ref() {
            metadata.insert("mesh.destination.namespace".to_string(), namespace.clone());
        }
        let (workload, app, service) = self.local_workload_labels();
        metadata.insert(
            "mesh.destination.workload".to_string(),
            workload.to_string(),
        );
        metadata.insert("mesh.destination.app".to_string(), app.to_string());
        metadata.insert("mesh.destination.service".to_string(), service.to_string());
    }

    fn insert_remote_source_workload_labels(
        &self,
        metadata: &mut HashMap<String, String>,
        identity: Option<&SpiffeId>,
    ) {
        let workload = identity
            .and_then(|identity| spiffe_path_value(identity, "sa"))
            .unwrap_or("unknown");
        metadata.insert("mesh.source.workload".to_string(), workload.to_string());
        metadata.insert("mesh.source.app".to_string(), workload.to_string());
        metadata.insert("mesh.source.service".to_string(), workload.to_string());
    }

    fn insert_proxy_destination_labels(
        &self,
        metadata: &mut HashMap<String, String>,
        namespace: &str,
        destination: &str,
    ) {
        metadata.insert(
            "mesh.destination.namespace".to_string(),
            namespace.to_string(),
        );
        metadata.insert(
            "mesh.destination.workload".to_string(),
            destination.to_string(),
        );
        metadata.insert("mesh.destination.app".to_string(), destination.to_string());
        metadata.insert(
            "mesh.destination.service".to_string(),
            destination.to_string(),
        );
    }

    fn export_span(&self, span: Option<SpanData>) {
        if self.span_reporting_disabled || self.trace_exporters.is_empty() {
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
                self.warn_export_drop(exporter.provider_name(), &error);
            }
        }
        if let Err(error) = last_exporter.try_export(span) {
            self.warn_export_drop(last_exporter.provider_name(), &error);
        }
    }

    fn warn_export_drop(&self, provider: &'static str, error: &str) {
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

    async fn log_with_precomputed_mesh_key(
        &self,
        summary: &TransactionSummary,
        mesh_key: Option<&crate::plugins::mesh::prometheus_helpers::MeshRequestKey>,
    ) {
        if summary.mirror {
            return;
        }
        // Service graph aggregates all mesh RED data; trace export below honors sampling.
        crate::plugins::mesh::service_graph::record_transaction_with_mesh_key(summary, mesh_key);
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

#[async_trait]
impl Plugin for WorkloadMetrics {
    fn name(&self) -> &str {
        "workload_metrics"
    }

    fn priority(&self) -> u16 {
        priority::WORKLOAD_METRICS
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.trace_context_enabled()
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // The authorization phase runs after every plugin's request-received
        // phase. Stamp telemetry here so mesh_authz rejects still retain RED
        // labels and trace context; before_proxy refreshes the same metadata
        // after route selection for accepted requests.
        let headers = std::mem::take(&mut ctx.headers);
        let captured_traceparent = has_valid_traceparent(&headers);
        let captured_b3 =
            has_b3_trace_context(&headers) || b3_sampling_decision(&headers).is_some();
        let captured_tracestate = header_value(&headers, TRACESTATE_HEADER).is_some();
        self.annotate_http_context(ctx, &headers);
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
        self.annotate_http_context(ctx, headers);
        if suppress_local_trace {
            clear_http_trace_metadata(&mut ctx.metadata);
        }
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            set_header_case_insensitive(headers, TRACEPARENT_HEADER, traceparent);
        }
        if let Some(tracestate) = ctx.metadata.get(TRACESTATE_HEADER) {
            set_header_case_insensitive(headers, TRACESTATE_HEADER, tracestate);
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
        if ctx.metadata.contains_key(IGNORED_UDP_SOURCE_SCOPE_METADATA)
            && ctx.metadata.get(MESH_SOURCE_PRINCIPAL).map(String::as_str)
                != ctx.peer_spiffe_id.as_ref().map(SpiffeId::as_str)
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
        self.insert_common_metadata(metadata);
        self.apply_telemetry_metadata(metadata, &HashMap::new());
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
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
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
        self.export_span(SpanData::from_stream_summary_with_kind(
            summary,
            &self.service_name,
            kind,
            2_048,
        ));
    }

    async fn log(&self, summary: &TransactionSummary) {
        let mesh_key = crate::plugins::mesh::prometheus_helpers::mesh_request_key(summary);
        self.log_with_precomputed_mesh_key(summary, mesh_key.as_ref())
            .await;
    }

    async fn log_with_mesh_key(
        &self,
        summary: &TransactionSummary,
        mesh_key: Option<&crate::plugins::mesh::prometheus_helpers::MeshRequestKey>,
    ) {
        self.log_with_precomputed_mesh_key(summary, mesh_key).await;
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

fn parse_direction_emit(config: &Value) -> Result<DirectionEmit, String> {
    match config.get("direction_emit") {
        None | Some(Value::Null) => Ok(DirectionEmit::server_only()),
        Some(value) => serde_json::from_value::<DirectionEmit>(value.clone())
            .map_err(|e| format!("workload_metrics: invalid direction_emit config: {e}")),
    }
}

fn parse_tracing_providers(config: &Value) -> Result<Vec<TracingProvider>, String> {
    if let Some(value) = config.get("tracing_providers") {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return serde_json::from_value::<Vec<TracingProvider>>(value.clone())
            .map_err(|e| format!("workload_metrics: invalid tracing_providers config: {e}"));
    }

    match config.get("tracing_provider") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(value) => Ok(vec![
            serde_json::from_value::<TracingProvider>(value.clone())
                .map_err(|e| format!("workload_metrics: invalid tracing_provider config: {e}"))?,
        ]),
    }
}

struct ParsedMetricConfig {
    request_count_tag_overrides: Option<String>,
    request_duration_tag_overrides: Option<String>,
    disabled_metrics_marker: Option<String>,
}

#[derive(Clone, Copy)]
enum MetricSelector {
    All,
    Emitted(MeshMetricFamily),
    RecognizedUnsupported(&'static str),
}

fn metric_selector(name: &str) -> Option<MetricSelector> {
    if name.trim().eq_ignore_ascii_case("ALL_METRICS") {
        return Some(MetricSelector::All);
    }
    if let Some(family) = MeshMetricFamily::from_config_name(name) {
        return Some(MetricSelector::Emitted(family));
    }
    match name.trim().to_ascii_uppercase().as_str() {
        "REQUEST_SIZE" => Some(MetricSelector::RecognizedUnsupported("REQUEST_SIZE")),
        "RESPONSE_SIZE" => Some(MetricSelector::RecognizedUnsupported("RESPONSE_SIZE")),
        "TCP_OPENED_CONNECTIONS" => Some(MetricSelector::RecognizedUnsupported(
            "TCP_OPENED_CONNECTIONS",
        )),
        "TCP_CLOSED_CONNECTIONS" => Some(MetricSelector::RecognizedUnsupported(
            "TCP_CLOSED_CONNECTIONS",
        )),
        "TCP_SENT_BYTES" => Some(MetricSelector::RecognizedUnsupported("TCP_SENT_BYTES")),
        "TCP_RECEIVED_BYTES" => Some(MetricSelector::RecognizedUnsupported("TCP_RECEIVED_BYTES")),
        "GRPC_REQUEST_MESSAGES" => Some(MetricSelector::RecognizedUnsupported(
            "GRPC_REQUEST_MESSAGES",
        )),
        "GRPC_RESPONSE_MESSAGES" => Some(MetricSelector::RecognizedUnsupported(
            "GRPC_RESPONSE_MESSAGES",
        )),
        _ => None,
    }
}

pub(crate) fn is_recognized_unsupported_istio_metric_family(name: &str) -> bool {
    matches!(
        metric_selector(name),
        Some(MetricSelector::RecognizedUnsupported(_))
    )
}

enum ParsedTagOperation<'a> {
    Remove,
    Rename(&'a str),
    Set(&'a str),
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
                format!("workload_metrics: new_name is required to rename metric tag '{name}'")
            }),
        Some("set") => {
            let value = operation
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!("workload_metrics: value is required to set metric tag '{name}'")
                })?;
            if value.len() > MAX_METRIC_TAG_VALUE_BYTES {
                return Err(format!(
                    "workload_metrics: metric tag '{name}' value exceeds {MAX_METRIC_TAG_VALUE_BYTES} bytes"
                ));
            }
            Ok(ParsedTagOperation::Set(value))
        }
        Some(operation_type) => Err(format!(
            "workload_metrics: unsupported operation '{operation_type}' for metric tag '{name}'"
        )),
        None => Err(format!(
            "workload_metrics: operation type is required for metric tag '{name}'"
        )),
    }
}

fn parse_metric_config(
    value: Option<&Value>,
    emit_unsupported_family_warning: bool,
) -> Result<ParsedMetricConfig, String> {
    let Some(metrics) = value else {
        return Ok(ParsedMetricConfig {
            request_count_tag_overrides: None,
            request_duration_tag_overrides: None,
            disabled_metrics_marker: None,
        });
    };
    let object = metrics
        .as_object()
        .ok_or_else(|| "workload_metrics: 'metrics' must be an object".to_string())?;
    let mut disabled_count = false;
    let mut disabled_duration = false;
    let mut ignored_metric_families = BTreeSet::new();
    if let Some(value) = object.get("disabled_metrics") {
        let disabled = value.as_array().ok_or_else(|| {
            "workload_metrics: metrics.disabled_metrics must be an array".to_string()
        })?;
        for metric in disabled {
            let name = metric.as_str().ok_or_else(|| {
                "workload_metrics: disabled metric names must be strings".to_string()
            })?;
            match metric_selector(name) {
                Some(MetricSelector::All) => {
                    disabled_count = true;
                    disabled_duration = true;
                }
                Some(MetricSelector::Emitted(MeshMetricFamily::RequestCount)) => {
                    disabled_count = true;
                }
                Some(MetricSelector::Emitted(MeshMetricFamily::RequestDuration)) => {
                    disabled_duration = true;
                }
                Some(MetricSelector::RecognizedUnsupported(canonical)) => {
                    ignored_metric_families.insert(canonical);
                }
                None => {
                    return Err(format!(
                        "workload_metrics: unsupported disabled metric '{name}'"
                    ));
                }
            }
        }
    }

    let mut request_count_plan = String::new();
    let mut request_duration_plan = String::new();
    if let Some(value) = object.get("tag_overrides") {
        let overrides = value.as_array().ok_or_else(|| {
            "workload_metrics: metrics.tag_overrides must be an array".to_string()
        })?;
        for entry in overrides {
            let name = entry.get("name").and_then(Value::as_str).ok_or_else(|| {
                "workload_metrics: metric tag override name is required".to_string()
            })?;
            let operation = entry
                .get("operation")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    format!("workload_metrics: operation is required for metric tag '{name}'")
                })?;
            let operation = parse_tag_operation(name, operation)?;
            let selector = match entry.get("metric") {
                None | Some(Value::Null) => MetricSelector::All,
                Some(Value::String(metric)) => metric_selector(metric).ok_or_else(|| {
                    format!(
                        "workload_metrics: unsupported metric '{metric}' for tag override '{name}'"
                    )
                })?,
                Some(_) => {
                    return Err(format!(
                        "workload_metrics: metric for tag override '{name}' must be a string"
                    ));
                }
            };
            let emitted_family = match selector {
                MetricSelector::All => None,
                MetricSelector::Emitted(family) => Some(family),
                MetricSelector::RecognizedUnsupported(canonical) => {
                    ignored_metric_families.insert(canonical);
                    continue;
                }
            };
            let label = MeshMetricLabel::from_config_name(name)
                .ok_or_else(|| format!("workload_metrics: unsupported metric tag '{name}'"))?;
            let encoded = match operation {
                ParsedTagOperation::Remove => format!("r{};", label.index()),
                ParsedTagOperation::Rename(new_name) => {
                    let new_label =
                        MeshMetricLabel::from_config_name(new_name).ok_or_else(|| {
                            format!("workload_metrics: unsupported renamed metric tag '{new_name}'")
                        })?;
                    format!("n{},{};", label.index(), new_label.index())
                }
                ParsedTagOperation::Set(value) => format!(
                    "s{},{value_len}:{value};",
                    label.index(),
                    value_len = value.len()
                ),
            };
            match emitted_family {
                None => {
                    request_count_plan.push_str(&encoded);
                    request_duration_plan.push_str(&encoded);
                }
                Some(MeshMetricFamily::RequestCount) => {
                    request_count_plan.push_str(&encoded);
                }
                Some(MeshMetricFamily::RequestDuration) => {
                    request_duration_plan.push_str(&encoded);
                }
            }
        }
    }

    if emit_unsupported_family_warning && !ignored_metric_families.is_empty() {
        let metric_families = ignored_metric_families
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        tracing::warn!(
            plugin = "workload_metrics",
            %metric_families,
            "ignoring Istio metric-family policy for standard families Ferrum does not emit"
        );
    }

    let disabled_marker = match (disabled_count, disabled_duration) {
        (true, true) => Some("request_count,request_duration".to_string()),
        (true, false) => Some("request_count".to_string()),
        (false, true) => Some("request_duration".to_string()),
        (false, false) => None,
    };
    Ok(ParsedMetricConfig {
        request_count_tag_overrides: (!request_count_plan.is_empty()).then_some(request_count_plan),
        request_duration_tag_overrides: (!request_duration_plan.is_empty())
            .then_some(request_duration_plan),
        disabled_metrics_marker: disabled_marker,
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
        validate_custom_tags(
            tracing.custom_tags.clone(),
            tracing.custom_header_tags.clone(),
        )?;
        validate_trace_provider_endpoints(&tracing.providers).map_err(|error| {
            format!("workload_metrics: invalid tracing exporter config: {error}")
        })?;
    }
    if let Some(metrics) = metrics {
        let metrics = serde_json::to_value(metrics)
            .map_err(|error| format!("workload_metrics: invalid translated metrics: {error}"))?;
        parse_metric_config(Some(&metrics), false)?;
    }
    Ok(())
}

struct ValidatedCustomTags {
    custom_tags: HashMap<String, String>,
    custom_header_tags: HashMap<String, String>,
    custom_trace_attributes_marker: Option<String>,
}

fn validate_custom_tags(
    custom_tags: HashMap<String, String>,
    custom_header_tags: HashMap<String, String>,
) -> Result<ValidatedCustomTags, String> {
    let mut names: Vec<String> = custom_tags
        .keys()
        .chain(custom_header_tags.keys())
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
                "workload_metrics: custom tag '{name}' value exceeds {MAX_CUSTOM_TAG_VALUE_BYTES} bytes"
            ));
        }
    }

    let mut normalized_header_tags = HashMap::with_capacity(custom_header_tags.len());
    for (name, header) in custom_header_tags {
        let header_name =
            http::header::HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                format!("workload_metrics: custom tag '{name}' has invalid header name '{header}'")
            })?;
        if is_sensitive_metadata_key(header_name.as_str()) {
            return Err(format!(
                "workload_metrics: custom tag '{name}' cannot copy sensitive header '{header}'"
            ));
        }
        normalized_header_tags.insert(name, header_name.as_str().to_string());
    }

    let marker = (!names.is_empty()).then(|| names.join(","));
    Ok(ValidatedCustomTags {
        custom_tags,
        custom_header_tags: normalized_header_tags,
        custom_trace_attributes_marker: marker,
    })
}

fn validate_custom_tag_name(name: &str) -> Result<(), String> {
    let allowed = !name.is_empty()
        && name.len() <= MAX_CUSTOM_TAG_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !allowed {
        return Err(format!(
            "workload_metrics: invalid custom tag name '{name}'"
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
            "workload_metrics: custom tag name '{name}' is reserved or sensitive"
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

fn request_protocol(ctx: &RequestContext, headers: &HashMap<String, String>) -> &'static str {
    if ctx
        .metadata
        .get("request_protocol")
        .is_some_and(|value| value == "hbone")
    {
        return "hbone";
    }
    let content_type = header_value(headers, "content-type")
        .or_else(|| ctx.raw_header_get("content-type"))
        .unwrap_or("");
    if content_type
        .split(';')
        .next()
        .is_some_and(|value| is_grpc_content_type(value.trim()))
    {
        "grpc"
    } else {
        "http"
    }
}

fn hbone_identity_from_headers(
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> Option<HboneIdentity> {
    if ctx
        .metadata
        .get("request_protocol")
        .is_none_or(|value| value != "hbone")
    {
        return None;
    }

    headers
        .get(BAGGAGE_HEADER)
        .map(String::as_str)
        .map(HboneIdentity::from_baggage_header)
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

fn existing_sampling_decision(
    metadata: &HashMap<String, String>,
    headers: &HashMap<String, String>,
) -> Option<bool> {
    if let Some(value) = metadata.get("trace_sampled") {
        return Some(value.eq_ignore_ascii_case("true"));
    }
    metadata
        .get(TRACEPARENT_HEADER)
        .and_then(|value| traceparent_sampling_decision(value))
        .or_else(|| {
            header_value(headers, TRACEPARENT_HEADER).and_then(traceparent_sampling_decision)
        })
        .or_else(|| b3_sampling_decision(headers))
}

fn clear_http_trace_metadata(metadata: &mut HashMap<String, String>) {
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

fn metadata_has_sampling_decision(metadata: &HashMap<String, String>) -> bool {
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
    if let Some(value) = header_value(headers, "b3") {
        return b3_single_sampling_decision(value);
    }
    if let Some(flags) = header_value(headers, "x-b3-flags")
        && flags.trim() == "1"
    {
        return Some(true);
    }
    header_value(headers, "x-b3-sampled").and_then(|value| match value.trim() {
        "1" => Some(true),
        "0" => Some(false),
        value if value.eq_ignore_ascii_case("true") => Some(true),
        value if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    })
}

fn has_b3_trace_context(headers: &HashMap<String, String>) -> bool {
    if let Some(value) = header_value(headers, "b3") {
        return parse_b3_single_trace_context(value).is_some();
    }

    header_value(headers, "x-b3-traceid")
        .and_then(normalize_b3_trace_id)
        .is_some()
        && header_value(headers, "x-b3-spanid")
            .and_then(normalize_b3_span_id)
            .is_some()
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

fn import_b3_trace_metadata(
    metadata: &mut HashMap<String, String>,
    headers: &HashMap<String, String>,
) {
    if metadata.contains_key(TRACEPARENT_HEADER) {
        return;
    }
    if let Some(value) = header_value(headers, "b3") {
        if let Some(context) = parse_b3_single_trace_context(value) {
            import_b3_trace_context(metadata, context.trace_id, context.span_id);
        }
        return;
    }
    let Some(trace_id) = header_value(headers, "x-b3-traceid").and_then(normalize_b3_trace_id)
    else {
        return;
    };
    let Some(parent_span_id) = header_value(headers, "x-b3-spanid").and_then(normalize_b3_span_id)
    else {
        return;
    };

    import_b3_trace_context(metadata, trace_id, parent_span_id);
}

fn import_b3_trace_context(
    metadata: &mut HashMap<String, String>,
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
    header_value(headers, TRACEPARENT_HEADER)
        .and_then(OtelTracing::parse_traceparent)
        .is_some()
}

fn clear_source_spiffe_labels(metadata: &mut HashMap<String, String>) {
    for key in [
        MESH_SOURCE_PRINCIPAL,
        MESH_SOURCE_TRUST_DOMAIN,
        MESH_SOURCE_NAMESPACE,
        MESH_SOURCE_SERVICE_ACCOUNT,
    ] {
        metadata.remove(key);
    }
}

fn insert_source_spiffe_labels(metadata: &mut HashMap<String, String>, identity: &SpiffeId) {
    metadata.insert(MESH_SOURCE_PRINCIPAL.to_string(), identity.to_string());
    metadata.insert(
        MESH_SOURCE_TRUST_DOMAIN.to_string(),
        identity.trust_domain().as_str().to_string(),
    );
    if let Some(namespace) = spiffe_path_value(identity, "ns") {
        metadata.insert(MESH_SOURCE_NAMESPACE.to_string(), namespace.to_string());
    }
    if let Some(service_account) = spiffe_path_value(identity, "sa") {
        metadata.insert(
            MESH_SOURCE_SERVICE_ACCOUNT.to_string(),
            service_account.to_string(),
        );
    }
}

fn insert_destination_spiffe_labels(metadata: &mut HashMap<String, String>, identity: &SpiffeId) {
    metadata.insert(
        "mesh.destination.principal".to_string(),
        identity.to_string(),
    );
    if let Some(namespace) = spiffe_path_value(identity, "ns") {
        metadata.insert(
            "mesh.destination.namespace".to_string(),
            namespace.to_string(),
        );
    }
}

fn spiffe_path_value<'a>(identity: &'a SpiffeId, key: &str) -> Option<&'a str> {
    let mut segments = identity.path_segments();
    while let Some(segment) = segments.next() {
        if segment == key {
            return segments.next();
        }
    }
    None
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
    fn custom_header_tags_resolve_request_header_values() {
        let metrics = WorkloadMetrics::new(&json!({
            "custom_tags": {
                "literal": "constant"
            },
            "custom_header_tags": {
                "tenant": "x-tenant"
            }
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
            "custom_header_tags": {"tenant": "x-tenant"}
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
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "payments",
            "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
            "labels": {"app": "checkout"},
            "trusted_hbone_assertors": [
                "spiffe://cluster.local/ns/istio-system/sa/ztunnel"
            ]
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
        let metrics = WorkloadMetrics::new(&json!({
            "namespace": "payments",
            "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
            "labels": {"app": "checkout"},
            "trusted_hbone_assertors": [
                "spiffe://cluster.local/ns/istio-system/sa/ztunnel"
            ]
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
            metrics.request_count_tag_overrides.as_deref(),
            Some("s0,4:edge;")
        );
        assert_eq!(
            metrics.request_duration_tag_overrides.as_deref(),
            Some("r11;")
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
            metadata: HashMap::from([
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
            err.contains("sampling_percentage must be between 0.0 and 100.0"),
            "{err}"
        );

        let err = WorkloadMetrics::new(&json!({
            "sampling_percentage": "100"
        }))
        .err()
        .expect("non-numeric sampling should fail");
        assert!(
            err.contains("sampling_percentage must be a number"),
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
                    "access_token_env": "LIGHTSTEP_ACCESS_TOKEN"
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
                assert_eq!(access_token_env, "LIGHTSTEP_ACCESS_TOKEN");
            }
            other => panic!("expected Lightstep, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tracing_provider_opentelemetry_round_trips() {
        let metrics = WorkloadMetrics::new(&json!({
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
        assert!(err.contains("invalid tracing_provider config"), "{err}");
    }

    #[test]
    fn tracing_provider_config_is_safe_without_tokio_runtime() {
        let metrics = WorkloadMetrics::new(&json!({
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
