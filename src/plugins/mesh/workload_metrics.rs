//! Mesh workload metadata plugin.
//!
//! Adds Istio/GAMMA-style identity labels into transaction metadata. The
//! existing logging and metrics sinks then pick them up without plugin-trait
//! changes.

use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::MeshTrafficDirection;
use crate::modes::mesh::config::TracingProvider;
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::plugins::mesh::authz::{
    TrustedAssertor, is_trusted_hbone_assertor, parse_trust_domain_aliases,
    parse_trusted_hbone_assertors,
};
use crate::plugins::otel_tracing::{
    OtelTracing, SpanData, SpanKind, TraceExporter, build_traceparent, ensure_trace_metadata,
    trace_exporters_from_providers, trace_is_sampled,
};
use crate::plugins::utils::PluginHttpClient;
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
    metric_tag_overrides: Vec<MetricTagOverrideConfig>,
    disabled_metrics: Vec<String>,
    /// Provider-specific tracing backends surfaced from Istio Telemetry CRD
    /// via the mesh slice. These also enable trace-context propagation when
    /// span reporting is disabled.
    tracing_providers: Vec<TracingProvider>,
    trace_exporters: Vec<Arc<dyn TraceExporter>>,
    span_reporting_disabled: bool,
    service_name: String,
    /// Which directions of a mesh hop this plugin instance should emit spans
    /// for. Defaults to SERVER-only.
    direction_emit: DirectionEmit,
}

#[derive(Debug)]
enum MetricTagOverrideConfig {
    Remove { name: String },
    Rename { name: String, new_name: String },
    Set { name: String, value: String },
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
        let custom_tags = config
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
        let custom_header_tags = config
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
        let (metric_tag_overrides, disabled_metrics) = parse_metric_config(config.get("metrics"))?;
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
            metric_tag_overrides,
            disabled_metrics,
            tracing_providers,
            trace_exporters,
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
            import_b3_trace_metadata(&mut ctx.metadata, headers);
            ensure_trace_metadata(&mut ctx.metadata, headers);
            if let Some(tracestate) = header_value(headers, TRACESTATE_HEADER) {
                ctx.metadata
                    .insert(TRACESTATE_HEADER.to_string(), tracestate.to_string());
            }
        }
        let hbone_identity = hbone_identity_from_headers(ctx, headers);
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
        let baggage_source_principal = hbone_identity
            .as_ref()
            .and_then(|identity| identity.source_principal.clone());
        let source_identity = match (ctx.peer_spiffe_id.as_ref(), baggage_source_principal) {
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
        .or_else(|| self.workload_spiffe_id.clone());
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
        if let Some(identity) = source_identity.as_ref() {
            insert_source_spiffe_labels(&mut ctx.metadata, identity);
        }
        self.insert_source_workload_labels(&mut ctx.metadata, source_identity.as_ref());
        if let Some(proxy) = ctx.matched_proxy.as_ref() {
            let destination = proxy.name.clone().unwrap_or_else(|| proxy.id.clone());
            ctx.metadata.insert(
                "mesh.destination.namespace".to_string(),
                proxy.namespace.clone(),
            );
            ctx.metadata
                .insert("mesh.destination.workload".to_string(), destination.clone());
            ctx.metadata
                .insert("mesh.destination.app".to_string(), destination.clone());
            ctx.metadata
                .insert("mesh.destination.service".to_string(), destination);
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
        for (key, value) in &self.custom_tags {
            metadata.insert(key.clone(), value.clone());
        }
        for (key, header_name) in &self.custom_header_tags {
            if let Some(value) = header_value(headers, header_name) {
                metadata.insert(key.clone(), value.to_string());
            }
        }
        for override_config in &self.metric_tag_overrides {
            match override_config {
                MetricTagOverrideConfig::Remove { name } => {
                    metadata.remove(name);
                }
                MetricTagOverrideConfig::Rename { name, new_name } => {
                    if let Some(value) = metadata.remove(name) {
                        metadata.insert(new_name.clone(), value);
                    }
                }
                MetricTagOverrideConfig::Set { name, value } => {
                    metadata.insert(name.clone(), value.clone());
                }
            }
        }
        if !self.disabled_metrics.is_empty() {
            metadata.insert(
                "mesh.metrics.disabled".to_string(),
                self.disabled_metrics.join(","),
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

    fn insert_source_workload_labels(
        &self,
        metadata: &mut HashMap<String, String>,
        source_identity: Option<&SpiffeId>,
    ) {
        if let Some(namespace) = metadata
            .get("mesh.source.namespace")
            .cloned()
            .or_else(|| self.namespace.clone())
        {
            metadata.insert("mesh.source.namespace".to_string(), namespace);
        }

        let service_account = metadata.get("mesh.source.service_account").cloned();
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
        .or(service_account.as_deref())
        .or_else(|| source_identity.and_then(|identity| spiffe_path_value(identity, "sa")))
        .unwrap_or("unknown");
        let app = first_label(&self.labels, &["app.kubernetes.io/name", "app", "k8s-app"])
            .unwrap_or(workload);
        let service = first_label(
            &self.labels,
            &["service.istio.io/canonical-name", "service", "app"],
        )
        .unwrap_or(workload);

        metadata.insert("mesh.source.workload".to_string(), workload.to_string());
        metadata.insert("mesh.source.app".to_string(), app.to_string());
        metadata.insert("mesh.source.service".to_string(), service.to_string());
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
                tracing::warn!(
                    provider = exporter.provider_name(),
                    "workload_metrics tracing export buffer full — dropping span: {}",
                    error
                );
            }
        }
        if let Err(error) = last_exporter.try_export(span) {
            tracing::warn!(
                provider = last_exporter.provider_name(),
                "workload_metrics tracing export buffer full — dropping span: {}",
                error
            );
        }
    }

    async fn log_with_precomputed_mesh_key(
        &self,
        summary: &TransactionSummary,
        mesh_key: Option<&crate::plugins::mesh::prometheus_helpers::MeshRequestKey>,
    ) {
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

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.annotate_http_context(ctx, headers);
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        if let Some(tracestate) = ctx.metadata.get(TRACESTATE_HEADER) {
            headers.insert(TRACESTATE_HEADER.to_string(), tracestate.clone());
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            response_headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        self.trace_context_enabled()
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let stamped_direction = ctx.mesh_direction;
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
            if ctx.tls_client_cert_der.is_some() {
                "mutual_tls"
            } else {
                "none"
            }
            .to_string(),
        );
        if let Some(identity) = ctx
            .authenticated_identity
            .as_deref()
            .and_then(|value| SpiffeId::new(value).ok())
            .or_else(|| {
                metadata
                    .get("peer_spiffe_id")
                    .and_then(|value| SpiffeId::new(value).ok())
            })
            .or_else(|| self.workload_spiffe_id.clone())
        {
            insert_source_spiffe_labels(metadata, &identity);
            self.insert_source_workload_labels(metadata, Some(&identity));
        } else {
            self.insert_source_workload_labels(metadata, None);
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

fn parse_metric_config(
    value: Option<&Value>,
) -> Result<(Vec<MetricTagOverrideConfig>, Vec<String>), String> {
    let Some(metrics) = value else {
        return Ok((Vec::new(), Vec::new()));
    };
    let object = metrics
        .as_object()
        .ok_or_else(|| "workload_metrics: 'metrics' must be an object".to_string())?;
    let disabled_metrics = object
        .get("disabled_metrics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|metric| !metric.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let mut tag_overrides = Vec::new();
    for entry in object
        .get("tag_overrides")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(operation) = entry.get("operation").and_then(Value::as_object) else {
            continue;
        };
        match operation.get("type").and_then(Value::as_str) {
            Some("remove") => tag_overrides.push(MetricTagOverrideConfig::Remove {
                name: name.to_string(),
            }),
            Some("rename") => {
                if let Some(new_name) = operation.get("new_name").and_then(Value::as_str) {
                    tag_overrides.push(MetricTagOverrideConfig::Rename {
                        name: name.to_string(),
                        new_name: new_name.to_string(),
                    });
                }
            }
            Some("set") => {
                if let Some(value) = operation.get("value").and_then(Value::as_str) {
                    tag_overrides.push(MetricTagOverrideConfig::Set {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    Ok((tag_overrides, disabled_metrics))
}

fn first_label<'a>(labels: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        labels
            .get(*key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    })
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

fn has_valid_traceparent(headers: &HashMap<String, String>) -> bool {
    header_value(headers, TRACEPARENT_HEADER)
        .and_then(OtelTracing::parse_traceparent)
        .is_some()
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
