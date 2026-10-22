//! Observability lifecycle for captured L4 mesh egress.
//!
//! These handlers bypass the ordinary stream proxy, so they invoke only the
//! configured builtin observability plugins. Destination-side mesh policy
//! remains the sole authorization point; no authn/authz plugin is run a second
//! time here.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::consumer_index::ConsumerIndex;
use crate::modes::mesh::MeshTrafficDirection;
use crate::plugins::{
    Direction, DisconnectCause, Plugin, PluginResult, ProxyProtocol, StreamConnectionContext,
    StreamTransactionSummary,
};
use crate::request_epoch::RequestEpoch;
use crate::retry::ErrorClass;

use super::mesh_udp_capture::{CapturedUdpOutcome, CapturedUdpOutcomeSignal};

const WORKLOAD_METRICS_PLUGIN: &str = "workload_metrics";
const PROMETHEUS_METRICS_PLUGIN: &str = "prometheus_metrics";

pub(crate) struct CapturedMeshEgressLifecycle {
    plugins: Vec<Arc<dyn Plugin>>,
    stream_ctx: Option<StreamConnectionContext>,
    namespace: String,
    proxy_id: String,
    proxy_name: Option<String>,
    client_ip: String,
    backend_target: String,
    protocol: String,
    connected_wall_at: chrono::DateTime<chrono::Utc>,
    connected_at: std::time::Instant,
    bytes_sent: u64,
    bytes_received: u64,
    connection_error: Option<String>,
    error_class: Option<ErrorClass>,
    disconnect_direction: Option<Direction>,
    disconnect_cause: Option<DisconnectCause>,
    udp_outcome_signal: Option<Arc<CapturedUdpOutcomeSignal>>,
    udp_byte_counters: Option<(Arc<AtomicU64>, Arc<AtomicU64>)>,
    completion_recorded: bool,
}

impl CapturedMeshEgressLifecycle {
    pub(crate) async fn start(
        epoch: &RequestEpoch,
        proxy: &crate::config::types::Proxy,
        protocol: ProxyProtocol,
        client_ip: std::net::IpAddr,
        destination_service: &str,
        destination_port: u16,
        asserted_source_identity: Option<&crate::identity::SpiffeId>,
    ) -> Option<Self> {
        // Keep the configured chain's order and wrappers: priority overrides
        // and memoized execution triggers apply to both lifecycle hooks. The
        // exporter must observe connect and disconnect alongside workload
        // attribution; a name-matching custom plugin must never run here.
        let plugins: Vec<_> = epoch
            .plugin_cache
            .plugins_for_protocol(&proxy.namespace, &proxy.id, protocol)
            .iter()
            .filter(|plugin| is_captured_lifecycle_plugin(plugin.as_ref()))
            .cloned()
            .collect();
        if plugins.is_empty() {
            return None;
        }

        // Captured egress is an identity boundary like any other accept path:
        // a dual-stack capture listener reports an IPv4 pod as
        // `::ffff:a.b.c.d`, which would give the same workload two distinct
        // `workload_metrics` label values and two stream-summary identities
        // (GHSA-vjwj-657f-5w9g). Fold it once, here, before any plugin runs.
        let client_ip = crate::util::client_identity::canonical_ip_string(client_ip);
        let mut stream_ctx = StreamConnectionContext::new(
            client_ip.clone(),
            client_ip.clone(),
            proxy.id.clone(),
            Some(destination_service.to_string()),
            destination_port,
            proxy.effective_scheme(),
            Arc::new(ConsumerIndex::from_inner(Arc::clone(&epoch.consumer_index))),
        );
        stream_ctx.proxy_namespace = proxy.namespace.clone();
        stream_ctx.proxy_lifecycle_generation = epoch
            .plugin_cache
            .proxy_lifecycle_generation(&proxy.namespace, &proxy.id);
        // NodeWaypoint TCP and Ambient UDP capture already verified the
        // originating pod's identity before handing the flow here; carry
        // it so workload_metrics attributes CLIENT spans/labels to the
        // captured source workload rather than the waypoint/ztunnel.
        stream_ctx.authenticated_identity =
            asserted_source_identity.map(|identity| identity.to_string());
        stream_ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
        let mut rejected_by = None;
        for plugin in &plugins {
            if matches!(
                plugin.on_stream_connect(&mut stream_ctx).await,
                PluginResult::Reject { .. }
            ) {
                rejected_by = Some(plugin.name().to_string());
                break;
            }
        }
        let rejected = rejected_by.is_some();
        stream_ctx.insert_metadata(
            "mesh.connection_security_policy".to_string(),
            "mutual_tls".to_string(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.namespace".to_string(),
            proxy.namespace.clone(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.workload".to_string(),
            destination_service.to_string(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.app".to_string(),
            destination_service.to_string(),
        );
        stream_ctx.insert_metadata(
            "mesh.destination.service".to_string(),
            destination_service.to_string(),
        );
        // Captured TCP egress must NOT finalize here: `set_target` later stamps
        // `mesh.destination.principal`, and opened/closed must share that label
        // set. A plugin-rejected path never reaches target selection, so
        // finalize once under the destination/security metadata stamped above.
        // Captured UDP egress stays excluded by its `udp` request protocol.
        if rejected {
            crate::plugins::mesh::prometheus_helpers::finalize_mesh_tcp_opened_stream(
                &mut stream_ctx,
            );
        }

        Some(Self {
            plugins,
            stream_ctx: Some(stream_ctx),
            namespace: proxy.namespace.clone(),
            proxy_id: proxy.id.clone(),
            proxy_name: Some(destination_service.to_string()),
            client_ip,
            backend_target: destination_service.to_string(),
            protocol: match protocol {
                ProxyProtocol::Udp => "udp",
                _ => "tcp",
            }
            .to_string(),
            connected_wall_at: chrono::Utc::now(),
            connected_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: Some(match rejected_by {
                Some(plugin) => {
                    format!("{plugin} rejected captured mesh egress lifecycle")
                }
                None => "captured mesh egress setup failed".to_string(),
            }),
            error_class: Some(ErrorClass::ConnectionPoolError),
            disconnect_direction: Some(Direction::ClientToBackend),
            disconnect_cause: Some(DisconnectCause::BackendError),
            udp_outcome_signal: None,
            udp_byte_counters: None,
            completion_recorded: false,
        })
    }

    /// Wired only by the captured-UDP relay in `mesh_udp_capture`, which is
    /// Linux-only (`IP_TRANSPARENT` + recvmsg cmsg). The lifecycle struct is
    /// shared with the captured-TCP path on every host, so the setters stay
    /// compiled — and stay covered by the in-crate tests below — rather than
    /// being conditionally removed from the type.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn set_udp_outcome_signal(&mut self, outcome_signal: Arc<CapturedUdpOutcomeSignal>) {
        self.udp_outcome_signal = Some(outcome_signal);
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn set_udp_byte_counters(
        &mut self,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
    ) {
        self.udp_byte_counters = Some((bytes_sent, bytes_received));
    }

    pub(crate) fn set_target(&mut self, target: &crate::config::types::UpstreamTarget) {
        self.backend_target = format!("{}:{}", target.host, target.port);
        if let Some(identity) = target
            .tags
            .get(crate::proxy::hbone_pool::MESH_SPIFFE_ID_TAG)
            && let Some(metadata) = self
                .stream_ctx
                .as_mut()
                .and_then(|ctx| ctx.metadata.as_mut())
        {
            metadata.insert("mesh.destination.principal".to_string(), identity.clone());
        }
        // Selected target metadata is now stamped; finalize TCP opened once so
        // opened and closed share `mesh.destination.principal` when present.
        // Idempotent if start already finalized a rejected path. UDP is a no-op.
        self.finalize_tcp_opened_once();
    }

    /// Finalize mesh TCP opened under the current stream metadata, once.
    /// No-op for UDP and when metadata is absent or already finalized.
    fn finalize_tcp_opened_once(&mut self) {
        if self.protocol != "tcp" {
            return;
        }
        let Some(stream_ctx) = self.stream_ctx.as_mut() else {
            return;
        };
        crate::plugins::mesh::prometheus_helpers::finalize_mesh_tcp_opened_stream(stream_ctx);
    }

    pub(crate) fn complete_tcp(&mut self, result: &crate::proxy::tcp_proxy::StreamCopyResult) {
        self.completion_recorded = true;
        self.bytes_sent = result.bytes_client_to_backend;
        self.bytes_received = result.bytes_backend_to_client;
        match result.first_failure.as_ref() {
            Some((direction, class, side, message)) => {
                self.connection_error = Some(message.clone());
                self.error_class = Some(*class);
                self.disconnect_direction = Some(*direction);
                self.disconnect_cause = Some(
                    crate::proxy::tcp_proxy::disconnect_cause_for_failure(*direction, class, *side),
                );
            }
            None => self.complete_gracefully(),
        }
    }

    pub(crate) fn complete_udp(
        &mut self,
        bytes_sent: u64,
        bytes_received: u64,
        outcome: CapturedUdpOutcome,
    ) {
        self.completion_recorded = true;
        self.bytes_sent = bytes_sent;
        self.bytes_received = bytes_received;
        match outcome {
            CapturedUdpOutcome::IdleTimeout => {
                // Idle expiry is how a healthy quiet UDP session normally
                // ends; the generic UDP lifecycle records it with no
                // connection error, and captured sessions must match so
                // DNS-style flows don't inflate error-rate dashboards.
                self.connection_error = None;
                self.error_class = None;
                self.disconnect_direction = None;
                self.disconnect_cause = Some(DisconnectCause::IdleTimeout);
            }
            CapturedUdpOutcome::ReturnPathEnded => {
                self.connection_error = Some("captured mesh UDP return path ended".to_string());
                self.error_class = Some(ErrorClass::ConnectionClosed);
                self.disconnect_direction = Some(Direction::BackendToClient);
                self.disconnect_cause = Some(DisconnectCause::BackendError);
            }
            CapturedUdpOutcome::EgressPathEnded => {
                self.connection_error = Some("captured mesh UDP egress path ended".to_string());
                self.error_class = Some(ErrorClass::RequestError);
                self.disconnect_direction = Some(Direction::ClientToBackend);
                self.disconnect_cause = Some(DisconnectCause::BackendError);
            }
            CapturedUdpOutcome::ProducerShutdown => self.complete_gracefully(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn complete_udp_client_reply_failure(
        &mut self,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        self.completion_recorded = true;
        self.bytes_sent = bytes_sent;
        self.bytes_received = bytes_received;
        self.connection_error = Some("captured mesh UDP reply send to client failed".to_string());
        self.error_class = Some(ErrorClass::ClientDisconnect);
        self.disconnect_direction = Some(Direction::BackendToClient);
        self.disconnect_cause = Some(DisconnectCause::RecvError);
    }

    fn complete_gracefully(&mut self) {
        self.completion_recorded = true;
        self.connection_error = None;
        self.error_class = None;
        self.disconnect_direction = None;
        self.disconnect_cause = Some(DisconnectCause::GracefulShutdown);
    }

    fn take_summary(&mut self) -> Option<StreamTransactionSummary> {
        // Setup failures that never reached `set_target` still need a coherent
        // once-only TCP lifecycle under the final metadata available here.
        // Idempotent when start (rejection) or set_target already finalized.
        self.finalize_tcp_opened_once();
        let mut stream_ctx = self.stream_ctx.take()?;
        Some(StreamTransactionSummary {
            namespace: self.namespace.clone(),
            proxy_id: self.proxy_id.clone(),
            proxy_lifecycle_generation: stream_ctx.proxy_lifecycle_generation,
            // Carry the connect-time execution-trigger outcomes so a skipped
            // instance stays skipped at disconnect.
            plugin_trigger_decisions: stream_ctx.plugin_trigger_decisions(),
            proxy_name: self.proxy_name.clone(),
            client_ip: self.client_ip.clone(),
            consumer_username: stream_ctx.effective_identity().map(str::to_owned),
            auth_method: stream_ctx.auth_method,
            backend_target: self.backend_target.clone(),
            backend_resolved_ip: None,
            protocol: self.protocol.clone(),
            listen_port: stream_ctx.listen_port,
            duration_ms: self.connected_at.elapsed().as_secs_f64() * 1000.0,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            connection_error: self.connection_error.clone(),
            error_class: self.error_class,
            disconnect_direction: self.disconnect_direction,
            disconnect_cause: self.disconnect_cause,
            timestamp_connected: self.connected_wall_at.to_rfc3339(),
            timestamp_disconnected: chrono::Utc::now().to_rfc3339(),
            sni_hostname: stream_ctx.sni_hostname.clone(),
            metadata: stream_ctx.take_metadata(),
        })
    }
}

/// The configured builtin observers the captured lifecycle runs. Provenance is
/// checked so a custom plugin reusing either name never runs here.
fn is_captured_lifecycle_plugin(plugin: &dyn Plugin) -> bool {
    matches!(
        plugin.name(),
        WORKLOAD_METRICS_PLUGIN | PROMETHEUS_METRICS_PLUGIN
    ) && crate::plugins::is_builtin_plugin(plugin)
}

impl Drop for CapturedMeshEgressLifecycle {
    fn drop(&mut self) {
        if !self.completion_recorded
            && let Some(outcome) = self.udp_outcome_signal.as_ref().and_then(|signal| {
                let outcome = signal.resolve_egress_completion(true);
                matches!(
                    outcome,
                    CapturedUdpOutcome::IdleTimeout | CapturedUdpOutcome::ProducerShutdown
                )
                .then_some(outcome)
            })
        {
            let (bytes_sent, bytes_received) = self
                .udp_byte_counters
                .as_ref()
                .map(|(sent, received)| {
                    (
                        sent.load(Ordering::Relaxed),
                        received.load(Ordering::Relaxed),
                    )
                })
                .unwrap_or((self.bytes_sent, self.bytes_received));
            self.complete_udp(bytes_sent, bytes_received, outcome);
        }
        let Some(summary) = self.take_summary() else {
            return;
        };
        let plugins = std::mem::take(&mut self.plugins);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                plugins = ?plugins.iter().map(|plugin| plugin.name()).collect::<Vec<_>>(),
                "captured mesh egress ended outside a Tokio runtime; disconnect hooks were dropped"
            );
            return;
        };
        runtime.spawn(async move {
            for plugin in plugins {
                plugin.on_stream_disconnect(&summary).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::BackendScheme;
    use std::sync::Mutex;

    struct SummaryCapture {
        tx: Mutex<Option<tokio::sync::oneshot::Sender<StreamTransactionSummary>>>,
    }

    #[async_trait::async_trait]
    impl Plugin for SummaryCapture {
        fn name(&self) -> &str {
            "summary_capture"
        }

        async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
            let tx = self.tx.lock().expect("summary sender mutex").take();
            if let Some(tx) = tx {
                let _ = tx.send(summary.clone());
            }
        }
    }

    fn metrics_plugin(
        id: &str,
        name: &str,
        config: serde_json::Value,
    ) -> crate::config::types::PluginConfig {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "namespace": "default",
            "plugin_name": name,
            "scope": "global",
            "enabled": true,
            "config": config
        }))
        .expect("test global plugin")
    }

    fn exporter(id: &str) -> crate::config::types::PluginConfig {
        metrics_plugin(id, "prometheus_metrics", serde_json::json!({}))
    }

    // These private lifecycle tests exercise the real cache rather than
    // installing observation markers or bypassing cache-owned wrappers.
    async fn start_configured_lifecycle(
        id: &str,
        scheme: BackendScheme,
        mut extra_plugins: Vec<crate::config::types::PluginConfig>,
        prepended_plugins: Vec<Arc<dyn Plugin>>,
    ) -> CapturedMeshEgressLifecycle {
        let service = format!("{id}.default.svc.cluster.local");
        let mut proxy: crate::config::types::Proxy = serde_json::from_value(serde_json::json!({
            "id": id,
            "namespace": "default",
            "name": service,
            "backend_scheme": scheme,
            "backend_host": "10.0.0.8",
            "backend_port": 5432,
            "listen_port": 15432
        }))
        .expect("test stream proxy");
        proxy.dispatch_kind = crate::config::types::DispatchKind::from(scheme);
        let mut plugin_configs = vec![metrics_plugin(
            &format!("{id}-workload"),
            "workload_metrics",
            serde_json::json!({
                "namespace": "default",
                "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
                "span_reporting_disabled": true
            }),
        )];
        plugin_configs.append(&mut extra_plugins);
        let config = crate::config::types::GatewayConfig {
            proxies: vec![proxy.clone()],
            plugin_configs,
            ..Default::default()
        };
        let plugin_cache = crate::plugin_cache::PluginCache::new(&config)
            .expect("configured builtin metric plugins");
        for plugin in prepended_plugins {
            plugin_cache
                .prepend_proxy_plugin_for_test(&proxy.namespace, &proxy.id, plugin)
                .expect("prepend custom plugin to the real protocol cache");
        }
        let consumers = ConsumerIndex::new(&config.consumers);
        let load_balancer = crate::load_balancer::LoadBalancerCache::new(&config);
        let store = crate::request_epoch::RequestEpochStore::from_runtime_parts(
            config,
            &plugin_cache,
            &consumers,
            &load_balancer,
        );
        let epoch = store.load();
        let protocol = if scheme.is_udp() {
            ProxyProtocol::Udp
        } else {
            ProxyProtocol::Tcp
        };
        let chain = epoch
            .plugin_cache
            .plugins_for_protocol(&proxy.namespace, &proxy.id, protocol);
        let lifecycle = CapturedMeshEgressLifecycle::start(
            &epoch,
            &proxy,
            protocol,
            "::ffff:10.0.0.2".parse().expect("test source IP"),
            &service,
            5432,
            None,
        )
        .await
        .expect("workload_metrics establishes the captured lifecycle");
        let expected: Vec<_> = chain
            .iter()
            .filter(|plugin| is_captured_lifecycle_plugin(plugin.as_ref()))
            .collect();
        assert_eq!(lifecycle.plugins.len(), expected.len());
        for (actual, expected) in lifecycle.plugins.iter().zip(expected) {
            assert!(
                Arc::ptr_eq(actual, expected),
                "retain cache order and wrappers"
            );
        }
        lifecycle
    }

    fn selected_target() -> crate::config::types::UpstreamTarget {
        crate::config::types::UpstreamTarget {
            host: "10.0.0.8".to_string(),
            port: 5432,
            service_port_policy_key: None,
            weight: 1,
            tags: std::collections::HashMap::from([(
                crate::proxy::hbone_pool::MESH_SPIFFE_ID_TAG.to_string(),
                "spiffe://cluster.local/ns/default/sa/orders".to_string(),
            )]),
            locality: None,
            path: None,
        }
    }

    fn observe_disconnect(
        lifecycle: &mut CapturedMeshEgressLifecycle,
    ) -> tokio::sync::oneshot::Receiver<StreamTransactionSummary> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        // Last in the real chain: receiving the summary proves that the
        // exporter disconnect hook has completed, without sleeps or retries.
        lifecycle.plugins.push(Arc::new(SummaryCapture {
            tx: Mutex::new(Some(tx)),
        }));
        rx
    }

    async fn disconnected(
        rx: tokio::sync::oneshot::Receiver<StreamTransactionSummary>,
    ) -> StreamTransactionSummary {
        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .expect("disconnect callback timeout")
            .expect("disconnect summary")
    }

    fn assert_tcp_metrics(id: &str, expected: Option<(u64, u64)>, principal: &str) {
        let output = crate::plugins::prometheus_metrics::global_registry().render_uncached();
        let service_label = format!("destination_service=\"{id}.default.svc.cluster.local\"");
        let mut labels = None;
        for (family, value) in [
            (
                "ferrum_mesh_tcp_connections_opened_total",
                expected.map(|_| 1),
            ),
            (
                "ferrum_mesh_tcp_connections_closed_total",
                expected.map(|_| 1),
            ),
            // Istio names response bytes sent and request bytes received.
            (
                "ferrum_mesh_tcp_sent_bytes_total",
                expected.map(|(_, received)| received),
            ),
            (
                "ferrum_mesh_tcp_received_bytes_total",
                expected.map(|(sent, _)| sent),
            ),
        ] {
            let lines: Vec<_> = output
                .lines()
                .filter(|line| {
                    line.starts_with(&format!("{family}{{")) && line.contains(&service_label)
                })
                .collect();
            match value {
                Some(value) => {
                    assert_eq!(lines.len(), 1, "one {family} series for {id}: {lines:?}");
                    let (series, actual) = lines[0].rsplit_once(' ').expect("counter value");
                    assert_eq!(actual, value.to_string(), "{family} for {id}");
                    assert!(series.contains(&format!("destination_principal=\"{principal}\"")));
                    let current = series.strip_prefix(family).expect("metric family");
                    if let Some(labels) = labels {
                        assert_eq!(current, labels, "all lifecycle families share final labels");
                    } else {
                        labels = Some(current);
                    }
                }
                None => assert!(lines.is_empty(), "unexpected {family} for {id}: {lines:?}"),
            }
        }
    }

    fn assert_stream_connections(id: &str, expected: Option<u64>) {
        let output = crate::plugins::prometheus_metrics::global_registry().render_uncached();
        let prefix = format!("ferrum_stream_connections_total{{proxy_id=\"{id}\",");
        let lines: Vec<_> = output
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();
        match expected {
            Some(expected) => {
                assert_eq!(lines.len(), 1, "one stream series: {lines:?}");
                assert_eq!(
                    lines[0].rsplit_once(' ').expect("counter value").1,
                    expected.to_string()
                );
            }
            None => assert!(
                lines.is_empty(),
                "skipped exporter must not record disconnect: {lines:?}"
            ),
        }
    }

    fn stream_context() -> StreamConnectionContext {
        let mut ctx = StreamConnectionContext::new(
            "10.0.0.2".to_string(),
            "10.0.0.2".to_string(),
            "mesh-egress".to_string(),
            Some("orders.default.svc.cluster.local".to_string()),
            5432,
            BackendScheme::Tcp,
            Arc::new(ConsumerIndex::new(&[])),
        );
        ctx.metadata = Some(std::collections::HashMap::from([(
            "mesh.direction".to_string(),
            "outbound".to_string(),
        )]));
        ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
        ctx
    }

    #[tokio::test]
    async fn drop_finalizes_captured_session_once_with_completion_state() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let plugin: Arc<dyn Plugin> = Arc::new(SummaryCapture {
            tx: Mutex::new(Some(tx)),
        });
        let mut lifecycle = CapturedMeshEgressLifecycle {
            plugins: vec![plugin],
            stream_ctx: Some(stream_context()),
            namespace: "default".to_string(),
            proxy_id: "mesh-egress".to_string(),
            proxy_name: Some("orders.default.svc.cluster.local".to_string()),
            client_ip: "10.0.0.2".to_string(),
            backend_target: "10.0.0.8:5432".to_string(),
            protocol: "tcp".to_string(),
            connected_wall_at: chrono::Utc::now(),
            connected_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: Some("setup failed".to_string()),
            error_class: Some(ErrorClass::ConnectionPoolError),
            disconnect_direction: Some(Direction::ClientToBackend),
            disconnect_cause: Some(DisconnectCause::BackendError),
            udp_outcome_signal: None,
            udp_byte_counters: None,
            completion_recorded: false,
        };
        lifecycle.complete_tcp(&crate::proxy::tcp_proxy::StreamCopyResult {
            bytes_client_to_backend: 42,
            bytes_backend_to_client: 84,
            first_failure: None,
        });

        drop(lifecycle);
        let summary = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
            .await
            .expect("disconnect callback timeout")
            .expect("disconnect summary");

        assert_eq!(summary.bytes_sent, 42);
        assert_eq!(summary.bytes_received, 84);
        assert_eq!(summary.protocol, "tcp");
        assert_eq!(
            summary.disconnect_cause,
            Some(DisconnectCause::GracefulShutdown)
        );
        assert!(summary.connection_error.is_none());
    }

    #[tokio::test]
    async fn udp_idle_expiry_finalizes_without_connection_error() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let plugin: Arc<dyn Plugin> = Arc::new(SummaryCapture {
            tx: Mutex::new(Some(tx)),
        });
        let mut lifecycle = CapturedMeshEgressLifecycle {
            plugins: vec![plugin],
            stream_ctx: Some(stream_context()),
            namespace: "default".to_string(),
            proxy_id: "mesh-egress".to_string(),
            proxy_name: Some("dns.kube-system.svc.cluster.local".to_string()),
            client_ip: "10.0.0.2".to_string(),
            backend_target: "10.0.0.8:53".to_string(),
            protocol: "udp".to_string(),
            connected_wall_at: chrono::Utc::now(),
            connected_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: Some("setup failed".to_string()),
            error_class: Some(ErrorClass::ConnectionPoolError),
            disconnect_direction: Some(Direction::ClientToBackend),
            disconnect_cause: Some(DisconnectCause::BackendError),
            udp_outcome_signal: None,
            udp_byte_counters: None,
            completion_recorded: false,
        };
        lifecycle.complete_udp(7, 9, CapturedUdpOutcome::IdleTimeout);

        drop(lifecycle);
        let summary = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
            .await
            .expect("disconnect callback timeout")
            .expect("disconnect summary");

        // Idle expiry is the normal end of a quiet UDP flow: it must match
        // the generic UDP lifecycle (IdleTimeout cause, no error) so healthy
        // DNS-style sessions don't register as errored spans.
        assert_eq!(summary.disconnect_cause, Some(DisconnectCause::IdleTimeout));
        assert!(summary.connection_error.is_none());
        assert!(summary.error_class.is_none());
        assert!(summary.disconnect_direction.is_none());
        assert_eq!(summary.bytes_sent, 7);
        assert_eq!(summary.bytes_received, 9);
    }

    #[tokio::test]
    async fn producer_shutdown_drop_preserves_live_udp_byte_counts() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let plugin: Arc<dyn Plugin> = Arc::new(SummaryCapture {
            tx: Mutex::new(Some(tx)),
        });
        let outcome_signal = Arc::new(CapturedUdpOutcomeSignal::new());
        let bytes_sent = Arc::new(AtomicU64::new(37));
        let bytes_received = Arc::new(AtomicU64::new(41));
        let mut lifecycle = CapturedMeshEgressLifecycle {
            plugins: vec![plugin],
            stream_ctx: Some(stream_context()),
            namespace: "default".to_string(),
            proxy_id: "mesh-egress".to_string(),
            proxy_name: Some("dns.kube-system.svc.cluster.local".to_string()),
            client_ip: "10.0.0.2".to_string(),
            backend_target: "10.0.0.8:53".to_string(),
            protocol: "udp".to_string(),
            connected_wall_at: chrono::Utc::now(),
            connected_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: Some("setup failed".to_string()),
            error_class: Some(ErrorClass::ConnectionPoolError),
            disconnect_direction: Some(Direction::ClientToBackend),
            disconnect_cause: Some(DisconnectCause::BackendError),
            udp_outcome_signal: Some(Arc::clone(&outcome_signal)),
            udp_byte_counters: None,
            completion_recorded: false,
        };
        lifecycle.set_udp_byte_counters(bytes_sent, bytes_received);
        outcome_signal.mark_producer_shutdown();

        drop(lifecycle);
        let summary = tokio::time::timeout(std::time::Duration::from_secs(1), rx)
            .await
            .expect("disconnect callback timeout")
            .expect("disconnect summary");

        assert_eq!(summary.bytes_sent, 37);
        assert_eq!(summary.bytes_received, 41);
        assert_eq!(
            summary.disconnect_cause,
            Some(DisconnectCause::GracefulShutdown)
        );
        assert!(summary.connection_error.is_none());
    }

    #[tokio::test]
    async fn set_target_stamps_principal_before_tcp_finalize_marker() {
        let id = "captured-egress-real-start-regression";
        let mut lifecycle = start_configured_lifecycle(
            id,
            BackendScheme::Tcp,
            vec![exporter("captured-egress-prometheus")],
            vec![],
        )
        .await;
        for name in ["workload_metrics", "prometheus_metrics"] {
            assert_eq!(
                lifecycle
                    .plugins
                    .iter()
                    .filter(|plugin| plugin.name() == name)
                    .count(),
                1
            );
        }
        let metadata = lifecycle
            .stream_ctx
            .as_ref()
            .and_then(|ctx| ctx.metadata.as_ref())
            .expect("metadata from actual connect hooks");
        assert!(
            metadata.contains_key(
                crate::plugins::mesh::prometheus_helpers::MESH_WORKLOAD_METRICS_OBSERVED_METADATA
            ),
            "the builtin workload_metrics hook must observe the captured stream"
        );
        assert!(
            metadata.contains_key(
                crate::plugins::mesh::prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA
            ),
            "configured builtin prometheus_metrics must observe real captured start"
        );
        assert!(
            !crate::plugins::mesh::prometheus_helpers::mesh_tcp_opened_finalized(metadata),
            "opened must wait for selected destination identity"
        );

        let target = selected_target();
        lifecycle.set_target(&target);
        lifecycle.set_target(&target);

        let metadata = lifecycle
            .stream_ctx
            .as_ref()
            .and_then(|ctx| ctx.metadata.as_ref())
            .expect("stream metadata");
        assert_eq!(
            metadata
                .get("mesh.destination.principal")
                .map(String::as_str),
            Some("spiffe://cluster.local/ns/default/sa/orders"),
            "set_target must stamp destination principal before finalize"
        );
        assert!(
            crate::plugins::mesh::prometheus_helpers::mesh_tcp_opened_finalized(metadata),
            "set_target must finalize TCP opened after principal insertion"
        );

        // Idempotent: a second finalize (as teardown would) must not clear the marker.
        lifecycle.finalize_tcp_opened_once();
        let metadata = lifecycle
            .stream_ctx
            .as_ref()
            .and_then(|ctx| ctx.metadata.as_ref())
            .expect("stream metadata");
        assert!(crate::plugins::mesh::prometheus_helpers::mesh_tcp_opened_finalized(metadata));
        lifecycle.complete_tcp(&crate::proxy::tcp_proxy::StreamCopyResult {
            bytes_client_to_backend: 42,
            bytes_backend_to_client: 84,
            first_failure: None,
        });
        let rx = observe_disconnect(&mut lifecycle);
        drop(lifecycle);
        let summary = disconnected(rx).await;
        assert_eq!(summary.client_ip, "10.0.0.2", "canonical capture identity");
        assert_eq!((summary.bytes_sent, summary.bytes_received), (42, 84));
        assert!(summary.connection_error.is_none());
        assert_tcp_metrics(
            id,
            Some((42, 84)),
            "spiffe://cluster.local/ns/default/sa/orders",
        );
        assert_stream_connections(id, Some(1));
    }

    #[tokio::test]
    async fn captured_tcp_setup_failure_finalizes_balanced_metrics_at_drop() {
        let id = "captured-egress-setup-failure";
        let mut lifecycle = start_configured_lifecycle(
            id,
            BackendScheme::Tcp,
            vec![exporter("captured-setup-prometheus")],
            vec![],
        )
        .await;
        let rx = observe_disconnect(&mut lifecycle);
        drop(lifecycle);
        let summary = disconnected(rx).await;
        assert_eq!(
            summary.connection_error.as_deref(),
            Some("captured mesh egress setup failed")
        );
        assert_eq!(summary.error_class, Some(ErrorClass::ConnectionPoolError));
        assert_eq!(
            summary.disconnect_cause,
            Some(DisconnectCause::BackendError)
        );
        assert_tcp_metrics(id, Some((0, 0)), "unknown");
        assert_stream_connections(id, Some(1));
    }

    #[tokio::test]
    async fn captured_tcp_cancelled_task_preserves_one_disconnect() {
        let id = "captured-egress-cancelled-task";
        let mut lifecycle = start_configured_lifecycle(
            id,
            BackendScheme::Tcp,
            vec![exporter("captured-cancel-prometheus")],
            vec![],
        )
        .await;
        lifecycle.set_target(&selected_target());
        let rx = observe_disconnect(&mut lifecycle);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _lifecycle = lifecycle;
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.expect("task owns lifecycle");
        task.abort();
        assert!(task.await.expect_err("task cancelled").is_cancelled());
        let summary = disconnected(rx).await;
        assert_eq!(
            summary.connection_error.as_deref(),
            Some("captured mesh egress setup failed")
        );
        assert_tcp_metrics(
            id,
            Some((0, 0)),
            "spiffe://cluster.local/ns/default/sa/orders",
        );
        assert_stream_connections(id, Some(1));
    }

    #[tokio::test]
    async fn captured_tcp_without_exporter_keeps_registry_silent() {
        let id = "captured-egress-no-exporter";
        let mut lifecycle =
            start_configured_lifecycle(id, BackendScheme::Tcp, vec![], vec![]).await;
        lifecycle.set_target(&selected_target());
        assert!(
            !crate::plugins::mesh::prometheus_helpers::mesh_tcp_opened_finalized(
                lifecycle
                    .stream_ctx
                    .as_ref()
                    .expect("context")
                    .metadata
                    .as_ref()
                    .expect("metadata")
            )
        );
        let rx = observe_disconnect(&mut lifecycle);
        drop(lifecycle);
        disconnected(rx).await;
        assert_tcp_metrics(id, None, "unknown");
        assert_stream_connections(id, None);
    }

    #[tokio::test]
    async fn captured_tcp_exporter_trigger_skips_connect_and_disconnect() {
        let id = "captured-egress-skipped-exporter";
        let mut exporter = exporter("captured-skipped-prometheus");
        exporter.trigger = Some(
            serde_json::from_value(serde_json::json!({
                "when": {"match": {"source_cidr": ["192.0.2.0/24"]}}
            }))
            .expect("network trigger"),
        );
        let mut lifecycle =
            start_configured_lifecycle(id, BackendScheme::Tcp, vec![exporter], vec![]).await;
        let metadata = lifecycle
            .stream_ctx
            .as_ref()
            .expect("context")
            .metadata
            .as_ref()
            .expect("metadata");
        assert_eq!(
            metadata
                .get("plugin_trigger.captured-skipped-prometheus.skipped")
                .map(String::as_str),
            Some("true")
        );
        assert!(!metadata.contains_key(
            crate::plugins::mesh::prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA
        ));
        lifecycle.set_target(&selected_target());
        let rx = observe_disconnect(&mut lifecycle);
        drop(lifecycle);
        disconnected(rx).await;
        assert_tcp_metrics(id, None, "unknown");
        // This also catches a disconnect that bypasses the trigger wrapper:
        // generic stream metrics have no mesh observation-marker gate.
        assert_stream_connections(id, None);
    }

    #[tokio::test]
    async fn captured_tcp_keeps_wrapped_exporter_order_and_scoped_workload_policy() {
        let id = "captured-egress-wrapped-order";
        let mut exporter = exporter("captured-wrapped-prometheus");
        exporter.priority_override = Some(9400);
        exporter.trigger = Some(
            serde_json::from_value(serde_json::json!({
                "when": {"match": {"source_cidr": ["10.0.0.0/8"]}}
            }))
            .expect("matching network trigger"),
        );
        let mut scoped_workload = metrics_plugin(
            "captured-scoped-workload",
            "workload_metrics",
            serde_json::json!({
                "namespace": "default", "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
                "span_reporting_disabled": true
            }),
        );
        scoped_workload.scope = crate::config::types::PluginScope::Proxy;
        scoped_workload.proxy_id = Some(id.to_string());
        let mut lifecycle = start_configured_lifecycle(
            id,
            BackendScheme::Tcp,
            vec![exporter, scoped_workload],
            vec![],
        )
        .await;
        assert_eq!(
            lifecycle
                .plugins
                .iter()
                .map(|plugin| plugin.name())
                .collect::<Vec<_>>(),
            vec!["workload_metrics", "prometheus_metrics"]
        );
        lifecycle.set_target(&selected_target());
        let rx = observe_disconnect(&mut lifecycle);
        drop(lifecycle);
        disconnected(rx).await;
        assert_tcp_metrics(
            id,
            Some((0, 0)),
            "spiffe://cluster.local/ns/default/sa/orders",
        );
        assert_stream_connections(id, Some(1));
    }

    struct SpoofedObservabilityPlugin {
        name: &'static str,
        calls: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl Plugin for SpoofedObservabilityPlugin {
        fn name(&self) -> &str {
            self.name
        }
        fn supported_protocols(&self) -> &'static [ProxyProtocol] {
            crate::plugins::ALL_PROTOCOLS
        }
        async fn on_stream_connect(&self, _: &mut StreamConnectionContext) -> PluginResult {
            self.calls.fetch_add(1, Ordering::Relaxed);
            PluginResult::Continue
        }
        async fn on_stream_disconnect(&self, _: &StreamTransactionSummary) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn captured_lifecycle_excludes_name_spoofs_and_unrelated_plugins() {
        let id = "captured-egress-builtin-standing";
        let calls = Arc::new(AtomicU64::new(0));
        let prepended_plugins: Vec<Arc<dyn Plugin>> =
            ["workload_metrics", "prometheus_metrics", "mesh_authz"]
                .into_iter()
                .map(|name| {
                    Arc::new(SpoofedObservabilityPlugin {
                        name,
                        calls: Arc::clone(&calls),
                    }) as Arc<dyn Plugin>
                })
                .collect();
        let mut lifecycle = start_configured_lifecycle(
            id,
            BackendScheme::Tcp,
            vec![
                exporter("captured-standing-prometheus"),
                metrics_plugin(
                    "captured-unused-throttle",
                    "tcp_connection_throttle",
                    serde_json::json!({"max_connections_per_key": 1}),
                ),
            ],
            prepended_plugins,
        )
        .await;
        assert_eq!(
            lifecycle.plugins.len(),
            2,
            "only configured builtin observability hooks"
        );
        lifecycle.set_target(&selected_target());
        let rx = observe_disconnect(&mut lifecycle);
        drop(lifecycle);
        disconnected(rx).await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "custom and auth hooks must never run"
        );
        assert_tcp_metrics(
            id,
            Some((0, 0)),
            "spiffe://cluster.local/ns/default/sa/orders",
        );
    }

    #[tokio::test]
    async fn captured_udp_real_hooks_never_emit_tcp_lifecycle_metrics() {
        let id = "captured-egress-real-udp";
        let mut lifecycle = start_configured_lifecycle(
            id,
            BackendScheme::Udp,
            vec![exporter("captured-udp-prometheus")],
            vec![],
        )
        .await;
        lifecycle.set_target(&selected_target());
        let metadata = lifecycle
            .stream_ctx
            .as_ref()
            .expect("context")
            .metadata
            .as_ref()
            .expect("metadata");
        assert!(metadata.contains_key(
            crate::plugins::mesh::prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA
        ));
        assert!(!crate::plugins::mesh::prometheus_helpers::mesh_tcp_opened_finalized(metadata));
        lifecycle.complete_udp(42, 84, CapturedUdpOutcome::IdleTimeout);
        let rx = observe_disconnect(&mut lifecycle);
        drop(lifecycle);
        let summary = disconnected(rx).await;
        assert_eq!(summary.protocol, "udp");
        assert_eq!(summary.disconnect_cause, Some(DisconnectCause::IdleTimeout));
        assert!(summary.connection_error.is_none());
        assert_tcp_metrics(id, None, "unknown");
        assert_stream_connections(id, Some(1));
    }

    #[tokio::test]
    async fn udp_set_target_does_not_finalize_tcp_opened() {
        let mut ctx = stream_context();
        ctx.metadata
            .get_or_insert_with(Default::default)
            .insert("mesh.request_protocol".to_string(), "udp".to_string());
        let mut lifecycle = CapturedMeshEgressLifecycle {
            plugins: vec![],
            stream_ctx: Some(ctx),
            namespace: "default".to_string(),
            proxy_id: "mesh-egress".to_string(),
            proxy_name: Some("dns.kube-system.svc.cluster.local".to_string()),
            client_ip: "10.0.0.2".to_string(),
            backend_target: "dns.kube-system.svc.cluster.local".to_string(),
            protocol: "udp".to_string(),
            connected_wall_at: chrono::Utc::now(),
            connected_at: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: Some("setup failed".to_string()),
            error_class: Some(ErrorClass::ConnectionPoolError),
            disconnect_direction: Some(Direction::ClientToBackend),
            disconnect_cause: Some(DisconnectCause::BackendError),
            udp_outcome_signal: None,
            udp_byte_counters: None,
            completion_recorded: false,
        };

        let mut target = crate::config::types::UpstreamTarget {
            host: "10.0.0.8".to_string(),
            port: 53,
            service_port_policy_key: None,
            weight: 1,
            tags: Default::default(),
            locality: None,
            path: None,
        };
        target.tags.insert(
            crate::proxy::hbone_pool::MESH_SPIFFE_ID_TAG.to_string(),
            "spiffe://cluster.local/ns/kube-system/sa/coredns".to_string(),
        );
        lifecycle.set_target(&target);
        lifecycle.finalize_tcp_opened_once();

        let metadata = lifecycle
            .stream_ctx
            .as_ref()
            .and_then(|ctx| ctx.metadata.as_ref())
            .expect("stream metadata");
        assert!(
            !crate::plugins::mesh::prometheus_helpers::mesh_tcp_opened_finalized(metadata),
            "UDP captured egress must never finalize TCP opened"
        );
    }
}
