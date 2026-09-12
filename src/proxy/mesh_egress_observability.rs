//! Workload-metrics lifecycle for captured L4 mesh egress.
//!
//! These handlers bypass the ordinary stream proxy, so they invoke only the
//! observability plugin by name. Destination-side mesh policy remains the sole
//! authorization point; no authn/authz plugin is run a second time here.

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
        let plugins: Vec<_> = epoch
            .plugin_cache
            .plugins_for_protocol(&proxy.namespace, &proxy.id, protocol)
            .iter()
            .filter(|plugin| plugin.name() == WORKLOAD_METRICS_PLUGIN)
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
        let mut rejected = false;
        for plugin in &plugins {
            if matches!(
                plugin.on_stream_connect(&mut stream_ctx).await,
                PluginResult::Reject { .. }
            ) {
                rejected = true;
                break;
            }
        }
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
            connection_error: Some(
                if rejected {
                    "workload metrics rejected captured mesh egress lifecycle"
                } else {
                    "captured mesh egress setup failed"
                }
                .to_string(),
            ),
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
                plugin = WORKLOAD_METRICS_PLUGIN,
                "captured mesh egress ended outside a Tokio runtime; span lifecycle was dropped"
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
        let mut ctx = stream_context();
        let metadata = ctx.metadata.get_or_insert_with(Default::default);
        metadata.insert("mesh.request_protocol".to_string(), "tcp".to_string());
        metadata.insert(
            crate::plugins::mesh::prometheus_helpers::MESH_WORKLOAD_METRICS_OBSERVED_METADATA
                .to_string(),
            "1".to_string(),
        );
        metadata.insert(
            crate::plugins::mesh::prometheus_helpers::MESH_PROMETHEUS_METRICS_OBSERVED_METADATA
                .to_string(),
            "1".to_string(),
        );
        let mut lifecycle = CapturedMeshEgressLifecycle {
            plugins: vec![],
            stream_ctx: Some(ctx),
            namespace: "default".to_string(),
            proxy_id: "mesh-egress".to_string(),
            proxy_name: Some("orders.default.svc.cluster.local".to_string()),
            client_ip: "10.0.0.2".to_string(),
            backend_target: "orders.default.svc.cluster.local".to_string(),
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

        let mut target = crate::config::types::UpstreamTarget {
            host: "10.0.0.8".to_string(),
            port: 5432,
            service_port_policy_key: None,
            weight: 1,
            tags: Default::default(),
            locality: None,
            path: None,
        };
        target.tags.insert(
            crate::proxy::hbone_pool::MESH_SPIFFE_ID_TAG.to_string(),
            "spiffe://cluster.local/ns/default/sa/orders".to_string(),
        );
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
