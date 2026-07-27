//! Raw-TCP mesh egress relay (both captured topologies).
//!
//! Captured outbound connections whose pre-NAT original destination
//! (`SO_ORIGINAL_DST`) matches a declared `(service VIP, stream-family port)`
//! pair never reach hyper: the accept loop branches here BEFORE any HTTP
//! parsing and the raw byte stream is relayed through an HTTP/2 CONNECT tunnel
//! to the LB-selected destination workload's app port. The tunnel transport is
//! whichever tag the materializer stamped on the selected target (mutually
//! exclusive):
//! - **Ambient** → `mesh.hbone`: relay over the shared HBONE pool (dial the
//!   peer's `:15008`, capability-probe-gated). HBONE is already a byte-stream
//!   tunnel; the destination's transparent inbound relay dials the authority.
//! - **Sidecar** → `mesh.mtls`: relay over a FRESH mesh-mTLS H2 CONNECT tunnel
//!   (dial the peer's `:15006`). The destination sidecar's inbound listener is
//!   topology-agnostic — a bare H2 CONNECT is recognized + relayed by the same
//!   `build_inbound_hbone_relay_proxy` machinery (gated by `is_hbone_connect` +
//!   `mesh_direction == Inbound`), so no destination-side changes are involved.
//!   Unlike HBONE there is NO capability registry: `mesh.mtls` peers are
//!   slice-declared sidecars by construction.
//!
//! Fail-closed rules (mirroring the HTTP per-port orig-dst path):
//! - the target must carry exactly one transport tag (`mesh.hbone` XOR
//!   `mesh.mtls`) and a loaded gateway SVID; HBONE additionally requires a
//!   capability-registry record proving HBONE support (enrolled from the same
//!   synthesized relay proxy used here, so probe and dispatch keys agree);
//! - same-cluster targets require an intact pinned `mesh.spiffe_id`; explicit
//!   cross-cluster targets instead require SNI, remote trust domain, gateway
//!   dial host, and real-pod CONNECT authority metadata;
//! - any gate failure closes the client connection; nothing is ever guessed
//!   or forwarded to a different destination.
//!
//! No policy plugins run here (there is no request): destination-side
//! `mesh_authz` on the outer CONNECT is the policy enforcement point. The
//! workload-metrics stream lifecycle does run once for source-side CLIENT
//! tracing, without invoking authorization a second time. The lookup table only
//! ever contains slice-declared service VIPs, so REGISTRY_ONLY admission holds
//! by construction. Passive-health/outlier
//! recording is intentionally absent, matching the stream-proxy paths (raw
//! TCP has no response status to classify); HBONE connection failures still
//! feed the HBONE relay failure metric, and both transports feed the LB's
//! least-connection accounting. A transport-labelled raw-TCP egress connection
//! counter is a planned observability follow-up.

use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{
    LoadBalancerConnectionGuard, ProxyState, backend_dispatch, hbone_pool, mesh_mtls_pool,
    tcp_proxy,
};
use crate::identity::SpiffeId;
use crate::load_balancer::{LoadBalancer, LoadBalancerCache, LoadBalancerCacheInner};
use crate::request_epoch::RequestEpoch;
use crate::router_cache::MeshTcpEgressEntry;

/// Relay one captured raw-TCP connection over the topology's mesh CONNECT
/// transport (Ambient → HBONE `:15008`; Sidecar → mesh-mTLS `:15006`), selected
/// from the LB-chosen target's transport tag. Consumes the stream; every early
/// return closes it (drop). The caller already holds the connection permit and
/// overload `ConnectionGuard` for the connection's lifetime.
pub(crate) async fn handle_mesh_tcp_egress(
    client_stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    state: &Arc<ProxyState>,
    epoch: &RequestEpoch,
    entry: &Arc<MeshTcpEgressEntry>,
    orig_dst: std::net::SocketAddr,
    asserted_source_identity: Option<&SpiffeId>,
) {
    let proxy = entry.relay_proxy.as_ref();
    let lb = &epoch.load_balancer;
    let mut observability = super::mesh_egress_observability::CapturedMeshEgressLifecycle::start(
        epoch,
        proxy,
        crate::plugins::ProxyProtocol::Tcp,
        remote_addr.ip(),
        &entry.service_fqdn,
        orig_dst.port(),
        asserted_source_identity,
    )
    .await;
    // Scope passive health to the stream-family dispatch port whenever an
    // effective port override exists. The per-port LB lane is stricter: it only
    // engages for selection-affecting policy fields, so passive-health-only
    // overrides can cap ejection by port without bypassing subset/upstream LB.
    let override_port = LoadBalancerCache::initial_dispatch_port_override_from(
        lb,
        &proxy.namespace,
        &entry.upstream_id,
    );
    let health_port_scope =
        backend_dispatch::stream_health_port_scope(proxy, lb, &entry.upstream_id, override_port);
    let port_lane = (health_port_scope.is_some()
        && match mesh_stream_port_lane_supported(proxy, override_port) {
            Ok(supported) => supported,
            Err(message) => {
                warn!(
                    service = %entry.service_fqdn,
                    port = override_port,
                    orig_dst = %orig_dst,
                    %message,
                    "Raw-TCP mesh egress per-port LB policy is unsupported; closing captured connection"
                );
                return;
            }
        })
    .then_some(override_port);
    if let Some(port) = port_lane {
        let strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
            lb,
            &proxy.namespace,
            &entry.upstream_id,
            Some(port),
            None,
        );
        if !matches!(strategy, crate::load_balancer::HashOnStrategy::Ip) {
            warn!(
                service = %entry.service_fqdn,
                port,
                orig_dst = %orig_dst,
                "Raw-TCP mesh egress per-port consistent hashing supports only source-IP hash keys; closing captured connection"
            );
            return;
        }
    }
    let lb_hash_key = mesh_stream_lb_hash_key_for_client_ip(remote_addr.ip());
    let health_ctx = backend_dispatch::health_context_for_selection(
        proxy,
        &state.health_checker,
        lb,
        &entry.upstream_id,
        health_port_scope,
    );
    let Some(selection) = (if let Some(port) = port_lane {
        LoadBalancerCache::select_target_for_port_from(
            lb,
            &proxy.namespace,
            &entry.upstream_id,
            &lb_hash_key,
            port,
            Some(&health_ctx),
        )
    } else {
        LoadBalancerCache::select_target_from(
            lb,
            &proxy.namespace,
            &entry.upstream_id,
            &lb_hash_key,
            Some(&health_ctx),
        )
    }) else {
        warn!(
            service = %entry.service_fqdn,
            orig_dst = %orig_dst,
            client_ip = %remote_addr.ip(),
            "Raw-TCP mesh egress has no selectable workload target; closing captured connection"
        );
        return;
    };
    let target = selection.target;
    if let Some(observability) = observability.as_mut() {
        observability.set_target(&target);
    }

    // A loaded gateway SVID is required for either transport — never dial a
    // mesh peer identity-less. (The pools re-check this; the early gate just
    // gives a clean close + log.)
    if state.gateway_svid_bundle.load().is_none() {
        warn!(
            service = %entry.service_fqdn,
            "Raw-TCP mesh egress requires a loaded gateway SVID; closing captured connection"
        );
        return;
    }

    // Least-connection accounting parity with the HTTP relay path. Held across
    // the transport-specific dial and the relay; dropped on any early return.
    let balancer = connection_balancer(&epoch.load_balancer, &proxy.namespace, &entry.upstream_id);
    let _lb_guard = LoadBalancerConnectionGuard::new(Some(Arc::clone(&target)), balancer);

    // Select the transport from the target's tag (mutually exclusive — the
    // materializer stamps exactly one). Ambient relays over the shared HBONE
    // pool (capability-probe-gated); Sidecar relays over a fresh mesh-mTLS
    // CONNECT tunnel with no capability registry.
    let (tunnel, transport) = if hbone_pool::target_hbone_enabled(&target) {
        // In-cluster target-effective capability keying: the enrollment pass builds probe
        // keys from the relay proxy AFTER per-target override resolution
        // (`BackendCapabilityProbeTarget::from_proxy`), so a DR
        // `portLevelSettings[].tls` on this stream upstream moves the Supported
        // record off the base relay-proxy key. This fail-closed gate must read
        // the SAME key or every session to that port drops forever. Explicit
        // cross-cluster targets bypass probing because only the operator gateway
        // is dialable; their SNI/trust-domain metadata is validated below.
        let cross_cluster = hbone_pool::target_hbone_cross_cluster(&target);
        if !cross_cluster
            && !crate::proxy::get_backend_capability_for_target(
                state.backend_capabilities.as_ref(),
                proxy,
                Some(&target),
            )
            .is_some_and(|record| record.hbone.is_supported())
        {
            debug!(
                service = %entry.service_fqdn,
                target_host = %target.host,
                target_port = target.port,
                "Raw-TCP mesh egress target has no proven HBONE capability yet; closing \
                 (the capability probe enrolls these targets — retry after the next refresh)"
            );
            return;
        }
        // Pinned peer identity: present-but-corrupt fails closed, exactly like
        // the HTTP HBONE dispatch path. An absent tag keeps trust-domain-only
        // verification for operator-supplied targets.
        let app_host = match hbone_pool::target_hbone_authority_host(&target) {
            Ok(host) => host,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Raw-TCP mesh egress target carries an invalid CONNECT authority; refusing dial"
                );
                return;
            }
        };
        if cross_cluster
            && !target
                .tags
                .contains_key(hbone_pool::HBONE_AUTHORITY_HOST_TAG)
        {
            warn!(
                service = %entry.service_fqdn,
                target_host = %target.host,
                "Cross-cluster raw-TCP HBONE target is missing its real-pod CONNECT authority; refusing dial"
            );
            return;
        }
        let (expected_peer, expected_trust_domain, sni_override) = if cross_cluster {
            let Some(sni) = hbone_pool::target_hbone_eastwest_sni(&target) else {
                warn!(service = %entry.service_fqdn, "Cross-cluster raw-TCP HBONE target is missing its SNI override; refusing dial");
                return;
            };
            let Some(td) = hbone_pool::target_hbone_cross_cluster_trust_domain(&target) else {
                warn!(service = %entry.service_fqdn, "Cross-cluster raw-TCP HBONE target is missing its trust domain; refusing dial");
                return;
            };
            (None, Some(td), Some(sni))
        } else {
            let expected_peer = match hbone_pool::target_expected_peer_spiffe(&target) {
                Ok(peer) => peer,
                Err(err) => {
                    warn!(service = %entry.service_fqdn, target_host = %target.host, error = %err,
                        "Raw-TCP mesh egress target carries a corrupt pinned identity; refusing dial");
                    return;
                }
            };
            (expected_peer, None, None)
        };
        let hbone_port = hbone_pool::target_hbone_port(&target);
        let dial_host = match hbone_pool::target_hbone_dial_host(&target) {
            Ok(host) => host,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Raw-TCP mesh egress target carries a corrupt HBONE dial host; refusing dial"
                );
                return;
            }
        };
        match state
            .hbone_pool
            .get_tunnel_via(
                proxy,
                dial_host,
                app_host,
                target.port,
                target.dispatch_policy_port(),
                hbone_port,
                expected_peer.as_ref(),
                expected_trust_domain.as_ref(),
                sni_override,
                asserted_source_identity,
            )
            .await
        {
            Ok(tunnel) => (tunnel, "hbone"),
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    target_port = target.port,
                    error = %err,
                    "Raw-TCP mesh egress HBONE tunnel failed; closing captured connection"
                );
                return;
            }
        }
    } else if mesh_mtls_pool::target_mesh_mtls_enabled(&target) {
        // Resolve the shared Sidecar dial plan: same-cluster targets require a
        // pinned destination identity; cross-cluster targets require SNI +
        // trust-domain scope and deliberately carry no pod pin.
        let dial_plan = match mesh_mtls_pool::MeshMtlsDialPlan::resolve(&target) {
            Ok(plan) => plan,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Raw-TCP mesh egress mesh.mtls dial metadata is invalid; refusing dial"
                );
                return;
            }
        };
        let dial_host = match mesh_mtls_pool::target_mesh_mtls_dial_host(&target) {
            Ok(host) => host,
            Err(err) => {
                warn!(service = %entry.service_fqdn, target_host = %target.host, error = %err,
                    "Raw-TCP mesh egress mesh.mtls dial host is invalid; refusing dial");
                return;
            }
        };
        let authority_host = match mesh_mtls_pool::target_mesh_mtls_authority_host(&target) {
            Some(host) => host,
            None if dial_plan.cross_cluster => {
                warn!(service = %entry.service_fqdn,
                    "Cross-cluster raw-TCP mesh.mtls target is missing its CONNECT authority; refusing dial");
                return;
            }
            None => target.host.as_str(),
        };
        let mtls_port = mesh_mtls_pool::target_mesh_mtls_port(&target);
        match state
            .mesh_mtls_pool
            .open_connect_tunnel(
                proxy,
                dial_host,
                authority_host,
                target.port,
                target.dispatch_policy_port(),
                mtls_port,
                dial_plan.expected_peer.as_ref(),
                dial_plan.expected_trust_domain.as_ref(),
                dial_plan.sni_override,
            )
            .await
        {
            Ok(tunnel) => (tunnel, "mtls"),
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    target_port = target.port,
                    error = %err,
                    "Raw-TCP mesh egress sidecar mesh-mTLS CONNECT tunnel failed; closing \
                     captured connection"
                );
                return;
            }
        }
    } else {
        warn!(
            service = %entry.service_fqdn,
            target_host = %target.host,
            "Raw-TCP mesh egress target carries neither mesh.hbone nor mesh.mtls; closing \
             (materializer bug?)"
        );
        return;
    };

    debug!(
        service = %entry.service_fqdn,
        transport,
        orig_dst = %orig_dst,
        target_host = %target.host,
        target_port = target.port,
        client_ip = %remote_addr.ip(),
        "Relaying captured raw-TCP connection over mesh CONNECT tunnel"
    );
    let buffer_size = state
        .adaptive_buffer
        .get_buffer_size(&proxy.namespace, &proxy.id);
    let result = tcp_proxy::bidirectional_copy_for_relay(
        client_stream,
        tunnel,
        super::hbone_proxy::proxy_idle_timeout(proxy, &state.env_config),
        super::hbone_proxy::proxy_half_close_cap(&state.env_config),
        super::hbone_proxy::backend_read_timeout(proxy),
        super::hbone_proxy::backend_write_timeout(proxy),
        buffer_size,
    )
    .await;
    if let Some(observability) = observability.as_mut() {
        observability.complete_tcp(&result);
    }
    state.adaptive_buffer.record_connection(
        &proxy.namespace,
        &proxy.id,
        result
            .bytes_client_to_backend
            .saturating_add(result.bytes_backend_to_client),
    );
    // Per-transport raw-TCP egress connection counter (success/failure),
    // covering BOTH HBONE and mesh-mTLS (mesh plan F7.4).
    crate::plugins::prometheus_metrics::global_registry()
        .record_mesh_tcp_egress_connection(transport, result.first_failure.is_none());
    if let Some((direction, class, side, message)) = result.first_failure.as_ref() {
        // The legacy per-direction relay-failure metric is HBONE-named, so keep
        // recording it for the HBONE transport only; mesh-mTLS failures surface
        // in the transport-labelled connections counter above + the warn log.
        if transport == "hbone" {
            crate::plugins::prometheus_metrics::global_registry()
                .record_hbone_relay_failure(&proxy.id, *direction, *class);
        }
        warn!(
            service = %entry.service_fqdn,
            proxy_id = %proxy.id,
            transport,
            direction = ?direction,
            io_side = ?side,
            error_class = %class,
            error = %message,
            bytes_in = result.bytes_client_to_backend,
            bytes_out = result.bytes_backend_to_client,
            "Raw-TCP mesh egress relay failed"
        );
    } else {
        debug!(
            service = %entry.service_fqdn,
            transport,
            bytes_in = result.bytes_client_to_backend,
            bytes_out = result.bytes_backend_to_client,
            "Raw-TCP mesh egress relay completed"
        );
    }
}

/// Resolve the balancer that owns raw-TCP mesh egress connection accounting.
///
/// Balancer snapshots are keyed by `(namespace, upstream_id)`. Keeping this
/// lookup behind the typed accessor prevents same-ID tenants from aliasing and
/// avoids allocating a runtime key on the connection hot path.
#[inline]
pub(crate) fn connection_balancer(
    snapshot: &LoadBalancerCacheInner,
    namespace: &str,
    upstream_id: &str,
) -> Option<Arc<LoadBalancer>> {
    snapshot.balancer(namespace, upstream_id).cloned()
}

fn stream_port_override_affects_selection(proxy: &crate::config::types::Proxy, port: u16) -> bool {
    let Some(override_config) = proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&port))
    else {
        return false;
    };
    override_config.algorithm.is_some()
        || override_config.hash_on.is_some()
        || override_config.locality_lb_setting.is_some()
}

fn mesh_stream_lb_hash_key_for_client_ip(ip: std::net::IpAddr) -> String {
    ip.to_canonical().to_string()
}

fn mesh_stream_port_lane_supported(
    proxy: &crate::config::types::Proxy,
    port: u16,
) -> Result<bool, &'static str> {
    let Some(override_config) = proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&port))
    else {
        return Ok(false);
    };
    match override_config.algorithm {
        Some(crate::config::types::LoadBalancerAlgorithm::LeastLatency) => {
            Err("per-port LEAST_LATENCY requires stream latency accounting")
        }
        _ => Ok(stream_port_override_affects_selection(proxy, port)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        mesh_stream_lb_hash_key_for_client_ip, mesh_stream_port_lane_supported,
        stream_port_override_affects_selection,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn proxy_with_override(
        override_config: crate::config::types::ResolvedPortOverride,
    ) -> crate::config::types::Proxy {
        let mut proxy: crate::config::types::Proxy = serde_yaml::from_str(
            r#"
id: mesh-tcp-relay
backend_scheme: tcp
backend_host: placeholder.local
backend_port: 0
listen_port: 15001
"#,
        )
        .expect("proxy fixture should deserialize");
        proxy.dispatch_port_overrides = Some(HashMap::from([(5432, override_config)]));
        proxy
    }

    #[test]
    fn mesh_tcp_stream_port_override_affects_selection_only_for_lb_fields() {
        let timeout_only = proxy_with_override(crate::config::types::ResolvedPortOverride {
            connect_timeout_ms: Some(250),
            ..Default::default()
        });
        assert!(!stream_port_override_affects_selection(&timeout_only, 5432));

        let keepalive_only = proxy_with_override(crate::config::types::ResolvedPortOverride {
            tcp_keepalive: Some(crate::config::types::TcpKeepaliveCfg::default()),
            ..Default::default()
        });
        assert!(!stream_port_override_affects_selection(
            &keepalive_only,
            5432
        ));

        let locality = proxy_with_override(crate::config::types::ResolvedPortOverride {
            locality_lb_setting: Some(crate::config::types::UpstreamLocalityLbSetting::default()),
            ..Default::default()
        });
        assert!(stream_port_override_affects_selection(&locality, 5432));

        let hash = proxy_with_override(crate::config::types::ResolvedPortOverride {
            hash_on: Some("ip".to_string()),
            ..Default::default()
        });
        assert!(stream_port_override_affects_selection(&hash, 5432));
    }

    #[test]
    fn mesh_tcp_stream_port_lane_rejects_least_latency() {
        let least_latency = proxy_with_override(crate::config::types::ResolvedPortOverride {
            algorithm: Some(crate::config::types::LoadBalancerAlgorithm::LeastLatency),
            ..Default::default()
        });

        assert!(stream_port_override_affects_selection(&least_latency, 5432));
        assert!(mesh_stream_port_lane_supported(&least_latency, 5432).is_err());
    }

    #[test]
    fn mesh_tcp_passive_only_port_override_scopes_health_without_lb_lane() {
        let mut config: crate::config::types::GatewayConfig =
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "proxies": [{
                    "id": "mesh-tcp-relay",
                    "backend_scheme": "tcp",
                    "backend_host": "placeholder.local",
                    "backend_port": 0,
                    "listen_port": 15001,
                    "upstream_id": "orders"
                }],
                "consumers": [],
                "plugin_configs": [],
                "upstreams": [{
                    "id": "orders",
                    "algorithm": "round_robin",
                    "targets": [
                        { "host": "orders-a.local", "port": 5432 },
                        { "host": "orders-b.local", "port": 5432 }
                    ],
                    "port_overrides": {
                        "5432": {
                            "passive_health_check": {
                                "unhealthy_threshold": 3,
                                "max_ejection_percent": 50
                            }
                        }
                    }
                }]
            }))
            .expect("gateway config should deserialize");
        config.resolve_dispatch_port_overrides();
        let proxy = config.proxies[0].clone();
        let cache = crate::load_balancer::LoadBalancerCache::new(&config);
        let snapshot = cache.load();
        let override_port =
            crate::load_balancer::LoadBalancerCache::initial_dispatch_port_override_from(
                &snapshot,
                &proxy.namespace,
                "orders",
            );

        let health_port_scope = super::backend_dispatch::stream_health_port_scope(
            &proxy,
            &snapshot,
            "orders",
            override_port,
        );
        let port_lane = (health_port_scope.is_some()
            && mesh_stream_port_lane_supported(&proxy, override_port).expect("supported policy"))
        .then_some(override_port);

        assert_eq!(
            health_port_scope,
            Some(5432),
            "passive-health-only mesh TCP overrides must scope health by stream port"
        );
        assert_eq!(
            port_lane, None,
            "passive-health-only mesh TCP overrides must not engage a per-port LB lane"
        );
    }

    #[test]
    fn mesh_stream_lb_hash_key_canonicalizes_ipv4_mapped_clients() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x020a));
        let plain = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        assert_eq!(
            mesh_stream_lb_hash_key_for_client_ip(mapped),
            mesh_stream_lb_hash_key_for_client_ip(plain)
        );
        assert_eq!(mesh_stream_lb_hash_key_for_client_ip(plain), "192.0.2.10");

        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10));
        assert_eq!(mesh_stream_lb_hash_key_for_client_ip(ipv6), "2001:db8::a");
    }
}
