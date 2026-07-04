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
//! - the pinned `mesh.spiffe_id` peer identity is REQUIRED to be intact — a
//!   corrupt/missing tag closes the connection rather than dialing unpinned
//!   (`mesh.mtls` always requires it; `mesh.hbone` keeps trust-domain-only
//!   verification when an operator target omits it);
//! - any gate failure closes the client connection; nothing is ever guessed
//!   or forwarded to a different destination.
//!
//! No per-request plugins run here (there is no request): destination-side
//! `mesh_authz` on the outer CONNECT is the policy enforcement point, and the
//! lookup table only ever contains slice-declared service VIPs, so
//! REGISTRY_ONLY admission holds by construction. Passive-health/outlier
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
use crate::load_balancer::LoadBalancerCache;
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
    // Engage the per-port LB lane (algorithm / locality / ejection-cap) when
    // all upstream targets share a single port — same pre-selection semantics
    // as the HTTP dispatch path.  Stream paths record no passive health, so the
    // health parameter stays None.
    let dispatch_port = backend_dispatch::initial_dispatch_port(
        proxy,
        LoadBalancerCache::initial_dispatch_port_override_from(lb, &entry.upstream_id),
    );
    let has_port_override =
        backend_dispatch::has_effective_port_override(proxy, lb, &entry.upstream_id, dispatch_port);
    let Some(selection) = (if has_port_override {
        LoadBalancerCache::select_target_for_port_from(
            lb,
            &entry.upstream_id,
            &proxy.id,
            dispatch_port,
            None,
        )
    } else {
        LoadBalancerCache::select_target_from(lb, &entry.upstream_id, &proxy.id, None)
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
    let balancer = epoch
        .load_balancer
        .balancers()
        .get(&entry.upstream_id)
        .cloned();
    let _lb_guard = LoadBalancerConnectionGuard::new(Some(Arc::clone(&target)), balancer);

    // Select the transport from the target's tag (mutually exclusive — the
    // materializer stamps exactly one). Ambient relays over the shared HBONE
    // pool (capability-probe-gated); Sidecar relays over a fresh mesh-mTLS
    // CONNECT tunnel with no capability registry.
    let (tunnel, transport) = if hbone_pool::target_hbone_enabled(&target) {
        if !state
            .backend_capabilities
            .get(proxy, Some(&target))
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
        let expected_peer = match hbone_pool::target_expected_peer_spiffe(&target) {
            Ok(peer) => peer,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Raw-TCP mesh egress target carries a corrupt pinned identity; refusing dial"
                );
                return;
            }
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
                &target.host,
                target.port,
                target.dispatch_policy_port(),
                hbone_port,
                expected_peer.as_ref(),
                // Raw-TCP HBONE egress is in-cluster only (the cross-cluster
                // append is HTTP-family-only, so no cross-cluster target ever
                // reaches this L4 datapath): no trust-domain scope / SNI override.
                None,
                None,
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
        // `mesh.mtls` targets are only ever produced by the materializer, which
        // always stamps the destination identity — a missing/corrupt pin is a
        // config-corruption signal and fails closed rather than dialing
        // unpinned. No capability registry: a slice-declared sidecar peer
        // speaks mesh-mTLS by construction.
        let expected_peer = match mesh_mtls_pool::target_mesh_mtls_expected_peer(&target) {
            Ok(peer) => peer,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Raw-TCP mesh egress mesh.mtls target carries no/invalid pinned identity; \
                     refusing dial"
                );
                return;
            }
        };
        let mtls_port = mesh_mtls_pool::target_mesh_mtls_port(&target);
        match state
            .mesh_mtls_pool
            .open_connect_tunnel(
                proxy,
                &target.host,
                target.port,
                target.dispatch_policy_port(),
                mtls_port,
                &expected_peer,
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
    let buffer_size = state.adaptive_buffer.get_buffer_size(&proxy.id);
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
    state.adaptive_buffer.record_connection(
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
