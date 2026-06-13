//! Raw-TCP mesh egress relay (Ambient).
//!
//! Captured outbound connections whose pre-NAT original destination
//! (`SO_ORIGINAL_DST`) matches a declared `(service VIP, stream-family port)`
//! pair never reach hyper: the accept loop branches here BEFORE any HTTP
//! parsing and the raw byte stream is relayed through an HBONE CONNECT tunnel
//! to the LB-selected destination workload's app port. HBONE is already a
//! byte-stream tunnel and the destination's transparent inbound relay dials
//! the CONNECT authority, so no destination-side changes are involved.
//!
//! Fail-closed rules (mirroring the HTTP per-port orig-dst path):
//! - the destination workload must carry the `mesh.hbone` tag, a loaded
//!   gateway SVID, and a capability-registry record proving HBONE support
//!   (enrolled by `collect_backend_capability_targets` from the same
//!   synthesized relay proxy used here, so probe and dispatch keys agree);
//! - the pinned `mesh.spiffe_id` peer identity is REQUIRED to be intact — a
//!   corrupt tag closes the connection rather than dialing unpinned;
//! - any gate failure closes the client connection; nothing is ever guessed
//!   or forwarded to a different destination.
//!
//! No per-request plugins run here (there is no request): destination-side
//! `mesh_authz` on the outer CONNECT is the policy enforcement point, and the
//! lookup table only ever contains slice-declared service VIPs, so
//! REGISTRY_ONLY admission holds by construction. Passive-health/outlier
//! recording is intentionally absent, matching the stream-proxy paths (raw
//! TCP has no response status to classify); connection failures still feed
//! the HBONE relay failure metric and the LB's least-connection accounting.

use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{LoadBalancerConnectionGuard, ProxyState, hbone_pool, tcp_proxy};
use crate::load_balancer::LoadBalancerCache;
use crate::request_epoch::RequestEpoch;
use crate::router_cache::MeshTcpEgressEntry;

/// Relay one captured raw-TCP connection over HBONE. Consumes the stream;
/// every early return closes it (drop). The caller already holds the
/// connection permit and overload `ConnectionGuard` for the connection's
/// lifetime.
pub(crate) async fn handle_mesh_tcp_egress(
    client_stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    state: &Arc<ProxyState>,
    epoch: &RequestEpoch,
    entry: &Arc<MeshTcpEgressEntry>,
    orig_dst: std::net::SocketAddr,
) {
    let proxy = entry.relay_proxy.as_ref();
    let Some(selection) = LoadBalancerCache::select_target_from(
        &epoch.load_balancer,
        &entry.upstream_id,
        &proxy.id,
        None,
    ) else {
        warn!(
            service = %entry.service_fqdn,
            orig_dst = %orig_dst,
            client_ip = %remote_addr.ip(),
            "Raw-TCP mesh egress has no selectable workload target; closing captured connection"
        );
        return;
    };
    let target = selection.target;

    // Transport gate — the raw-TCP analog of `supports_hbone_backend`, minus
    // the HTTP dispatch-kind check (there is no HTTP dispatch here).
    if !hbone_pool::target_hbone_enabled(&target) {
        warn!(
            service = %entry.service_fqdn,
            target_host = %target.host,
            "Raw-TCP mesh egress target carries no mesh.hbone tag; closing (materializer bug?)"
        );
        return;
    }
    if state.gateway_svid_bundle.load().is_none() {
        warn!(
            service = %entry.service_fqdn,
            "Raw-TCP mesh egress requires a loaded gateway SVID; closing captured connection"
        );
        return;
    }
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
    // the HTTP HBONE dispatch path.
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

    // Least-connection accounting parity with the HTTP relay path.
    let balancer = epoch
        .load_balancer
        .balancers()
        .get(&entry.upstream_id)
        .cloned();
    let _lb_guard = LoadBalancerConnectionGuard::new(Some(Arc::clone(&target)), balancer);

    let tunnel = match state
        .hbone_pool
        .get_tunnel(
            proxy,
            &target.host,
            target.port,
            hbone_port,
            expected_peer.as_ref(),
        )
        .await
    {
        Ok(tunnel) => tunnel,
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
    };

    debug!(
        service = %entry.service_fqdn,
        orig_dst = %orig_dst,
        target_host = %target.host,
        target_port = target.port,
        client_ip = %remote_addr.ip(),
        "Relaying captured raw-TCP connection over HBONE"
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
    if let Some((direction, class, side, message)) = result.first_failure.as_ref() {
        crate::plugins::prometheus_metrics::global_registry()
            .record_hbone_relay_failure(&proxy.id, *direction, *class);
        warn!(
            service = %entry.service_fqdn,
            proxy_id = %proxy.id,
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
            bytes_in = result.bytes_client_to_backend,
            bytes_out = result.bytes_backend_to_client,
            "Raw-TCP mesh egress relay completed"
        );
    }
}
