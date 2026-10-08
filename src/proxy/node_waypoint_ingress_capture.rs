//! NodeWaypoint transparent inbound **capture** listener (issue #3287).
//!
//! The node-agent's `ferrum_tc_ingress_redirect` classifier steers inbound TCP
//! for an enrolled `podIP:appPort` into this listener with `bpf_sk_assign()`.
//! Nothing is NAT-ed: the packet still carries the workload's real destination,
//! which is exactly why this socket must be bound `IP_TRANSPARENT` — the
//! accepted socket's *local* address is a workload address that is not
//! configured on this host, and only a transparent socket may bind/reply from
//! it.
//!
//! # Why this is not the HBONE listener
//!
//! The HBONE listener (`:15008`) terminates authenticated HTTP/2 CONNECT over
//! verified mesh mTLS. What arrives here is ordinary application traffic —
//! plaintext HTTP, Redis, Postgres, or the application's own TLS — and
//! `IP_TRANSPARENT` preserves addresses, it does not transform a payload.
//! Steering captured bytes at HBONE would attempt a mesh TLS handshake on
//! application data and fail. So this is a distinct protocol boundary with its
//! own port, its own accept loop, and **no TLS termination at all**.
//!
//! # Gates, in order
//!
//! 1. **Captured-ness.** The recovered original destination must be a real
//!    off-listener address. A direct dial to the capture port itself resolves
//!    to the listener's own address and is refused — this listener is not a
//!    general-purpose relay anyone on the node may address.
//! 2. **Ownership and destination identity.** The destination must resolve to
//!    exactly one slice-declared in-mesh workload address+port
//!    ([`crate::proxy::build_node_waypoint_capture_relay_entry`]) — the same
//!    open-relay guard the inbound HBONE relay uses, tightened to a single
//!    unambiguous workload. This runs FIRST because the two gates below are
//!    both properties of that workload, not of the listener.
//! 3. **PeerAuthentication.** The effective inbound posture of **that exact
//!    workload** on the captured app port must admit plaintext. Resolved from
//!    the workload's own namespace/labels against the live slice's
//!    PeerAuthentication set — deliberately NOT from the listener-wide
//!    `ProxyState::mesh_inbound_tls_policy` port table, which is keyed by port
//!    alone and would let a `PERMISSIVE` pod admit direct plaintext to a
//!    `STRICT` pod that happens to share the app port. Under `STRICT` the
//!    connection is refused and the peer must come over authenticated mesh
//!    transport (HBONE) instead. This is the whole reason the redirect can be
//!    enabled without weakening STRICT.
//! 4. **Authorization.** The relay hands off to
//!    [`crate::proxy::mesh_tcp_inbound::handle_mesh_tcp_inbound`], which runs
//!    the L4 `on_stream_connect` chain (including the mesh-injected
//!    `__mesh_authz`) with the captured **app** port as the authorization
//!    destination and the destination workload's `PolicyScopeCache` stamped on
//!    the stream context, then relays byte-for-byte and emits the disconnect
//!    summary.
//!
//! Every one of these is fail-CLOSED: an unresolvable destination, an ambiguous
//! one, or a posture that cannot be established closes the connection rather
//! than relaying it under some other workload's policy.
//!
//! The backend dial carries `SO_MARK = NODE_WAYPOINT_INBOUND_AUTH_MARK`, so the
//! pod-veth `ferrum_tc_inbound` guard admits it as an authorized relay dial and
//! `ferrum_tc_ingress_redirect` bypasses it as already-relayed instead of
//! steering it back here in a loop.
//!
//! # Admission (issue #4626)
//!
//! Gate 0, ahead of all four above, is connection admission — and it runs in the
//! accept loop, not in the spawned task. This listener fronts ordinary
//! application traffic for every enrolled pod on the node, so a peer that can
//! reach one PERMISSIVE/DISABLE workload (or that simply dials the capture port
//! directly, which gate 1 refuses) could otherwise hold arbitrarily many tasks,
//! descriptors, plugin states, and backend sockets: the `ConnectionGuard` the
//! task took only *recorded* occupancy for graceful drain, it never reserved or
//! refused capacity. Impact is node-wide, not per-pod.
//!
//! So, between `accept()` and `tokio::spawn`:
//!
//! 1. `overload.reject_new_connections` — the same single relaxed atomic load
//!    the ordinary proxy accept loop performs, at the same boundary. Critical
//!    overload admits nothing.
//! 2. A [`crate::util::conn_limit::ConnLimiter`] sized from
//!    `FERRUM_MAX_CONNECTIONS` with a `FERRUM_TCP_MAX_CONNECTIONS_PER_IP`
//!    per-source share. `max_connections` is a per-listener cap in Ferrum
//!    rather than one process-wide pool (see the in-netns capture listeners in
//!    `modes::mesh`), so this listener gets its own limiter of that size — a
//!    saturated capture path must not starve inbound HBONE, and vice versa.
//!
//! The per-source key is the socket peer. The redirect NATs nothing, so that IS
//! the real client address; and the effective source the relay derives later is
//! only knowable after the task exists, which is one allocation too late.
//!
//! The permit is moved into the connection task and released on drop, so it
//! covers every exit: not-captured, destination-denied, STRICT refusal, dial
//! failure, relay error, cancellation, and shutdown. Repeated accept errors go
//! through `AcceptBackoff` + a rate-limited log, so fd exhaustion cannot spin
//! the loop.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use super::ProxyState;
use crate::modes::mesh::config::MtlsMode;
use crate::modes::mesh::node_waypoint_observability::{
    NodeWaypointCaptureAdmissionRejectReason, record_capture_admission_rejection,
};
use crate::util::conn_limit::{ConnLimiter, ConnPermit};

/// Accept backlog for the capture listener. Matches the value the generic proxy
/// listener uses for mesh listeners.
const CAPTURE_BACKLOG: i32 = 1024;

/// Bind the transparent capture socket and serve until shutdown.
///
/// Bind failure is returned as an error, never swallowed: the caller records it
/// as a listener startup failure, which fails readiness. That is the fail-closed
/// half of the contract — if the redirect is armed in the kernel but this socket
/// never comes up, every in-scope packet is dropped by the classifier, so the
/// proxy must not report itself healthy.
pub async fn start_listener(
    addr: SocketAddr,
    state: ProxyState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), anyhow::Error> {
    crate::modes::mesh::validate_ingress_capture_addr(addr).map_err(|e| anyhow::anyhow!(e))?;

    // Shared once for the lifetime of the listener, matching every other
    // listener entry point: they take `ProxyState` by value and refcount it
    // here so each accepted connection clones an `Arc`, not the struct.
    let state = Arc::new(state);

    // `transparent = true` is passed only here. A transparent socket may bind
    // and source non-local addresses, so the capability stays scoped to the one
    // listener that provably needs it rather than being switched on process-wide.
    // The shared factory is exclusive (never SO_REUSEPORT). A single accept loop
    // also keeps `bpf_sk_assign`'s wildcard listener lookup unambiguous.
    let listener: TcpListener = super::create_proxy_socket(
        addr,
        CAPTURE_BACKLOG,
        None,
        // Transparent, but NOT dual-stack: the tc ingress redirect hands this
        // socket the workload's real `podIP:appPort` intact via
        // `bpf_sk_assign`, so it keeps the host's default V6ONLY posture and
        // the configured wildcard family.
        super::ProxyListenerBind {
            transparent: true,
            dual_stack: false,
        },
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to bind the NodeWaypoint transparent inbound capture listener on {addr}: {e}. \
             The eBPF tc ingress redirect steers captured podIP:appPort traffic at this port, so \
             without it every enrolled pod's inbound traffic is dropped fail-closed. Ensure the \
             container has NET_ADMIN (IP_TRANSPARENT) and the port is free."
        )
    })?;

    // This listener's own admission controller (issue #4626). Sized from
    // `FERRUM_MAX_CONNECTIONS` with a `FERRUM_TCP_MAX_CONNECTIONS_PER_IP`
    // per-source share, exactly like the stream data path, and built through
    // `pool_shard_amount` because captured application traffic is a data-plane
    // hot path rather than a management surface.
    let limiter = build_capture_conn_limiter(&state);
    let limits = limiter.snapshot();
    crate::modes::mesh::node_waypoint_observability::install_capture_conn_limiter(Arc::clone(
        &limiter,
    ));

    info!(
        %addr,
        max_connections = limits.max_connections,
        max_connections_per_ip = limits.max_connections_per_ip,
        "NodeWaypoint transparent inbound capture listener bound; the eBPF tc ingress redirect \
         steers captured podIP:appPort traffic here"
    );
    if let Some(tx) = started_tx {
        let _ = tx.send(());
    }

    // Repeated `accept()` failures under fd exhaustion (EMFILE/ENFILE) neither
    // consume the pending connection nor clear read-readiness, so without a
    // backoff the select! arm re-fires immediately and spins the CPU and the
    // log pipeline. Both helpers are the ones every other Ferrum accept loop
    // uses.
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    let mut reject_log = crate::util::accept_backoff::LogRateLimiter::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        accept_backoff.on_success();
                        // Gate 0, before any clone or spawn: a refused socket
                        // costs one accept() and one atomic — never a task,
                        // relay state, or backend dial.
                        let permit = match admit_captured_connection(
                            &limiter,
                            &state,
                            remote_addr,
                        ) {
                            Ok(permit) => permit,
                            Err(reason) => {
                                record_capture_admission_rejection(reason);
                                if let Some(suppressed) =
                                    reject_log.on_event(crate::socket_opts::monotonic_now_ms())
                                {
                                    warn!(
                                        suppressed,
                                        %addr,
                                        client_ip = %remote_addr.ip(),
                                        reason = reason.as_str(),
                                        "Refusing a NodeWaypoint captured connection at the \
                                         admission ceiling before allocating a task"
                                    );
                                }
                                drop(stream);
                                continue;
                            }
                        };
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            // Held for the whole relay lifetime: dropping the
                            // task future releases the global and per-source
                            // slots on every exit, including cancellation.
                            let _admission = permit;
                            // Counted for graceful drain like every other
                            // accepted connection.
                            let _conn_guard =
                                crate::overload::ConnectionGuard::new(&state.overload);
                            handle_captured_connection(stream, remote_addr, addr, &state).await;
                        });
                    }
                    Err(e) => {
                        if let Some(suppressed) =
                            accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                        {
                            warn!(
                                suppressed,
                                %addr,
                                error = %e,
                                "NodeWaypoint capture listener accept failed"
                            );
                        }
                        if let Some(delay) = accept_backoff.on_error(e.kind()) {
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!(%addr, "NodeWaypoint transparent inbound capture listener shutting down");
                return Ok(());
            }
        }
    }
}

/// Build this listener's connection admission controller.
///
/// `FERRUM_MAX_CONNECTIONS` is a **per-listener** cap in Ferrum, not one
/// process-wide pool (the in-netns capture listeners document the same choice),
/// so the capture path gets its own limiter of that size: a saturated capture
/// path must not be able to starve inbound HBONE, and vice versa. `0` on either
/// knob disables that dimension, matching every other surface.
pub fn build_capture_conn_limiter(state: &ProxyState) -> Arc<ConnLimiter> {
    capture_conn_limiter_from_env(&state.env_config)
}

/// The [`build_capture_conn_limiter`] body, taking only the configuration it
/// actually reads so the sizing contract is testable without a `ProxyState`.
pub fn capture_conn_limiter_from_env(env_config: &crate::config::EnvConfig) -> Arc<ConnLimiter> {
    Arc::new(ConnLimiter::with_per_ip_shard_amount_and_ipv6_prefix(
        env_config.max_connections,
        // `usize` on 64-bit; a 32-bit build clamps rather than wrapping.
        usize::try_from(env_config.tcp_max_connections_per_ip).unwrap_or(usize::MAX),
        env_config.pool_shard_amount,
        env_config.per_ip_ipv6_prefix,
    ))
}

/// Decide whether one accepted socket is admitted.
///
/// Ordered so the cheapest, most decisive check runs first: under critical
/// overload nothing is admitted at all, which is the same verdict (and the same
/// single relaxed atomic load) the ordinary proxy accept loop reaches.
fn admit_captured_connection(
    limiter: &Arc<ConnLimiter>,
    state: &ProxyState,
    remote_addr: SocketAddr,
) -> Result<ConnPermit, NodeWaypointCaptureAdmissionRejectReason> {
    admit_captured_connection_with(
        limiter,
        state
            .overload
            .reject_new_connections
            .load(std::sync::atomic::Ordering::Relaxed),
        remote_addr.ip(),
    )
}

/// The admission decision itself, with the overload verdict already read.
///
/// Split out so the ordering contract — overload first, then the global cap,
/// then the per-source share — is exercisable without standing up a
/// `ProxyState`, and so a rejection is provably reachable before any task
/// exists rather than only observable after one.
pub fn admit_captured_connection_with(
    limiter: &Arc<ConnLimiter>,
    reject_new_connections: bool,
    remote_ip: std::net::IpAddr,
) -> Result<ConnPermit, NodeWaypointCaptureAdmissionRejectReason> {
    if reject_new_connections {
        return Err(NodeWaypointCaptureAdmissionRejectReason::Overload);
    }
    limiter
        .try_acquire(remote_ip)
        .map_err(NodeWaypointCaptureAdmissionRejectReason::from)
}

/// The original destination of a captured connection.
///
/// Read from `getsockname()`, **not** `SO_ORIGINAL_DST`: the redirect performs
/// no NAT, so there is no conntrack entry to consult — the socket's local
/// address already is the workload's `podIP:appPort`.
fn captured_original_dst(
    stream: &tokio::net::TcpStream,
    listen_addr: SocketAddr,
) -> Option<SocketAddr> {
    let local = stream.local_addr().ok()?;
    if local.port() == 0 {
        return None;
    }
    // A direct dial to the capture port lands on the listener's own address
    // family/port with a local host address; only a *captured* connection
    // carries a foreign destination. Refuse anything whose port is the capture
    // port — that connection was addressed to this listener, not redirected to
    // it, and it carries no original destination to relay to.
    if local.port() == listen_addr.port() {
        return None;
    }
    if local.ip().is_unspecified() || local.ip().is_loopback() {
        return None;
    }
    Some(local)
}

/// Whether a resolved destination-workload PeerAuthentication mode admits
/// direct plaintext on the capture path.
///
/// `mtls_mode_accepts_plaintext` admits both PERMISSIVE and DISABLE (DISABLE
/// means "no mesh TLS", i.e. plaintext is expected, not refused); STRICT is the
/// mode that forbids exactly this.
fn captured_plaintext_admitted(mode: MtlsMode) -> bool {
    super::mtls_mode_accepts_plaintext(mode)
}

async fn handle_captured_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
    state: &Arc<ProxyState>,
) {
    let Some(orig_dst) = captured_original_dst(&stream, listen_addr) else {
        debug!(
            client_ip = %remote_addr.ip(),
            %listen_addr,
            "Refusing a connection on the NodeWaypoint capture listener that carries no captured \
             original destination; this listener only serves eBPF-redirected traffic"
        );
        drop(stream);
        return;
    };

    // ONE epoch load backs the ownership guard, the destination workload's
    // PeerAuthentication posture, and the policy scope handed to authz, so a
    // concurrent slice apply can never pair one workload's posture with
    // another's scope.
    let epoch = state.request_epoch.load();
    let Some(destination) = super::build_node_waypoint_capture_relay_entry(orig_dst, &epoch) else {
        debug!(
            client_ip = %remote_addr.ip(),
            %orig_dst,
            "Refusing a captured connection whose original destination does not resolve to exactly \
             one slice-declared in-mesh workload address and port; without the exact destination \
             workload there is no PeerAuthentication posture or policy scope to enforce"
        );
        // Same open-relay guard, same ADR counter as the inbound HBONE relay
        // (issue #3334): `relay_destination_denied` is the destination-policy
        // reason for exactly this rejection, and the counter is
        // transport-agnostic, so an operator watching it sees captured-plaintext
        // refusals too instead of a misleading zero. No HBONE handshake phase is
        // recorded — this listener terminates no TLS and admits no CONNECT, so
        // the three phases in the ADR increment-ownership contract do not apply.
        crate::modes::mesh::node_waypoint_observability::record_destination_policy_rejection(
            crate::modes::mesh::node_waypoint_observability::NodeWaypointDestinationPolicyRejectReason::RelayDestinationDenied,
        );
        drop(stream);
        return;
    };

    if !captured_plaintext_admitted(destination.mtls_mode) {
        // STRICT for THIS destination workload on this app port. The posture is
        // per-workload, not per-port: another pod on the same node serving the
        // same app port under PERMISSIVE does not admit plaintext here. The peer
        // must arrive over authenticated mesh transport instead. This is a
        // policy outcome, not an error, so it stays at debug with no
        // request-derived content beyond the peer IP.
        debug!(
            client_ip = %remote_addr.ip(),
            %orig_dst,
            app_port = orig_dst.port(),
            mode = ?destination.mtls_mode,
            "Refusing captured direct plaintext: the PeerAuthentication posture of the destination \
             workload requires verified mesh transport"
        );
        drop(stream);
        return;
    }

    // Hand off to the shared captured-inbound relay: L4 authorization chain on
    // the captured app port with the destination workload's policy scope,
    // marked backend dial, byte-for-byte relay, and the stream
    // disconnect/transaction lifecycle.
    super::mesh_tcp_inbound::handle_mesh_tcp_inbound(
        stream,
        remote_addr,
        state,
        &epoch,
        &destination.entry,
        orig_dst,
    )
    .await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_wildcard_capture_address_is_accepted() {
        // `bpf_sk_assign` resolves the listener with a wildcard socket lookup,
        // so a specific-IP bind is invisible to the classifier and every
        // captured packet would be dropped fail-closed.
        assert!(
            crate::modes::mesh::validate_ingress_capture_addr("0.0.0.0:15006".parse().unwrap())
                .is_ok()
        );
        assert!(
            crate::modes::mesh::validate_ingress_capture_addr("[::]:15006".parse().unwrap())
                .is_ok()
        );
        let err =
            crate::modes::mesh::validate_ingress_capture_addr("10.0.0.5:15006".parse().unwrap())
                .unwrap_err();
        assert!(err.contains("wildcard"), "{err}");
        let err = crate::modes::mesh::validate_ingress_capture_addr("0.0.0.0:0".parse().unwrap())
            .unwrap_err();
        assert!(err.contains("non-zero port"), "{err}");
    }

    mod destination_policy {
        use std::collections::HashMap;

        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{
            AppProtocol, MeshConfig, MtlsMode, NodeWaypointEndpoint, PeerAuthentication,
            PolicyScope, Workload, WorkloadPort, WorkloadSelector,
        };
        use crate::modes::mesh::slice::{
            node_waypoint_capture_destinations_from_workloads,
            node_waypoint_capture_peer_authentications_for_destinations,
        };
        use crate::proxy::resolve_node_waypoint_capture_destination;

        const APP_PORT: u16 = 8080;
        /// The NodeWaypoint serving this node. Enrolled pods name it in
        /// `Workload.node_waypoint.spiffe_id`; it lives in `ferrum`, while the
        /// pods it captures for live in application namespaces.
        const NODE_WAYPOINT: &str = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint";
        /// A DIFFERENT node's NodeWaypoint. Pods pointing at it are NOT this
        /// proxy's to capture for.
        const OTHER_NODE_WAYPOINT: &str = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-b";

        fn trust_domain() -> TrustDomain {
            TrustDomain::new("cluster.local").expect("trust domain")
        }

        fn workload(namespace: &str, service: &str, address: &str, app: &str) -> Workload {
            let td = trust_domain();
            let mut labels = HashMap::new();
            labels.insert("app".to_string(), app.to_string());
            Workload {
                spiffe_id: SpiffeId::from_parts(&td, &format!("ns/{namespace}/sa/{service}"))
                    .expect("spiffe id"),
                selector: WorkloadSelector {
                    labels,
                    namespace: Some(namespace.to_string()),
                },
                service_name: service.to_string(),
                service_namespace: None,
                addresses: vec![address.to_string()],
                ports: vec![WorkloadPort {
                    port: APP_PORT,
                    protocol: AppProtocol::Http,
                    name: None,
                }],
                trust_domain: td,
                namespace: namespace.to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: Some(NodeWaypointEndpoint {
                    address: "10.0.0.1".to_string(),
                    hbone_port: 15008,
                    spiffe_id: SpiffeId::new(NODE_WAYPOINT).expect("node waypoint spiffe id"),
                    node_name: None,
                    node_uid: None,
                    network: None,
                    cluster: None,
                }),
                remote_provenance: false,
            }
        }

        /// Build the mesh view a NodeWaypoint DP actually holds: the CP-resolved
        /// capture inventory, derived through the SAME helpers the slice builder
        /// uses, with `workloads` left EMPTY. That emptiness is the point — it is
        /// the subscription-namespace routing view, and the capture resolver must
        /// not depend on it.
        fn capture_mesh(
            workloads: Vec<Workload>,
            peer_authentications: Vec<PeerAuthentication>,
        ) -> MeshConfig {
            let destinations = node_waypoint_capture_destinations_from_workloads(
                workloads.iter(),
                Some(NODE_WAYPOINT),
            );
            let capture_peer_authentications =
                node_waypoint_capture_peer_authentications_for_destinations(
                    peer_authentications.iter(),
                    &destinations,
                );
            MeshConfig {
                node_waypoint_capture_destinations: destinations,
                node_waypoint_capture_peer_authentications: capture_peer_authentications,
                ..MeshConfig::default()
            }
        }

        /// A selector-scoped PeerAuthentication targeting `app=<app>` in
        /// `namespace`.
        fn selector_peer_auth(
            name: &str,
            namespace: &str,
            app: &str,
            mode: MtlsMode,
        ) -> PeerAuthentication {
            let mut labels = HashMap::new();
            labels.insert("app".to_string(), app.to_string());
            PeerAuthentication {
                name: name.to_string(),
                namespace: namespace.to_string(),
                scope: None,
                selector: Some(WorkloadSelector {
                    labels,
                    namespace: Some(namespace.to_string()),
                }),
                mtls_mode: mode,
                port_overrides: HashMap::new(),
            }
        }

        /// Two pods on one node share app port 8080 through the SAME capture
        /// listener. One is STRICT, the other PERMISSIVE. Because a NodeWaypoint
        /// listener is shared, a port-keyed posture table would give both pods
        /// whichever mode won the port — so this pins that the posture is
        /// resolved per DESTINATION WORKLOAD and that the permissive neighbour
        /// can never admit direct plaintext to the strict one.
        #[test]
        fn two_workloads_sharing_an_app_port_do_not_cross_apply_peer_authentication() {
            let mesh = capture_mesh(
                vec![
                    workload("payments", "ledger", "10.244.1.7", "ledger"),
                    workload("payments", "reports", "10.244.1.8", "reports"),
                ],
                vec![
                    selector_peer_auth("ledger-strict", "payments", "ledger", MtlsMode::Strict),
                    selector_peer_auth(
                        "reports-permissive",
                        "payments",
                        "reports",
                        MtlsMode::Permissive,
                    ),
                ],
            );

            let strict = resolve_node_waypoint_capture_destination(
                format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                &mesh,
                true,
            )
            .expect("the strict workload's destination still resolves");
            assert_eq!(
                strict.mtls_mode,
                MtlsMode::Strict,
                "the STRICT pod's posture must not be relaxed by a PERMISSIVE pod that happens \
                 to share the app port on this node"
            );
            assert!(
                !super::super::captured_plaintext_admitted(strict.mtls_mode),
                "captured direct plaintext to a STRICT workload must be refused"
            );

            let permissive = resolve_node_waypoint_capture_destination(
                format!("10.244.1.8:{APP_PORT}").parse().unwrap(),
                &mesh,
                true,
            )
            .expect("the permissive workload's destination resolves");
            assert_eq!(permissive.mtls_mode, MtlsMode::Permissive);
            assert!(
                super::super::captured_plaintext_admitted(permissive.mtls_mode),
                "the PERMISSIVE pod is unaffected by its STRICT neighbour"
            );
        }

        /// The relay entry must carry the destination workload's scope: stream
        /// `mesh_authz` runs with `per_pod_policy_scoping` on for NodeWaypoint,
        /// so an absent scope denies every captured connection `scope_missing`
        /// as soon as one namespace/selector-scoped policy exists.
        #[test]
        fn the_capture_relay_entry_stamps_the_destination_workload_scope() {
            let mesh = capture_mesh(
                vec![workload("payments", "ledger", "10.244.1.7", "ledger")],
                Vec::new(),
            );
            let destination = resolve_node_waypoint_capture_destination(
                format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                &mesh,
                true,
            )
            .expect("destination resolves");

            let scope = destination
                .entry
                .node_waypoint_policy_scope
                .as_ref()
                .expect("the capture relay must stamp the destination workload's policy scope");
            assert_eq!(scope.namespace, "payments");
            assert_eq!(scope.labels.get("app").map(String::as_str), Some("ledger"));
            assert_eq!(
                destination.entry.socket_mark,
                Some(crate::ebpf::NODE_WAYPOINT_INBOUND_AUTH_MARK)
            );
            assert!(
                destination.entry.requires_destination_mesh_authz,
                "NodeWaypoint capture entries must require destination mesh authz"
            );
            assert!(
                destination.entry.has_destination_mesh_authz,
                "test fixture stamps authz-ready so the connect path may proceed"
            );
            // No PeerAuthentication at all is Istio's PERMISSIVE default.
            assert_eq!(destination.mtls_mode, MtlsMode::Permissive);
        }

        #[test]
        fn capture_entry_without_mesh_managed_authz_is_marked_not_ready() {
            let mesh = capture_mesh(
                vec![workload("payments", "ledger", "10.244.1.7", "ledger")],
                Vec::new(),
            );
            let destination = resolve_node_waypoint_capture_destination(
                format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                &mesh,
                false,
            )
            .expect("destination resolves");
            assert!(destination.entry.requires_destination_mesh_authz);
            assert!(!destination.entry.has_destination_mesh_authz);
            assert!(
                crate::proxy::mesh_tcp_inbound::capture_requires_destination_authz_refusal(
                    &destination.entry,
                    true,
                ),
                "capture handler must refuse when mesh-managed authz was absent at synthesis, \
                 even if the serving generation is itself ready"
            );
        }

        /// Fail closed when the destination cannot be pinned to exactly one
        /// workload identity: no slice record at all, or two records claiming
        /// the address with divergent policy identity (picking either would
        /// silently choose whose policy applies).
        #[test]
        fn an_unresolvable_or_ambiguous_destination_is_refused() {
            let known = workload("payments", "ledger", "10.244.1.7", "ledger");
            let mesh = capture_mesh(vec![known.clone()], Vec::new());
            assert!(
                resolve_node_waypoint_capture_destination(
                    format!("10.244.9.9:{APP_PORT}").parse().unwrap(),
                    &mesh,
                    true,
                )
                .is_none(),
                "an address no slice workload declares must be refused, not relayed"
            );

            // Duplicate records for ONE pod are normal (several services backed
            // by the same workload) and must still resolve.
            let duplicate = capture_mesh(vec![known.clone(), known.clone()], Vec::new());
            assert!(
                resolve_node_waypoint_capture_destination(
                    format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                    &duplicate,
                    true,
                )
                .is_some(),
                "identical duplicate workload records collapse to one scope"
            );

            let impostor = workload("attacker", "spoof", "10.244.1.7", "spoof");
            let ambiguous = capture_mesh(vec![known, impostor], Vec::new());
            assert!(
                resolve_node_waypoint_capture_destination(
                    format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                    &ambiguous,
                    true,
                )
                .is_none(),
                "two divergent workload identities on one address are ambiguous and must fail \
                 closed rather than pick whose policy applies"
            );
        }

        /// The root finding: a NodeWaypoint in `ferrum` captures for a pod in
        /// `payments`. `payments`'s STRICT PeerAuthentication is namespace-scoped
        /// and would never survive the CP's subscription-namespace narrowing, so
        /// resolving against the ordinary `peer_authentications` view saw no
        /// policy and defaulted PERMISSIVE — admitting direct plaintext to a
        /// STRICT workload. The dedicated capture inventory carries it.
        #[test]
        fn a_cross_namespace_destination_enforces_its_own_strict_peer_authentication() {
            let ledger = workload("payments", "ledger", "10.244.1.7", "ledger");
            let payments_strict = PeerAuthentication {
                name: "payments-default".to_string(),
                namespace: "payments".to_string(),
                scope: Some(PolicyScope::Namespace {
                    namespace: "payments".to_string(),
                }),
                selector: None,
                mtls_mode: MtlsMode::Strict,
                port_overrides: HashMap::new(),
            };

            // The NodeWaypoint's OWN namespace view: `workloads` and
            // `peer_authentications` are narrowed to `ferrum`, so neither names
            // the `payments` pod nor its policy. Only the capture inventory does.
            let mut mesh = capture_mesh(vec![ledger], vec![payments_strict.clone()]);
            assert!(
                mesh.workloads.is_empty() && mesh.peer_authentications.is_empty(),
                "the fixture must prove the ordinary namespace views cannot answer this"
            );
            assert_eq!(
                mesh.node_waypoint_capture_peer_authentications,
                vec![payments_strict],
                "the captured pod's own-namespace STRICT policy must ride the capture inventory"
            );

            let destination = resolve_node_waypoint_capture_destination(
                format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                &mesh,
                true,
            )
            .expect("the cross-namespace destination resolves");
            assert_eq!(destination.mtls_mode, MtlsMode::Strict);
            assert!(
                !super::super::captured_plaintext_admitted(destination.mtls_mode),
                "direct plaintext to a STRICT cross-namespace destination must be refused"
            );

            // The proxy's OWN `peer_authentications` view must not be able to
            // relax the capture posture. A PERMISSIVE policy that (wrongly)
            // matched the destination's namespace in that view is ignored:
            // resolution reads the capture inventory only.
            mesh.peer_authentications = vec![PeerAuthentication {
                name: "own-view-permissive".to_string(),
                namespace: "payments".to_string(),
                scope: Some(PolicyScope::Namespace {
                    namespace: "payments".to_string(),
                }),
                selector: None,
                mtls_mode: MtlsMode::Permissive,
                port_overrides: HashMap::new(),
            }];
            let still_strict = resolve_node_waypoint_capture_destination(
                format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                &mesh,
                true,
            )
            .expect("the cross-namespace destination still resolves");
            assert_eq!(
                still_strict.mtls_mode,
                MtlsMode::Strict,
                "the proxy's own subscription-namespace PeerAuthentication view must never \
                 participate in — let alone relax — the captured destination's posture"
            );
        }

        /// A pod enrolled on a DIFFERENT node's NodeWaypoint is not this
        /// proxy's to terminate, and an EMPTY inventory (legacy CP, unauthorized
        /// namespace, or a node with no enrolled pods) resolves nothing.
        #[test]
        fn a_foreign_or_missing_capture_inventory_fails_closed() {
            let mut foreign = workload("payments", "ledger", "10.244.1.7", "ledger");
            foreign.node_waypoint = foreign.node_waypoint.map(|mut endpoint| {
                endpoint.spiffe_id =
                    SpiffeId::new(OTHER_NODE_WAYPOINT).expect("other node waypoint spiffe id");
                endpoint
            });
            let mesh = capture_mesh(vec![foreign.clone()], Vec::new());
            assert!(
                mesh.node_waypoint_capture_destinations.is_empty(),
                "a pod enrolled on another node's NodeWaypoint must not enter this inventory"
            );
            assert!(
                resolve_node_waypoint_capture_destination(
                    format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                    &mesh,
                    true,
                )
                .is_none(),
                "a foreign-node destination must be refused"
            );

            // A legacy CP that emits no inventory leaves it empty even though the
            // workload is present in the ordinary view. Resolution must refuse
            // rather than fall back to `workloads` (which carries no proof this
            // NodeWaypoint owns the pod, and whose policy view is the wrong one).
            let legacy = MeshConfig {
                workloads: vec![workload("payments", "ledger", "10.244.1.7", "ledger")],
                ..MeshConfig::default()
            };
            assert!(
                resolve_node_waypoint_capture_destination(
                    format!("10.244.1.7:{APP_PORT}").parse().unwrap(),
                    &legacy,
                    true,
                )
                .is_none(),
                "an absent capture inventory must fail closed, never fall back to `workloads`"
            );
        }

        /// The captured port must be one the destination workload declares.
        #[test]
        fn an_undeclared_destination_port_is_refused() {
            let mesh = capture_mesh(
                vec![workload("payments", "ledger", "10.244.1.7", "ledger")],
                Vec::new(),
            );
            assert!(
                resolve_node_waypoint_capture_destination(
                    "10.244.1.7:9999".parse().unwrap(),
                    &mesh,
                    true,
                )
                .is_none(),
                "a port the destination workload does not declare must be refused"
            );
        }
    }
}
