//! ServiceWaypoint L7 termination on the HBONE `:15008` listener (issue #7501).
//!
//! A `ServiceWaypoint` is the L7 terminator for the Services bound to it. An
//! authenticated HBONE `CONNECT` whose `:authority` names an HTTP-family port
//! of a bound Service (its ClusterIP, a Service host variant, or one backing
//! pod endpoint; [`crate::modes::mesh::service_waypoint_l7::ServiceWaypointL7TargetIndex`])
//! is not relayed at L4. Instead:
//!
//! 1. The outer `CONNECT` passes the same transport gates as an L4 HBONE relay,
//!    without running the plugin chain (an `AuthorizationPolicy` with
//!    HTTP-only rules cannot be judged against a tunnel; every inner request
//!    runs the full chain instead): a verified peer SPIFFE identity
//!    (`hbone_unauthenticated_peer`), the credential gate against the inbound
//!    admission trust in force (`hbone_peer_trust_withdrawn` /
//!    `hbone_peer_revoked`), and the PeerAuthentication transport posture.
//!    No backend is dialed at `CONNECT` time.
//! 2. The tunnel is registered with the admission fence under
//!    [`HboneRelayDestinationGate::ServiceWaypointL7`]. A sweep re-checks the
//!    peer credential (expiry, trust, CRL), the PeerAuthentication posture
//!    and the bound-Service liveness; a revocation cuts the outer stream with
//!    `RST_STREAM(CONNECT_ERROR)`.
//! 3. The upgraded stream is served by an inner HTTP/1.1 + HTTP/2 server
//!    (`hyper_util::server::conn::auto::Builder`) with the frontend's header,
//!    frame and stream ceilings. Each inner request runs through the ordinary
//!    request pipeline (`RequestGuard` drain, hop limit, canonical path,
//!    plugin chain, backend dispatch) carrying an unforgeable
//!    [`ServiceWaypointL7Context`]: the router resolves it ONLY inside its
//!    bound Service's route partition after the inner `Host` / `:authority`
//!    was pinned to that Service (`403 service_waypoint_host_mismatch`), and
//!    `mesh_authz` reads a trusted `source.principal` assertion only from the
//!    OUTER `CONNECT`'s baggage.
//! 4. A clean close or an idle timeout ends the outer stream with
//!    `END_STREAM`; a fence revocation, inner protocol error (non-HTTP bytes
//!    included: they are never relayed at L4) or overload teardown resets it
//!    with `RST_STREAM(CONNECT_ERROR)` (#5781 / #5858 contract).
//!
//! The metric families
//! `ferrum_mesh_service_waypoint_l7_tunnels_active`,
//! `ferrum_mesh_service_waypoint_l7_tunnel_terminations_total{reason}` and
//! `ferrum_mesh_service_waypoint_route_refusals_total{reason}` are process
//! static, closed-cardinality, and rendered outside the registry cache.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info};

use super::hbone_admission_fence::{
    AdmittedHboneTunnel, HboneAdmissionSnapshot, HboneConnectCredential, HbonePeerCredential,
    HboneRelayDestinationGate,
};
use super::{ProxyBody, ProxyState, RequestConnectionMetadata, build_response, record_request};
use crate::modes::mesh::service_waypoint_l7::{ServiceWaypointL7Context, ServiceWaypointL7Target};
use crate::plugins::utils::log_sampling::warn_sampled;
use crate::plugins::{HboneReuseContext, ProxyProtocol, RequestContext};
use crate::request_epoch::RequestEpoch;

// ── Metrics ────────────────────────────────────────────────────────────────

/// Whether the families are emitted. Set at mesh startup for a
/// `ServiceWaypoint` and on the first admitted L7 tunnel, so a process that
/// never terminates HBONE at L7 never advertises them.
static METRICS_ENABLED: AtomicBool = AtomicBool::new(false);
static L7_TUNNELS_ACTIVE: AtomicU64 = AtomicU64::new(0);
static L7_TUNNEL_TERMINATIONS: [AtomicU64; ServiceWaypointL7TunnelTermination::ALL.len()] =
    [const { AtomicU64::new(0) }; ServiceWaypointL7TunnelTermination::ALL.len()];
static ROUTE_REFUSALS: [AtomicU64; ServiceWaypointRouteRefusal::ALL.len()] =
    [const { AtomicU64::new(0) }; ServiceWaypointRouteRefusal::ALL.len()];

/// Why an L7-terminated ServiceWaypoint tunnel ended. Closed label set of
/// `ferrum_mesh_service_waypoint_l7_tunnel_terminations_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceWaypointL7TunnelTermination {
    /// The peer closed the tunnel (or the server drained it gracefully).
    /// The outer stream ended with `END_STREAM`.
    CleanClose,
    /// No request and no byte crossed the tunnel for the idle timeout, or
    /// no first request arrived within the header-read timeout. `END_STREAM`.
    IdleTimeout,
    /// The admission fence revoked the tunnel (credential, PeerAuthentication,
    /// or bound-Service withdrawal). `RST_STREAM(CONNECT_ERROR)`.
    FenceRevoked,
    /// The inner HTTP framing failed: malformed or non-HTTP bytes, or an
    /// HTTP/2 protocol error. `RST_STREAM(CONNECT_ERROR)`; never an L4 relay.
    InnerProtocolError,
    /// The gateway tore the tunnel down: the shutdown drain wait ended with
    /// requests still in flight, or an authorization-lifetime transport close.
    /// `RST_STREAM(CONNECT_ERROR)`.
    Overload,
}

impl ServiceWaypointL7TunnelTermination {
    pub const ALL: [Self; 5] = [
        Self::CleanClose,
        Self::IdleTimeout,
        Self::FenceRevoked,
        Self::InnerProtocolError,
        Self::Overload,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CleanClose => "clean_close",
            Self::IdleTimeout => "idle_timeout",
            Self::FenceRevoked => "fence_revoked",
            Self::InnerProtocolError => "inner_protocol_error",
            Self::Overload => "overload",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::CleanClose => 0,
            Self::IdleTimeout => 1,
            Self::FenceRevoked => 2,
            Self::InnerProtocolError => 3,
            Self::Overload => 4,
        }
    }

    /// Whether this ending resets the outer `CONNECT` stream with
    /// `RST_STREAM(CONNECT_ERROR)` rather than ending it cleanly.
    pub const fn resets_stream(self) -> bool {
        !matches!(self, Self::CleanClose | Self::IdleTimeout)
    }
}

/// Why a ServiceWaypoint refused to route a request or a carried route.
/// Closed label set of `ferrum_mesh_service_waypoint_route_refusals_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceWaypointRouteRefusal {
    /// An inner request's `Host` / `:authority` does not name the bound
    /// Service its tunnel was admitted for (`403
    /// service_waypoint_host_mismatch`).
    HostMismatch,
    /// A carried route names a destination in another namespace that is not
    /// an authorized cross-namespace target (slice preparation).
    CrossNamespaceRefused,
    /// A carried route names an in-cluster Service the slice does not model
    /// (slice preparation).
    UnmodeledService,
    /// A carried route's `rewrite.authority` names no Service the route may
    /// reach (slice preparation).
    AuthorityRewriteRefused,
    /// A carried route's weighted split cannot be represented (slice
    /// preparation).
    UnrepresentableSplit,
    /// An inner request arrived after its bound Service's binding left the
    /// current generation, before the fence revoked the tunnel (`403
    /// service_waypoint_binding_absent`).
    BindingAbsent,
}

impl ServiceWaypointRouteRefusal {
    pub const ALL: [Self; 6] = [
        Self::HostMismatch,
        Self::CrossNamespaceRefused,
        Self::UnmodeledService,
        Self::AuthorityRewriteRefused,
        Self::UnrepresentableSplit,
        Self::BindingAbsent,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostMismatch => "host_mismatch",
            Self::CrossNamespaceRefused => "cross_namespace_refused",
            Self::UnmodeledService => "unmodeled_service",
            Self::AuthorityRewriteRefused => "authority_rewrite_refused",
            Self::UnrepresentableSplit => "unrepresentable_split",
            Self::BindingAbsent => "binding_absent",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::HostMismatch => 0,
            Self::CrossNamespaceRefused => 1,
            Self::UnmodeledService => 2,
            Self::AuthorityRewriteRefused => 3,
            Self::UnrepresentableSplit => 4,
            Self::BindingAbsent => 5,
        }
    }
}

/// Enable (or disable) the families. Mesh startup calls this with
/// `topology == ServiceWaypoint`. Counters stay monotonic either way.
pub fn set_metrics_enabled(enabled: bool) {
    METRICS_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Record `count` refusals for `reason`.
pub fn record_route_refusals(reason: ServiceWaypointRouteRefusal, count: u64) {
    if count == 0 {
        return;
    }
    METRICS_ENABLED.store(true, Ordering::Relaxed);
    ROUTE_REFUSALS[reason.index()].fetch_add(count, Ordering::Relaxed);
}

/// Concurrent L7-terminated tunnels now.
pub fn l7_tunnels_active() -> u64 {
    L7_TUNNELS_ACTIVE.load(Ordering::Relaxed)
}

/// Tunnels that ended for `reason` since process start.
pub fn l7_tunnel_terminations(reason: ServiceWaypointL7TunnelTermination) -> u64 {
    L7_TUNNEL_TERMINATIONS[reason.index()].load(Ordering::Relaxed)
}

/// Refusals for `reason` since process start.
pub fn route_refusals(reason: ServiceWaypointRouteRefusal) -> u64 {
    ROUTE_REFUSALS[reason.index()].load(Ordering::Relaxed)
}

fn record_termination(reason: ServiceWaypointL7TunnelTermination) {
    L7_TUNNEL_TERMINATIONS[reason.index()].fetch_add(1, Ordering::Relaxed);
}

/// Holds one active-tunnel gauge slot for the life of a served tunnel.
struct ActiveTunnelGauge;

impl ActiveTunnelGauge {
    fn new() -> Self {
        METRICS_ENABLED.store(true, Ordering::Relaxed);
        L7_TUNNELS_ACTIVE.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveTunnelGauge {
    fn drop(&mut self) {
        L7_TUNNELS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Render the families into Prometheus exposition. `ns_label` is the
/// registry's `,namespace="…"` suffix (or empty). Every label value is a
/// compiled-in constant; nothing peer- or request-controlled is rendered.
pub fn render_prometheus(output: &mut String, ns_label: &str) {
    if !METRICS_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    output.push_str(
        "# HELP ferrum_mesh_service_waypoint_l7_tunnels_active Concurrent L7-terminated \
ServiceWaypoint HBONE CONNECT tunnels.\n",
    );
    output.push_str("# TYPE ferrum_mesh_service_waypoint_l7_tunnels_active gauge\n");
    let only_namespace = ns_label.strip_prefix(',').unwrap_or(ns_label);
    if only_namespace.is_empty() {
        output.push_str(&format!(
            "ferrum_mesh_service_waypoint_l7_tunnels_active {}\n",
            l7_tunnels_active()
        ));
    } else {
        output.push_str(&format!(
            "ferrum_mesh_service_waypoint_l7_tunnels_active{{{only_namespace}}} {}\n",
            l7_tunnels_active()
        ));
    }
    output.push_str(
        "# HELP ferrum_mesh_service_waypoint_l7_tunnel_terminations_total L7-terminated \
ServiceWaypoint HBONE tunnels ended, by closed reason.\n",
    );
    output.push_str("# TYPE ferrum_mesh_service_waypoint_l7_tunnel_terminations_total counter\n");
    for reason in ServiceWaypointL7TunnelTermination::ALL {
        output.push_str(&format!(
            "ferrum_mesh_service_waypoint_l7_tunnel_terminations_total{{reason=\"{}\"{}}} {}\n",
            reason.as_str(),
            ns_label,
            l7_tunnel_terminations(reason)
        ));
    }
    output.push_str(
        "# HELP ferrum_mesh_service_waypoint_route_refusals_total ServiceWaypoint inner \
requests and carried VirtualService routes refused, by closed reason.\n",
    );
    output.push_str("# TYPE ferrum_mesh_service_waypoint_route_refusals_total counter\n");
    for reason in ServiceWaypointRouteRefusal::ALL {
        output.push_str(&format!(
            "ferrum_mesh_service_waypoint_route_refusals_total{{reason=\"{}\"{}}} {}\n",
            reason.as_str(),
            ns_label,
            route_refusals(reason)
        ));
    }
}

// ── Inner request refusals ─────────────────────────────────────────────────

/// `mesh_authz.deny_policy` of an inner request whose `Host` / `:authority`
/// does not name its tunnel's bound Service.
pub const SERVICE_WAYPOINT_HOST_MISMATCH_POLICY: &str = "service_waypoint_host_mismatch";
/// `mesh_authz.deny_policy` of an inner request whose bound Service binding
/// left the current generation before the fence revoked its tunnel.
pub const SERVICE_WAYPOINT_BINDING_ABSENT_POLICY: &str = "service_waypoint_binding_absent";
/// `mesh_authz.deny_policy` of an outer `CONNECT` whose authority maps to
/// more than one bound Service HTTP port.
pub const SERVICE_WAYPOINT_AMBIGUOUS_TARGET_POLICY: &str = "ambiguous_service_waypoint_target";
/// `mesh_authz.deny_policy` of an inner request whose tunnel's peer
/// certificate no longer yields an admissible SPIFFE identity.
const SERVICE_WAYPOINT_PEER_IDENTITY_POLICY: &str = "service_waypoint_peer_identity_unavailable";

pub(super) const HOST_MISMATCH_BODY: &str =
    r#"{"error":"Request host does not match the ServiceWaypoint tunnel's bound Service"}"#;
pub(super) const BINDING_ABSENT_BODY: &str =
    r#"{"error":"The ServiceWaypoint tunnel's bound Service is no longer bound here"}"#;
const AMBIGUOUS_TARGET_BODY: &str =
    r#"{"error":"HBONE CONNECT authority maps to more than one bound Service port"}"#;
const PEER_IDENTITY_BODY: &str = r#"{"error":"HBONE tunnel requires an authenticated mesh peer"}"#;

/// Record an inner-request refusal on `/mesh/policy-denies/recent` (the
/// `rule` is the fixed deny policy, the source the tunnel's verified peer)
/// and stamp it on the request's metadata. Never echoes the request host.
pub(super) fn record_inner_refusal(ctx: &mut RequestContext, deny_policy: &'static str) {
    ctx.metadata.insert(
        "mesh_authz.deny_policy".to_string(),
        deny_policy.to_string(),
    );
    crate::modes::mesh::policy_deny_log::record_global(
        crate::modes::mesh::policy_deny_log::PolicyDenyEvent {
            rule: deny_policy.to_string(),
            source: ctx
                .peer_spiffe_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            destination: None,
            reason: deny_policy.to_string(),
            at: crate::time_compat::UtcTimestamp::now(),
            reevaluation: false,
        },
    );
}

/// Refuse an outer `CONNECT` whose authority is ambiguous between two bound
/// Services, before any upgrade.
pub(super) fn refuse_ambiguous_connect(
    state: &ProxyState,
    ctx: &mut RequestContext,
) -> Response<ProxyBody> {
    warn_sampled!(
        denial = SERVICE_WAYPOINT_AMBIGUOUS_TARGET_POLICY,
        "Refused HBONE CONNECT whose authority maps to more than one ServiceWaypoint-bound \
         Service HTTP port"
    );
    refuse_connect(
        state,
        ctx,
        StatusCode::FORBIDDEN,
        SERVICE_WAYPOINT_AMBIGUOUS_TARGET_POLICY,
        AMBIGUOUS_TARGET_BODY,
    )
}

/// Admit (or refuse) an inner request's peer identity: the tunnel's verified
/// certificate SPIFFE principal, re-derived per request from the outer
/// connection's client certificate so its validity window still bounds every
/// request. `false` refuses the request.
pub(super) fn admit_inner_peer_identity(state: &ProxyState, ctx: &mut RequestContext) -> bool {
    if crate::plugins::mesh::spiffe_identity::admit_verified_peer_certificate_principal(ctx)
        .is_some()
    {
        return true;
    }
    ctx.metadata.insert(
        "mesh_authz.deny_policy".to_string(),
        SERVICE_WAYPOINT_PEER_IDENTITY_POLICY.to_string(),
    );
    ctx.terminal_record.mark_counted();
    record_request(state, StatusCode::FORBIDDEN.as_u16());
    false
}

/// The refusal response of [`admit_inner_peer_identity`].
pub(super) fn inner_peer_identity_refusal() -> Response<ProxyBody> {
    build_response(StatusCode::FORBIDDEN, PEER_IDENTITY_BODY)
}

fn refuse_connect(
    state: &ProxyState,
    ctx: &mut RequestContext,
    status: StatusCode,
    deny_policy: &'static str,
    body: &'static str,
) -> Response<ProxyBody> {
    ctx.metadata.insert(
        "mesh_authz.deny_policy".to_string(),
        deny_policy.to_string(),
    );
    ctx.terminal_record.mark_counted();
    record_request(state, status.as_u16());
    build_response(status, body)
}

// ── Outer CONNECT admission ────────────────────────────────────────────────

/// Admit an authenticated HBONE `CONNECT` the target index classified as
/// `TerminateL7(target)`, register it with the admission fence, answer `200`,
/// and serve the upgraded stream with the inner HTTP server.
///
/// Called by the frontend handler before routing and before any plugin runs.
/// Every refusal here happens before the upgrade, so a refused `CONNECT`
/// never becomes a tunnel.
#[allow(clippy::too_many_arguments)]
pub(super) fn terminate_connect(
    state: &Arc<ProxyState>,
    epoch: &RequestEpoch,
    mut req: Request<Incoming>,
    ctx: &mut RequestContext,
    target: Arc<ServiceWaypointL7Target>,
    remote_addr: SocketAddr,
    is_tls: bool,
    mesh_inbound_pre_handshake_app_port: Option<u16>,
    admission_sweep_epoch: u64,
) -> Response<ProxyBody> {
    // Gate 1: a verified peer SPIFFE identity, published exactly as
    // `spiffe_identity` would publish it, with its certificate provenance so
    // the credential gate below applies.
    if crate::plugins::mesh::spiffe_identity::admit_verified_peer_certificate_principal(ctx)
        .is_none()
    {
        debug!(
            namespace = %target.namespace,
            service_port = target.service_port,
            "Rejected ServiceWaypoint L7 HBONE CONNECT with no authenticated peer identity"
        );
        return refuse_connect(
            state,
            ctx,
            StatusCode::FORBIDDEN,
            "hbone_unauthenticated_peer",
            PEER_IDENTITY_BODY,
        );
    }
    // Gate 2: the retained chain against the inbound admission trust in force.
    let peer_credential =
        match HbonePeerCredential::from_admitted_connect(ctx, &state.hbone_admission_fence) {
            HboneConnectCredential::Admit(credential) => credential,
            HboneConnectCredential::Refuse(refusal) => {
                let reason = refusal.connect_reason();
                debug!(
                    reason,
                    "Rejected ServiceWaypoint L7 HBONE CONNECT whose peer chain no longer \
                     survives the inbound admission trust in force"
                );
                return refuse_connect(
                    state,
                    ctx,
                    StatusCode::FORBIDDEN,
                    reason,
                    PEER_IDENTITY_BODY,
                );
            }
        };
    let Some(partition) = epoch
        .route_table
        .service_waypoint_l7_routes()
        .partition(&target)
    else {
        // The index named a target this generation built no partition for.
        // Never relay it at L4 instead: refuse.
        return refuse_connect(
            state,
            ctx,
            StatusCode::FORBIDDEN,
            "hbone_relay_destination_denied",
            r#"{"error":"HBONE relay destination not allowed"}"#,
        );
    };
    let default_route = Arc::clone(&partition.default_route);
    // Gate 3: the PeerAuthentication transport posture for the bound port.
    if super::mesh_inbound_peer_auth_transport_mismatch(
        state,
        ctx.mesh_direction,
        mesh_inbound_pre_handshake_app_port,
        &default_route,
        None,
        is_tls,
        ctx.tls_client_cert_der.is_some(),
    )
    .is_some()
    {
        return refuse_connect(
            state,
            ctx,
            StatusCode::FORBIDDEN,
            "hbone_peer_auth_transport_mismatch",
            r#"{"error":"Mesh inbound transport does not satisfy PeerAuthentication for the resolved application port"}"#,
        );
    }
    // Process-wide L7 tunnel ceiling (`FERRUM_MAX_CONNECTIONS`): one outer
    // HTTP/2 connection must not multiply inner servers without bound.
    let tunnel_permit = match state.service_waypoint_l7_tunnels.as_ref() {
        Some(limit) => match Arc::clone(limit).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                warn_sampled!(
                    denial = "service_waypoint_l7_tunnel_capacity",
                    "Refused ServiceWaypoint L7 HBONE CONNECT: the L7 tunnel ceiling \
                     (FERRUM_MAX_CONNECTIONS) is reached"
                );
                return refuse_connect(
                    state,
                    ctx,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_waypoint_l7_tunnel_capacity",
                    r#"{"error":"ServiceWaypoint L7 tunnel capacity exhausted"}"#,
                );
            }
        },
        None => None,
    };
    let Some(on_upgrade) = req.extensions_mut().remove::<OnUpgrade>() else {
        return refuse_connect(
            state,
            ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            "hbone_upgrade_missing",
            r#"{"error":"HBONE upgrade handle missing"}"#,
        );
    };

    // The outer CONNECT's baggage, the ONLY HBONE assertion the inner
    // requests are judged by. Read from the pristine wire block.
    let outer_baggage = crate::plugins::mesh::authz::hbone_wire_folded_baggage(ctx);
    let context = Arc::new(ServiceWaypointL7Context {
        target: ServiceWaypointL7Target::clone(&target),
        outer_baggage,
    });

    let reuse_context = HboneReuseContext::from(&*ctx);
    let tunnel = state.hbone_admission_fence.admit(HboneAdmissionSnapshot {
        ctx: ctx.clone(),
        proxy: Arc::clone(&default_route),
        upstream_target: None,
        is_tls,
        has_verified_peer_certificate: ctx.tls_client_cert_der.is_some(),
        mesh_inbound_pre_handshake_app_port,
        destination_gate: HboneRelayDestinationGate::ServiceWaypointL7(
            ServiceWaypointL7Target::clone(&target),
        ),
        resolved_ip: None,
        // Not a configured proxy: the bound-Service gate is the presence check.
        proxy_lifecycle_generation: None,
        request_protocol: ProxyProtocol::Http,
        grpc_web_request: false,
        admission_sweep_epoch,
        peer_credential,
        // No outer chain admitted this tunnel, so there is no chain
        // classification for a sweep to re-fold: every inner request runs the
        // whole chain itself.
        advertised_inner_reuse: false,
        reuse_context,
    });
    // Inner application connection reuse is safe while the fence holds the
    // tunnel: every inner request is judged by the full chain.
    let advertise_tunnel_reuse = tunnel.fence_in_force();

    let inner = InnerTunnelFacts {
        context,
        remote_addr,
        frontend_listen_port: ctx.frontend_listen_port,
        frontend_sni_hostname: ctx.frontend_sni_hostname.clone(),
        destination_ip: ctx.destination_ip,
        tls_client_cert_der: ctx.tls_client_cert_der.clone(),
        tls_client_cert_chain_der: ctx.tls_client_cert_chain_der.clone(),
        mtls_auth_connection_cache: ctx.mtls_auth_connection_cache.clone(),
        peer_spiffe_extraction_cache: ctx.peer_spiffe_extraction_cache.clone(),
        client_trust_session: ctx.client_trust_session.clone(),
        shutdown_rx: ctx.websocket_shutdown_rx.clone(),
        idle_timeout: super::hbone_proxy::proxy_idle_timeout_for_policy_port(
            &default_route,
            &state.env_config,
            Some(target.service_port),
        ),
    };
    info!(
        namespace = %target.namespace,
        service = %target.service,
        service_port = target.service_port,
        "Admitted ServiceWaypoint L7 HBONE tunnel"
    );
    let serve_state = Arc::clone(state);
    tokio::spawn(async move {
        let _permit = tunnel_permit;
        match on_upgrade.await {
            Ok(upgraded) => serve_tunnel(serve_state, upgraded, tunnel, inner).await,
            Err(error) => {
                // Registered before the upgrade; a peer that vanished here
                // must not leave a sweepable entry behind.
                tunnel.retire();
                debug!(
                    error_kind = crate::retry::error_class_log_kind(
                        crate::retry::classify_boxed_error(&error)
                    ),
                    "ServiceWaypoint L7 HBONE upgrade failed"
                );
            }
        }
    });

    ctx.terminal_record.mark_counted();
    record_request(state, StatusCode::OK.as_u16());
    let mut response = Response::builder().status(StatusCode::OK);
    if advertise_tunnel_reuse {
        response = response.header(
            crate::modes::mesh::hbone::TUNNEL_REUSE_HEADER,
            crate::modes::mesh::hbone::TUNNEL_REUSE_FENCED,
        );
    }
    response.body(ProxyBody::empty()).unwrap_or_else(|_| {
        build_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"Internal server error"}"#,
        )
    })
}

/// Everything an inner request inherits from the admitted outer tunnel.
struct InnerTunnelFacts {
    context: Arc<ServiceWaypointL7Context>,
    remote_addr: SocketAddr,
    frontend_listen_port: Option<u16>,
    frontend_sni_hostname: Option<String>,
    destination_ip: Option<std::net::IpAddr>,
    tls_client_cert_der: Option<Arc<Vec<u8>>>,
    tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    mtls_auth_connection_cache: Option<Arc<crate::plugins::mtls_auth::MtlsAuthConnectionCache>>,
    peer_spiffe_extraction_cache:
        Option<Arc<crate::plugins::mesh::spiffe_identity::SpiffeIdentityConnectionCache>>,
    client_trust_session: Option<crate::tls::ClientTrustSession>,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    idle_timeout: Option<Duration>,
}

// ── Tunnel IO ──────────────────────────────────────────────────────────────

/// The upgraded outer `CONNECT` stream as the inner server's transport.
///
/// Records the last instant a byte crossed it (idle accounting) and, when
/// asked to before it is dropped, resets the outer HTTP/2 stream with
/// `RST_STREAM(CONNECT_ERROR)` instead of the clean `END_STREAM` a plain drop
/// sends. The reset is requested on DROP because the inner server owns the
/// transport until it is torn down, which is exactly when a revocation or a
/// protocol error must be signalled.
struct TunnelIo {
    inner: TokioIo<hyper::upgrade::Upgraded>,
    activity: Arc<TunnelActivity>,
}

#[derive(Default)]
struct TunnelActivity {
    /// Monotonic milliseconds of the last byte read or written.
    last_activity_ms: AtomicU64,
    /// Set when the tunnel ends in a way that must reset the outer stream.
    reset_on_drop: AtomicBool,
    /// Inner requests whose response body has not yet ended.
    requests_in_flight: AtomicUsize,
}

impl TunnelActivity {
    fn touch(&self) {
        self.last_activity_ms
            .store(crate::socket_opts::monotonic_now_ms(), Ordering::Relaxed);
    }
}

impl Drop for TunnelIo {
    fn drop(&mut self) {
        if self.activity.reset_on_drop.load(Ordering::Acquire)
            && !self.inner.inner_mut().reset_with_connect_error()
        {
            debug!("ServiceWaypoint L7 HBONE stream already closed; no RST_STREAM sent");
        }
    }
}

impl AsyncRead for TunnelIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        polled
    }
}

impl AsyncWrite for TunnelIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.touch();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// Flush only. Shutting the upgraded writer down would queue the outer
    /// `END_STREAM` from inside the inner server (hyper's HTTP/1 dispatcher
    /// shuts its transport down before it returns the protocol result), before
    /// the tunnel supervisor has decided between a clean end and
    /// `RST_STREAM(CONNECT_ERROR)`. The supervisor owns the outer close: it
    /// drops this transport, and `Drop` sends the reset when one was
    /// requested, else the clean `END_STREAM` a dropped writer sends.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if matches!(polled, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.touch();
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Resolves when the tunnel has had no in-flight request and no byte in
/// either direction for `timeout`. Never resolves without a timeout.
async fn tunnel_idle(activity: Arc<TunnelActivity>, timeout: Option<Duration>) {
    let Some(timeout) = timeout.filter(|timeout| !timeout.is_zero()) else {
        std::future::pending::<()>().await;
        return;
    };
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    loop {
        let last = activity.last_activity_ms.load(Ordering::Relaxed);
        let now = crate::socket_opts::monotonic_now_ms();
        let elapsed = now.saturating_sub(last);
        if elapsed >= timeout_ms && activity.requests_in_flight.load(Ordering::Acquire) == 0 {
            return;
        }
        let wait = timeout_ms
            .saturating_sub(elapsed)
            .max(1_000)
            .min(timeout_ms);
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
}

/// Decrements the in-flight count when an inner request ends, however it
/// ends: carried by the service future and then by the response body
/// ([`TunnelResponseBody`]), so a request counts until its body is done.
struct InFlightRequest(Arc<TunnelActivity>);

impl InFlightRequest {
    fn new(activity: &Arc<TunnelActivity>) -> Self {
        activity.requests_in_flight.fetch_add(1, Ordering::AcqRel);
        activity.touch();
        Self(Arc::clone(activity))
    }
}

impl Drop for InFlightRequest {
    fn drop(&mut self) {
        self.0.requests_in_flight.fetch_sub(1, Ordering::AcqRel);
        self.0.touch();
    }
}

/// An inner response body that keeps its request counted in flight on the
/// tunnel until the body reaches its end or is dropped (hyper finished or
/// abandoned the stream). Every frame also counts as tunnel activity.
struct TunnelResponseBody {
    inner: ProxyBody,
    in_flight: InFlightRequest,
}

impl hyper::body::Body for TunnelResponseBody {
    type Data = <ProxyBody as hyper::body::Body>::Data;
    type Error = <ProxyBody as hyper::body::Body>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        // `ProxyBody` and `InFlightRequest` are both `Unpin`.
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(Some(Ok(_)))) {
            this.in_flight.0.touch();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

// ── Inner server ───────────────────────────────────────────────────────────

/// Serve one admitted, upgraded L7 tunnel to its end.
async fn serve_tunnel(
    state: Arc<ProxyState>,
    upgraded: hyper::upgrade::Upgraded,
    tunnel: AdmittedHboneTunnel,
    facts: InnerTunnelFacts,
) {
    let _gauge = ActiveTunnelGauge::new();
    let activity = Arc::new(TunnelActivity::default());
    activity.touch();
    let io = TunnelIo {
        inner: TokioIo::new(upgraded),
        activity: Arc::clone(&activity),
    };
    // Observe raw HTTP/1 framing exactly as the frontend does: an inner
    // HTTP/1 request with no observer is refused fail closed.
    let (io, h1_framing_signals) = super::h1_framing_guard::H1FramingGuardIo::new(
        io,
        super::http1_parser_max_buf_size(state.max_header_size_bytes),
        Some(facts.remote_addr),
    );
    let io = TokioIo::new(io);

    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    {
        let mut http1 = builder.http1();
        http1.max_buf_size(super::http1_parser_max_buf_size(
            state.max_header_size_bytes,
        ));
        http1.writev(true);
        if state.env_config.http_header_read_timeout_seconds > 0 {
            http1.timer(TokioTimer::new());
            http1.header_read_timeout(Duration::from_secs(
                state.env_config.http_header_read_timeout_seconds,
            ));
        }
    }
    builder
        .http2()
        .timer(TokioTimer::new())
        .response_write_timeout(super::client_write_stall::h2_response_write_timeout(
            state.env_config.http_client_write_timeout_seconds,
        ))
        .max_header_list_size(super::h2_parser_max_header_list_size(
            state.max_header_size_bytes,
        ))
        .initial_stream_window_size(state.env_config.frontend_h2_initial_stream_window_size)
        .initial_connection_window_size(state.env_config.frontend_h2_initial_connection_window_size)
        .adaptive_window(false)
        .max_frame_size(state.env_config.frontend_h2_max_frame_size)
        // Per-tunnel stream ceiling: one tunnel never runs more concurrent
        // inner requests than one frontend connection may.
        .max_concurrent_streams(state.env_config.server_http2_max_concurrent_streams)
        .max_pending_accept_reset_streams(Some(
            state
                .env_config
                .server_http2_max_pending_accept_reset_streams,
        ))
        .max_local_error_reset_streams(Some(
            state.env_config.server_http2_max_local_error_reset_streams,
        ))
        .enable_connect_protocol();

    let authorization_closer = crate::proxy::auth_lifetime::AuthorizationConnectionCloser::new();
    let mut authorization_close_rx = authorization_closer.subscribe();
    let header_read_timeout_seconds = state.env_config.http_header_read_timeout_seconds;
    let admission = super::frontend_admission::FrontendAdmission::new();
    let service_admission = Arc::clone(&admission);
    let service_signals = Arc::clone(&h1_framing_signals);
    let service_activity = Arc::clone(&activity);
    let service_state = Arc::clone(&state);
    let drain_state = Arc::clone(&state);
    let facts = Arc::new(facts);
    let service_facts = Arc::clone(&facts);
    let svc = service_fn(move |req: Request<Incoming>| {
        service_admission.mark();
        let in_flight = InFlightRequest::new(&service_activity);
        let state = Arc::clone(&service_state);
        let facts = Arc::clone(&service_facts);
        let http1_framing_result =
            super::consume_h1_framing_result(req.version(), Some(service_signals.as_ref()));
        let request_method = req.method().clone();
        let response_h1_framing_signals = matches!(
            req.version(),
            hyper::Version::HTTP_10 | hyper::Version::HTTP_11
        )
        .then(|| Arc::clone(&service_signals));
        let connection_metadata = RequestConnectionMetadata {
            frontend_listen_port: facts.frontend_listen_port,
            http1_framing_result,
            h1_framing_signals: response_h1_framing_signals.clone(),
            frontend_sni_hostname: facts.frontend_sni_hostname.clone(),
            mesh_direction: Some(crate::modes::mesh::MeshTrafficDirection::Inbound),
            destination_ip: facts.destination_ip,
            peer_spiffe_extraction_cache: facts.peer_spiffe_extraction_cache.clone(),
            websocket_shutdown_rx: facts.shutdown_rx.clone(),
            client_trust_session: facts.client_trust_session.clone(),
            authorization_connection_closer: Some(authorization_closer.clone()),
            service_waypoint_l7: Some(Arc::clone(&facts.context)),
            ..RequestConnectionMetadata::default()
        };
        async move {
            let mut response = super::construct_frontend_proxy_request(
                req,
                state,
                facts.remote_addr,
                true,
                facts.tls_client_cert_der.clone(),
                facts.tls_client_cert_chain_der.clone(),
                facts.mtls_auth_connection_cache.clone(),
                connection_metadata,
            )
            .await;
            super::apply_h1_framing_connection_close(&mut response, http1_framing_result);
            if let Some(signals) = response_h1_framing_signals.as_ref()
                && super::h1_response_ends_framing_observation(&request_method, &response)
            {
                signals.disable_observation();
            }
            // The tunnel counts this request in flight until its RESPONSE
            // BODY ends (or is dropped), not when the head is produced: a
            // streaming body that pauses longer than the idle timeout is
            // still an active request, and the idle timer must not cut it.
            response.map(|response| {
                response.map(|body| TunnelResponseBody {
                    inner: body,
                    in_flight,
                })
            })
        }
    });

    // Boxed (not stack-pinned) so the teardown below drops the connection,
    // and with it the tunnel transport, at a known point.
    let mut conn = Box::pin(builder.serve_connection_with_upgrades(io, svc));
    let mut shutdown_rx = facts.shutdown_rx.clone();
    let revocation = tunnel.revocation_token();

    let ending = tokio::select! {
        biased;
        () = revocation.cancelled() => ServiceWaypointL7TunnelTermination::FenceRevoked,
        result = conn.as_mut() => match result {
            Ok(()) => ServiceWaypointL7TunnelTermination::CleanClose,
            Err(_) => ServiceWaypointL7TunnelTermination::InnerProtocolError,
        },
        () = admission.wait_pre_request_deadline(header_read_timeout_seconds) => {
            ServiceWaypointL7TunnelTermination::IdleTimeout
        }
        () = tunnel_idle(Arc::clone(&activity), facts.idle_timeout) => {
            ServiceWaypointL7TunnelTermination::IdleTimeout
        }
        () = shutdown_signalled(&mut shutdown_rx) => {
            // Graceful drain: GOAWAY / end keep-alive and let in-flight inner
            // requests finish, bounded by the shutdown drain wait.
            conn.as_mut().graceful_shutdown();
            tokio::select! {
                biased;
                () = revocation.cancelled() => ServiceWaypointL7TunnelTermination::FenceRevoked,
                result = conn.as_mut() => match result {
                    Ok(()) => ServiceWaypointL7TunnelTermination::CleanClose,
                    Err(_) => ServiceWaypointL7TunnelTermination::InnerProtocolError,
                },
                () = drain_state.overload.wait_for_drain_wait_end() => {
                    ServiceWaypointL7TunnelTermination::Overload
                }
            }
        }
        () = crate::proxy::auth_lifetime::authorization_close_requested(
            &mut authorization_close_rx,
        ) => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(
                super::AUTHORIZATION_TRANSPORT_CLOSE_SETTLE,
                conn.as_mut(),
            )
            .await;
            ServiceWaypointL7TunnelTermination::Overload
        }
    };

    // Deregister first, so a sweep in the teardown window neither re-judges
    // nor counts a tunnel that carries nothing any more. A revocation the
    // sweep already claimed stays the reason.
    let retired_first = tunnel.retire();
    // A head the HTTP/1 framing guard refused before hyper parsed it ends the
    // connection "cleanly" from hyper's point of view; it is still an inner
    // protocol error, and the tunnel is reset, never relayed.
    let parse_rejects = h1_framing_signals.take_parse_rejects();
    let ending = if !retired_first && tunnel.revoked_reason().is_some() {
        ServiceWaypointL7TunnelTermination::FenceRevoked
    } else if parse_rejects > 0 && !ending.resets_stream() {
        ServiceWaypointL7TunnelTermination::InnerProtocolError
    } else {
        ending
    };
    if ending.resets_stream() {
        activity.reset_on_drop.store(true, Ordering::Release);
    }
    // Dropping the connection drops the transport, which ends (or resets)
    // the outer stream.
    drop(conn);
    record_termination(ending);
    for _ in 0..parse_rejects {
        record_request(&state, StatusCode::BAD_REQUEST.as_u16());
    }
    let namespace = &facts.context.target.namespace;
    match ending {
        ServiceWaypointL7TunnelTermination::FenceRevoked => info!(
            namespace = %namespace,
            service_port = facts.context.target.service_port,
            reason = tunnel
                .revoked_reason()
                .map(super::hbone_admission_fence::HboneRevocationReason::as_str)
                .unwrap_or("unknown"),
            "ServiceWaypoint L7 HBONE tunnel closed: admission revoked"
        ),
        ServiceWaypointL7TunnelTermination::InnerProtocolError => warn_sampled!(
            service_port = facts.context.target.service_port,
            termination = ending.as_str(),
            "ServiceWaypoint L7 HBONE tunnel reset: the inner bytes are not valid HTTP"
        ),
        _ => debug!(
            namespace = %namespace,
            service_port = facts.context.target.service_port,
            termination = ending.as_str(),
            "ServiceWaypoint L7 HBONE tunnel closed"
        ),
    }
}

/// Resolves when the listener's shutdown signal fires. Never resolves on a
/// connection without one.
async fn shutdown_signalled(receiver: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    let Some(receiver) = receiver.as_mut() else {
        std::future::pending::<()>().await;
        return;
    };
    if *receiver.borrow_and_update() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow_and_update() {
            return;
        }
    }
    std::future::pending::<()>().await;
}
