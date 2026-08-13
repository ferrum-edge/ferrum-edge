//! Dynamic HTTP-family listener lifecycle for Gateway API listener ports.
//!
//! Ferrum's process-wide `FERRUM_PROXY_HTTP_PORT` / `FERRUM_PROXY_HTTPS_PORT`
//! sockets serve every port-agnostic route. A Gateway API `Gateway` instead
//! declares its own listener ports (`:80`, `:443`, `:8080`, …), and port-aware
//! route identity is only real if those ports are actually bound: without a
//! socket on `:8080` a route scoped to that listener can never be reached.
//!
//! [`GatewayListenerManager`] owns that socket set. It derives the desired
//! listeners from the exact [`crate::request_epoch::RequestEpoch`] config
//! generation — every HTTP-family proxy that carries a `listen_port`,
//! classified plaintext or TLS by `GatewayConfig::http_tls_listen_ports` — and
//! reconciles the live set on every config publication.
//!
//! # Lifecycle contract
//!
//! - **Startup.** The manager subscribes to config publications in
//!   [`GatewayListenerManager::new`], *before* the mode's first reconcile, and
//!   the supervisor consumes that same receiver. A publication that lands
//!   between the readiness reconcile and [`GatewayListenerManager::run`] is
//!   therefore still delivered — it cannot be swallowed as "already seen".
//! - **Update.** A port whose TLS class, bind address, or mesh direction changed
//!   is closed, **awaited**, and only then rebound: with
//!   `FERRUM_ACCEPT_THREADS > 1` both generations bind the same port through
//!   `SO_REUSEPORT`, so an overlap would let the kernel hand new connections to
//!   a retiring generation with obsolete protocol/direction state or leave a
//!   wildcard socket claiming a more-specific replacement.
//!   Awaiting the accept-loop task closes every accept socket first; already
//!   accepted connections keep draining in their own tasks through the cloned
//!   shutdown receivers they hold.
//! - **Removal / withdrawal.** Routes are withdrawn by the atomic
//!   `ArcSwap` config publish that *precedes* this reconcile, so from the
//!   instant a listener leaves the config its port answers `404` — never stale
//!   routing. The socket itself closes asynchronously: the accept loop stops
//!   taking new connections as soon as it observes its per-listener shutdown
//!   signal and then drains in-flight requests under the normal graceful
//!   shutdown budget. The bounded window is therefore "already-accepted
//!   connections finish; nothing new is routed", not "traffic keeps being
//!   served". Finished drains are reaped on every reconcile, so completed
//!   handles never accumulate until process exit.
//! - **Supervision.** A started listener whose task later finishes — cleanly,
//!   with an error, or by panic — is reaped on the next reconcile, surfaced on
//!   [`GatewayListenerManager::bind_failures`], and rebound. A dead accept loop
//!   is never mistaken for a healthy port. Reaping is per protocol half: a dead
//!   TCP accept loop retires the whole listener, while a dead QUIC task is
//!   joined and retried on its own, leaving the port's H1/H2 accept loop and
//!   its admitted routes untouched.
//! - **Shutdown.** The global shutdown signal closes every managed listener and
//!   the manager awaits their drains, logging both listener errors
//!   (`Ok(Err(..))`) and join failures (`Err(..)`), before returning.
//!
//! # HTTP/3
//!
//! When HTTP/3 is enabled and frontend TLS is configured, every TLS-class
//! Gateway listener port also gets its own QUIC socket, added, withdrawn and
//! class-flipped with the TCP listener it accompanies. Without that a
//! TLS-classified port is reachable over HTTP/1.1 and HTTP/2 but not HTTP/3,
//! and the port-aware H3 route lookup would have no socket to run on. The ports
//! that really have a QUIC listener are published to
//! `ProxyState::gateway_h3_alt_svc`, so `Alt-Svc` advertises HTTP/3 only where
//! it exists.
//!
//! # Ports this manager refuses
//!
//! A Gateway listener port that collides with a socket Ferrum already owns is
//! never stolen. A process-global proxy frontend of the same class already
//! satisfies the listener — the router keys the request by the real accepted
//! port — so the manager records it as already served and binds no duplicate
//! socket. A **dedicated** Sidecar ingress bind override on that same port is
//! never absorbed this way: widening a loopback-only ownership claim onto the
//! global frontend would violate bind isolation (#3266), so the collision is
//! refused fail-closed instead. Every other **TCP** collision is skipped
//! fail-closed:
//!
//! - an HTTP listener on the global HTTPS port (or the reverse),
//! - admin HTTP/HTTPS ports and the CP gRPC port,
//! - any port claimed by a TCP/TLS stream proxy in the same config, and
//! - any port two HTTP-family proxies claim with different TLS classes.
//!
//! A UDP/DTLS stream claim on the same numeric port is different. TCP and UDP
//! are independent socket namespaces, so the HTTPS TCP listener still binds and
//! serves H1/H2. When HTTP/3 is enabled the optional QUIC half is refused for
//! that port only (`quic_refused`), `ensure_quic` is not called while the
//! collision exists, and `Alt-Svc` stays tied to a live QUIC task. Adding the
//! UDP/DTLS claim live drains only QUIC; removing it starts QUIC on the already
//! running TCP listener. A stale reconcile cannot leave QUIC up after a newer
//! epoch reserved the UDP port.
//!
//! A refusal — and any bind failure, such as `:80` without
//! `CAP_NET_BIND_SERVICE` — is recorded in
//! [`GatewayListenerManager::bind_failures`] and logged, then retried on a slow
//! tick. It is deliberately never fatal: a Gateway listener port is
//! control-plane input, and killing the process over one unbindable port would
//! take down every healthy listener with it.
//!
//! Routing fails closed for both admission refusals and OS bind failures. They
//! are published in the exact request epoch so an unavailable listener cannot
//! become reachable through the process-global proxy or the single-listener
//! Service remap. This includes dedicated Sidecar ingress binds, where
//! remapping a loopback-only listener onto a process-global frontend would
//! widen its exposure. QUIC-only degradations do **not** enter the refused-route
//! set, so an available H1/H2 half remains routable.
//!
//! # Observability
//!
//! Every pass also publishes a bounded, structured realization snapshot to the
//! shared [`crate::proxy::gateway_listener_status::GatewayListenerStatus`]
//! installed by the mode (issue #3810). That snapshot — not the raw
//! [`GatewayListenerManager::bind_failures`] seam — is what authenticated
//! `/health` detail and the fixed-cardinality `ferrum_gateway_listener_*`
//! Prometheus families read, and it clears automatically when a retry binds the
//! port. It is published only after the matching admission decision was
//! accepted for the same generation, and the status object fences stale
//! generations of its own accord, so a pass that lost the epoch race can never
//! overwrite the current generation's status.
//!
//! Classification is a single model shared with that module: the affected
//! protocol half ([`crate::proxy::gateway_listener_status::GatewayListenerProtocolHalf`])
//! and a bounded reason
//! ([`crate::proxy::gateway_listener_status::GatewayListenerFailureCategory`]).
//! A QUIC-only failure is `(Quic, …)` with its TCP half absent from the
//! failure set entirely, which is exactly how a same-port UDP/DTLS collision
//! reports itself while H1/H2 keep serving.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::{Mutex, oneshot, watch};
use tracing::{error, info, warn};

use crate::config::types::{DispatchKind, GatewayConfig};
use crate::proxy::ProxyState;
use crate::proxy::gateway_listener_status::{
    GatewayListenerFailureCategory, GatewayListenerFailureObservation, GatewayListenerProtocolHalf,
    GatewayListenerStatus, GatewayListenerTransientEvent,
};

/// Whether a Gateway listener port terminates TLS on the frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GatewayListenerClass {
    Plaintext,
    Tls,
}

impl GatewayListenerClass {
    fn label(self) -> &'static str {
        match self {
            Self::Plaintext => "HTTP",
            Self::Tls => "HTTPS",
        }
    }
}

/// Protocol-scoped QUIC admission failure for a TLS-class listener that still
/// keeps its TCP half in [`GatewayListenerPlan::ports`].
///
/// A whole-listener (TCP) refusal withdraws the port; this one does not, so it
/// is deliberately a separate, smaller type. Its bounded classification comes
/// from the single shared model in
/// [`crate::proxy::gateway_listener_status`] — there is no second reason enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayListenerProtocolFailure {
    UdpStreamCollision,
}

impl GatewayListenerProtocolFailure {
    pub fn message(self, port: u16) -> String {
        match self {
            Self::UdpStreamCollision => format!(
                "port {port} is claimed by a UDP/DTLS stream proxy in the same config; \
                 the TLS-class Gateway listener's HTTP/3 socket is not bound"
            ),
        }
    }

    pub fn category(self) -> GatewayListenerFailureCategory {
        match self {
            Self::UdpStreamCollision => GatewayListenerFailureCategory::UdpStreamCollision,
        }
    }
}

/// Whole-listener (TCP) admission refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayListenerRefusal {
    /// Bounded classification, shared with the observability surfaces so a
    /// refusal reason and a Prometheus `reason` label can never diverge.
    pub category: GatewayListenerFailureCategory,
    pub message: String,
}

/// One Gateway API listener port a config wants bound, including the exact
/// OS bind address for that generation (default proxy bind or a dedicated
/// Sidecar ingress override).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesiredGatewayListener {
    pub class: GatewayListenerClass,
    pub bind_addr: IpAddr,
    /// Dedicated Sidecar ingress binds are real inbound mesh listeners, not
    /// ordinary process-global frontends. Stamping the direction is required
    /// both for route isolation and for mesh authorization.
    pub mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
}

/// The set of Gateway API listener ports a config wants bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayListenerPlan {
    pub ports: BTreeMap<u16, DesiredGatewayListener>,
    /// Desired ports already served by a process-global proxy frontend of the
    /// same class. No dynamic bind and no failure are needed for these.
    pub already_served: BTreeMap<u16, GatewayListenerClass>,
    /// Ports the config asked for that this process refuses to bind at the TCP
    /// half, with a bounded reason. Surfaced rather than silently dropped.
    pub refused: BTreeMap<u16, GatewayListenerRefusal>,
    /// TLS-class ports whose optional QUIC/HTTP/3 half cannot be realized while
    /// the TCP listener remains desired in [`Self::ports`].
    pub quic_refused: BTreeMap<u16, GatewayListenerProtocolFailure>,
}

fn sidecar_ingress_bind_for_port(config: &GatewayConfig, port: u16) -> Option<IpAddr> {
    config
        .mesh
        .as_ref()
        .and_then(|mesh| mesh.sidecar_ingress_bind_override(port))
}

fn desired_gateway_bind(config: &GatewayConfig, port: u16, default_bind_addr: IpAddr) -> IpAddr {
    sidecar_ingress_bind_for_port(config, port).unwrap_or(default_bind_addr)
}

impl GatewayListenerPlan {
    /// Derive the desired listener set from a published config.
    ///
    /// `reserved` is [`ProxyState::reserved_gateway_ports`] — the effective
    /// reservation for *this* process, not `EnvConfig` alone, so a pre-bound
    /// in-process harness socket is honored too.
    ///
    /// `default_bind_addr` is the process proxy bind used when the generation
    /// carries no dedicated Sidecar ingress override for a port. The resolved
    /// address is part of live restart identity.
    ///
    /// `http3_enabled` makes TLS-class listeners reserve their QUIC UDP port in
    /// addition to the HTTP TCP port.
    pub fn from_config(
        config: &GatewayConfig,
        reserved: &std::collections::HashSet<u16>,
        existing_frontends: &BTreeMap<u16, GatewayListenerClass>,
        default_bind_addr: IpAddr,
        http3_enabled: bool,
    ) -> Self {
        // TCP/TLS raw-stream claims collide with every HTTP-family TCP listener.
        // UDP/DTLS claims collide only with TLS-class listeners when HTTP/3 adds
        // a QUIC socket on the same numeric port.
        let mut tcp_stream_ports: BTreeSet<u16> = BTreeSet::new();
        let mut udp_stream_ports: BTreeSet<u16> = BTreeSet::new();
        for proxy in &config.proxies {
            if matches!(
                proxy.dispatch_kind,
                DispatchKind::TcpRaw | DispatchKind::TcpTls
            ) && let Some(port) = proxy.listen_port
            {
                tcp_stream_ports.insert(port);
            }
            if matches!(
                proxy.dispatch_kind,
                DispatchKind::UdpRaw | DispatchKind::UdpDtls
            ) && let Some(port) = proxy.listen_port
            {
                udp_stream_ports.insert(port);
            }
        }

        let mut ports: BTreeMap<u16, DesiredGatewayListener> = BTreeMap::new();
        let mut already_served: BTreeMap<u16, GatewayListenerClass> = BTreeMap::new();
        let mut refused: BTreeMap<u16, GatewayListenerRefusal> = BTreeMap::new();
        let mut quic_refused: BTreeMap<u16, GatewayListenerProtocolFailure> = BTreeMap::new();
        for proxy in &config.proxies {
            if proxy.dispatch_kind.is_stream() {
                continue;
            }
            let Some(port) = proxy.listen_port else {
                continue;
            };
            if port == 0 {
                continue;
            }
            // TLS class comes from this proxy's own namespace-qualified entry.
            let class = if config
                .http_tls_listen_ports
                .contains(&(proxy.namespace.clone(), port))
            {
                GatewayListenerClass::Tls
            } else {
                GatewayListenerClass::Plaintext
            };
            let bind_addr = desired_gateway_bind(config, port, default_bind_addr);
            let dedicated_bind = sidecar_ingress_bind_for_port(config, port).is_some();
            let mesh_direction =
                dedicated_bind.then_some(crate::modes::mesh::MeshTrafficDirection::Inbound);
            if dedicated_bind && class == GatewayListenerClass::Tls {
                refused
                    .entry(port)
                    .or_insert_with(|| GatewayListenerRefusal {
                        category: GatewayListenerFailureCategory::DedicatedBindTlsUnsupported,
                        message: format!(
                            "port {port} has a dedicated Sidecar ingress bind but is marked as a \
                             frontend-TLS listener; Sidecar bind materialization supports plaintext \
                             HTTP-family listeners only"
                        ),
                    });
                continue;
            }
            if let Some(existing) = existing_frontends.get(&port) {
                if dedicated_bind {
                    // A dedicated Sidecar ingress bind claims exclusive OS
                    // ownership. Absorbing it into the process-global
                    // same-class frontend would silently widen loopback-only
                    // traffic onto the shared socket (#3266).
                    refused
                        .entry(port)
                        .or_insert_with(|| GatewayListenerRefusal {
                            category: GatewayListenerFailureCategory::DedicatedBindConflict,
                            message: format!(
                                "port {port} has a dedicated Sidecar ingress bind but is already \
                                 owned by a process-global {} proxy listener; the dedicated bind \
                                 is not served",
                                existing.label()
                            ),
                        });
                } else if *existing == class {
                    already_served.insert(port, class);
                } else {
                    refused
                        .entry(port)
                        .or_insert_with(|| GatewayListenerRefusal {
                            category: GatewayListenerFailureCategory::ProcessGlobalClassMismatch,
                            message: format!(
                                "port {port} is already owned by a process-global {} proxy \
                             listener, but this Gateway listener requires {}; the Gateway \
                             listener is not served",
                                existing.label(),
                                class.label()
                            ),
                        });
                }
                continue;
            }
            // `reserved_gateway_ports()` covers the admin and CP gRPC
            // listeners, the mesh UDP capture socket, and the process-global
            // proxy ports this gateway did not adopt as a same-class frontend
            // above — name the set rather than guessing which member it was.
            if reserved.contains(&port) {
                refused
                    .entry(port)
                    .or_insert_with(|| GatewayListenerRefusal {
                        category: GatewayListenerFailureCategory::PortReserved,
                        message: format!(
                            "port {port} is reserved by another Ferrum listener \
                         (proxy/admin/control-plane/capture); the Gateway listener is not bound"
                        ),
                    });
                continue;
            }
            if tcp_stream_ports.contains(&port) {
                refused
                    .entry(port)
                    .or_insert_with(|| GatewayListenerRefusal {
                        category: GatewayListenerFailureCategory::StreamPortCollision,
                        message: format!(
                            "port {port} is claimed by a TCP/TLS stream proxy in the same config; \
                         the HTTP-family Gateway listener is not bound"
                        ),
                    });
                continue;
            }
            // UDP/DTLS claims the UDP namespace only. Keep the TCP listener in
            // `ports` and refuse the optional QUIC half when HTTP/3 is on.
            if http3_enabled
                && class == GatewayListenerClass::Tls
                && udp_stream_ports.contains(&port)
            {
                quic_refused
                    .entry(port)
                    .or_insert(GatewayListenerProtocolFailure::UdpStreamCollision);
            }
            if let Some(existing) = ports.insert(
                port,
                DesiredGatewayListener {
                    class,
                    bind_addr,
                    mesh_direction,
                },
            ) && existing.class != class
            {
                // One socket cannot be both plaintext and TLS. The Gateway API
                // translator refuses this at admission, so reaching it means a
                // hand-authored config: refuse the port outright rather than
                // letting whichever proxy happened to sort first decide the
                // socket's protocol for the other.
                refused.entry(port).or_insert_with(|| GatewayListenerRefusal {
                    category: GatewayListenerFailureCategory::ClassConflict,
                    message: format!(
                        "port {port} is claimed as both plaintext and TLS by HTTP-family proxies \
                         in this config; one socket cannot serve both, so the listener is not bound"
                    ),
                });
            }
        }
        // Every TCP refusal reason wins over any class this port also resolved to.
        // QUIC-only refusals deliberately leave the port in `ports`.
        ports.retain(|port, _| !refused.contains_key(port));
        already_served.retain(|port, _| !refused.contains_key(port));
        quic_refused.retain(|port, _| ports.contains_key(port));
        Self {
            ports,
            already_served,
            refused,
            quic_refused,
        }
    }
}

/// A refusal or bind failure for one Gateway listener port (or protocol half).
///
/// `protocol` and `category` are orthogonal: the half that is unavailable and
/// why. A QUIC bind failure beside a healthy TCP listener is
/// `(Quic, BindFailed)` rather than a separate "quic bind failed" reason, so
/// the metric label space stays the product of two closed sets and an alert on
/// `reason="bind_failed"` covers both halves.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerBindFailure {
    pub port: u16,
    pub error: String,
    /// Which protocol half is not serving. A TCP entry means the whole listener
    /// is unavailable; a QUIC entry means only HTTP/3 is, and H1/H2 keep
    /// serving on the same port.
    pub protocol: GatewayListenerProtocolHalf,
    /// Bounded reason, safe as a fixed-cardinality metric label.
    pub category: GatewayListenerFailureCategory,
}

impl GatewayListenerBindFailure {
    fn tcp(port: u16, category: GatewayListenerFailureCategory, error: impl Into<String>) -> Self {
        Self {
            port,
            error: error.into(),
            protocol: GatewayListenerProtocolHalf::Tcp,
            category,
        }
    }

    fn quic(port: u16, category: GatewayListenerFailureCategory, error: impl Into<String>) -> Self {
        Self {
            port,
            error: error.into(),
            protocol: GatewayListenerProtocolHalf::Quic,
            category,
        }
    }

    fn observation(&self) -> GatewayListenerFailureObservation {
        GatewayListenerFailureObservation::new(
            self.port,
            self.protocol,
            self.category,
            self.error.clone(),
        )
    }
}

/// Everything one reconcile pass decided for a single config generation.
///
/// Grouped rather than returned as a tuple because the caller must publish the
/// route-admission decision, the `Alt-Svc` set, and the operator-facing status
/// as one coherent view of the same generation.
struct ReconcileOutcome {
    failures: Vec<GatewayListenerBindFailure>,
    /// Active failures for the bounded status snapshot. Listener-task deaths
    /// that successfully rebind in the same pass are omitted here and published
    /// as transient events instead. A death whose same-pass replacement failed
    /// is not treated as recovered: the replacement error remains an active
    /// observation, and no transient recovery is claimed.
    status_observations: Vec<GatewayListenerFailureObservation>,
    transient_events: Vec<GatewayListenerTransientEvent>,
    refused_route_ports: BTreeSet<u16>,
    h3_ports: Vec<u16>,
    /// Gateway listener ports this process must bind for this generation.
    desired_listeners: usize,
    /// Gateway listener ports with a live TCP accept loop at the end of the pass.
    active_listeners: usize,
}

type ListenerTask = tokio::task::JoinHandle<Result<(), anyhow::Error>>;

struct DrainingListenerTask {
    port: u16,
    task: ListenerTask,
}

struct LiveListener {
    class: GatewayListenerClass,
    /// Exact OS bind address this accept loop was started with. Part of
    /// restart identity so a dedicated Sidecar ingress bind change (for
    /// example `127.0.0.1` → `::1`) retires the old socket.
    bind_addr: IpAddr,
    /// Direction stamped on every accepted connection. Dedicated Sidecar
    /// ingress binds use `Inbound`; ordinary Gateway listeners use `None`.
    mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
    shutdown_tx: watch::Sender<bool>,
    /// The TCP accept-loop task. Returns once every accept socket is closed;
    /// accepted connections drain in their own tasks.
    tcp: ListenerTask,
    /// The QUIC listener task on the same port, when HTTP/3 is enabled and this
    /// is a TLS-class listener.
    quic: Option<ListenerTask>,
    /// Independent of [`Self::shutdown_tx`] so a UDP/DTLS collision can drain
    /// only QUIC without closing the TCP accept loop or existing H1/H2
    /// connections.
    quic_shutdown_tx: Option<watch::Sender<bool>>,
}

impl LiveListener {
    /// Whether the TCP accept loop has ended. A started listener whose accept
    /// loop has exited is not a healthy port, however it exited: the whole
    /// listener must be retired and rebound.
    fn tcp_ended(&self) -> bool {
        self.tcp.is_finished()
    }

    /// Whether the QUIC task has ended. Scoped to HTTP/3 alone — the TCP accept
    /// loop on the same port keeps serving H1/H2, so this half is reaped and
    /// retried in place rather than tearing the listener down.
    fn quic_ended(&self) -> bool {
        self.quic.as_ref().is_some_and(ListenerTask::is_finished)
    }

    /// Signal both protocol halves to stop accepting. QUIC uses an independent
    /// watch channel so UDP/DTLS collisions can drain it alone.
    fn signal_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(tx) = self.quic_shutdown_tx.as_ref() {
            let _ = tx.send(true);
        }
    }

    fn tasks(self) -> Vec<ListenerTask> {
        let mut tasks = vec![self.tcp];
        tasks.extend(self.quic);
        tasks
    }
}

/// TLS material for Gateway listeners that terminate TLS.
///
/// The dynamic slot is preferred so frontend cert rotation reaches these
/// sockets exactly as it reaches the global HTTPS listener.
#[derive(Clone, Default)]
pub struct GatewayListenerTls {
    pub static_config: Option<Arc<rustls::ServerConfig>>,
    pub reload_slot: Option<crate::tls::SharedFrontendTls>,
}

impl GatewayListenerTls {
    fn is_configured(&self) -> bool {
        self.static_config.is_some() || self.reload_slot.is_some()
    }

    /// The `ServerConfig` a QUIC listener starts from.
    ///
    /// The reload slot is preferred, exactly as for TCP; an empty slot (DP
    /// before its first CP-delivered TLS overlay) is not an error — the H3
    /// listener binds disabled and enables itself on the reload path.
    fn quic_initial_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        if let Some(slot) = self.reload_slot.as_ref() {
            let current = slot.load_full();
            if let Some(config) = (*current).clone() {
                return Some(config);
            }
        }
        self.static_config.clone()
    }
}

/// HTTP/3 inputs for TLS-class Gateway listener ports.
///
/// Present only when `FERRUM_ENABLE_HTTP3` is on and the mode resolved frontend
/// TLS; the fields mirror the global H3 listener's so a dynamic port behaves
/// identically to `FERRUM_PROXY_HTTPS_PORT`.
#[derive(Clone)]
pub struct GatewayListenerHttp3 {
    pub config: crate::http3::config::Http3ServerConfig,
    pub tls_policy: crate::tls::TlsPolicy,
    pub client_ca_bundle_path: Option<String>,
    pub client_crls: crate::tls::CrlList,
    /// Frontend TLS live-reload inputs, when the mode enabled reload. Held as
    /// parts because `Http3FrontendTlsReload` is built per listener.
    pub tls_slot: Option<crate::tls::SharedFrontendTls>,
    pub tls_revision_rx: Option<watch::Receiver<u64>>,
}

impl GatewayListenerHttp3 {
    fn frontend_tls_reload(&self) -> Option<crate::http3::server::Http3FrontendTlsReload> {
        let tls_slot = self.tls_slot.clone()?;
        let revision_rx = self.tls_revision_rx.clone()?;
        Some(crate::http3::server::Http3FrontendTlsReload {
            tls_slot,
            revision_rx,
        })
    }
}

pub struct GatewayListenerManager {
    state: ProxyState,
    bind_addr: std::net::IpAddr,
    tls: GatewayListenerTls,
    http3: Option<GatewayListenerHttp3>,
    /// Serialize startup, supervisor, retry, and test-triggered reconciles. A
    /// pass may await socket retirement; overlapping passes could otherwise
    /// mutate the live listener set from different config generations.
    reconcile_lock: Mutex<()>,
    listeners: Mutex<BTreeMap<u16, LiveListener>>,
    /// Retiring listener tasks keyed by the port whose accept socket they may
    /// still own. Finished handles are reaped on every reconcile and the rest
    /// are awaited at shutdown, so a removal never leaks a task past process
    /// exit or permits an incompatible replacement to bind early.
    draining: Mutex<Vec<DrainingListenerTask>>,
    /// Config-publication receiver, created in [`Self::new`] — before the
    /// mode's readiness reconcile — and consumed by [`Self::run`]. Subscribing
    /// inside `run` would mark every publication since construction as already
    /// seen, and the slow retry tick only reconciles when a bind failure is
    /// outstanding, so a missed publication could stay missed indefinitely.
    revisions: Mutex<Option<watch::Receiver<u64>>>,
    /// Process-global HTTP/HTTPS proxy sockets that can directly serve a
    /// same-port Gateway route without a second bind.
    existing_frontends: BTreeMap<u16, GatewayListenerClass>,
    bind_failures: arc_swap::ArcSwap<Vec<GatewayListenerBindFailure>>,
    /// Shared realization status read by authenticated `/health` and by the
    /// Prometheus renderer (issue #3810). `None` only in tests that do not
    /// assert on observability.
    status: Option<Arc<GatewayListenerStatus>>,
}

impl GatewayListenerManager {
    pub fn new(state: ProxyState, bind_addr: std::net::IpAddr, tls: GatewayListenerTls) -> Self {
        let revisions = state.subscribe_config_revision();
        let mut existing_frontends = BTreeMap::new();
        if state.env_config.proxy_http_port != 0 {
            existing_frontends.insert(
                state.env_config.proxy_http_port,
                GatewayListenerClass::Plaintext,
            );
        }
        if tls.is_configured() && state.env_config.proxy_https_port != 0 {
            existing_frontends.insert(state.env_config.proxy_https_port, GatewayListenerClass::Tls);
        }
        Self {
            state,
            bind_addr,
            tls,
            http3: None,
            reconcile_lock: Mutex::new(()),
            listeners: Mutex::new(BTreeMap::new()),
            draining: Mutex::new(Vec::new()),
            revisions: Mutex::new(Some(revisions)),
            existing_frontends,
            bind_failures: arc_swap::ArcSwap::from_pointee(Vec::new()),
            status: None,
        }
    }

    /// Publish bounded realization status to a shared observability surface.
    ///
    /// The mode installs the same handle on `AdminState`, so authenticated
    /// `/health` detail and `/metrics` observe exactly what this manager last
    /// decided — without either of them reaching into the manager's live
    /// listener map.
    #[must_use]
    pub fn with_status(mut self, status: Arc<GatewayListenerStatus>) -> Self {
        self.status = Some(status);
        self
    }

    /// Override the process-global frontend ports with the sockets actually
    /// adopted by the mode. File-mode harnesses may pass pre-bound listeners
    /// whose live ports differ from `EnvConfig`.
    #[must_use]
    pub fn with_existing_frontends(
        mut self,
        plaintext_port: Option<u16>,
        tls_port: Option<u16>,
    ) -> Self {
        self.existing_frontends.clear();
        if let Some(port) = plaintext_port.filter(|port| *port != 0) {
            self.existing_frontends
                .insert(port, GatewayListenerClass::Plaintext);
        }
        if let Some(port) = tls_port.filter(|port| *port != 0) {
            self.existing_frontends
                .insert(port, GatewayListenerClass::Tls);
        }
        self
    }

    /// Bind a QUIC listener beside every TLS-class Gateway listener port.
    #[must_use]
    pub fn with_http3(mut self, http3: GatewayListenerHttp3) -> Self {
        self.http3 = Some(http3);
        self
    }

    /// Ports currently bound by this manager, for tests and diagnostics.
    // The binary target re-declares these modules, so a `pub` item consumed
    // only by `tests/` reads as dead code there.
    #[allow(dead_code)]
    pub async fn active_ports(&self) -> Vec<u16> {
        self.listeners.lock().await.keys().copied().collect()
    }

    /// `(port, bind_addr)` pairs currently owned by this manager.
    #[allow(dead_code)]
    pub async fn active_binds(&self) -> Vec<(u16, IpAddr)> {
        self.listeners
            .lock()
            .await
            .iter()
            .map(|(port, listener)| (*port, listener.bind_addr))
            .collect()
    }

    /// Ports that currently have a live QUIC listener, for tests and
    /// diagnostics.
    #[allow(dead_code)]
    pub async fn active_http3_ports(&self) -> Vec<u16> {
        self.listeners
            .lock()
            .await
            .iter()
            .filter_map(|(port, listener)| listener.quic.is_some().then_some(*port))
            .collect()
    }

    /// Most recent refusals / bind failures. Lock-free read.
    // Same bin-target caveat as `active_ports`: this raw seam is consumed by
    // `tests/` and external library callers. Production observability consumes
    // the shared `GatewayListenerStatus` instead (issue #3810).
    #[allow(dead_code)]
    pub fn bind_failures(&self) -> Arc<Vec<GatewayListenerBindFailure>> {
        self.bind_failures.load_full()
    }

    /// Bind newly-declared Gateway listener ports and close withdrawn ones.
    ///
    /// Returns the failures observed in this pass, which are also published to
    /// [`Self::bind_failures`] for operators. They are advisory: see the module
    /// docs for why an unbindable listener port is never fatal.
    pub async fn reconcile(&self) -> Vec<GatewayListenerBindFailure> {
        let _reconcile_guard = self.reconcile_lock.lock().await;
        loop {
            let expected = self.state.request_epoch.load();
            let ReconcileOutcome {
                failures,
                status_observations,
                transient_events,
                refused_route_ports,
                h3_ports,
                desired_listeners,
                active_listeners,
            } = self.reconcile_generation(&expected).await;
            if !self
                .state
                .publish_gateway_listener_admission(&expected, refused_route_ports)
            {
                // The config changed while this pass awaited socket/drain
                // work. Its decision must never govern the newer route table;
                // immediately reconcile the latest generation instead of
                // relying on a possibly coalesced watch notification.
                warn!(
                    config_generation = expected.config_generation,
                    "Discarding stale Gateway listener admission decision and reconciling the latest generation"
                );
                continue;
            }
            self.state.publish_gateway_h3_alt_svc(&h3_ports);
            self.bind_failures.store(Arc::new(failures.clone()));
            // Publish the bounded operator-facing status last, and only after
            // the admission decision was accepted for this exact generation.
            // The status object fences stale generations independently, so a
            // pass that lost the admission race can never overwrite a newer
            // generation's status even if it reached this point.
            if let Some(status) = self.status.as_ref() {
                status.publish_transients(
                    expected.config_generation,
                    desired_listeners,
                    active_listeners,
                    status_observations,
                    transient_events,
                    crate::proxy::gateway_listener_status::now_unix_ms(),
                );
            }
            return failures;
        }
    }

    async fn reconcile_generation(
        &self,
        expected: &crate::request_epoch::RequestEpoch,
    ) -> ReconcileOutcome {
        let config = expected.config();
        let plan = GatewayListenerPlan::from_config(
            config,
            self.state.reserved_gateway_ports.as_ref(),
            &self.existing_frontends,
            self.bind_addr,
            self.http3.is_some(),
        );
        let mut failures: Vec<GatewayListenerBindFailure> = plan
            .refused
            .iter()
            .map(|(port, refusal)| {
                GatewayListenerBindFailure::tcp(*port, refusal.category, refusal.message.clone())
            })
            .collect();
        for (port, quic_failure) in &plan.quic_refused {
            failures.push(GatewayListenerBindFailure::quic(
                *port,
                quic_failure.category(),
                quic_failure.message(*port),
            ));
        }
        for failure in &failures {
            warn!(
                port = failure.port,
                protocol = failure.protocol.as_str(),
                reason = failure.category.as_str(),
                "Gateway API listener refused: {}",
                failure.error
            );
        }

        self.reap_finished_drains().await;

        let mut live = self.listeners.lock().await;
        let mut listener_task_ended_tcp: BTreeSet<u16> = BTreeSet::new();
        let mut listener_task_ended_quic: BTreeSet<u16> = BTreeSet::new();

        // Reap listeners whose TCP accept loop ended after startup. A finished
        // accept loop means the port is no longer served; leaving the entry in
        // place would make every later reconcile treat it as healthy and never
        // rebind. Both halves are retired together here because the QUIC task
        // cannot outlive the TCP listener it shares a port identity with.
        let dead_tcp: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| listener.tcp_ended().then_some(*port))
            .collect();
        // Ports whose QUIC task ended while the TCP accept loop is still
        // serving. HTTP/3 alone is unavailable there: H1/H2 keep serving, the
        // routes stay admitted, and `Alt-Svc` simply stops advertising the port
        // until `ensure_quic` below rebinds it. Tearing the whole listener down
        // for this would take a healthy TCP socket offline and misreport it as
        // a TCP failure.
        let dead_quic: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| {
                (!listener.tcp_ended() && listener.quic_ended()).then_some(*port)
            })
            .collect();
        for port in dead_tcp {
            if let Some(listener) = live.remove(&port) {
                listener.signal_shutdown();
                let (error, pending) = Self::describe_ended_listener(listener).await;
                if !pending.is_empty() {
                    self.draining.lock().await.extend(
                        pending
                            .into_iter()
                            .map(|task| DrainingListenerTask { port, task }),
                    );
                }
                error!(port, "Gateway API listener ended unexpectedly: {error}");
                // Raw `bind_failures()` always records the death. A transient
                // recovery is published only if the TCP half is live again at
                // the end of this pass; a failed replacement stays fail-closed.
                listener_task_ended_tcp.insert(port);
                failures.push(GatewayListenerBindFailure::tcp(
                    port,
                    GatewayListenerFailureCategory::ListenerTaskEnded,
                    error,
                ));
            }
        }
        for port in dead_quic {
            let Some(listener) = live.get_mut(&port) else {
                continue;
            };
            let Some(error) = Self::reap_ended_quic(listener).await else {
                continue;
            };
            error!(
                port,
                "Gateway API HTTP/3 listener ended unexpectedly: {error}"
            );
            // Recorded in the raw reconcile result for logs and `bind_failures()`.
            // A transient failure+recovery pair is published only when this half
            // is live again by the end of the pass. A failed rebind leaves the
            // bind/retirement error as the durable active failure instead of
            // claiming a recovery that did not occur.
            listener_task_ended_quic.insert(port);
            failures.push(GatewayListenerBindFailure::quic(
                port,
                GatewayListenerFailureCategory::ListenerTaskEnded,
                error,
            ));
        }

        // Close listeners whose port left the config, and rebind ports whose
        // TLS class, bind address, or mesh direction changed — a live socket
        // is one class on one address with one direction, never ambiguous.
        let stale: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| {
                let drifted = !plan.ports.get(port).is_some_and(|desired| {
                    desired.class == listener.class
                        && desired.bind_addr == listener.bind_addr
                        && desired.mesh_direction == listener.mesh_direction
                });
                drifted.then_some(*port)
            })
            .collect();
        let stale_route_ports: BTreeSet<u16> = stale.iter().copied().collect();
        // Ports whose retiring generation has not finished closing its accept
        // sockets. Rebinding them in this pass could co-serve two classes or
        // leave a wildcard socket claiming a more-specific replacement, so
        // they are left unbound and retried.
        let mut defer_rebind: BTreeSet<u16> = BTreeSet::new();
        for port in stale {
            let Some(listener) = live.remove(&port) else {
                continue;
            };
            let replacing = plan.ports.contains_key(&port);
            let class_changed = plan
                .ports
                .get(&port)
                .is_some_and(|desired| desired.class != listener.class);
            let retire_reason = match plan.ports.get(&port) {
                Some(desired) if desired.class != listener.class => "its frontend class changed",
                Some(_) => "its bind address or mesh direction changed",
                None => "no longer declared by config",
            };
            info!(
                port,
                "Closing Gateway API {} listener — {}",
                listener.class.label(),
                retire_reason
            );
            listener.signal_shutdown();
            if replacing {
                // The replacement binds the same port. With
                // `FERRUM_ACCEPT_THREADS > 1` both generations use
                // SO_REUSEPORT, so until every old accept socket is closed the
                // kernel could hand new connections to the retiring class or
                // bind address. Await the accept-loop task — accepted
                // connections keep draining independently through their cloned
                // shutdown receivers.
                let mut retired = true;
                let mut pending: Vec<ListenerTask> = Vec::new();
                for task in listener.tasks() {
                    match Self::await_listener_task(port, task).await {
                        Ok(()) => {}
                        Err(task) => {
                            retired = false;
                            pending.push(task);
                        }
                    }
                }
                if !retired {
                    // Fail closed: keep the port unbound rather than starting
                    // the new class/bind beside accept loops that are still up.
                    let error = format!(
                        "port {port} did not finish retiring its previous listener identity within \
                         {}s; the replacement listener is deferred to the next reconcile",
                        CLASS_FLIP_RETIRE_TIMEOUT.as_secs()
                    );
                    let reason = if class_changed {
                        GatewayListenerFailureCategory::ClassFlipDeferred
                    } else {
                        GatewayListenerFailureCategory::RetirementPending
                    };
                    warn!(port, "Gateway API listener rebind deferred: {error}");
                    failures.push(GatewayListenerBindFailure::tcp(port, reason, error));
                    defer_rebind.insert(port);
                    self.draining.lock().await.extend(
                        pending
                            .into_iter()
                            .map(|task| DrainingListenerTask { port, task }),
                    );
                }
            } else {
                self.draining.lock().await.extend(
                    listener
                        .tasks()
                        .into_iter()
                        .map(|task| DrainingListenerTask { port, task }),
                );
            }
        }

        // A timed-out retiring task may still own an SO_REUSEPORT accept
        // socket. Keep its port unavailable across later reconcile passes —
        // not only the pass that initiated retirement — until every old task
        // actually exits. Otherwise the next retry could bind a replacement
        // of the opposite TLS class beside the wedged generation.
        self.reap_finished_drains().await;
        let retiring_ports: BTreeSet<u16> = self
            .draining
            .lock()
            .await
            .iter()
            .map(|drain| drain.port)
            .collect();

        // Admission refusals suppress remapping. Start from plan.refused
        // (reserved / stream / TLS-class collisions) and every port whose old
        // accept loop is still draining, including a listener withdrawn from
        // the current plan. A request already accepted by that old listener
        // must not be remapped to the sole surviving listener. Extend this set
        // for other reconcile-time decisions that likewise must not leak onto
        // the process-global proxy. Every `spawn_listener` error is included;
        // in particular, a failed dedicated Sidecar ingress bind must not widen
        // its loopback-only route through single-listener remapping.
        // QUIC-only collisions stay out of this set so H1/H2 routes remain
        // reachable on the TCP half.
        let mut refused_route_ports: BTreeSet<u16> = plan.refused.keys().copied().collect();
        refused_route_ports.extend(stale_route_ports);
        refused_route_ports.extend(retiring_ports.iter().copied());

        for (port, desired) in &plan.ports {
            if defer_rebind.contains(port) || retiring_ports.contains(port) {
                refused_route_ports.insert(*port);
                if !failures.iter().any(|failure| {
                    failure.port == *port
                        && failure.protocol == GatewayListenerProtocolHalf::Tcp
                        && matches!(
                            failure.category,
                            GatewayListenerFailureCategory::ClassFlipDeferred
                                | GatewayListenerFailureCategory::RetirementPending
                        )
                }) {
                    let error = format!(
                        "port {port} still has a retiring Gateway listener task; the replacement \
                         listener remains deferred until every previous accept socket closes"
                    );
                    warn!(
                        port = *port,
                        "Gateway API listener rebind deferred: {error}"
                    );
                    failures.push(GatewayListenerBindFailure::tcp(
                        *port,
                        GatewayListenerFailureCategory::RetirementPending,
                        error,
                    ));
                }
                continue;
            }
            if let Some(listener) = live.get_mut(port) {
                if let Some(quic_failure) = plan.quic_refused.get(port) {
                    // Live addition of a UDP/DTLS claim: drain only QUIC.
                    self.stop_quic(*port, listener).await;
                    if !failures.iter().any(|failure| {
                        failure.port == *port
                            && failure.protocol == GatewayListenerProtocolHalf::Quic
                            && failure.category == quic_failure.category()
                    }) {
                        failures.push(GatewayListenerBindFailure::quic(
                            *port,
                            quic_failure.category(),
                            quic_failure.message(*port),
                        ));
                    }
                } else if let Some(error) = self
                    .ensure_quic(*port, listener, expected.config_generation)
                    .await
                {
                    failures.push(error);
                }
                continue;
            }
            if desired.class == GatewayListenerClass::Tls && !self.tls.is_configured() {
                let error = format!(
                    "port {port} is a TLS-terminating Gateway listener but frontend TLS is not \
                     configured on this gateway; the listener is not bound"
                );
                warn!(port = *port, "Gateway API listener refused: {error}");
                failures.push(GatewayListenerBindFailure::tcp(
                    *port,
                    GatewayListenerFailureCategory::FrontendTlsMissing,
                    error,
                ));
                refused_route_ports.insert(*port);
                continue;
            }
            match self.spawn_listener(*port, *desired).await {
                Ok(mut listener) => {
                    if let Some(quic_failure) = plan.quic_refused.get(port) {
                        // Initial collision: bind TCP, never call ensure_quic.
                        if !failures.iter().any(|failure| {
                            failure.port == *port
                                && failure.protocol == GatewayListenerProtocolHalf::Quic
                                && failure.category == quic_failure.category()
                        }) {
                            failures.push(GatewayListenerBindFailure::quic(
                                *port,
                                quic_failure.category(),
                                quic_failure.message(*port),
                            ));
                        }
                    } else if let Some(error) = self
                        .ensure_quic(*port, &mut listener, expected.config_generation)
                        .await
                    {
                        failures.push(error);
                    }
                    live.insert(*port, listener);
                }
                Err(error) => {
                    error!(port = *port, "Gateway API listener bind failed: {error}");
                    failures.push(GatewayListenerBindFailure::tcp(
                        *port,
                        GatewayListenerFailureCategory::BindFailed,
                        error,
                    ));
                    refused_route_ports.insert(*port);
                }
            }
        }

        let h3_ports: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| listener.quic.is_some().then_some(*port))
            .collect();
        // Every declared Gateway listener port this process must bind itself.
        // `already_served` ports are excluded: a process-global frontend of the
        // same class already serves them, so no dynamic socket is desired. A
        // QUIC-only refusal is NOT counted here — its port is still in
        // `plan.ports` and its TCP half is expected to bind and serve.
        let desired_listeners = plan.ports.len() + plan.refused.len();
        let active_listeners = live.len();

        let status_observations: Vec<GatewayListenerFailureObservation> = failures
            .iter()
            .filter(|failure| failure.category != GatewayListenerFailureCategory::ListenerTaskEnded)
            .map(GatewayListenerBindFailure::observation)
            .collect();
        // A transient pair is valid only when that exact protocol half is live
        // again by publication. Failed TCP replacement and failed QUIC rebind
        // keep their replacement error as the active failure (already in
        // `status_observations`) and must not count a recovery. Raw
        // `ListenerTaskEnded` rows stay in `failures` for logs/`bind_failures()`.
        let mut transient_events: Vec<GatewayListenerTransientEvent> = Vec::new();
        for port in listener_task_ended_tcp {
            if live.contains_key(&port) {
                transient_events.push(GatewayListenerTransientEvent {
                    port,
                    protocol: GatewayListenerProtocolHalf::Tcp,
                    category: GatewayListenerFailureCategory::ListenerTaskEnded,
                });
            }
        }
        for port in listener_task_ended_quic {
            if live
                .get(&port)
                .is_some_and(|listener| listener.quic.is_some())
            {
                transient_events.push(GatewayListenerTransientEvent {
                    port,
                    protocol: GatewayListenerProtocolHalf::Quic,
                    category: GatewayListenerFailureCategory::ListenerTaskEnded,
                });
            }
        }

        drop(live);

        ReconcileOutcome {
            failures,
            status_observations,
            transient_events,
            refused_route_ports,
            h3_ports,
            desired_listeners,
            active_listeners,
        }
    }

    /// Drop finished drains so completed handles cannot accumulate for the life
    /// of the process, logging anything they failed with.
    async fn reap_finished_drains(&self) {
        let mut draining = self.draining.lock().await;
        let mut retained = Vec::with_capacity(draining.len());
        for drain in std::mem::take(&mut *draining) {
            if drain.task.is_finished() {
                Self::log_listener_task_outcome(drain.task.await);
            } else {
                retained.push(drain);
            }
        }
        *draining = retained;
    }

    /// Render why a listener stopped serving, awaiting each of its tasks under
    /// the same bounded budget as a class flip. Tasks that have not finished are
    /// returned so the caller can leave them draining instead of blocking.
    async fn describe_ended_listener(listener: LiveListener) -> (String, Vec<ListenerTask>) {
        let mut reasons: Vec<String> = Vec::new();
        let mut pending: Vec<ListenerTask> = Vec::new();
        for mut task in listener.tasks() {
            match tokio::time::timeout(CLASS_FLIP_RETIRE_TIMEOUT, &mut task).await {
                Ok(Ok(Ok(()))) => reasons.push("accept loop exited without error".to_string()),
                Ok(Ok(Err(err))) => reasons.push(format!("{err:#}")),
                Ok(Err(err)) => reasons.push(format!("listener task ended abnormally: {err}")),
                Err(_) => {
                    reasons.push("a sibling listener task is still draining".to_string());
                    pending.push(task);
                }
            }
        }
        (
            format!(
                "the listener stopped serving and is being rebound ({})",
                reasons.join("; ")
            ),
            pending,
        )
    }

    /// Reap a QUIC task that has already ended, leaving the TCP accept loop and
    /// its already-accepted H1/H2 connections untouched.
    ///
    /// Returns the rendered reason so the caller can report the failure against
    /// the QUIC half alone, or `None` when there was nothing to reap. Clearing
    /// the handle and its shutdown sender is what lets [`Self::ensure_quic`]
    /// retry the port: a fresh watch channel is installed with the new task
    /// rather than signalling one whose receiver is gone.
    async fn reap_ended_quic(listener: &mut LiveListener) -> Option<String> {
        // Only ever called for a task `quic_ended()` already observed finished,
        // so this join returns immediately and cannot stall the reconcile pass.
        // Joining rather than dropping the handle is how the task's error or
        // panic payload is recovered instead of being discarded.
        let task = listener.quic.take()?;
        listener.quic_shutdown_tx = None;
        let reason = match task.await {
            Ok(Ok(())) => "the HTTP/3 listener exited without error".to_string(),
            Ok(Err(err)) => format!("{err:#}"),
            Err(err) => format!("the HTTP/3 listener task ended abnormally: {err}"),
        };
        Some(format!(
            "HTTP/3 (QUIC) stopped serving and is being rebound ({reason}); HTTP/1.1 and HTTP/2 \
             keep serving on this port"
        ))
    }

    /// Await a retiring listener task under a bound. `Err(task)` hands the
    /// still-running task back so the caller can defer instead of assuming the
    /// old generation is gone.
    async fn await_listener_task(port: u16, mut task: ListenerTask) -> Result<(), ListenerTask> {
        // `JoinHandle` is `Future + Unpin`, so the borrow keeps the handle
        // usable when the budget expires — the task is deferred, never leaked.
        match tokio::time::timeout(CLASS_FLIP_RETIRE_TIMEOUT, &mut task).await {
            Ok(outcome) => {
                Self::log_listener_task_outcome(outcome);
                Ok(())
            }
            Err(_) => {
                warn!(
                    port,
                    "Gateway API listener did not stop accepting within the retire budget"
                );
                Err(task)
            }
        }
    }

    fn log_listener_task_outcome(
        outcome: Result<Result<(), anyhow::Error>, tokio::task::JoinError>,
    ) {
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(err)) => warn!("Gateway API listener returned an error: {err:#}"),
            Err(err) => warn!("Gateway API listener task ended abnormally: {err}"),
        }
    }

    /// Bind the QUIC socket for a TLS-class listener when HTTP/3 is enabled.
    ///
    /// Returns the failure when the QUIC listener could not be started. The TCP
    /// listener keeps serving H1/H2 in that case and the QUIC bind is retried on
    /// the next reconcile / retry tick; `Alt-Svc` does not advertise HTTP/3 for
    /// the port until the socket exists, so no client is steered at a socket
    /// that is not there.
    ///
    /// `expected_generation` fences a stale reconcile: if a newer config epoch
    /// published while the QUIC bind awaited, the freshly started QUIC task is
    /// stopped immediately so it cannot restore H3 after a newer epoch reserved
    /// the UDP port.
    async fn ensure_quic(
        &self,
        port: u16,
        listener: &mut LiveListener,
        expected_generation: u64,
    ) -> Option<GatewayListenerBindFailure> {
        let http3 = self.http3.as_ref()?;
        if listener.class != GatewayListenerClass::Tls || listener.quic.is_some() {
            return None;
        }
        let Some(tls_config) = self.tls.quic_initial_config() else {
            return Some(GatewayListenerBindFailure::quic(
                port,
                GatewayListenerFailureCategory::FrontendTlsMissing,
                format!(
                    "port {port} has no frontend TLS material for an HTTP/3 listener; HTTP/3 is not \
                     served on this Gateway listener port"
                ),
            ));
        };
        let addr = SocketAddr::new(listener.bind_addr, port);
        let (started_tx, started_rx) = oneshot::channel();
        let (quic_shutdown_tx, quic_shutdown_rx) = watch::channel(false);
        let state = self.state.clone();
        let h3_config = http3.config.clone();
        let tls_policy = http3.tls_policy.clone();
        let options = crate::http3::server::Http3ListenerOptions {
            client_ca_bundle_path: http3.client_ca_bundle_path.clone(),
            client_crls: http3.client_crls.clone(),
            started_tx: Some(started_tx),
            frontend_tls_reload: http3.frontend_tls_reload(),
        };
        let task = tokio::spawn(async move {
            crate::http3::server::start_http3_listener_with_signal(
                addr,
                state,
                quic_shutdown_rx,
                tls_config,
                h3_config,
                &tls_policy,
                options,
            )
            .await
        });
        match started_rx.await {
            Ok(()) => {
                listener.quic = Some(task);
                listener.quic_shutdown_tx = Some(quic_shutdown_tx);
                if self.state.request_epoch.load().config_generation != expected_generation {
                    // A newer epoch published while this bind awaited. Drop the
                    // QUIC half now so a concurrent UDP/DTLS claim from that
                    // epoch can own the port; the next loop iteration applies
                    // the current plan (start again, or leave refused).
                    warn!(
                        port,
                        expected_generation,
                        "Discarding QUIC bind from a stale Gateway listener reconcile"
                    );
                    self.stop_quic(port, listener).await;
                    return None;
                }
                info!(port, "Gateway API HTTP/3 (QUIC) listener started on {addr}");
                None
            }
            Err(_) => {
                let error = match task.await {
                    Ok(Err(err)) => format!("{err:#}"),
                    Ok(Ok(())) => "HTTP/3 listener exited before reporting readiness".to_string(),
                    Err(err) => format!("HTTP/3 listener task panicked: {err}"),
                };
                error!(port, "Gateway API HTTP/3 listener bind failed: {error}");
                Some(GatewayListenerBindFailure::quic(
                    port,
                    GatewayListenerFailureCategory::BindFailed,
                    error,
                ))
            }
        }
    }

    /// Stop and drain only the QUIC half of a live listener.
    ///
    /// The TCP accept loop and already-accepted H1/H2 connections are left
    /// intact. A wedged QUIC task is aborted after the retire budget so it
    /// cannot retain the UDP port against a stream proxy or a later
    /// `ensure_quic`.
    async fn stop_quic(&self, port: u16, listener: &mut LiveListener) {
        if let Some(tx) = listener.quic_shutdown_tx.take() {
            let _ = tx.send(true);
        }
        let Some(mut task) = listener.quic.take() else {
            return;
        };
        match tokio::time::timeout(CLASS_FLIP_RETIRE_TIMEOUT, &mut task).await {
            Ok(outcome) => {
                Self::log_listener_task_outcome(outcome);
                info!(port, "Gateway API HTTP/3 (QUIC) listener stopped");
            }
            Err(_) => {
                warn!(
                    port,
                    "Gateway API HTTP/3 listener did not stop within the retire budget; aborting"
                );
                task.abort();
                Self::log_listener_task_outcome(task.await);
            }
        }
    }

    async fn spawn_listener(
        &self,
        port: u16,
        desired: DesiredGatewayListener,
    ) -> Result<LiveListener, String> {
        let addr = SocketAddr::new(desired.bind_addr, port);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (started_tx, started_rx) = oneshot::channel();
        let state = self.state.clone();
        let tls = self.tls.clone();
        let task = tokio::spawn(async move {
            match desired.class {
                GatewayListenerClass::Plaintext => match desired.mesh_direction {
                    Some(mesh_direction) => {
                        crate::proxy::start_mesh_plaintext_listener_with_signal(
                            addr,
                            state,
                            shutdown_rx,
                            None,
                            Some(mesh_direction),
                            Some(started_tx),
                        )
                        .await
                    }
                    None => {
                        crate::proxy::start_proxy_listener_with_tls_and_signal(
                            addr,
                            state,
                            shutdown_rx,
                            None,
                            Some(started_tx),
                        )
                        .await
                    }
                },
                GatewayListenerClass::Tls => {
                    if let Some(slot) = tls.reload_slot {
                        crate::proxy::start_proxy_listener_with_dynamic_tls_and_signal(
                            addr,
                            state,
                            shutdown_rx,
                            slot,
                            Some(started_tx),
                        )
                        .await
                    } else {
                        crate::proxy::start_proxy_listener_with_tls_and_signal(
                            addr,
                            state,
                            shutdown_rx,
                            tls.static_config,
                            Some(started_tx),
                        )
                        .await
                    }
                }
            }
        });

        // The signal is sent only after every accept socket is bound, and the
        // sender is dropped when the listener returns early — so a closed
        // channel is exactly "bind failed", with the real error in the task.
        match started_rx.await {
            Ok(()) => {
                info!(
                    port,
                    "Gateway API {} listener started on {addr}",
                    desired.class.label()
                );
                Ok(LiveListener {
                    class: desired.class,
                    bind_addr: desired.bind_addr,
                    mesh_direction: desired.mesh_direction,
                    shutdown_tx,
                    tcp: task,
                    quic: None,
                    quic_shutdown_tx: None,
                })
            }
            Err(_) => Err(match task.await {
                Ok(Err(err)) => format!("{err:#}"),
                Ok(Ok(())) => "listener exited before reporting readiness".to_string(),
                Err(err) => format!("listener task panicked: {err}"),
            }),
        }
    }

    /// Close every managed listener and await its drain.
    pub async fn shutdown_all(&self) {
        let listeners: Vec<LiveListener> = {
            let mut live = self.listeners.lock().await;
            std::mem::take(&mut *live).into_values().collect()
        };
        let mut tasks: Vec<ListenerTask> = Vec::new();
        for listener in listeners {
            listener.signal_shutdown();
            tasks.extend(listener.tasks());
        }
        tasks.extend(
            std::mem::take(&mut *self.draining.lock().await)
                .into_iter()
                .map(|drain| drain.task),
        );
        for task in tasks {
            // Both halves are logged: a listener that returned an error and a
            // task that panicked are different faults and neither may be
            // silently dropped.
            Self::log_listener_task_outcome(task.await);
        }
        self.state.publish_gateway_h3_alt_svc(&[]);
    }

    /// Drive the manager for the life of the process.
    ///
    /// The initial reconcile has already run; this loop reconciles on every
    /// subsequent config publication, supervises listener tasks and retries
    /// outstanding bind failures on a slow tick, and shuts every listener down
    /// on the global shutdown signal.
    ///
    /// A bind failure is deliberately **not** fatal, in any mode. A Gateway
    /// listener port is control-plane input (or, for `:80`/`:443`, a port the
    /// container may lack `CAP_NET_BIND_SERVICE` for), so killing the gateway
    /// would take down every healthy listener over one unbindable port. The
    /// failure is loud, surfaced on [`Self::bind_failures`], and retried.
    /// Admission refusals and ordinary OS bind failures stay unreachable
    /// through the intentional single-listener Service remap.
    pub async fn run(
        self: Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), anyhow::Error> {
        // The receiver created in `new()`, before the mode's readiness
        // reconcile. A publication in between is still pending on it.
        let mut revisions = match self.revisions.lock().await.take() {
            Some(revisions) => revisions,
            None => {
                warn!(
                    "Gateway API listener supervisor started twice; subscribing to config \
                     publications again"
                );
                self.state.subscribe_config_revision()
            }
        };
        let mut retry = tokio::time::interval(BIND_RETRY_INTERVAL);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        retry.tick().await; // the first tick completes immediately
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                changed = revisions.changed() => {
                    if changed.is_err() {
                        // The publisher is gone; nothing more can change.
                        break;
                    }
                    self.reconcile().await;
                }
                _ = retry.tick() => {
                    // Reconcile even when the previous pass was healthy. A TCP
                    // or QUIC accept-loop can end after that pass; checking only
                    // an already-populated failure list would leave the first
                    // healthy-to-dead transition invisible forever unless an
                    // unrelated config publication happened to arrive.
                    self.reconcile().await;
                }
            }
        }
        self.shutdown_all().await;
        Ok(())
    }
}

/// How often an unbound Gateway listener port is retried.
const BIND_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a class-flipping listener may take to close its accept sockets
/// before the replacement bind is deferred to the next reconcile. Bounded so a
/// wedged accept loop cannot stall the supervisor, and fail-closed so the two
/// frontend classes never coexist on one port.
const CLASS_FLIP_RETIRE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
mod tests {
    //! Supervision of already-started listener tasks.
    //!
    //! Deliberately inline and minimal: killing a live accept-loop task and
    //! observing the drain queue are private-state behaviors, and exposing an
    //! "abort this listener" or "inspect my drains" API on the production
    //! manager to reach them from `tests/` would be a worse trade.

    use super::*;
    use crate::config::EnvConfig;
    use crate::config::types::GatewayConfig;
    use crate::dns::{DnsCache, DnsConfig};

    fn port_scoped_config(port: u16) -> GatewayConfig {
        let proxy: crate::config::types::Proxy = serde_json::from_value(serde_json::json!({
            "id": "gw-a",
            "hosts": ["app.example.com"],
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 1,
            "listen_port": port,
        }))
        .expect("port-scoped proxy should deserialize");
        let mut config = GatewayConfig {
            proxies: vec![proxy],
            ..GatewayConfig::default()
        };
        config.resolve_dispatch_kind();
        config
    }

    fn test_state(config: GatewayConfig) -> ProxyState {
        let env = EnvConfig {
            proxy_http_port: 0,
            proxy_https_port: 0,
            admin_http_port: 0,
            admin_https_port: 0,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            ..EnvConfig::default()
        };
        ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
            .expect("proxy state")
            .0
    }

    async fn free_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    fn cumulative_series(
        status: &crate::proxy::gateway_listener_status::GatewayListenerStatus,
        protocol: GatewayListenerProtocolHalf,
        category: GatewayListenerFailureCategory,
        recoveries: bool,
    ) -> u64 {
        let cumulative = status.cumulative();
        let series = if recoveries {
            &cumulative.recoveries_total
        } else {
            &cumulative.failures_total
        };
        series
            .iter()
            .find(|entry| entry.protocol == protocol && entry.category == category)
            .map_or(0, |entry| entry.value)
    }

    /// A started listener whose accept-loop task later dies must be reaped,
    /// surfaced as a failure, and rebound — never left in the live map where
    /// the next reconcile would read the port as healthy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_listener_task_is_reaped_surfaced_and_rebound() {
        let port = free_port().await;
        // A locally-owned status handle, never the process-global one: killing
        // a live accept-loop task is private-state behavior (see the module
        // note above), and the published category is the only way to prove the
        // observability surface distinguishes a dead accept loop from a bind
        // refusal.
        let status = Arc::new(crate::proxy::gateway_listener_status::GatewayListenerStatus::new());
        let manager = GatewayListenerManager::new(
            test_state(port_scoped_config(port)),
            std::net::IpAddr::from([127, 0, 0, 1]),
            GatewayListenerTls::default(),
        )
        .with_status(status.clone());
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(manager.active_ports().await, vec![port]);
        assert!(
            !status.snapshot().degraded(),
            "a healthy listener must publish no active failure"
        );

        // Kill the accept loop behind the manager's back, exactly as a panic
        // or an unexpected loop exit would.
        {
            let live = manager.listeners.lock().await;
            live.get(&port).expect("listener").tcp.abort();
        }
        // Let the abort land before reconciling.
        while !manager
            .listeners
            .lock()
            .await
            .get(&port)
            .expect("listener")
            .tcp_ended()
        {
            tokio::task::yield_now().await;
        }

        let failures = manager.reconcile().await;
        assert!(
            failures.iter().any(|failure| failure.port == port),
            "the dead listener must be surfaced as a failure: {failures:?}"
        );
        assert_eq!(
            manager.active_ports().await,
            vec![port],
            "the port must be rebound, not left dead"
        );
        assert!(
            !manager
                .listeners
                .lock()
                .await
                .get(&port)
                .expect("listener")
                .tcp_ended(),
            "the rebound listener must be live"
        );
        // The pass that reaped the dead task rebinded in the same reconcile, so
        // the death is transient: no active failure while the cumulative
        // counters record one onset and one recovery.
        let snapshot = status.snapshot();
        assert_eq!(snapshot.active_failures, 0, "{snapshot:?}");
        assert!(!snapshot.degraded());
        assert_eq!(
            status
                .cumulative()
                .failures_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Tcp
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );
        assert_eq!(
            status
                .cumulative()
                .recoveries_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Tcp
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );

        // A later healthy pass must not double-count the transient death.
        manager.reconcile().await;
        assert!(!status.snapshot().degraded());
        assert_eq!(
            status
                .cumulative()
                .failures_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Tcp
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );
        assert_eq!(
            status
                .cumulative()
                .recoveries_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Tcp
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );
        manager.shutdown_all().await;
    }

    /// A reaped TCP accept loop whose same-pass replacement fails must not be
    /// published as a transient recovery. The death stays in raw
    /// `bind_failures()`, and the failed bind is the durable active failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_listener_task_failed_rebind_is_not_published_as_recovered() {
        let port = free_port().await;
        let status = Arc::new(crate::proxy::gateway_listener_status::GatewayListenerStatus::new());
        let manager = GatewayListenerManager::new(
            test_state(port_scoped_config(port)),
            std::net::IpAddr::from([127, 0, 0, 1]),
            GatewayListenerTls::default(),
        )
        .with_status(status.clone());
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(manager.active_ports().await, vec![port]);

        {
            let live = manager.listeners.lock().await;
            live.get(&port).expect("listener").tcp.abort();
        }
        while !manager
            .listeners
            .lock()
            .await
            .get(&port)
            .expect("listener")
            .tcp_ended()
        {
            tokio::task::yield_now().await;
        }

        let occupied = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                    Ok(listener) => break listener,
                    Err(_) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the reaped listener never released {port}"
                        );
                        tokio::task::yield_now().await;
                    }
                }
            }
        };

        let failures = manager.reconcile().await;
        assert!(
            failures.iter().any(|failure| {
                failure.port == port
                    && failure.protocol == GatewayListenerProtocolHalf::Tcp
                    && failure.category == GatewayListenerFailureCategory::ListenerTaskEnded
            }),
            "raw bind_failures must still report the death: {failures:?}"
        );
        assert!(
            failures.iter().any(|failure| {
                failure.port == port
                    && failure.protocol == GatewayListenerProtocolHalf::Tcp
                    && failure.category == GatewayListenerFailureCategory::BindFailed
            }),
            "raw bind_failures must still report the failed replacement: {failures:?}"
        );
        assert!(
            manager.active_ports().await.is_empty(),
            "the occupied port must not be rebound"
        );

        let snapshot = status.snapshot();
        assert!(snapshot.degraded(), "{snapshot:?}");
        assert_eq!(snapshot.active_failures, 1, "{snapshot:?}");
        assert_eq!(snapshot.failures[0].port, port);
        assert_eq!(
            snapshot.failures[0].category,
            GatewayListenerFailureCategory::BindFailed
        );
        assert_eq!(
            cumulative_series(
                &status,
                GatewayListenerProtocolHalf::Tcp,
                GatewayListenerFailureCategory::ListenerTaskEnded,
                false,
            ),
            0,
            "a failed replacement must not count a transient ListenerTaskEnded onset"
        );
        assert_eq!(
            cumulative_series(
                &status,
                GatewayListenerProtocolHalf::Tcp,
                GatewayListenerFailureCategory::ListenerTaskEnded,
                true,
            ),
            0,
            "a failed replacement must not claim a ListenerTaskEnded recovery"
        );
        assert_eq!(
            cumulative_series(
                &status,
                GatewayListenerProtocolHalf::Tcp,
                GatewayListenerFailureCategory::BindFailed,
                false,
            ),
            1
        );

        drop(occupied);
        manager.shutdown_all().await;
    }

    /// A withdrawn listener's drain handle is reaped once it finishes, so
    /// completed handles cannot accumulate until process exit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn finished_drain_handles_do_not_accumulate() {
        let port = free_port().await;
        let state = test_state(port_scoped_config(port));
        let manager = GatewayListenerManager::new(
            state.clone(),
            std::net::IpAddr::from([127, 0, 0, 1]),
            GatewayListenerTls::default(),
        );
        manager.reconcile().await;
        assert_eq!(manager.active_ports().await, vec![port]);

        // Withdraw the listener; its accept loop drains asynchronously.
        state.update_config(GatewayConfig::default());
        manager.reconcile().await;
        assert!(manager.active_ports().await.is_empty());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            manager.reconcile().await;
            if manager.draining.lock().await.is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a finished drain handle was never reaped"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        manager.shutdown_all().await;
    }

    /// A retiring task that outlives one reconcile must keep ownership of its
    /// port visible to every later pass. Rebinding while it may still hold an
    /// SO_REUSEPORT socket would let plaintext and TLS accept loops coexist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pending_retirement_blocks_rebind_across_reconcile_passes() {
        let port = free_port().await;
        let manager = GatewayListenerManager::new(
            test_state(port_scoped_config(port)),
            std::net::IpAddr::from([127, 0, 0, 1]),
            GatewayListenerTls::default(),
        );
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(())
        });
        manager
            .draining
            .lock()
            .await
            .push(DrainingListenerTask { port, task });

        for _ in 0..2 {
            let failures = manager.reconcile().await;
            assert!(
                failures.iter().any(|failure| failure.port == port),
                "the deferred port must stay operator-visible: {failures:?}"
            );
            assert!(
                manager.active_ports().await.is_empty(),
                "no replacement may bind while an earlier accept task can still own the port"
            );
        }

        let mut draining = manager.draining.lock().await;
        let drain = draining.pop().expect("pending drain");
        drop(draining);
        drain.task.abort();
        let _ = drain.task.await;
        manager.shutdown_all().await;
    }

    /// A QUIC bind that finishes after a newer config generation published must
    /// not leave HTTP/3 up when that newer epoch reserved the UDP port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_quic_bind_is_fenced_after_udp_claim() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let port = free_port().await;
        let https = port_scoped_config(port);
        let mut tls_https = https.clone();
        tls_https
            .http_tls_listen_ports
            .insert((crate::config::types::default_namespace(), port));
        let state = test_state(tls_https.clone());
        let manager = tls_h3_manager(state.clone());
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(manager.active_http3_ports().await, vec![port]);
        let stale_generation = state.request_epoch.load().config_generation;

        let mut with_udp = tls_https;
        let udp: crate::config::types::Proxy = serde_json::from_value(serde_json::json!({
            "id": "udp-stream",
            "backend_scheme": "udp",
            "backend_host": "127.0.0.1",
            "backend_port": 1,
            "listen_port": port,
        }))
        .expect("udp proxy");
        with_udp.proxies.push(udp);
        with_udp.resolve_dispatch_kind();
        assert!(state.update_config(with_udp).applied());

        // Simulate a late ensure_quic from the pre-UDP generation.
        {
            let mut live = manager.listeners.lock().await;
            let listener = live.get_mut(&port).expect("listener");
            if let Some(tx) = listener.quic_shutdown_tx.take() {
                let _ = tx.send(true);
            }
            if let Some(task) = listener.quic.take() {
                task.abort();
                let _ = task.await;
            }
            let _ = manager.ensure_quic(port, listener, stale_generation).await;
            assert!(
                listener.quic.is_none(),
                "stale generation must not restore QUIC after a newer UDP claim"
            );
        }

        let failures = manager.reconcile().await;
        assert!(
            failures.iter().any(|failure| {
                failure.port == port
                    && failure.protocol == GatewayListenerProtocolHalf::Quic
                    && failure.category == GatewayListenerFailureCategory::UdpStreamCollision
            }),
            "current epoch must keep QUIC refused: {failures:?}"
        );
        assert!(manager.active_http3_ports().await.is_empty());
        manager.shutdown_all().await;
    }

    /// A TLS-class Gateway listener manager with HTTP/3 enabled, so a port that
    /// is in `http_tls_listen_ports` binds both a TCP accept loop and a QUIC
    /// listener.
    fn tls_h3_manager(state: ProxyState) -> GatewayListenerManager {
        GatewayListenerManager::new(
            state,
            std::net::IpAddr::from([127, 0, 0, 1]),
            GatewayListenerTls {
                static_config: Some(test_self_signed_server_config()),
                reload_slot: None,
            },
        )
        .with_http3(GatewayListenerHttp3 {
            config: crate::http3::config::Http3ServerConfig::default(),
            tls_policy: crate::tls::TlsPolicy {
                protocol_versions: vec![&rustls::version::TLS13, &rustls::version::TLS12],
                crypto_provider: std::sync::Arc::new(rustls::crypto::ring::default_provider()),
                prefer_server_cipher_order: true,
                session_cache_size: 1024,
                early_data_max_size: 0,
            },
            client_ca_bundle_path: None,
            client_crls: std::sync::Arc::new(Vec::new()),
            tls_slot: None,
            tls_revision_rx: None,
        })
    }

    /// A QUIC task that dies while the TCP accept loop is still healthy is a
    /// HTTP/3-only outage. It must be joined, reported against the QUIC half,
    /// and retried — never allowed to retire the healthy TCP listener, which
    /// would take H1/H2 offline and falsely report the port's TCP half down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_quic_task_is_reaped_on_its_own_half_without_stopping_tcp() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let port = free_port().await;
        let mut config = port_scoped_config(port);
        config
            .http_tls_listen_ports
            .insert((crate::config::types::default_namespace(), port));
        let status = Arc::new(crate::proxy::gateway_listener_status::GatewayListenerStatus::new());
        let manager = tls_h3_manager(test_state(config)).with_status(status.clone());
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(manager.active_ports().await, vec![port]);
        assert_eq!(manager.active_http3_ports().await, vec![port]);
        assert!(!status.snapshot().degraded());

        // Kill only the QUIC task behind the manager's back, exactly as a panic
        // or an unexpected endpoint exit would. The TCP accept loop is
        // untouched; its task id is the identity the rebind must preserve.
        let tcp_id = {
            let live = manager.listeners.lock().await;
            let listener = live.get(&port).expect("listener");
            listener.quic.as_ref().expect("quic task").abort();
            listener.tcp.id()
        };
        while !manager
            .listeners
            .lock()
            .await
            .get(&port)
            .expect("listener")
            .quic_ended()
        {
            tokio::task::yield_now().await;
        }

        let failures = manager.reconcile().await;
        assert!(
            failures.iter().any(|failure| {
                failure.port == port
                    && failure.protocol == GatewayListenerProtocolHalf::Quic
                    && failure.category == GatewayListenerFailureCategory::ListenerTaskEnded
            }),
            "the dead QUIC task must be surfaced on the QUIC half: {failures:?}"
        );
        assert!(
            failures
                .iter()
                .all(|failure| failure.protocol == GatewayListenerProtocolHalf::Quic),
            "a healthy TCP accept loop must never be reported as failed: {failures:?}"
        );

        let live = manager.listeners.lock().await;
        let listener = live.get(&port).expect("listener must not be retired");
        assert!(
            !listener.tcp_ended(),
            "the TCP accept loop must still be serving H1/H2"
        );
        assert_eq!(
            listener.tcp.id(),
            tcp_id,
            "the healthy TCP accept loop must be the original task, not a rebind"
        );
        drop(live);

        // The rebind does not leave an active failure: the death is transient on
        // the QUIC half only, while the healthy TCP half stays out of the
        // snapshot entirely.
        let snapshot = status.snapshot();
        assert_eq!(snapshot.active_failures, 0, "{snapshot:?}");
        assert!(!snapshot.degraded());
        assert!(
            snapshot.failures.is_empty(),
            "the healthy TCP half must not appear in the published status: {snapshot:?}"
        );
        assert_eq!(
            status
                .cumulative()
                .failures_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Quic
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );
        assert_eq!(
            status
                .cumulative()
                .recoveries_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Quic
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );

        // Clearing the handle lets the existing `ensure_quic` path retry the
        // port. That retry can lose a race with the aborted endpoint's socket
        // close, so recovery is asserted across retry passes rather than
        // pinned to the first one — what matters is that HTTP/3 comes back
        // without a restart and the status stays healthy.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            manager.reconcile().await;
            if !status.snapshot().degraded() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the QUIC half never rebound: {:?}",
                status.snapshot()
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_eq!(manager.active_http3_ports().await, vec![port]);
        assert_eq!(manager.active_ports().await, vec![port]);
        // The death is counted exactly once however many retries the rebind
        // took: a still-failing retry ages its entry instead of re-counting an
        // onset, so its recovery is counted once too.
        assert_eq!(
            status
                .cumulative()
                .failures_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Quic
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );
        assert_eq!(
            status
                .cumulative()
                .recoveries_total
                .iter()
                .find(|series| {
                    series.protocol == GatewayListenerProtocolHalf::Quic
                        && series.category == GatewayListenerFailureCategory::ListenerTaskEnded
                })
                .map(|series| series.value),
            Some(1)
        );
        manager.shutdown_all().await;
    }

    /// A reaped QUIC task whose same-pass rebind fails must not be published as
    /// a transient recovery. TCP stays up; the failed QUIC bind is the durable
    /// active failure, and raw `bind_failures()` still reports the death.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_quic_task_failed_rebind_is_not_published_as_recovered() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let port = free_port().await;
        let mut config = port_scoped_config(port);
        config
            .http_tls_listen_ports
            .insert((crate::config::types::default_namespace(), port));
        let status = Arc::new(crate::proxy::gateway_listener_status::GatewayListenerStatus::new());
        let manager = tls_h3_manager(test_state(config)).with_status(status.clone());
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(manager.active_ports().await, vec![port]);
        assert_eq!(manager.active_http3_ports().await, vec![port]);

        let tcp_id = {
            let live = manager.listeners.lock().await;
            let listener = live.get(&port).expect("listener");
            listener.quic.as_ref().expect("quic task").abort();
            listener.tcp.id()
        };
        while !manager
            .listeners
            .lock()
            .await
            .get(&port)
            .expect("listener")
            .quic_ended()
        {
            tokio::task::yield_now().await;
        }

        let occupied = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match std::net::UdpSocket::bind(("127.0.0.1", port)) {
                    Ok(socket) => break socket,
                    Err(_) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the reaped QUIC listener never released {port}"
                        );
                        tokio::task::yield_now().await;
                    }
                }
            }
        };

        let failures = manager.reconcile().await;
        assert!(
            failures.iter().any(|failure| {
                failure.port == port
                    && failure.protocol == GatewayListenerProtocolHalf::Quic
                    && failure.category == GatewayListenerFailureCategory::ListenerTaskEnded
            }),
            "raw bind_failures must still report the QUIC death: {failures:?}"
        );
        assert!(
            failures.iter().any(|failure| {
                failure.port == port
                    && failure.protocol == GatewayListenerProtocolHalf::Quic
                    && failure.category == GatewayListenerFailureCategory::BindFailed
            }),
            "raw bind_failures must still report the failed QUIC rebind: {failures:?}"
        );
        assert!(
            failures
                .iter()
                .all(|failure| failure.protocol == GatewayListenerProtocolHalf::Quic),
            "the healthy TCP half must not be reported as failed: {failures:?}"
        );
        assert_eq!(manager.active_ports().await, vec![port]);
        assert!(manager.active_http3_ports().await.is_empty());

        let live = manager.listeners.lock().await;
        let listener = live.get(&port).expect("listener must not be retired");
        assert!(!listener.tcp_ended());
        assert_eq!(listener.tcp.id(), tcp_id);
        assert!(listener.quic.is_none());
        drop(live);

        let snapshot = status.snapshot();
        assert!(snapshot.degraded(), "{snapshot:?}");
        assert_eq!(snapshot.active_failures, 1, "{snapshot:?}");
        assert_eq!(snapshot.failures[0].port, port);
        assert_eq!(
            snapshot.failures[0].protocol,
            GatewayListenerProtocolHalf::Quic
        );
        assert_eq!(
            snapshot.failures[0].category,
            GatewayListenerFailureCategory::BindFailed
        );
        assert_eq!(
            cumulative_series(
                &status,
                GatewayListenerProtocolHalf::Quic,
                GatewayListenerFailureCategory::ListenerTaskEnded,
                false,
            ),
            0,
            "a failed QUIC rebind must not count a transient ListenerTaskEnded onset"
        );
        assert_eq!(
            cumulative_series(
                &status,
                GatewayListenerProtocolHalf::Quic,
                GatewayListenerFailureCategory::ListenerTaskEnded,
                true,
            ),
            0,
            "a failed QUIC rebind must not claim a ListenerTaskEnded recovery"
        );
        assert_eq!(
            cumulative_series(
                &status,
                GatewayListenerProtocolHalf::Quic,
                GatewayListenerFailureCategory::BindFailed,
                false,
            ),
            1
        );

        drop(occupied);
        manager.shutdown_all().await;
    }

    fn test_self_signed_server_config() -> std::sync::Arc<rustls::ServerConfig> {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["app.example.com".to_string()]).expect("params");
        let cert = params.self_signed(&key_pair).expect("self-sign");
        let cert_pem = cert.pem();
        let mut cert_reader = cert_pem.as_bytes();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(Result::ok)
            .collect();
        let key_pem = key_pair.serialize_pem();
        let mut key_reader = key_pem.as_bytes();
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .expect("read key")
            .expect("key present");
        std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("server config"),
        )
    }

    fn config_with_dedicated_bind(port: u16, bind: IpAddr) -> GatewayConfig {
        let mut config = port_scoped_config(port);
        let mut mesh = crate::modes::mesh::config::MeshConfig::default();
        mesh.sidecar_ingress_bind_overrides.insert(port, bind);
        config.mesh = Some(Box::new(mesh));
        config
    }

    fn routable_dedicated_bind_config(
        frontend_port: u16,
        backend_port: u16,
        bind: IpAddr,
    ) -> GatewayConfig {
        let mut config = config_with_dedicated_bind(frontend_port, bind);
        let proxy = config.proxies.first_mut().expect("proxy");
        proxy.id = format!(
            "{}default-app-{frontend_port}",
            crate::modes::mesh::MESH_INGRESS_BIND_PROXY_ID_PREFIX
        );
        proxy.listen_path = Some("/".to_string());
        proxy.backend_port = backend_port;
        config
    }

    /// A dedicated Sidecar ingress bind address change must retire the old
    /// socket and rebind — port/class alone are not enough restart identity.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bind_address_change_restarts_live_listener() {
        let port = free_port().await;
        let first = IpAddr::from([127, 0, 0, 1]);
        let second = IpAddr::from([127, 0, 0, 2]);
        let state = test_state(config_with_dedicated_bind(port, first));
        let manager = GatewayListenerManager::new(
            state.clone(),
            // Distinct default so the override is visibly ownership, not the
            // process-wide proxy bind.
            IpAddr::from([0, 0, 0, 0]),
            GatewayListenerTls::default(),
        );
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(manager.active_binds().await, vec![(port, first)]);

        state.update_config(config_with_dedicated_bind(port, second));
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(
            manager.active_binds().await,
            vec![(port, second)],
            "bind-address drift must rebind the live Gateway listener"
        );
        manager.shutdown_all().await;
    }

    /// The dedicated HTTP bind is an inbound mesh listener, not merely a
    /// loopback socket. A live request must survive direction-scoped routing
    /// and reach the configured local application backend.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dedicated_sidecar_http_bind_serves_live_inbound_route() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend.local_addr().expect("backend addr").port();
        let backend_task = tokio::spawn(async move {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), backend.accept())
                    .await
                    .expect("backend accept timeout")
                    .expect("backend accept");
            let mut request = [0u8; 4096];
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut request))
                    .await
                    .expect("backend read timeout")
                    .expect("backend read");
            assert!(
                String::from_utf8_lossy(&request[..read]).contains("GET / HTTP/1.1"),
                "dedicated bind must forward the HTTP request"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\ndedicated-ok",
                )
                .await
                .expect("backend response");
        });

        let frontend_port = free_port().await;
        let bind = IpAddr::from([127, 0, 0, 1]);
        let manager = GatewayListenerManager::new(
            test_state(routable_dedicated_bind_config(
                frontend_port,
                backend_port,
                bind,
            )),
            IpAddr::from([0, 0, 0, 0]),
            GatewayListenerTls::default(),
        );
        assert!(manager.reconcile().await.is_empty());

        let mut client = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect((bind, frontend_port)),
        )
        .await
        .expect("dedicated bind connect timeout")
        .expect("connect dedicated bind");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut response),
        )
        .await
        .expect("dedicated bind response timeout")
        .expect("read response");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("dedicated-ok"), "{response}");

        backend_task.await.expect("backend task");
        manager.shutdown_all().await;
    }

    /// An OS bind failure for a dedicated Sidecar ingress listener must refuse
    /// route admission. Leaving it eligible would let the single-listener
    /// Service remap serve a loopback-only route on the process-global frontend.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dedicated_bind_failure_refuses_process_global_remap() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("occupy loopback port");
        let port = occupied.local_addr().expect("occupied addr").port();
        let state = test_state(config_with_dedicated_bind(
            port,
            IpAddr::from([127, 0, 0, 1]),
        ));
        let manager = GatewayListenerManager::new(
            state.clone(),
            IpAddr::from([0, 0, 0, 0]),
            GatewayListenerTls::default(),
        );

        let failures = manager.reconcile().await;
        assert!(
            failures.iter().any(|failure| failure.port == port),
            "occupied dedicated bind must be surfaced: {failures:?}"
        );
        assert!(
            state
                .find_proxy_on_frontend_for_test(Some("app.example.com"), "/api", Some(0), false,)
                .is_none(),
            "dedicated bind failure must not remap onto a process-global frontend"
        );

        drop(occupied);
        manager.shutdown_all().await;
    }

    /// Dedicated Sidecar ingress ownership on a process-global same-class
    /// frontend port must refuse, never absorb into `already_served`.
    #[test]
    fn dedicated_bind_on_existing_frontend_is_refused_not_already_served() {
        let port = 18080;
        let config = config_with_dedicated_bind(port, IpAddr::from([127, 0, 0, 1]));
        let mut existing = BTreeMap::new();
        existing.insert(port, GatewayListenerClass::Plaintext);
        let plan = GatewayListenerPlan::from_config(
            &config,
            &std::collections::HashSet::new(),
            &existing,
            IpAddr::from([0, 0, 0, 0]),
            false,
        );
        assert!(
            !plan.already_served.contains_key(&port),
            "dedicated bind must not be classified as already served: {:?}",
            plan.already_served
        );
        assert!(
            !plan.ports.contains_key(&port),
            "dedicated bind collision must not schedule a dynamic bind: {:?}",
            plan.ports
        );
        let reason = plan.refused.get(&port).expect("refusal");
        assert_eq!(
            reason.category,
            GatewayListenerFailureCategory::DedicatedBindConflict
        );
        assert!(
            reason.message.contains("dedicated Sidecar ingress bind"),
            "refusal must name the dedicated-bind collision: {}",
            reason.message
        );
    }
}
