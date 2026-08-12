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
//! - **Update.** A port whose TLS class changed is closed, **awaited**, and
//!   only then rebound: with `FERRUM_ACCEPT_THREADS > 1` both generations bind
//!   the same port through `SO_REUSEPORT`, so an overlap would let the kernel
//!   hand new connections to the retiring plaintext (or TLS) accept loop.
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
//!   is never mistaken for a healthy port.
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
//! socket. Every other collision is skipped fail-closed:
//!
//! - an HTTP listener on the global HTTPS port (or the reverse),
//! - admin HTTP/HTTPS ports and the CP gRPC port,
//! - any port claimed by a TCP/TLS stream proxy in the same config, and
//! - any port two HTTP-family proxies claim with different TLS classes.
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
//! Service remap.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, oneshot, watch};
use tracing::{error, info, warn};

use crate::config::types::{DispatchKind, GatewayConfig};
use crate::proxy::ProxyState;

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

/// The set of Gateway API listener ports a config wants bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayListenerPlan {
    pub ports: BTreeMap<u16, GatewayListenerClass>,
    /// Desired ports already served by a process-global proxy frontend of the
    /// same class. No dynamic bind and no failure are needed for these.
    pub already_served: BTreeMap<u16, GatewayListenerClass>,
    /// Ports the config asked for that this process refuses to bind, with the
    /// reason. Surfaced rather than silently dropped.
    pub refused: BTreeMap<u16, String>,
}

impl GatewayListenerPlan {
    /// Derive the desired listener set from a published config.
    ///
    /// `reserved` is [`ProxyState::reserved_gateway_ports`] — the effective
    /// reservation for *this* process, not `EnvConfig` alone, so a pre-bound
    /// in-process harness socket is honored too.
    ///
    /// `http3_enabled` makes TLS-class listeners reserve their QUIC UDP port in
    /// addition to the HTTP TCP port.
    pub fn from_config(
        config: &GatewayConfig,
        reserved: &std::collections::HashSet<u16>,
        existing_frontends: &BTreeMap<u16, GatewayListenerClass>,
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

        let mut ports: BTreeMap<u16, GatewayListenerClass> = BTreeMap::new();
        let mut already_served: BTreeMap<u16, GatewayListenerClass> = BTreeMap::new();
        let mut refused: BTreeMap<u16, String> = BTreeMap::new();
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
            if let Some(existing) = existing_frontends.get(&port) {
                if *existing == class {
                    already_served.insert(port, class);
                } else {
                    refused.entry(port).or_insert_with(|| {
                        format!(
                            "port {port} is already owned by a process-global {} proxy \
                             listener, but this Gateway listener requires {}; the Gateway \
                             listener is not served",
                            existing.label(),
                            class.label()
                        )
                    });
                }
                continue;
            }
            // `reserved_gateway_ports()` covers the admin and CP gRPC
            // listeners, the mesh UDP capture socket, and the process-global
            // proxy ports this gateway did not adopt as a same-class frontend
            // above — name the set rather than guessing which member it was.
            if reserved.contains(&port) {
                refused.entry(port).or_insert_with(|| {
                    format!(
                        "port {port} is reserved by another Ferrum listener \
                         (proxy/admin/control-plane/capture); the Gateway listener is not bound"
                    )
                });
                continue;
            }
            if tcp_stream_ports.contains(&port) {
                refused.entry(port).or_insert_with(|| {
                    format!(
                        "port {port} is claimed by a TCP/TLS stream proxy in the same config; \
                         the HTTP-family Gateway listener is not bound"
                    )
                });
                continue;
            }
            if http3_enabled
                && class == GatewayListenerClass::Tls
                && udp_stream_ports.contains(&port)
            {
                refused.entry(port).or_insert_with(|| {
                    format!(
                        "port {port} is claimed by a UDP/DTLS stream proxy in the same config; \
                         the TLS-class Gateway listener's HTTP/3 socket is not bound"
                    )
                });
                continue;
            }
            if let Some(existing) = ports.insert(port, class)
                && existing != class
            {
                // One socket cannot be both plaintext and TLS. The Gateway API
                // translator refuses this at admission, so reaching it means a
                // hand-authored config: refuse the port outright rather than
                // letting whichever proxy happened to sort first decide the
                // socket's protocol for the other.
                refused.entry(port).or_insert_with(|| {
                    format!(
                        "port {port} is claimed as both plaintext and TLS by HTTP-family proxies \
                         in this config; one socket cannot serve both, so the listener is not bound"
                    )
                });
            }
        }
        // Every refusal reason wins over any class this port also resolved to.
        ports.retain(|port, _| !refused.contains_key(port));
        already_served.retain(|port, _| !refused.contains_key(port));
        Self {
            ports,
            already_served,
            refused,
        }
    }
}

/// A refusal or bind failure for one Gateway listener port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GatewayListenerBindFailure {
    pub port: u16,
    pub error: String,
}

type ListenerTask = tokio::task::JoinHandle<Result<(), anyhow::Error>>;

struct DrainingListenerTask {
    port: u16,
    task: ListenerTask,
}

struct LiveListener {
    class: GatewayListenerClass,
    shutdown_tx: watch::Sender<bool>,
    /// The TCP accept-loop task. Returns once every accept socket is closed;
    /// accepted connections drain in their own tasks.
    tcp: ListenerTask,
    /// The QUIC listener task on the same port, when HTTP/3 is enabled and this
    /// is a TLS-class listener.
    quic: Option<ListenerTask>,
}

impl LiveListener {
    /// Whether either task has ended. A started listener whose accept loop has
    /// exited is not a healthy port, however it exited.
    fn is_finished(&self) -> bool {
        self.tcp.is_finished() || self.quic.as_ref().is_some_and(ListenerTask::is_finished)
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
        }
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
    // Same bin-target caveat as `active_ports`: the observability seam is
    // consumed by `tests/` and external library callers, not by the binary.
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
            let (failures, refused_route_ports, h3_ports) =
                self.reconcile_generation(&expected).await;
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
            return failures;
        }
    }

    async fn reconcile_generation(
        &self,
        expected: &crate::request_epoch::RequestEpoch,
    ) -> (Vec<GatewayListenerBindFailure>, BTreeSet<u16>, Vec<u16>) {
        let config = expected.config();
        let plan = GatewayListenerPlan::from_config(
            config,
            self.state.reserved_gateway_ports.as_ref(),
            &self.existing_frontends,
            self.http3.is_some(),
        );
        let mut failures: Vec<GatewayListenerBindFailure> = plan
            .refused
            .iter()
            .map(|(port, error)| GatewayListenerBindFailure {
                port: *port,
                error: error.clone(),
            })
            .collect();
        for failure in &failures {
            warn!(
                port = failure.port,
                "Gateway API listener refused: {}", failure.error
            );
        }

        self.reap_finished_drains().await;

        let mut live = self.listeners.lock().await;

        // Reap listeners whose task ended after startup. A finished accept loop
        // means the port is no longer served; leaving the entry in place would
        // make every later reconcile treat it as healthy and never rebind.
        let dead: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| listener.is_finished().then_some(*port))
            .collect();
        for port in dead {
            if let Some(listener) = live.remove(&port) {
                let _ = listener.shutdown_tx.send(true);
                let (error, pending) = Self::describe_ended_listener(listener).await;
                if !pending.is_empty() {
                    self.draining.lock().await.extend(
                        pending
                            .into_iter()
                            .map(|task| DrainingListenerTask { port, task }),
                    );
                }
                error!(port, "Gateway API listener ended unexpectedly: {error}");
                failures.push(GatewayListenerBindFailure { port, error });
            }
        }

        // Close listeners whose port left the config, and rebind ports whose
        // TLS class changed — a socket is plaintext or TLS, never both.
        let stale: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| {
                (plan.ports.get(port) != Some(&listener.class)).then_some(*port)
            })
            .collect();
        let stale_route_ports: BTreeSet<u16> = stale.iter().copied().collect();
        // Ports whose retiring generation has not finished closing its accept
        // sockets. Rebinding them in this pass could co-serve two classes, so
        // they are left unbound and retried.
        let mut defer_rebind: BTreeSet<u16> = BTreeSet::new();
        for port in stale {
            let Some(listener) = live.remove(&port) else {
                continue;
            };
            let class_flip = plan.ports.contains_key(&port);
            info!(
                port,
                "Closing Gateway API {} listener — {}",
                listener.class.label(),
                if class_flip {
                    "its frontend class changed"
                } else {
                    "no longer declared by config"
                }
            );
            let _ = listener.shutdown_tx.send(true);
            if class_flip {
                // The replacement binds the same port. With
                // `FERRUM_ACCEPT_THREADS > 1` both generations use
                // SO_REUSEPORT, so until every old accept socket is closed the
                // kernel could hand new connections to the retiring class.
                // Await the accept-loop task — accepted connections keep
                // draining independently through their cloned shutdown
                // receivers.
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
                    // the new class beside accept loops that are still up.
                    let error = format!(
                        "port {port} did not finish retiring its previous frontend class within \
                         {}s; the replacement listener is deferred to the next reconcile",
                        CLASS_FLIP_RETIRE_TIMEOUT.as_secs()
                    );
                    warn!(port, "Gateway API listener class flip deferred: {error}");
                    failures.push(GatewayListenerBindFailure { port, error });
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
        // the process-global proxy.
        let mut refused_route_ports: BTreeSet<u16> = plan.refused.keys().copied().collect();
        refused_route_ports.extend(stale_route_ports);
        refused_route_ports.extend(retiring_ports.iter().copied());

        for (port, class) in &plan.ports {
            if defer_rebind.contains(port) || retiring_ports.contains(port) {
                refused_route_ports.insert(*port);
                if !failures.iter().any(|failure| failure.port == *port) {
                    let error = format!(
                        "port {port} still has a retiring Gateway listener task; the replacement \
                         listener remains deferred until every previous accept socket closes"
                    );
                    warn!(
                        port = *port,
                        "Gateway API listener rebind deferred: {error}"
                    );
                    failures.push(GatewayListenerBindFailure { port: *port, error });
                }
                continue;
            }
            if let Some(listener) = live.get_mut(port) {
                // Retry a QUIC socket that did not come up with its TCP peer.
                if let Some(error) = self.ensure_quic(*port, listener).await {
                    failures.push(GatewayListenerBindFailure { port: *port, error });
                }
                continue;
            }
            if *class == GatewayListenerClass::Tls && !self.tls.is_configured() {
                let error = format!(
                    "port {port} is a TLS-terminating Gateway listener but frontend TLS is not \
                     configured on this gateway; the listener is not bound"
                );
                warn!(port = *port, "Gateway API listener refused: {error}");
                failures.push(GatewayListenerBindFailure { port: *port, error });
                refused_route_ports.insert(*port);
                continue;
            }
            match self.spawn_listener(*port, *class).await {
                Ok(mut listener) => {
                    if let Some(error) = self.ensure_quic(*port, &mut listener).await {
                        failures.push(GatewayListenerBindFailure { port: *port, error });
                    }
                    live.insert(*port, listener);
                }
                Err(error) => {
                    error!(port = *port, "Gateway API listener bind failed: {error}");
                    failures.push(GatewayListenerBindFailure { port: *port, error });
                    refused_route_ports.insert(*port);
                }
            }
        }

        let h3_ports: Vec<u16> = live
            .iter()
            .filter_map(|(port, listener)| listener.quic.is_some().then_some(*port))
            .collect();
        drop(live);

        (failures, refused_route_ports, h3_ports)
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
    /// Returns the failure reason when the QUIC listener could not be started.
    /// The TCP listener keeps serving H1/H2 in that case and the QUIC bind is
    /// retried on the next reconcile / retry tick; `Alt-Svc` does not advertise
    /// HTTP/3 for the port until the socket exists, so no client is steered at
    /// a socket that is not there.
    async fn ensure_quic(&self, port: u16, listener: &mut LiveListener) -> Option<String> {
        let http3 = self.http3.as_ref()?;
        if listener.class != GatewayListenerClass::Tls || listener.quic.is_some() {
            return None;
        }
        let Some(tls_config) = self.tls.quic_initial_config() else {
            return Some(format!(
                "port {port} has no frontend TLS material for an HTTP/3 listener; HTTP/3 is not \
                 served on this Gateway listener port"
            ));
        };
        let addr = SocketAddr::new(self.bind_addr, port);
        let (started_tx, started_rx) = oneshot::channel();
        let state = self.state.clone();
        let shutdown_rx = listener.shutdown_tx.subscribe();
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
                shutdown_rx,
                tls_config,
                h3_config,
                &tls_policy,
                options,
            )
            .await
        });
        match started_rx.await {
            Ok(()) => {
                info!(port, "Gateway API HTTP/3 (QUIC) listener started on {addr}");
                listener.quic = Some(task);
                None
            }
            Err(_) => {
                let error = match task.await {
                    Ok(Err(err)) => format!("{err:#}"),
                    Ok(Ok(())) => "HTTP/3 listener exited before reporting readiness".to_string(),
                    Err(err) => format!("HTTP/3 listener task panicked: {err}"),
                };
                error!(port, "Gateway API HTTP/3 listener bind failed: {error}");
                Some(error)
            }
        }
    }

    async fn spawn_listener(
        &self,
        port: u16,
        class: GatewayListenerClass,
    ) -> Result<LiveListener, String> {
        let addr = SocketAddr::new(self.bind_addr, port);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (started_tx, started_rx) = oneshot::channel();
        let state = self.state.clone();
        let tls = self.tls.clone();
        let task = tokio::spawn(async move {
            match class {
                GatewayListenerClass::Plaintext => {
                    crate::proxy::start_proxy_listener_with_tls_and_signal(
                        addr,
                        state,
                        shutdown_rx,
                        None,
                        Some(started_tx),
                    )
                    .await
                }
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
                    class.label()
                );
                Ok(LiveListener {
                    class,
                    shutdown_tx,
                    tcp: task,
                    quic: None,
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
            let _ = listener.shutdown_tx.send(true);
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

    /// A started listener whose accept-loop task later dies must be reaped,
    /// surfaced as a failure, and rebound — never left in the live map where
    /// the next reconcile would read the port as healthy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_listener_task_is_reaped_surfaced_and_rebound() {
        let port = free_port().await;
        let manager = GatewayListenerManager::new(
            test_state(port_scoped_config(port)),
            std::net::IpAddr::from([127, 0, 0, 1]),
            GatewayListenerTls::default(),
        );
        assert!(manager.reconcile().await.is_empty());
        assert_eq!(manager.active_ports().await, vec![port]);

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
            .is_finished()
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
                .is_finished(),
            "the rebound listener must be live"
        );
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
}
