//! Receiver-side admission fence for live HBONE tunnels (issue #5042, step 1).
//!
//! An HBONE CONNECT is admitted exactly once: the peer identity gate, the
//! effective PeerAuthentication transport mode, the relay-destination
//! ownership guard, and the authorize-phase plugin chain (`mesh_authz`) all
//! judge the CONNECT request, and the relay then byte-copies for as long as the
//! tunnel lives. Without this fence a tunnel admitted under one policy
//! generation kept flowing after the operator published a tighter one; only
//! the admitting credential's lifetime bounded it. That is also what blocks
//! source-side inner-connection reuse (#5042 step 2): a reused tunnel would
//! carry later requests under a stale decision.
//!
//! The fence keeps a registry of live admitted tunnels, each holding the
//! admission snapshot those gates evaluated. Every request-epoch publication
//! and every inbound PeerAuthentication swap schedules ONE sweep (concurrent
//! requests coalesce) that re-applies the gates to every live tunnel against
//! the CURRENT epoch and policy. A tunnel that would no longer be admitted is
//! revoked: its relay observes the cancellation as a terminal transport error,
//! which resets the CONNECT stream toward the peer and closes the backend leg
//! through the relay's ordinary teardown path.
//!
//! Sweeps run off the request path on one background task at a time, and only
//! authorize plugins that declare themselves re-evaluation-safe
//! ([`crate::plugins::Plugin::reevaluates_live_admission`]) are re-run. That
//! keeps a publication's cost to local policy evaluation over the live
//! tunnels — microseconds per tunnel, no external call and no consumed budget —
//! so a routine config apply can never drain a real client's rate-limit budget
//! or mass-revoke healthy tunnels because an external authorizer is briefly
//! unreachable. Within `mesh_authz`, `CUSTOM` (`ext_authz`) delegations are
//! additionally NOT re-consulted (see
//! [`crate::plugins::mesh::authz::MESH_AUTHZ_REEVALUATION_METADATA_KEY`]): the
//! provider's admission-time verdict stands for the tunnel's life, exactly as
//! before, while the local DENY/ALLOW tiers are re-applied.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use dashmap::DashMap;
use futures_util::FutureExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::hbone_proxy::{
    inbound_hbone_relay_effective_destination_decision,
    inbound_ingress_relay_effective_destination_allowed,
};
use super::{
    MeshInboundTlsPolicy, SharedMeshInboundTlsPolicy, inbound_hbone_relay_destination_decision,
    mesh_egress_udp_destination_allowed, mesh_inbound_peer_auth_transport_mismatch_for_policy,
};
use crate::config::types::{Proxy, UpstreamTarget};
use crate::plugins::mesh::authz::MESH_AUTHZ_REEVALUATION_METADATA_KEY;
use crate::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use crate::request_epoch::{RequestEpoch, RequestEpochStore};

/// Client-visible / log-visible message for a tunnel the fence revoked. A
/// compiled-in literal: no policy name, principal, or destination.
pub const HBONE_ADMISSION_REVOKED_MESSAGE: &str =
    "HBONE tunnel terminated: mesh admission revoked by a later policy generation";

/// Why a sweep revoked a live tunnel. Fixed cardinality; used as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HboneRevocationReason {
    /// The admitting configured proxy is gone from the published generation
    /// (or was deleted and recreated, which is a new incarnation).
    ProxyWithdrawn,
    /// The tunnel's transport no longer satisfies the effective
    /// PeerAuthentication mode for its application port.
    PeerAuthTransport,
    /// The relay destination is no longer one this terminator owns.
    RelayDestination,
    /// The authorize-phase chain now denies the admitted CONNECT.
    AuthorizationDenied,
    /// Re-evaluation itself could not produce a verdict (an authorize plugin
    /// unwound). Fail closed: an un-judgeable tunnel is cut rather than left
    /// serving under a generation nothing checked it against.
    ReevaluationFailed,
}

impl HboneRevocationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyWithdrawn => "proxy_withdrawn",
            Self::PeerAuthTransport => "peer_auth_transport",
            Self::RelayDestination => "relay_destination",
            Self::AuthorizationDenied => "authorization_denied",
            Self::ReevaluationFailed => "reevaluation_failed",
        }
    }

    const ALL: [Self; 5] = [
        Self::ProxyWithdrawn,
        Self::PeerAuthTransport,
        Self::RelayDestination,
        Self::AuthorizationDenied,
        Self::ReevaluationFailed,
    ];

    const fn index(self) -> usize {
        match self {
            Self::ProxyWithdrawn => 0,
            Self::PeerAuthTransport => 1,
            Self::RelayDestination => 2,
            Self::AuthorizationDenied => 3,
            Self::ReevaluationFailed => 4,
        }
    }

    fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }
}

/// Which relay-destination ownership guard admitted the tunnel, so the sweep
/// re-applies exactly that guard (`handle_hbone_request` /
/// `handle_hbone_udp_request` parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HboneRelayDestinationGate {
    /// Synthesized Ambient/NodeWaypoint/ServiceWaypoint inbound relay: the
    /// destination must remain one this proxy terminates for.
    InboundRelay,
    /// Synthesized Sidecar `ingress[]` remap: the declared listener →
    /// `defaultEndpoint` mapping must remain intact.
    IngressRelay,
    /// Datagram-over-HBONE relay: a terminator-owned local destination, or an
    /// admitted EgressGateway external UDP endpoint.
    Datagram,
    /// Explicitly configured proxy: no ownership guard applies; presence in the
    /// published generation is the gate.
    Configured,
}

/// Everything the CONNECT admission gates evaluated, captured after admission
/// so a sweep can re-run the same decision against a later generation.
pub struct HboneAdmissionSnapshot {
    /// Request context after the authorize and `before_proxy` phases. Cloned
    /// per sweep because `authorize` takes `&mut`.
    pub ctx: RequestContext,
    /// The effective (post-route-override) proxy the relay dialed through.
    pub proxy: Arc<Proxy>,
    pub upstream_target: Option<Arc<UpstreamTarget>>,
    pub is_tls: bool,
    pub has_verified_peer_certificate: bool,
    pub mesh_inbound_pre_handshake_app_port: Option<u16>,
    pub destination_gate: HboneRelayDestinationGate,
    /// The address the relay actually dialled, when one was resolved. The
    /// ordinary inbound relay screens post-DNS loopback answers before the
    /// dial, and the sweep re-applies that screen to this address — authority
    /// matching admits a declared hostname without resolving it, so the
    /// authority decision alone cannot see a tunnel pinned to `127.0.0.0/8`.
    pub resolved_ip: Option<IpAddr>,
    /// `Some` only for a proxy present in the published configuration;
    /// synthesized relay proxies are absent from every generation by design.
    pub proxy_lifecycle_generation: Option<u64>,
    /// The protocol the request path resolved the admitting plugin view with.
    /// The authorize chain is protocol-scoped and an HBONE CONNECT carrying
    /// `content-type: application/grpc` classifies as gRPC, so the sweep must
    /// re-resolve the SAME view rather than assume plain HTTP.
    pub request_protocol: ProxyProtocol,
    /// Whether the admitting view came from `grpc_web_request_view` rather than
    /// `request_view`; see [`Self::request_protocol`].
    pub grpc_web_request: bool,
    /// [`HboneAdmissionFence::sweep_epoch`] as captured BEFORE the request path
    /// read the epoch and PeerAuthentication policy these gates judged. See
    /// [`HboneAdmissionFence::admit`] for the publish-then-recheck contract.
    pub admission_sweep_epoch: u64,
}

struct AdmittedHboneTunnelInner {
    id: u64,
    token: CancellationToken,
    /// `u8::MAX` until revoked; then `HboneRevocationReason::index()`.
    revoked: AtomicU8,
    /// Set by [`AdmittedHboneTunnel::retire`] the moment the relay ends, so a
    /// sweep already holding this handle neither re-evaluates nor revokes a
    /// tunnel that is no longer carrying bytes.
    retired: AtomicBool,
    snapshot: HboneAdmissionSnapshot,
    fence: Weak<HboneAdmissionFence>,
}

const NOT_REVOKED: u8 = u8::MAX;

impl Drop for AdmittedHboneTunnelInner {
    fn drop(&mut self) {
        if let Some(fence) = self.fence.upgrade() {
            let ptr = std::ptr::from_mut(self).cast_const();
            fence
                .tunnels
                .remove_if(&self.id, |_, weak| std::ptr::eq(weak.as_ptr(), ptr));
        }
    }
}

/// One live admitted tunnel. Held by the relay task; dropping the last handle
/// deregisters the tunnel. Cheap to clone (one `Arc` bump).
#[derive(Clone)]
pub struct AdmittedHboneTunnel {
    inner: Arc<AdmittedHboneTunnelInner>,
}

impl AdmittedHboneTunnel {
    /// The admission snapshot; the relay reads its `ctx` for the transaction
    /// summary so the tunnel is cloned once, not twice.
    pub fn snapshot(&self) -> &HboneAdmissionSnapshot {
        &self.inner.snapshot
    }

    /// Owned cancellation handle for the relay's termination bound.
    pub fn revocation_token(&self) -> CancellationToken {
        self.inner.token.clone()
    }

    /// Whether a sweep revoked this tunnel, and why.
    pub fn revoked_reason(&self) -> Option<HboneRevocationReason> {
        HboneRevocationReason::from_index(self.inner.revoked.load(Ordering::Acquire))
    }

    /// Deregister the tunnel the instant its relay ends, before the transaction
    /// summary and the operator logging chain run.
    ///
    /// A sweep that is already holding this handle skips a retired tunnel, and
    /// [`Self::revoke`] refuses one, so
    /// `ferrum_mesh_hbone_tunnel_revocations_total` and
    /// [`HboneAdmissionFence::live_tunnels`] count only tunnels that are still
    /// carrying bytes. `Drop` stays the safety net for every path that cannot
    /// reach this call.
    pub fn retire(&self) {
        self.inner.retired.store(true, Ordering::Release);
        if let Some(fence) = self.inner.fence.upgrade() {
            let ptr = Arc::as_ptr(&self.inner);
            fence
                .tunnels
                .remove_if(&self.inner.id, |_, weak| std::ptr::eq(weak.as_ptr(), ptr));
        }
    }

    fn revoke(&self, reason: HboneRevocationReason) -> bool {
        if self.inner.retired.load(Ordering::Acquire) {
            return false;
        }
        // Record the reason BEFORE cancelling. The relay reads
        // `revoked_reason()` as soon as it observes the cancellation, and the
        // datagram relay has no first-failure record to classify instead, so a
        // cancellation the reason has not caught up with would be reported as a
        // transport failure. Nothing depends on seeing the cancellation edge
        // first: the only `is_cancelled()` reader is the sweep loop, and sweeps
        // are serialized by `sweep_serial`.
        let recorded = self
            .inner
            .revoked
            .compare_exchange(
                NOT_REVOKED,
                reason.index() as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        self.inner.token.cancel();
        recorded
    }
}

/// Process-wide registry of live admitted HBONE tunnels plus the sweep that
/// re-applies their admission gates. One per `ProxyState`.
pub struct HboneAdmissionFence {
    tunnels: DashMap<u64, Weak<AdmittedHboneTunnelInner>>,
    next_id: AtomicU64,
    sweeps_requested: AtomicU64,
    sweeps_completed: AtomicU64,
    /// Serializes sweeps; a request that arrives mid-sweep is folded into the
    /// next pass by the requested/completed counters.
    sweep_serial: tokio::sync::Mutex<()>,
    revocations: [AtomicU64; HboneRevocationReason::ALL.len()],
    reevaluations: AtomicU64,
    request_epoch: Arc<RequestEpochStore>,
    mesh_inbound_tls_policy: SharedMeshInboundTlsPolicy,
}

impl HboneAdmissionFence {
    pub fn new(
        request_epoch: Arc<RequestEpochStore>,
        mesh_inbound_tls_policy: SharedMeshInboundTlsPolicy,
    ) -> Self {
        Self {
            tunnels: DashMap::new(),
            next_id: AtomicU64::new(1),
            sweeps_requested: AtomicU64::new(0),
            sweeps_completed: AtomicU64::new(0),
            sweep_serial: tokio::sync::Mutex::new(()),
            revocations: Default::default(),
            reevaluations: AtomicU64::new(0),
            request_epoch,
            mesh_inbound_tls_policy,
        }
    }

    /// Register an admitted tunnel. The returned handle keeps it sweepable
    /// until the relay retires or drops it.
    ///
    /// Publish-then-recheck closes the admission race. The request path spends
    /// the whole authenticate/authorize/`before_proxy` chain, the
    /// circuit-breaker check, the upgrade-handle extraction, and a full backend
    /// dial between reading the epoch and reaching this insert, and a
    /// publication landing inside that window schedules a sweep whose registry
    /// read — including the `tunnels.is_empty()` fast path — can complete
    /// BEFORE the insert. Such a tunnel would then be judged only by the
    /// superseded generation, and, because sweeps are exclusively
    /// publication-driven, would never be re-judged on a quiet mesh.
    ///
    /// The request path therefore captures [`Self::sweep_epoch`] BEFORE it
    /// reads the epoch and the PeerAuthentication policy the gates evaluate
    /// (both publishers bump the counter AFTER their store, so a gate that read
    /// stale state necessarily captured a stale counter too). If the counter
    /// has moved by the time the tunnel is registered, this schedules a fresh
    /// sweep that is guaranteed to see it. The insert and the
    /// sequentially-consistent load below are ordered against
    /// [`Self::request_sweep`]'s increment and its registry read, so at least
    /// one of the two sides observes the other.
    pub fn admit(self: &Arc<Self>, snapshot: HboneAdmissionSnapshot) -> AdmittedHboneTunnel {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let admission_sweep_epoch = snapshot.admission_sweep_epoch;
        let inner = Arc::new(AdmittedHboneTunnelInner {
            id,
            token: CancellationToken::new(),
            revoked: AtomicU8::new(NOT_REVOKED),
            retired: AtomicBool::new(false),
            snapshot,
            fence: Arc::downgrade(self),
        });
        self.tunnels.insert(id, Arc::downgrade(&inner));
        let tunnel = AdmittedHboneTunnel { inner };
        if self.sweeps_requested.load(Ordering::SeqCst) != admission_sweep_epoch {
            self.request_sweep();
        }
        tunnel
    }

    /// The sweep-request counter as of this call.
    ///
    /// The HBONE request path captures it before loading the request epoch it
    /// admits against and carries it in
    /// [`HboneAdmissionSnapshot::admission_sweep_epoch`]; [`Self::admit`]
    /// compares it against the live counter to detect a publication that raced
    /// the admission. Two relaxed-cost atomic loads per CONNECT, nothing on the
    /// byte-relay path.
    pub fn sweep_epoch(&self) -> u64 {
        self.sweeps_requested.load(Ordering::SeqCst)
    }

    /// Number of tunnels currently registered.
    pub fn live_tunnels(&self) -> usize {
        self.tunnels.len()
    }

    /// Revocations recorded for `reason` since process start.
    pub fn revocations(&self, reason: HboneRevocationReason) -> u64 {
        self.revocations[reason.index()].load(Ordering::Relaxed)
    }

    /// Live-tunnel authorize-chain re-evaluations performed by sweeps.
    pub fn reevaluations(&self) -> u64 {
        self.reevaluations.load(Ordering::Relaxed)
    }

    /// Sweeps that have run to completion.
    pub fn sweeps_completed(&self) -> u64 {
        self.sweeps_completed.load(Ordering::Acquire)
    }

    /// Schedule a sweep against the current request epoch and inbound
    /// PeerAuthentication policy. Returns immediately; the sweep runs on the
    /// ambient tokio runtime.
    ///
    /// Outside a runtime the request cannot be scheduled at all, so it is
    /// dropped with a `warn!` naming the live-tunnel count it could not
    /// re-judge — the one place this fence can silently stop being a fence.
    /// Every production publication path (`ProxyState::update_config` /
    /// `update_mesh_config` / the incremental applies, and
    /// `apply_mesh_inbound_tls_reload`) runs inside the runtime, `spawn_blocking`
    /// workers carry a runtime context, and startup publication precedes every
    /// live tunnel.
    pub fn request_sweep(self: &Arc<Self>) {
        // Sequentially consistent: `admit` inserts into the registry and then
        // loads this counter, while this increments the counter and then reads
        // the registry. One of the two must observe the other, or an admission
        // racing this publication would escape the fence entirely.
        self.sweeps_requested.fetch_add(1, Ordering::SeqCst);
        if self.tunnels.is_empty() {
            // Nothing to fence; account the sweep as complete so waiters see a
            // settled state without spawning.
            let requested = self.sweeps_requested.load(Ordering::Acquire);
            self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!(
                requested = self.sweeps_requested.load(Ordering::Acquire),
                completed = self.sweeps_completed.load(Ordering::Acquire),
                live_tunnels = self.tunnels.len(),
                "HBONE admission fence sweep requested outside a tokio runtime; live tunnels \
                 will not be re-judged until the next in-runtime publication"
            );
            return;
        };
        let fence = Arc::clone(self);
        handle.spawn(async move {
            fence.run_pending_sweeps().await;
        });
    }

    async fn run_pending_sweeps(self: Arc<Self>) {
        let _serial = self.sweep_serial.lock().await;
        loop {
            let requested = self.sweeps_requested.load(Ordering::Acquire);
            if self.sweeps_completed.load(Ordering::Acquire) >= requested {
                return;
            }
            self.sweep_once().await;
            self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
        }
    }

    async fn sweep_once(&self) {
        let epoch = self.request_epoch.load();
        let policy = self.mesh_inbound_tls_policy.load_full();
        let live: Vec<AdmittedHboneTunnel> = self
            .tunnels
            .iter()
            .filter_map(|entry| entry.value().upgrade())
            .map(|inner| AdmittedHboneTunnel { inner })
            .collect();
        let mut revoked = 0usize;
        for tunnel in live {
            if tunnel.inner.token.is_cancelled() || tunnel.inner.retired.load(Ordering::Acquire) {
                continue;
            }
            // One authorize plugin that unwinds must not take the rest of the
            // sweep — and every later publication — with it: the task would die
            // before `sweeps_completed` advanced, leaving every tunnel after it
            // in iteration order permanently un-swept while the log showed only
            // a task panic. Fail closed on the tunnel whose verdict is missing.
            // The shipped `release` profile is `panic = "abort"`, so this is the
            // dev/test-profile net; under `abort` the process is gone and no
            // tunnel is left silently unfenced either way.
            let reevaluate = self.reevaluate(&tunnel.inner.snapshot, &epoch, &policy);
            let outcome = std::panic::AssertUnwindSafe(reevaluate)
                .catch_unwind()
                .await;
            let reason = match outcome {
                Ok(reason) => reason,
                Err(_) => {
                    error!(
                        proxy_id = %tunnel.inner.snapshot.proxy.id,
                        config_generation = epoch.config_generation(),
                        "HBONE admission fence re-evaluation panicked; revoking the tunnel it \
                         could not judge"
                    );
                    Some(HboneRevocationReason::ReevaluationFailed)
                }
            };
            let Some(reason) = reason else {
                continue;
            };
            if tunnel.revoke(reason) {
                revoked += 1;
                self.revocations[reason.index()].fetch_add(1, Ordering::Relaxed);
                crate::plugins::prometheus_metrics::global_registry()
                    .record_hbone_tunnel_revocation(&tunnel.inner.snapshot.proxy.id, reason);
                warn!(
                    proxy_id = %tunnel.inner.snapshot.proxy.id,
                    reason = reason.as_str(),
                    config_generation = epoch.config_generation(),
                    "Revoked a live HBONE tunnel: its CONNECT would no longer be admitted \
                     under the current policy generation"
                );
            }
        }
        if revoked > 0 {
            info!(
                revoked,
                config_generation = epoch.config_generation(),
                "HBONE admission fence sweep revoked live tunnels"
            );
        } else {
            debug!(
                config_generation = epoch.config_generation(),
                "HBONE admission fence sweep left every live tunnel admitted"
            );
        }
    }

    /// Re-apply the CONNECT admission gates to one snapshot. `Some(reason)`
    /// means the tunnel must be revoked. Gate order mirrors
    /// `handle_hbone_request`: transport, destination ownership, then the
    /// authorize chain.
    async fn reevaluate(
        &self,
        snapshot: &HboneAdmissionSnapshot,
        epoch: &RequestEpoch,
        policy: &MeshInboundTlsPolicy,
    ) -> Option<HboneRevocationReason> {
        let proxy = &snapshot.proxy;
        // A configured proxy must still be published under the same lifecycle
        // incarnation. Synthesized relay proxies are never in `config.proxies`;
        // their ownership guard below is the presence check.
        if let Some(admitted_generation) = snapshot.proxy_lifecycle_generation
            && epoch
                .plugin_cache
                .proxy_lifecycle_generation(&proxy.namespace, &proxy.id)
                != Some(admitted_generation)
        {
            return Some(HboneRevocationReason::ProxyWithdrawn);
        }

        if mesh_inbound_peer_auth_transport_mismatch_for_policy(
            policy,
            snapshot.ctx.mesh_direction,
            snapshot.mesh_inbound_pre_handshake_app_port,
            proxy,
            snapshot.upstream_target.as_deref(),
            snapshot.is_tls,
            snapshot.has_verified_peer_certificate,
        )
        .is_some()
        {
            return Some(HboneRevocationReason::PeerAuthTransport);
        }

        let mesh = epoch.config.mesh.as_deref();
        let destination_owned = match snapshot.destination_gate {
            HboneRelayDestinationGate::InboundRelay => {
                let authority_owned = inbound_hbone_relay_effective_destination_decision(
                    proxy,
                    snapshot.upstream_target.as_deref(),
                    mesh,
                    snapshot.ctx.mesh_inbound_terminator_ip,
                )
                .is_ok();
                authority_owned && inbound_relay_resolved_ip_admitted(mesh, snapshot.resolved_ip)
            }
            HboneRelayDestinationGate::IngressRelay => {
                inbound_ingress_relay_effective_destination_allowed(
                    proxy,
                    snapshot.upstream_target.as_deref(),
                    mesh,
                    snapshot.ctx.mesh_inbound_listener_authz_port,
                )
            }
            HboneRelayDestinationGate::Datagram => {
                let (app_host, app_port) = snapshot
                    .upstream_target
                    .as_deref()
                    .map(|target| (target.host.as_str(), target.port))
                    .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));
                inbound_hbone_relay_destination_decision(
                    app_host,
                    app_port,
                    mesh,
                    snapshot.ctx.mesh_inbound_terminator_ip,
                )
                .is_ok()
                    || mesh_egress_udp_destination_allowed(app_host, app_port, mesh)
            }
            HboneRelayDestinationGate::Configured => true,
        };
        if !destination_owned {
            return Some(HboneRevocationReason::RelayDestination);
        }

        // The authorize chain is protocol-scoped and the admitting view is
        // peer-selectable: an HBONE CONNECT carrying `content-type:
        // application/grpc` classifies as gRPC, and a gRPC-Web request resolves
        // an entirely separate view. Re-resolve exactly the view
        // `plugin_cache_view` resolved at admission, never a hardcoded HTTP one.
        let view = if snapshot.grpc_web_request {
            epoch
                .plugin_cache
                .grpc_web_request_view(&proxy.namespace, &proxy.id)
        } else {
            epoch
                .plugin_cache
                .request_view(&proxy.namespace, &proxy.id, snapshot.request_protocol)
        };
        // Only plugins whose `authorize` is free of side effects and external
        // I/O are re-run (`Plugin::reevaluates_live_admission`). A sweep that
        // consumed a rate-limit token or issued one ext_authz/OPA call per live
        // tunnel would revoke healthy, policy-compliant tunnels and drain a real
        // client's budget — a worse outcome than the stale admission this fence
        // exists to close.
        let authorize = view.authorize_plugins();
        let reevaluated: Vec<&Arc<dyn Plugin>> = authorize
            .iter()
            .filter(|plugin| plugin.reevaluates_live_admission())
            .collect();
        if reevaluated.is_empty() {
            return None;
        }
        self.reevaluations.fetch_add(1, Ordering::Relaxed);
        let mut ctx = snapshot.ctx.clone();
        ctx.metadata.insert(
            MESH_AUTHZ_REEVALUATION_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        for plugin in reevaluated {
            match plugin.authorize(&mut ctx).await {
                PluginResult::Continue => {}
                PluginResult::Reject { .. } | PluginResult::RejectBinary { .. } => {
                    debug!(
                        proxy_id = %proxy.id,
                        plugin = plugin.name(),
                        deny_policy = ctx
                            .metadata
                            .get("mesh_authz.deny_policy")
                            .map(String::as_str)
                            .unwrap_or("<unset>"),
                        "Authorize chain denies a live HBONE tunnel's CONNECT under the current \
                         generation"
                    );
                    return Some(HboneRevocationReason::AuthorizationDenied);
                }
            }
        }
        None
    }
}

/// Re-apply `connect_backend`'s post-DNS loopback screen
/// (`screen_ordinary_inbound_hbone_relay_dns_candidates`) to the address the
/// ordinary inbound relay actually dialled.
///
/// Authority matching admits a declared hostname WITHOUT resolving it, so the
/// authority decision alone cannot see a live tunnel pinned to `127.0.0.0/8`,
/// `::1`, or mapped IPv4 loopback. A slice change that withdraws the Sidecar
/// own-namespace privilege (Sidecar → Ambient/waypoint posture on the same
/// host/port) must cut that tunnel, exactly as it would refuse a fresh CONNECT.
/// `None` means nothing was resolved, so there is no screen to re-apply; a
/// missing mesh snapshot is already refused by the authority decision.
fn inbound_relay_resolved_ip_admitted(
    mesh: Option<&crate::modes::mesh::config::MeshConfig>,
    resolved_ip: Option<IpAddr>,
) -> bool {
    let (Some(mesh), Some(ip)) = (mesh, resolved_ip) else {
        return true;
    };
    mesh.screen_inbound_relay_resolved_ips([ip]).is_ok()
}
