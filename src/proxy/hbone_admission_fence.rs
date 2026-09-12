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
//! Sweeps run off the request path on one background task at a time. The
//! per-tunnel cost is one authorize-chain evaluation, so a publication costs
//! `O(live tunnels x policies)` — microseconds per tunnel — and never touches a
//! tunnel whose admission still holds. `CUSTOM` (`ext_authz`) delegations are
//! NOT re-consulted by a sweep (see
//! [`crate::plugins::mesh::authz::MESH_AUTHZ_REEVALUATION_METADATA_KEY`]): the
//! provider's admission-time verdict stands for the tunnel's life, exactly as
//! before, while the local DENY/ALLOW tiers are re-applied.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

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
use crate::plugins::{PluginResult, ProxyProtocol, RequestContext};
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
}

impl HboneRevocationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyWithdrawn => "proxy_withdrawn",
            Self::PeerAuthTransport => "peer_auth_transport",
            Self::RelayDestination => "relay_destination",
            Self::AuthorizationDenied => "authorization_denied",
        }
    }

    const ALL: [Self; 4] = [
        Self::ProxyWithdrawn,
        Self::PeerAuthTransport,
        Self::RelayDestination,
        Self::AuthorizationDenied,
    ];

    const fn index(self) -> usize {
        match self {
            Self::ProxyWithdrawn => 0,
            Self::PeerAuthTransport => 1,
            Self::RelayDestination => 2,
            Self::AuthorizationDenied => 3,
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
    /// `Some` only for a proxy present in the published configuration;
    /// synthesized relay proxies are absent from every generation by design.
    pub proxy_lifecycle_generation: Option<u64>,
}

struct AdmittedHboneTunnelInner {
    id: u64,
    token: CancellationToken,
    /// `u8::MAX` until revoked; then `HboneRevocationReason::index()`.
    revoked: AtomicU8,
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

    fn revoke(&self, reason: HboneRevocationReason) -> bool {
        // Cancel first so `is_cancelled()` observers see the edge before the
        // exactly-once accounting swap; the swap still keeps accounting once.
        self.inner.token.cancel();
        self.inner
            .revoked
            .compare_exchange(
                NOT_REVOKED,
                reason.index() as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
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
    /// until the relay drops it.
    ///
    /// Publish-then-recheck is unnecessary here: a sweep already running reads
    /// the registry after this insert or before it, and in the latter case the
    /// publication that scheduled the sweep is the same generation the
    /// admission gates just evaluated on the request path.
    pub fn admit(self: &Arc<Self>, snapshot: HboneAdmissionSnapshot) -> AdmittedHboneTunnel {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(AdmittedHboneTunnelInner {
            id,
            token: CancellationToken::new(),
            revoked: AtomicU8::new(NOT_REVOKED),
            snapshot,
            fence: Arc::downgrade(self),
        });
        self.tunnels.insert(id, Arc::downgrade(&inner));
        AdmittedHboneTunnel { inner }
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
    /// ambient tokio runtime. Outside a runtime nothing can hold a live tunnel,
    /// so the request is dropped.
    pub fn request_sweep(self: &Arc<Self>) {
        self.sweeps_requested.fetch_add(1, Ordering::AcqRel);
        if self.tunnels.is_empty() {
            // Nothing to fence; account the sweep as complete so waiters see a
            // settled state without spawning.
            let requested = self.sweeps_requested.load(Ordering::Acquire);
            self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
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
            if tunnel.inner.token.is_cancelled() {
                continue;
            }
            let Some(reason) = self
                .reevaluate(&tunnel.inner.snapshot, &epoch, &policy)
                .await
            else {
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
                inbound_hbone_relay_effective_destination_decision(
                    proxy,
                    snapshot.upstream_target.as_deref(),
                    mesh,
                    snapshot.ctx.mesh_inbound_terminator_ip,
                )
                .is_ok()
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

        let authorize = epoch
            .plugin_cache
            .request_view(&proxy.namespace, &proxy.id, ProxyProtocol::Http)
            .authorize_plugins();
        if authorize.is_empty() {
            return None;
        }
        self.reevaluations.fetch_add(1, Ordering::Relaxed);
        let mut ctx = snapshot.ctx.clone();
        ctx.metadata.insert(
            MESH_AUTHZ_REEVALUATION_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        for plugin in authorize.iter() {
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
