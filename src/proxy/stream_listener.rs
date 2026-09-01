//! Manages lifecycle of TCP/UDP stream proxy listeners.
//!
//! The `StreamListenerManager` reconciles the set of active listeners against
//! the current `GatewayConfig`. On config reload it starts new listeners,
//! stops removed ones, and restarts listeners whose port or protocol changed.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::backend_conn_limit::{BackendConnectionLimiter, SharedBackendConnectionLimiter};
use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::db_backend::NamespacedResourceId;
use crate::config::types::{BackendScheme, GatewayConfig, Proxy};
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;
use crate::request_epoch::RequestEpochStore;
use crate::tls::TlsPolicy;
use crate::tls::source::{CertSource, MaterialKind, load_material};

use super::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics};
use super::udp_proxy::{UdpListenerConfig, UdpProxyMetrics};

/// Live slot for a per-listener `DtlsServer`. The inner `Option<Arc<...>>` is
/// `None` until the listener task publishes the server (post-bind) and
/// becomes `Some` for the lifetime of the listener.
type DtlsServerSlot = Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::DtlsServer>>>>;

const STREAM_LISTENER_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);

/// How long reconcile waits for a newly spawned NodeWaypoint UDP/DTLS listener
/// to set `started` after a successful port probe. Steering is published only
/// for listeners that actually bound. A timeout leaves that destination
/// unsteered (fail-closed) until the bind-success watch observes `started` or
/// the next reconcile; it must never mark a port with no serving socket.
const NODE_WAYPOINT_UDP_STEER_BIND_WAIT: Duration = Duration::from_secs(2);

/// Deterministic fence for NodeWaypoint UDP steering publication tests.
///
/// Both barriers have two parties (the production waiter and the test). The
/// production path awaits `entered` then `release` so the test can inject a
/// concurrent owner event in between. Not used on the datagram hot path.
pub struct NodeWaypointUdpSteerHold {
    entered: tokio::sync::Barrier,
    release: tokio::sync::Barrier,
}

impl NodeWaypointUdpSteerHold {
    #[allow(dead_code)] // External unit tests sequence publication vs failure/shutdown.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Barrier::new(2),
            release: tokio::sync::Barrier::new(2),
        })
    }

    /// Wait until the production waiter has reached this fence.
    #[allow(dead_code)] // External unit tests.
    pub async fn wait_entered(&self) {
        self.entered.wait().await;
    }

    /// Let the production waiter continue past this fence.
    #[allow(dead_code)] // External unit tests.
    pub async fn wait_release(&self) {
        self.release.wait().await;
    }

    async fn wait(&self) {
        self.wait_entered().await;
        self.wait_release().await;
    }
}

/// Bounded, redacted frontend DTLS live-reload status.
///
/// Exposes generation/convergence counters only — never PEM, key bytes, secret
/// URIs, or source path material.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FrontendDtlsReloadStatus {
    /// Last accepted generation id (`0` means none published yet).
    pub generation: u64,
    /// Listeners successfully live-swapped on the last accepted publish.
    pub last_swapped_listeners: u64,
    /// Unix seconds of the last accepted publish, when any.
    pub last_success_unix: Option<u64>,
    /// Unix seconds of the last rejected candidate, when any.
    pub last_failure_unix: Option<u64>,
    /// Fixed-cardinality last outcome label (`none`, `accepted`, `rejected`).
    pub last_outcome: &'static str,
}

impl Default for FrontendDtlsReloadStatus {
    fn default() -> Self {
        Self {
            generation: 0,
            last_swapped_listeners: 0,
            last_success_unix: None,
            last_failure_unix: None,
            last_outcome: "none",
        }
    }
}

fn unix_now_secs() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

/// Run one collector-side observation while generation publication is fenced.
/// The consumer must both apply the snapshot and expose its listener handle
/// inside this call so no newer publisher can miss the handle and then be
/// overwritten by the stale snapshot.
async fn with_current_frontend_dtls_generation<T>(
    publish_lock: &Arc<tokio::sync::Mutex<()>>,
    generation_slot: &Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::FrontendDtlsGeneration>>>>,
    consume: impl FnOnce(Option<&Arc<crate::dtls::FrontendDtlsGeneration>>) -> T,
) -> T {
    let _publish_guard = publish_lock.lock().await;
    let generation = generation_slot.load_full();
    consume(generation.as_ref().as_ref())
}

/// Explicit ownership class of a terminating DTLS frontend listener (issue
/// #3858).
///
/// DTLS frontend configuration and reload are **listener- and owner-scoped**.
/// Mesh `PeerAuthentication`, client-CA, CRL and identity updates may reach
/// [`Self::MeshNodeWaypoint`] listeners only; an ordinary operator
/// `FERRUM_DTLS_*` listener sharing the process keeps byte-identical identity
/// and verifier state across every mesh slice apply. There is deliberately no
/// process-wide DTLS fanout: the two owners have separate generation slots and
/// separate publish entry points, so neither can seed or overwrite the other.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DtlsListenerOwner {
    /// Ordinary operator/gateway listener configured from `FERRUM_DTLS_*`.
    Operator,
    /// Ferrum-generated NodeWaypoint Service listener. Its accepted config is
    /// keyed by the generated listener's stable namespaced identity, so a
    /// listener created or restarted after a successful slice apply receives
    /// exactly the generation already live on its peers.
    MeshNodeWaypoint { listener_key: String },
}

impl DtlsListenerOwner {
    #[inline]
    fn from_node_waypoint_flag(
        identity: &NamespacedResourceId,
        node_waypoint_udp_owner: bool,
    ) -> Self {
        if node_waypoint_udp_owner {
            Self::MeshNodeWaypoint {
                listener_key: identity.runtime_key(),
            }
        } else {
            Self::Operator
        }
    }

    #[inline]
    fn is_mesh_node_waypoint(&self) -> bool {
        matches!(self, Self::MeshNodeWaypoint { .. })
    }
}

/// One accepted owner-scoped DTLS generation for generated `MeshNodeWaypoint`
/// listeners (issue #3858).
///
/// Carries the COMPLETE candidate set for one accepted mesh slice: every
/// generated DTLS route's frontend config, derived from the dedicated DTLS
/// server identity plus that route's effective `PeerAuthentication` workload /
/// service scope and the accepted client-CA + CRL snapshot. Publication is
/// all-or-nothing — the mesh builds and validates every required candidate
/// BEFORE the slice is accepted, so a malformed CA/CRL, a failed verifier
/// build, or a Strict route with no client CA rejects the whole slice and
/// both owners retain their complete last-good serving generation.
///
/// A listener whose key is absent from the accepted map is NOT covered by this
/// generation and stays deferred rather than falling back to another owner's
/// material.
pub struct MeshNodeWaypointDtlsGeneration {
    #[allow(dead_code)] // External unit tests / diagnostics.
    generation: u64,
    configs: std::collections::BTreeMap<String, crate::dtls::FrontendDtlsConfig>,
}

impl MeshNodeWaypointDtlsGeneration {
    #[allow(dead_code)] // External unit tests / diagnostics.
    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[inline]
    fn config_for(&self, listener_key: &str) -> Option<&crate::dtls::FrontendDtlsConfig> {
        self.configs.get(listener_key)
    }

    /// Sorted listener keys covered by this generation (diagnostics / tests).
    #[allow(dead_code)] // Test / introspection surface.
    pub fn covered_listener_keys(&self) -> Vec<String> {
        self.configs.keys().cloned().collect()
    }
}

/// Owner-scoped analogue of [`with_current_frontend_dtls_generation`] for
/// generated NodeWaypoint listeners. Shares the same publish lock so a
/// collector cannot expose a handle between an owner-scoped publish's slot
/// store and its live swap.
async fn with_current_mesh_node_waypoint_dtls_generation<T>(
    publish_lock: &Arc<tokio::sync::Mutex<()>>,
    generation_slot: &Arc<arc_swap::ArcSwap<Option<Arc<MeshNodeWaypointDtlsGeneration>>>>,
    consume: impl FnOnce(Option<&Arc<MeshNodeWaypointDtlsGeneration>>) -> T,
) -> T {
    let _publish_guard = publish_lock.lock().await;
    let generation = generation_slot.load_full();
    consume(generation.as_ref().as_ref())
}

/// Handle for a running stream listener — keeps the shutdown channel and task handle.
struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
    listen_port: u16,
    /// Exact OS bind address this listener was started with. Part of restart
    /// identity so a dedicated Sidecar ingress bind change retires the old
    /// socket instead of leaving it running indefinitely.
    bind_addr: IpAddr,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
    /// Whether this listener was spawned with the datagram client-address
    /// metadata gate engaged (issue #3289). Part of the restart key.
    datagram_client_address: bool,
    /// Exact amplification posture captured by every UDP candidate served by
    /// this listener. A factor change must retire the listener's session map:
    /// each `UdpSession` copies its factor at admission, so keeping the listener
    /// would let an established unlimited session outlive a tightened policy.
    udp_amplification_restart_key: Vec<(NamespacedResourceId, Option<u32>)>,
    backend_tls_reload_key: Option<BackendTlsReloadKey>,
    /// Backend routing snapshot taken when this TCP+TLS listener was spawned
    /// (`None` for non-TcpTls listeners). Compared against the live config in
    /// the keep-old-listener guard so an invalid TLS rotation bundled with a
    /// routing change tears the listener down instead of silently pairing the
    /// stale cached TLS config with connections routed to a new backend.
    backend_routing_key: Option<StreamBackendRoutingKey>,
    /// Sorted SNI-group member proxy identities for shared `__sni_{port}`
    /// passthrough listeners (`None` for individual listeners). Part of the
    /// restart key: the accept loop captures the candidate list at spawn, so a
    /// membership change (proxy added to / removed from a shared passthrough
    /// port) must restart the listener or new connections keep routing
    /// against the stale set. Candidates are namespace-qualified because a
    /// shared port can host same-ID passthrough proxies from two namespaces.
    sni_ids: Option<Vec<NamespacedResourceId>>,
    started: Arc<AtomicBool>,
    tcp_metrics: Option<Arc<TcpProxyMetrics>>,
    udp_metrics: Option<Arc<UdpProxyMetrics>>,
    /// Live DTLS server slot for UDP+DTLS listeners. The collector task
    /// publishes the server into this slot once
    /// `start_dtls_frontend_listener` has bound and constructed it. Held so
    /// ordinary frontend DTLS live reload
    /// ([`StreamListenerManager::publish_frontend_dtls_generation`]) can call
    /// [`crate::dtls::DtlsServer::swap_frontend_config`] on the same instance
    /// the recv loop is using. `None` for TCP/UDP-plain listeners.
    dtls_server: Option<DtlsServerSlot>,
    /// Spawn generation for this map entry. A failed older generation must not
    /// retract or republish a replacement that now owns the same key.
    generation: u64,
    /// Exact generated-listener ownership, carried from the accepted
    /// [`NamespacedResourceId`] at spawn. Never re-derived from a runtime-key
    /// substring.
    node_waypoint_udp_owner: bool,
    /// Explicit DTLS ownership class (issue #3858), carried from the accepted
    /// identity at spawn. Decides which generation slot may ever reach this
    /// listener's `DtlsServer`. `Operator` for every non-generated listener,
    /// including TCP listeners (which hold no DTLS server at all).
    dtls_owner: DtlsListenerOwner,
}

/// Reload key for the cached backend TLS `ClientConfig` a TCP+TLS listener
/// builds once at spawn ([`super::tcp_proxy::CachedBackendTlsConfig`]).
///
/// Must cover every input the builder bakes into the cached config: the
/// verify flag, the effective CA (proxy-resolved or global fallback — same
/// precedence as `BackendTlsConfigBuilder::custom_ca_path`), client cert/key,
/// and the SAN allow-list (baked into the verifier). Fields are fingerprinted
/// by *content* so in-place rotation (cert-manager rewriting the same path,
/// or a secret backend serving new bytes under a stable URI) restarts the
/// listener and refreshes the cached config.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendTlsReloadKey {
    verify_server_cert: bool,
    server_ca_cert: Option<BackendTlsMaterialReloadKey>,
    client_cert: Option<BackendTlsMaterialReloadKey>,
    client_key: Option<BackendTlsMaterialReloadKey>,
    /// SAN allow-list baked into the cached server verifier
    /// (`SanAllowListVerifier`). Config-carried, not file-backed, but it still
    /// changes the cached `ClientConfig`, so it must restart the listener.
    san_allow_list: Vec<String>,
    /// Content fingerprint of the active gateway CRL list
    /// (`FERRUM_TLS_CRL_FILE_PATH`), `None` when no CRLs are loaded. CRLs are
    /// compiled into the cached verifier, so a CRL rotation (delivered via
    /// [`StreamListenerManager::set_crls`]) must change the key and rebuild
    /// the listener's cached `ClientConfig`. Treated as material *content*
    /// (not source identity) by [`Self::same_tls_sources`], so a CRL rotation
    /// that pairs with invalid cert material still qualifies for the
    /// keep-old-listener path.
    crl_fingerprint: Option<String>,
}

/// Backend routing identity for a TCP+TLS stream proxy, captured at listener
/// spawn. Routing itself is read live per connection (via the request epoch),
/// so a routing change alone never restarts a listener — this snapshot exists
/// only to gate the keep-old-listener path on backend TLS rotation: keeping a
/// listener's stale cached TLS config is only safe while its connections
/// still route to the same backend the cache was built alongside.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StreamBackendRoutingKey {
    backend_host: String,
    backend_port: u16,
    upstream_id: Option<String>,
    upstream_subset: Option<String>,
    /// Sorted `(host, port)` set of the targets this proxy can actually dial
    /// (`None` when the proxy routes by `backend_host`/`backend_port`
    /// directly, `Some(empty)` when the upstream no longer exists or the
    /// subset matches nothing). When `upstream_subset` is set, the set is
    /// filtered through the same labels-⊆-tags rule the load balancer uses
    /// to build `subset_indices`, so a subset-label or target-tag edit that
    /// changes effective membership registers as routing drift even though
    /// the upstream's full endpoint list is intact. A config update can
    /// change all of this without touching any proxy field, and
    /// `resolve_backend_target` reads the live load-balancer snapshot — so
    /// the keep-old-listener guard must treat the change as routing drift,
    /// or stale cached TLS could be paired with connections dialing newly
    /// selected targets.
    upstream_targets: Option<Vec<(String, u16)>>,
}

impl StreamBackendRoutingKey {
    fn from_proxy(proxy: &Proxy, config: &GatewayConfig) -> Self {
        let upstream_targets = proxy.upstream_id.as_ref().map(|upstream_id| {
            let mut targets: Vec<(String, u16)> = config
                .upstreams
                .iter()
                .find(|u| {
                    // Upstream references are namespace-local. A bare-id match
                    // would latch onto another tenant's same-id upstream and
                    // gate TLS-cache retention against the wrong target set.
                    u.namespace.as_str() == proxy.namespace.as_str()
                        && u.id.as_str() == upstream_id.as_str()
                })
                .map(|u| {
                    // Mirror `LoadBalancer::with_subsets_and_port_overrides`:
                    // a target belongs to a subset when its tags contain
                    // every subset label. A requested-but-undefined subset
                    // matches nothing — same as subset selection returning
                    // `None`.
                    match proxy.upstream_subset.as_deref() {
                        Some(subset_name) => u
                            .subsets
                            .as_deref()
                            .and_then(|defs| defs.iter().find(|d| d.name == subset_name))
                            .map(|def| {
                                u.targets
                                    .iter()
                                    .filter(|t| {
                                        def.labels
                                            .iter()
                                            .all(|(k, v)| t.tags.get(k).is_some_and(|tv| tv == v))
                                    })
                                    .map(|t| (t.host.clone(), t.port))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        None => u.targets.iter().map(|t| (t.host.clone(), t.port)).collect(),
                    }
                })
                .unwrap_or_default();
            targets.sort();
            targets
        });
        Self {
            backend_host: proxy.backend_host.clone(),
            backend_port: proxy.backend_port,
            upstream_id: proxy.upstream_id.clone(),
            upstream_subset: proxy.upstream_subset.clone(),
            upstream_targets,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendTlsMaterialReloadKey {
    /// Stable, non-secret source identifier (inline PEM is digested — same
    /// redaction rule as `CertSource::pool_key_component`).
    source: String,
    /// `sha256:<hex>` of the materialized bytes, or `error:<details>` when the
    /// source cannot be loaded — kept in the key so a load failure vs success
    /// transition (file appears / secret becomes reachable) restarts the
    /// listener.
    fingerprint: String,
}

impl BackendTlsReloadKey {
    /// True when `other` references the same TLS *source configuration* as
    /// `self`: verify flag, SAN allow-list, and the (non-fingerprint) source
    /// identity of CA / client cert / client key are all unchanged. When this
    /// holds, any difference between the two keys can only be rotated
    /// material *content* under the same configured sources — the case the
    /// keep-old-listener path in [`StreamListenerManager::reconcile`] is
    /// allowed to ride out. A source identity change (new path/URI, source
    /// added or removed, verify or SAN change) is a deliberate config edit
    /// and must NOT be treated as an in-place rotation.
    fn same_tls_sources(&self, other: &Self) -> bool {
        fn source_matches(
            a: &Option<BackendTlsMaterialReloadKey>,
            b: &Option<BackendTlsMaterialReloadKey>,
        ) -> bool {
            match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => a.source == b.source,
                _ => false,
            }
        }
        // `crl_fingerprint` is intentionally NOT compared: the CRL file path
        // is fixed gateway config and only its *content* rotates, which is
        // exactly the in-place-rotation case this predicate exists to admit.
        self.verify_server_cert == other.verify_server_cert
            && self.san_allow_list == other.san_allow_list
            && source_matches(&self.server_ca_cert, &other.server_ca_cert)
            && source_matches(&self.client_cert, &other.client_cert)
            && source_matches(&self.client_key, &other.client_key)
    }

    async fn from_proxy(
        proxy: &Proxy,
        global_tls_ca_bundle_path: Option<&str>,
        crl_fingerprint: Option<&str>,
    ) -> Self {
        // Deliberately the RAW configured value, not `effective_ca_source`: this
        // key is a source *identity*, and `system://` must stay distinguishable
        // from "no CA configured" (which falls back to the global bundle). The
        // sentinel has no loadable material, so its fingerprint is a stable
        // unsupported-scheme marker rather than file content.
        let server_ca_cert_source = proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .or(global_tls_ca_bundle_path);

        Self {
            verify_server_cert: proxy.resolved_tls.verify_server_cert,
            server_ca_cert: match server_ca_cert_source {
                Some(source) => Some(
                    BackendTlsMaterialReloadKey::from_source_value(source, MaterialKind::CaBundle)
                        .await,
                ),
                None => None,
            },
            client_cert: match proxy.resolved_tls.client_cert_path.as_deref() {
                Some(source) => Some(
                    BackendTlsMaterialReloadKey::from_source_value(source, MaterialKind::Cert)
                        .await,
                ),
                None => None,
            },
            client_key: match proxy.resolved_tls.client_key_path.as_deref() {
                Some(source) => Some(
                    BackendTlsMaterialReloadKey::from_source_value(source, MaterialKind::Key).await,
                ),
                None => None,
            },
            san_allow_list: proxy.resolved_tls.san_allow_list.clone(),
            crl_fingerprint: crl_fingerprint.map(str::to_owned),
        }
    }
}

/// Content fingerprint of the active CRL list, `None` when empty. Folded into
/// every TCP+TLS [`BackendTlsReloadKey`] so a CRL rotation restarts the
/// listeners whose cached verifier compiled the old revocation list. Cold
/// path — computed once per reconcile, never per connection.
fn crl_list_fingerprint(crls: &crate::tls::CrlList) -> Option<String> {
    use crate::fips::approved::Sha256;
    if crls.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    for crl in crls.iter() {
        let der: &[u8] = crl.as_ref();
        hasher.update((der.len() as u64).to_le_bytes());
        hasher.update(der);
    }
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

impl BackendTlsMaterialReloadKey {
    /// Fingerprint a backend TLS material source by the bytes the TLS builder
    /// actually consumes.
    ///
    /// Resolves through the same [`CertSource`] / [`load_material`]
    /// abstraction as `load_backend_material` in `src/tls/backend.rs`, so
    /// every supported source kind (plain path, inline PEM, `file://`,
    /// vault/aws/azure/gcp/k8s/acme/managed URIs) is fingerprinted by content.
    /// A raw `std::fs::read` of the config string would freeze the key for
    /// non-path sources: a `file:///x.pem` or stable secret URI rotation
    /// would never change the key and the cached config would go stale
    /// forever. Cold path only — runs during reconcile, never per connection.
    async fn from_source_value(value: &str, kind: MaterialKind) -> Self {
        let source = CertSource::parse(value, kind);
        let fingerprint = match load_material(&source, kind).await {
            Ok(material) => format!("sha256:{}", hex::encode(material.fingerprint)),
            Err(err) => format!("error:{}", err.failure_class()),
        };

        Self {
            source: source.pool_key_component(),
            fingerprint,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct StreamListenerOverloadSnapshot {
    pub dtls_demux_sessions_total: u64,
    pub dtls_demux_sessions: Vec<DtlsDemuxSessionSnapshot>,
    /// Bounded frontend-DTLS material generation and convergence status.
    pub frontend_dtls_reload: FrontendDtlsReloadStatus,
    /// Number of configured stream-listener resources that are not serving
    /// after the most recent `reconcile()` — hard bind failures PLUS listeners
    /// deferred/degraded for a config reason (e.g. waiting on frontend TLS
    /// material). In DP mode these binds are intentionally non-fatal (a bad
    /// CP-pushed config must not brick the data plane), so this count plus
    /// [`Self::bind_failures`] give operators structured visibility beyond the
    /// warn log. `0` once every configured stream listener is serving. Each
    /// entry's `kind` distinguishes a hard failure from a deferral.
    pub bind_failures_total: usize,
    /// Structured per-resource stream-listener non-serving reasons from the most
    /// recent `reconcile()` plus durable asynchronous listener-task failures,
    /// classified by [`StreamBindFailure::kind`]. Empty once every configured
    /// stream listener is serving.
    pub bind_failures: Vec<StreamBindFailure>,
}

/// Why a configured stream listener is not serving after the most recent
/// [`StreamListenerManager::reconcile`]. Serialized in the `/overload`
/// `stream_listeners.bind_failures[].kind` field so operators can tell a hard
/// bind failure apart from a listener merely deferred while it waits on
/// frontend TLS material.
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamListenerDegradation {
    /// The socket bind/probe failed (e.g. the port is already in use). Counts
    /// as a hard bind failure returned to the startup path.
    BindFailed,
    /// Backend TLS config validation failed while starting a new TCP+TLS
    /// listener, so the listener was not installed. Hard bind failure.
    BackendTlsInvalid,
    /// In-place backend TLS material rotated to invalid content; the previous
    /// listener was kept running rather than tearing down the port. Hard bind
    /// failure (surfaced so the failed rotation is visible).
    BackendTlsRotationInvalid,
    /// A `frontend_tls` TCP listener is deferred because the rustls
    /// `ServerConfig` has not been loaded yet. Non-fatal: the listener starts
    /// once TLS material arrives (which itself re-triggers reconcile).
    FrontendTlsDeferred,
    /// A `frontend_tls` UDP/DTLS listener is deferred because the DTLS cert/key
    /// material has not been loaded yet. Non-fatal, same lifecycle as
    /// [`Self::FrontendTlsDeferred`].
    FrontendDtlsDeferred,
    /// A `frontend_tls` UDP/DTLS listener could not build its DTLS
    /// `ServerConfig` from the configured material, so it was skipped. Non-fatal
    /// at reconcile (retried), but reported so the misconfiguration is visible.
    FrontendDtlsBuildFailed,
}

impl StreamListenerDegradation {
    /// Whether this degradation is a hard bind failure that the startup path
    /// treats as fatal (file/database mode) or warn-logs (DP/runtime reconcile).
    /// Deferred/skip reasons return `false` so a listener merely waiting on TLS
    /// material never fails startup.
    fn is_hard_bind_failure(self) -> bool {
        matches!(
            self,
            Self::BindFailed | Self::BackendTlsInvalid | Self::BackendTlsRotationInvalid
        )
    }
}

/// A single stream-listener (TCP/UDP/DTLS) that is not serving after the most
/// recent [`StreamListenerManager::reconcile`]. Surfaced in the admin
/// `/overload` response under `stream_listeners.bind_failures` so a non-serving
/// listener — a hard bind failure (e.g. a port conflict on a CP-pushed proxy in
/// DP mode) OR a listener deferred/degraded for a config reason — is observable
/// rather than only warn-logged. The `kind` field classifies which.
///
/// Identity is `(namespace, proxy_id, listen_port)`: proxy IDs are unique only
/// within a namespace, so a bare-ID record would let one tenant's rebind clear
/// another tenant's failure (issue #3094).
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamBindFailure {
    pub namespace: String,
    pub proxy_id: String,
    pub listen_port: u16,
    pub error: String,
    pub kind: StreamListenerDegradation,
}

impl StreamBindFailure {
    fn new(
        identity: &NamespacedResourceId,
        listen_port: u16,
        error: impl Into<String>,
        kind: StreamListenerDegradation,
    ) -> Self {
        Self {
            namespace: identity.namespace.clone(),
            proxy_id: identity.id.clone(),
            listen_port,
            error: error.into(),
            kind,
        }
    }

    fn same_resource(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.proxy_id == other.proxy_id
            && self.listen_port == other.listen_port
    }
}

/// Exact `(namespace, id)` config lookup for a stream proxy.
///
/// Stream listeners must never resolve a proxy by bare ID: a same-ID proxy in
/// another namespace would match first and bind that tenant's routing/TLS
/// identity onto this listener.
fn find_proxy_by_identity<'a>(
    config: &'a GatewayConfig,
    identity: &NamespacedResourceId,
) -> Option<&'a Proxy> {
    config
        .proxies
        .iter()
        .find(|p| p.id == identity.id && p.namespace == identity.namespace)
}

fn listener_failures(
    identity: &NamespacedResourceId,
    sni_ids: Option<&[NamespacedResourceId]>,
    listen_port: u16,
    error: &str,
    kind: StreamListenerDegradation,
) -> Vec<StreamBindFailure> {
    match sni_ids {
        Some(ids) => ids
            .iter()
            .map(|candidate| StreamBindFailure::new(candidate, listen_port, error, kind))
            .collect(),
        None => vec![StreamBindFailure::new(identity, listen_port, error, kind)],
    }
}

fn append_bind_failure(
    snapshot: &arc_swap::ArcSwap<Vec<StreamBindFailure>>,
    failure: StreamBindFailure,
) {
    snapshot.rcu(|current| {
        let mut next = (**current).clone();
        if let Some(existing) = next
            .iter_mut()
            .find(|existing| existing.same_resource(&failure))
        {
            *existing = failure.clone();
        } else {
            next.push(failure.clone());
        }
        Arc::new(next)
    });
}

fn remove_bind_failures(
    snapshot: &arc_swap::ArcSwap<Vec<StreamBindFailure>>,
    identities: &[NamespacedResourceId],
) {
    snapshot.rcu(|current| {
        Arc::new(
            current
                .iter()
                .filter(|failure| {
                    !identities.iter().any(|identity| {
                        identity.namespace == failure.namespace && identity.id == failure.proxy_id
                    })
                })
                .cloned()
                .collect(),
        )
    });
}

fn merge_bind_failures(base: &mut Vec<StreamBindFailure>, additional: &[StreamBindFailure]) {
    for failure in additional {
        if let Some(existing) = base
            .iter_mut()
            .find(|existing| existing.same_resource(failure))
        {
            *existing = failure.clone();
        } else {
            base.push(failure.clone());
        }
    }
}

/// Proxy fields needed to derive the same runtime listener key that
/// [`StreamListenerManager::reconcile`] uses in `effective_desired`.
struct StreamListenerKeyCandidate {
    identity: NamespacedResourceId,
    port: u16,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
    has_hosts: bool,
    has_stream_match: bool,
    /// Whether reconcile may represent this generated Service listener with
    /// the shared `__nwudp_{port}` socket instead of its individual runtime
    /// key. Readiness must recognize the reconciled shared handle or a healthy
    /// same-port NodeWaypoint UDP group can never complete startup.
    node_waypoint_udp_destination_member: bool,
}

/// Whether a stream proxy belongs to the **opaque-TLS SNI routing plane**: it
/// never terminates or re-originates TLS, so a client's ClientHello reaches the
/// backend verbatim and `server_name` is a usable route predicate.
///
/// Mirrors `Proxy::joins_opaque_tls_sni_plane` on the config type; both must
/// stay in step or a listener would be grouped one way and validated another.
#[inline]
fn joins_sni_plane(passthrough: bool, scheme: BackendScheme, frontend_tls: bool) -> bool {
    passthrough || (!frontend_tls && matches!(scheme, BackendScheme::Tcp))
}

/// Whether a candidate is a member of its port's `__sni_{port}` group.
///
/// A port that carries ANY passthrough candidate keeps the historical
/// membership — the passthrough set alone — so an invalid mixed-shape snapshot
/// that somehow reaches reconcile despite admission validation groups exactly
/// as it always did. Only a port with no passthrough candidate at all forms the
/// new opaque-`tcp` SNI group.
#[inline]
fn sni_group_member(
    port_has_passthrough: bool,
    passthrough: bool,
    scheme: BackendScheme,
    frontend_tls: bool,
) -> bool {
    if port_has_passthrough {
        passthrough
    } else {
        joins_sni_plane(passthrough, scheme, frontend_tls)
    }
}

/// Returns `(sni_group_ports, l4_group_ports)` using the same grouping rules as
/// `reconcile`'s `sni_groups` / `l4_match_groups` construction. Each SNI port
/// maps to whether it carries a passthrough candidate, which is what
/// [`sni_group_member`] needs.
fn stream_listener_group_ports(
    candidates: &[StreamListenerKeyCandidate],
) -> (
    std::collections::HashMap<u16, bool>,
    std::collections::HashSet<u16>,
) {
    // `.0` counts passthrough candidates only (the historical "two passthrough
    // proxies share a port" trigger); `.1` records whether ANY SNI-plane
    // candidate on the port declares `hosts`, which is what promotes an
    // ordinary opaque `tcp` listener onto the SNI routing plane.
    let mut sni_signal_by_port: std::collections::HashMap<u16, (usize, bool)> =
        std::collections::HashMap::new();
    let mut l4_by_port: std::collections::HashMap<u16, (usize, bool)> =
        std::collections::HashMap::new();

    for candidate in candidates {
        if candidate.passthrough {
            let entry = sni_signal_by_port.entry(candidate.port).or_default();
            entry.0 += 1;
            entry.1 |= candidate.has_hosts;
        } else if matches!(candidate.scheme, BackendScheme::Tcp | BackendScheme::Tcps) {
            if candidate.has_hosts
                && joins_sni_plane(false, candidate.scheme, candidate.frontend_tls)
            {
                sni_signal_by_port.entry(candidate.port).or_default().1 = true;
            }
            let entry = l4_by_port.entry(candidate.port).or_default();
            entry.0 += 1;
            entry.1 |= candidate.has_stream_match;
        }
    }

    let sni_ports: std::collections::HashMap<u16, bool> = sni_signal_by_port
        .into_iter()
        .filter(|(_, (passthrough_count, has_hosts))| *passthrough_count > 1 || *has_hosts)
        .map(|(port, (passthrough_count, _))| (port, passthrough_count > 0))
        .collect();

    let l4_ports: std::collections::HashSet<u16> = l4_by_port
        .into_iter()
        .filter(|(port, (count, has_constrained))| {
            *count > 1 && *has_constrained && !sni_ports.contains_key(port)
        })
        .map(|(port, _)| port)
        .collect();

    (sni_ports, l4_ports)
}

fn stream_listener_runtime_key(
    candidate: &StreamListenerKeyCandidate,
    sni_ports: &std::collections::HashMap<u16, bool>,
    l4_ports: &std::collections::HashSet<u16>,
) -> String {
    if sni_ports
        .get(&candidate.port)
        .is_some_and(|port_has_passthrough| {
            sni_group_member(
                *port_has_passthrough,
                candidate.passthrough,
                candidate.scheme,
                candidate.frontend_tls,
            )
        })
    {
        format!("__sni_{}", candidate.port)
    } else if !candidate.passthrough
        && matches!(candidate.scheme, BackendScheme::Tcp | BackendScheme::Tcps)
        && l4_ports.contains(&candidate.port)
    {
        format!("__l4_{}", candidate.port)
    } else {
        candidate.identity.runtime_key()
    }
}

#[cfg(test)]
mod bind_failure_snapshot_tests {
    use super::*;

    #[test]
    fn async_listener_failure_is_appended_to_published_snapshot() {
        // Model the hardest ordering in the spawned listener error path: the
        // task appends before reconcile publishes its base snapshot. The
        // handoff channel must restore the entry that base publication replaces.
        let snapshot = arc_swap::ArcSwap::from_pointee(Vec::new());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let failure = StreamBindFailure {
            namespace: "ferrum".to_string(),
            proxy_id: "async-bind".to_string(),
            listen_port: 9443,
            error: "TCP stream listener task failed: address already in use".to_string(),
            kind: StreamListenerDegradation::BindFailed,
        };
        append_bind_failure(&snapshot, failure.clone());
        tx.send(failure).expect("handoff receiver should be open");

        snapshot.store(Arc::new(Vec::new()));
        while let Ok(failure) = rx.try_recv() {
            append_bind_failure(&snapshot, failure);
        }

        let failures = snapshot.load_full();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].proxy_id, "async-bind");
        assert_eq!(failures[0].listen_port, 9443);
        assert!(matches!(
            failures[0].kind,
            StreamListenerDegradation::BindFailed
        ));
    }

    #[test]
    fn async_listener_failure_survives_later_reconcile_snapshot() {
        let async_failures = arc_swap::ArcSwap::from_pointee(Vec::new());
        let failure = StreamBindFailure {
            namespace: "ferrum".to_string(),
            proxy_id: "async-bind".to_string(),
            listen_port: 9443,
            error: "TCP stream listener task failed: accept loop exited".to_string(),
            kind: StreamListenerDegradation::BindFailed,
        };
        append_bind_failure(&async_failures, failure);

        // A later unrelated reconcile rebuilds its base degradations from the
        // current cycle. Durable asynchronous failures must be merged back in.
        let mut later_reconcile = Vec::new();
        merge_bind_failures(&mut later_reconcile, &async_failures.load_full());

        assert_eq!(later_reconcile.len(), 1);
        assert_eq!(later_reconcile[0].proxy_id, "async-bind");
        assert_eq!(later_reconcile[0].listen_port, 9443);
    }
}

/// One configured stream proxy that wants a listener, resolved from config
/// during [`StreamListenerManager::reconcile`] and keyed by its
/// `(namespace, id)` identity.
struct DesiredStreamProxy {
    /// Stable declaration priority captured before the desired-map erases
    /// `GatewayConfig.proxies` order. Lower values resolve first.
    declaration_order: usize,
    port: u16,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
    stream_proxy_protocol: bool,
    /// Whether the proxy declares `hosts`; a lone passthrough proxy with hosts
    /// still needs SNI resolution so its host predicates are enforced.
    has_hosts: bool,
    /// Whether the proxy carries compiled L4 stream_match predicates. Shared
    /// non-passthrough ports with stream_match form an L4 match group.
    has_stream_match: bool,
    /// Whether this is a Ferrum-generated plain-UDP NodeWaypoint Service
    /// listener (issue #3861). Several may share one numeric port; the shared
    /// socket demultiplexes by exact local destination address.
    node_waypoint_udp_destination_member: bool,
    /// Whether this member publishes at least one exact ClusterIP destination.
    /// A headless member must use its individual direct-node-address listener.
    node_waypoint_udp_has_destination_route: bool,
    /// Validated amplification factor encoded losslessly for cold-path listener
    /// drift detection. `None` is the explicit unlimited posture.
    udp_amplification_factor_bits: Option<u32>,
    backend_tls_reload_key: Option<BackendTlsReloadKey>,
    backend_tls_validation_error: Option<String>,
}

impl DesiredStreamProxy {
    /// Whether this proxy asks for the datagram client-address metadata gate.
    ///
    /// `stream_proxy_protocol` selects the connection-borne PROXY header on
    /// tcp/tcp_tls and the per-datagram DGRAM envelope on udp/dtls; only the
    /// latter is this gate.
    #[inline]
    fn runs_datagram_client_address_gate(&self) -> bool {
        self.stream_proxy_protocol && self.scheme.is_udp()
    }

    /// See [`joins_sni_plane`].
    #[inline]
    fn joins_sni_plane(&self) -> bool {
        joins_sni_plane(self.passthrough, self.scheme, self.frontend_tls)
    }

    /// See [`sni_group_member`].
    #[inline]
    fn is_sni_group_member(&self, port_has_passthrough: bool) -> bool {
        sni_group_member(
            port_has_passthrough,
            self.passthrough,
            self.scheme,
            self.frontend_tls,
        )
    }
}

/// One listener the reconcile pass wants running: either an individual proxy
/// (keyed `namespace|id`) or a shared SNI passthrough group (keyed
/// `__sni_{port}`).
struct DesiredStreamListener {
    /// Exact owning identity for this listener's representative proxy. For SNI
    /// groups this is the first semantic-priority candidate; per-connection
    /// resolution picks the concrete tenant from [`Self::sni_ids`]. Never
    /// inferred and never defaulted — it is carried from the config entry that
    /// produced it.
    identity: NamespacedResourceId,
    port: u16,
    /// Exact OS bind address derived from the reconcile's `current_config`
    /// (dedicated Sidecar ingress override or the manager default). Carried
    /// through preflight and task startup so spawn never reloads config for
    /// the bind after desired-state construction.
    bind_addr: IpAddr,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
    /// Whether this listener runs the datagram client-address metadata gate:
    /// `stream_proxy_protocol: true` on a udp/dtls proxy (issue #3289). Part of
    /// the restart key — the receive loop captures the gate at spawn, so a
    /// toggle must rebuild the listener rather than keep decoding (or not
    /// decoding) under the previous decision.
    ///
    /// The gate's other inputs — receive-boundary protocol (`frontend_tls` /
    /// `passthrough`), `bind_addr`, and `port` — are already restart-key fields
    /// on their own, which is what guarantees a reloaded listener rebuilds the
    /// correct domain binding (issue #3856) instead of inheriting another
    /// listener's, and starts from a fresh replay window (issue #3862).
    datagram_client_address: bool,
    /// Ordered candidate identity + amplification posture. Empty for TCP.
    /// Included in restart identity so policy update/delete retires every
    /// session admitted under the old response budget. Shared NodeWaypoint UDP
    /// groups still store the full member list so a retained Service whose
    /// factor changed can retire sessions; membership add/remove itself stays
    /// out of the restart key and republishes the destination table in place.
    udp_amplification_restart_key: Vec<(NamespacedResourceId, Option<u32>)>,
    backend_tls_reload_key: Option<BackendTlsReloadKey>,
    /// Result of building the complete cached backend TLS config before the
    /// listener-map guard is acquired. `None` means accepted.
    backend_tls_validation_error: Option<String>,
    sni_ids: Option<Vec<NamespacedResourceId>>,
    /// Members of a shared `__nwudp_{port}` NodeWaypoint UDP destination group
    /// (issue #3861), sorted for determinism. `None` for every other listener,
    /// including a first-time single-claimant NodeWaypoint UDP listener (which
    /// keeps the direct-node-address boundary).
    ///
    /// Deliberately excluded from the listener restart key: a membership change
    /// republishes the exact destination table under the running socket. A
    /// previously shared port that shrinks to one remaining VIP claimant MUST
    /// keep this `Some` so the listener key stays `__nwudp_{port}` — dissolving
    /// the group stops the socket and races a rebind of the survivor.
    node_waypoint_udp_ids: Option<Vec<NamespacedResourceId>>,
}

/// Runtime key for a shared NodeWaypoint UDP destination listener.
#[inline]
fn node_waypoint_udp_listener_key(port: u16) -> String {
    format!("__nwudp_{port}")
}

/// Whether a NodeWaypoint UDP destination-plane port should keep (or form) the
/// shared `__nwudp_{port}` listener.
///
/// More than one claimant always shares. A first-time single claimant stays
/// individual so the documented direct-node-address boundary remains. Once
/// that port is already bound under `__nwudp_{port}`, shrinking to one
/// remaining VIP claimant must keep the shared key: dissolving it stops the
/// socket and races a rebind that can leave the survivor unbound (`EADDRINUSE`).
/// A headless survivor has no exact destination route, so it must return to an
/// individual listener rather than retaining an unusable shared router.
#[inline]
fn retain_shared_node_waypoint_udp_listener(
    member_count: usize,
    shared_listener_already_running: bool,
    single_claimant_has_destination_route: bool,
) -> bool {
    member_count > 1
        || (member_count == 1
            && shared_listener_already_running
            && single_claimant_has_destination_route)
}

fn udp_amplification_restart_key_for_ids(
    ids: &[NamespacedResourceId],
    desired: &std::collections::HashMap<NamespacedResourceId, DesiredStreamProxy>,
) -> Vec<(NamespacedResourceId, Option<u32>)> {
    ids.iter()
        .filter_map(|identity| {
            desired.get(identity).and_then(|candidate| {
                candidate
                    .scheme
                    .is_udp()
                    .then_some((identity.clone(), candidate.udp_amplification_factor_bits))
            })
        })
        .collect()
}

/// Restart when amplification posture drifted for a candidate this listener
/// still serves.
///
/// Individual and SNI listeners compare the full ordered key (#3873): SNI
/// membership is already a restart via `sni_ids`. Shared NodeWaypoint UDP
/// groups (#3861) republish membership in place, so only a still-present
/// member whose factor changed may retire the session map.
fn udp_amplification_restart_required(
    old: &[(NamespacedResourceId, Option<u32>)],
    new: &[(NamespacedResourceId, Option<u32>)],
    node_waypoint_shared: bool,
) -> bool {
    if !node_waypoint_shared {
        return old != new;
    }
    let new_by_id: std::collections::HashMap<&NamespacedResourceId, Option<u32>> =
        new.iter().map(|(id, bits)| (id, *bits)).collect();
    old.iter()
        .any(|(id, bits)| new_by_id.get(id).is_some_and(|new_bits| new_bits != bits))
}

#[derive(Debug, serde::Serialize)]
pub struct DtlsDemuxSessionSnapshot {
    pub listener_key: String,
    pub listen_port: u16,
    pub sessions: u64,
}

struct DtlsDemuxMetricEntry {
    listener_key: String,
    listen_port: u16,
    sessions: Arc<AtomicU64>,
}

enum StreamBackendMetricEntry {
    Tcp(Arc<TcpProxyMetrics>),
    Udp(Arc<UdpProxyMetrics>),
}

/// Manages the set of active TCP/UDP stream listeners.
///
/// All state is behind a tokio `Mutex` to serialize reconciliation calls.
/// Reconciliation happens only on config reload — not on the hot request path.
pub struct StreamListenerManager {
    /// Serializes whole reconcile transactions without making the listener-map
    /// guard span asynchronous preparation, socket probes, or task shutdown.
    reconcile_serial: tokio::sync::Mutex<()>,
    listeners: Arc<tokio::sync::Mutex<std::collections::HashMap<String, ListenerHandle>>>,
    dtls_metrics: arc_swap::ArcSwap<Vec<DtlsDemuxMetricEntry>>,
    stream_backend_metrics: arc_swap::ArcSwap<Vec<StreamBackendMetricEntry>>,
    /// Structured snapshot of the most recent `reconcile()`'s stream-listener
    /// bind failures plus durable asynchronous listener-task failures.
    /// Published at the end of every reconcile (startup and runtime/CP-pushed),
    /// lock-free via `ArcSwap`, and surfaced in the admin `/overload` response.
    /// In DP mode these binds are non-fatal, so this is the operator-facing
    /// counterpart to the per-failure warn log.
    bind_failures: Arc<arc_swap::ArcSwap<Vec<StreamBindFailure>>>,
    /// Listener-task failures persist independently of reconcile snapshots so
    /// a later reconcile cannot erase a failure reported by an older task.
    /// Entries clear when the proxy is removed or a replacement is spawned.
    async_bind_failures: Arc<arc_swap::ArcSwap<Vec<StreamBindFailure>>>,
    bind_addr: IpAddr,
    config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    dns_cache: DnsCache,
    request_epoch: Arc<RequestEpochStore>,
    circuit_breaker_cache: Arc<CircuitBreakerCache>,
    health_checker: Arc<HealthChecker>,
    /// Frontend TLS config for TCP stream proxies with `frontend_tls: true`.
    /// Uses `Arc<ArcSwap<...>>` so the **same** slot can be cloned into every
    /// TCP accept loop and snapshotted per accept. This lets mesh
    /// PeerAuthentication live reload swap the slot once and have every
    /// active TCP+TLS listener pick up the new `ServerConfig` on the next
    /// handshake without rebinding the listener. The TLS config may also be
    /// loaded after `ProxyState::new()` (e.g., file mode where TLS certs are
    /// validated after the proxy state is built).
    frontend_tls_config: Arc<arc_swap::ArcSwap<Option<Arc<rustls::ServerConfig>>>>,
    /// DTLS frontend source identity for UDP stream proxies with
    /// `frontend_tls: true`. Stored as a single ArcSwap payload so cert/key
    /// and optional client-CA source strings are published atomically to
    /// reconcile() and listener startup. Live-reloaded crypto bytes live in
    /// [`Self::frontend_dtls_generation`]; these strings identify the sources
    /// only and are never logged as secret material.
    frontend_dtls_material: arc_swap::ArcSwap<Option<(String, String, Option<String>)>>,
    /// Last accepted immutable frontend DTLS material generation. Live reload
    /// and startup both publish here after validating a complete candidate so
    /// every active `DtlsServer` and every listener created afterwards observe
    /// the same generation. A rejected candidate never replaces this slot.
    frontend_dtls_generation:
        Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::FrontendDtlsGeneration>>>>,
    /// Monotonic counter backing [`crate::dtls::FrontendDtlsGeneration::generation`].
    frontend_dtls_generation_counter: AtomicU64,
    /// Serializes the complete generation publish and active-listener swap so
    /// concurrent ordinary frontend DTLS rotations cannot publish an older
    /// generation after a newer one.
    frontend_dtls_publish: Arc<tokio::sync::Mutex<()>>,
    /// Redacted reload status for admin/metrics (no PEM, keys, or secret URIs).
    frontend_dtls_reload_status: arc_swap::ArcSwap<FrontendDtlsReloadStatus>,
    /// Last accepted **owner-scoped** DTLS generation for generated
    /// `MeshNodeWaypoint` listeners (issue #3858).
    ///
    /// Deliberately a SEPARATE slot from [`Self::frontend_dtls_generation`]:
    /// a mesh `PeerAuthentication` / client-CA / CRL change may only reach
    /// listeners the mesh itself generated. Ordinary operator `FERRUM_DTLS_*`
    /// listeners keep byte-identical identity and verifier state across every
    /// mesh slice apply, and no mesh generation may seed or overwrite the
    /// ordinary slot. Both publications share
    /// [`Self::frontend_dtls_publish`], so a collector can never pair one
    /// owner's handle with another owner's generation.
    mesh_node_waypoint_dtls_generation:
        Arc<arc_swap::ArcSwap<Option<Arc<MeshNodeWaypointDtlsGeneration>>>>,
    /// Monotonic counter backing [`MeshNodeWaypointDtlsGeneration::generation`].
    mesh_node_waypoint_dtls_generation_counter: AtomicU64,
    /// Redacted owner-scoped DTLS reload status (no PEM, keys, or source paths).
    mesh_node_waypoint_dtls_reload_status: arc_swap::ArcSwap<FrontendDtlsReloadStatus>,
    /// Live exact destination route tables for shared `__nwudp_{port}`
    /// NodeWaypoint UDP listeners (issue #3861), keyed by listen port.
    ///
    /// Only touched on the cold reconcile path (never awaited across), so a
    /// plain `std::sync::Mutex` is correct here; the datagram hot path reads
    /// the router's own `ArcSwap` snapshot lock-free.
    node_waypoint_udp_routers: std::sync::Mutex<
        std::collections::HashMap<
            u16,
            Arc<crate::proxy::node_waypoint_udp_destination::NodeWaypointUdpDestinationRouter>,
        >,
    >,
    /// Global override to disable backend TLS certificate verification.
    tls_no_verify: bool,
    /// Global CA bundle path for outbound TLS verification (fallback when proxy has no per-proxy CA).
    tls_ca_bundle_path: Option<String>,
    /// Global default TCP idle timeout in seconds (per-proxy `tcp_idle_timeout_seconds` overrides).
    tcp_idle_timeout_seconds: u64,
    /// Hard cap (seconds) on Phase 2 of the TCP bidirectional relay.
    /// Bounds the half-close drain even when `tcp_idle_timeout_seconds = 0`.
    tcp_half_close_max_wait_seconds: u64,
    /// Frontend TLS handshake timeout in seconds for TCP+TLS stream listeners.
    frontend_tls_handshake_timeout_seconds: u64,
    /// Maximum concurrent UDP sessions per proxy.
    udp_max_sessions: usize,
    /// UDP session cleanup interval in seconds.
    udp_cleanup_interval_seconds: u64,
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    tls_policy: Option<Arc<TlsPolicy>>,
    /// Certificate Revocation Lists for backend TLS verification. Swappable:
    /// `reload_backend_tls_material` pushes freshly loaded CRLs through
    /// [`Self::set_crls`] before reconciling, so restarted listeners compile
    /// the rotated revocation list instead of the startup snapshot.
    crls: arc_swap::ArcSwapAny<crate::tls::CrlList>,
    /// Adaptive buffer tracker for dynamic copy buffer and batch limit sizing.
    adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
    /// Number of datagrams per `recvmmsg` syscall on Linux.
    udp_recvmmsg_batch_size: usize,
    /// Normalized shard count for hot UDP session maps.
    pool_shard_amount: usize,
    /// Whether TCP Fast Open is enabled for TCP stream proxy sockets.
    tcp_fastopen_enabled: bool,
    /// Listen backlog for TCP stream proxy sockets.
    tcp_listen_backlog: u32,
    /// Number of duplicated exclusive-listen TCP stream accept loops.
    accept_threads: usize,
    /// Server-side TCP Fast Open queue length for TCP stream proxy sockets.
    tcp_fastopen_queue_len: u16,
    /// Shared overload state for connection accounting and load shedding.
    overload: Arc<crate::overload::OverloadState>,
    /// Enable kTLS for splice on TLS paths.
    ktls_enabled: bool,
    /// Enable io_uring-based splice.
    io_uring_splice_enabled: bool,
    /// Whether frontend TCP TLS handshake failures should increment mesh mTLS metrics.
    record_mesh_mtls_metric: bool,
    /// `FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK`: whether an opaque-TLS SNI
    /// listener may route provably non-TLS opening bytes to its catch-all
    /// instead of closing the connection.
    ///
    /// Stored as an atomic rather than a constructor argument because the
    /// production `EnvConfig` is available only at
    /// [`Self::set_stream_sni_plaintext_fallback`] time, and because the value
    /// is read once per listener spawn (never on the per-connection hot path).
    /// Defaults to fail-closed, so a manager built without the setter — every
    /// test harness — behaves like a gateway that never authorized a fallback.
    stream_sni_plaintext_fallback: AtomicBool,
    /// SO_BUSY_POLL duration in microseconds for UDP sockets.
    so_busy_poll_us: u32,
    /// Enable UDP GRO on frontend sockets.
    udp_gro_enabled: bool,
    /// Enable UDP GSO for batched sending.
    udp_gso_enabled: bool,
    /// Enable IP_PKTINFO / IPV6_PKTINFO on frontend UDP sockets.
    udp_pktinfo_enabled: bool,
    /// Global shutdown receiver. When the gateway-wide SIGTERM/SIGINT fires,
    /// every spawned listener observes it via this receiver in addition to the
    /// per-listener `shutdown_tx` (which is only fired on config-driven removal).
    ///
    /// Stored in `ArcSwap` because it is injected after construction by
    /// [`Self::set_global_shutdown_rx`] — `StreamListenerManager` is built
    /// inside `ProxyState::new()` (synchronous) but the watch channel is
    /// created in `main.rs` and threaded into each mode separately.
    global_shutdown_rx: arc_swap::ArcSwap<Option<watch::Receiver<bool>>>,
    /// Backend TLS reload epoch shared with every spawned UDP/DTLS listener.
    /// `reload_backend_tls_material` bumps it (via
    /// [`Self::bump_backend_tls_reload_epoch`]) after backend cert/key/CA
    /// bytes change in place, so listener-local backend DTLS config caches —
    /// keyed by paths/options, which cannot observe content rotation — drop
    /// entries built from the pre-rotation material. TCP listeners use the
    /// config-path-based `BackendTlsReloadKey` restart instead.
    backend_tls_reload_epoch: Arc<AtomicU64>,
    /// Mesh `outboundTrafficPolicy: REGISTRY_ONLY` enforcement slot shared
    /// with `ProxyState`. Each spawned TCP / UDP listener gets the same
    /// `Arc<ArcSwap<...>>` so slice updates that swap the contents are
    /// observed without restarting the listener. `None` outside mesh mode
    /// — readers short-circuit on the contained `Option::None`.
    mesh_outbound_enforcement:
        crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
    /// Immutable trusted gateway binding parsed during EnvConfig admission.
    /// Cloned into TCP listener/accept state as an `Arc` pointer only.
    stream_gateway_ref: Option<Arc<str>>,
    /// Node-waypoint identity resolver shared with `ProxyState`. Present only
    /// in `NodeWaypoint` topology; `None` everywhere else. When set, each
    /// spawned **TCP** stream accept loop resolves the accepted connection's
    /// socket cookie to a source pod identity and stamps the per-pod
    /// `PolicyScopeCache` onto `StreamConnectionContext.node_waypoint_policy_scope`
    /// so `mesh_authz` enforces namespace/selector-scoped policies per source
    /// pod (parity with the HTTP/HBONE path in `src/proxy/mod.rs`).
    ///
    /// Stored in `ArcSwap` because it is injected after construction by
    /// [`Self::set_node_waypoint_identity_resolver`] — the manager is built
    /// inside `ProxyState::new()` (synchronous) while the resolver is created
    /// later in the mesh runtime, before the first `reconcile()`.
    ///
    /// UDP/DTLS listeners deliberately do NOT consume this: node-waypoint
    /// capture is socket-cookie based on per-connection TCP sockets
    /// (`connect4`/`connect6` cgroup hooks), and a shared UDP frontend socket
    /// has no per-source-pod cookie. See [`Self::set_node_waypoint_identity_resolver`].
    node_waypoint_identity_resolver: arc_swap::ArcSwap<Option<Arc<NodeWaypointIdentityResolver>>>,
    /// NodeWaypoint UDP/DTLS per-datagram source-attribution index (issue
    /// #3286). Populated by the mesh runtime in NodeWaypoint topology only;
    /// snapshotted into each UDP listener spawn so a session's source pod is
    /// resolved from the kernel ingress interface + registered source address
    /// before `mesh_authz` evaluates scoped policy.
    node_waypoint_udp_source_index: arc_swap::ArcSwap<
        Option<Arc<crate::proxy::node_waypoint_udp_identity::NodeWaypointUdpSourceIndex>>,
    >,
    /// Service-path steering datapath (issue #3286). Populated by the mesh
    /// runtime in NodeWaypoint topology only. The manager publishes bound
    /// destinations into this instance after a successful listener bind on the
    /// accepted serving generation — never from config preparation.
    node_waypoint_udp_steering: arc_swap::ArcSwap<
        Option<Arc<crate::proxy::node_waypoint_udp_steering::NodeWaypointUdpSteering>>,
    >,
    /// Per-spawn generation for [`ListenerHandle::generation`].
    node_waypoint_udp_listener_generation: AtomicU64,
    /// Serving-owner fence: shutdown clears this under the listener-map lock
    /// before retracting so a bind-success watcher cannot republish after
    /// teardown. Lock order is listener map, then the steering mutex; a
    /// listener task joined under the map lock must not await that map.
    node_waypoint_udp_steering_open: Arc<AtomicBool>,
    /// Test fence: bind-watch after `started`, before the listener-map lock.
    node_waypoint_udp_steer_before_map_hold:
        arc_swap::ArcSwap<Option<Arc<NodeWaypointUdpSteerHold>>>,
    /// Test fence: publication after eligibility, before installing a plan.
    node_waypoint_udp_steer_before_install_hold:
        arc_swap::ArcSwap<Option<Arc<NodeWaypointUdpSteerHold>>>,
    /// Pre-parsed trusted proxy CIDR set (from `FERRUM_TRUSTED_PROXIES`).
    /// Shared with each spawned TCP stream accept loop that has
    /// `stream_proxy_protocol: true`. The accept loop honors the forwarded
    /// address from the PROXY header only when the socket peer belongs to
    /// this set; untrusted peers are rejected outright to prevent IP spoofing.
    /// Empty when `FERRUM_TRUSTED_PROXIES` is not set.
    trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
    /// Shared secret authenticating the datagram client-address envelope
    /// (`FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`, issue #3289), published after
    /// construction by [`Self::set_datagram_client_address_secret`] because the
    /// manager is built before that value is threaded in. `None` leaves
    /// udp/dtls metadata trust resting on `FERRUM_TRUSTED_PROXIES` alone (with
    /// no authenticity and no freshness); it never disables the envelope itself,
    /// so a listener can not silently fall back to the socket peer. Published
    /// once at startup — the secret does not rotate under a live listener.
    datagram_client_address_secret: arc_swap::ArcSwapOption<String>,
    /// The ONE gateway-wide DestinationRule `connectionPool.tcp.maxConnections`
    /// counter, shared with `ProxyState` and therefore with WebSocket, the
    /// pooled multiplexed transports, and reqwest.
    ///
    /// Every spawned TCP stream listener's [`TcpProxyMetrics`] gets a clone of
    /// this exact `Arc`, so a destination's ceiling is per destination — not one
    /// ceiling per stream listener plus another for the whole HTTP family.
    ///
    /// `OnceLock`, not `ArcSwap`: [`Self::attach_backend_conn_limit`] installs
    /// the shared instance once, before the first `reconcile()`, and the value
    /// can never be replaced afterwards. That matters because live
    /// [`crate::backend_conn_limit::BackendConnectionGuard`]s hold `Arc`s into
    /// the counters of whichever limiter admitted them — swapping the limiter on
    /// a config reload or listener restart would strand those guards on an
    /// orphaned map and let the destination be admitted up to `cap` a second
    /// time while the old sessions are still relaying. A manager built without
    /// the attach (focused tests, standalone callers) lazily initializes its
    /// own private limiter on first use, which is safe because nothing else
    /// shares it.
    backend_conn_limit: std::sync::OnceLock<SharedBackendConnectionLimiter>,
}

impl StreamListenerManager {
    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn new(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        request_epoch: Arc<RequestEpochStore>,
        circuit_breaker_cache: Arc<CircuitBreakerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<String>,
        tcp_idle_timeout_seconds: u64,
        tcp_half_close_max_wait_seconds: u64,
        frontend_tls_handshake_timeout_seconds: u64,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
        udp_recvmmsg_batch_size: usize,
        tcp_fastopen_enabled: bool,
        tcp_listen_backlog: u32,
        accept_threads: usize,
        tcp_fastopen_queue_len: u16,
        overload: Arc<crate::overload::OverloadState>,
        ktls_enabled: bool,
        io_uring_splice_enabled: bool,
        record_mesh_mtls_metric: bool,
        so_busy_poll_us: u32,
        udp_gro_enabled: bool,
        udp_gso_enabled: bool,
        udp_pktinfo_enabled: bool,
        trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
    ) -> Self {
        Self::new_with_epoch(
            bind_addr,
            config,
            dns_cache,
            request_epoch,
            circuit_breaker_cache,
            frontend_tls_config,
            tls_no_verify,
            tls_ca_bundle_path,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            frontend_tls_handshake_timeout_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            tls_policy,
            crls,
            adaptive_buffer,
            udp_recvmmsg_batch_size,
            tcp_fastopen_enabled,
            tcp_listen_backlog,
            accept_threads,
            tcp_fastopen_queue_len,
            overload,
            ktls_enabled,
            io_uring_splice_enabled,
            record_mesh_mtls_metric,
            so_busy_poll_us,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
            trusted_proxies,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_epoch(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        request_epoch: Arc<RequestEpochStore>,
        circuit_breaker_cache: Arc<CircuitBreakerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<String>,
        tcp_idle_timeout_seconds: u64,
        tcp_half_close_max_wait_seconds: u64,
        frontend_tls_handshake_timeout_seconds: u64,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
        udp_recvmmsg_batch_size: usize,
        tcp_fastopen_enabled: bool,
        tcp_listen_backlog: u32,
        accept_threads: usize,
        tcp_fastopen_queue_len: u16,
        overload: Arc<crate::overload::OverloadState>,
        ktls_enabled: bool,
        io_uring_splice_enabled: bool,
        record_mesh_mtls_metric: bool,
        so_busy_poll_us: u32,
        udp_gro_enabled: bool,
        udp_gso_enabled: bool,
        udp_pktinfo_enabled: bool,
        trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
    ) -> Self {
        Self::new_with_epoch_and_mesh_enforcement(
            bind_addr,
            config,
            dns_cache,
            request_epoch,
            circuit_breaker_cache,
            frontend_tls_config,
            tls_no_verify,
            tls_ca_bundle_path,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            frontend_tls_handshake_timeout_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            tls_policy,
            crls,
            adaptive_buffer,
            udp_recvmmsg_batch_size,
            tcp_fastopen_enabled,
            tcp_listen_backlog,
            accept_threads,
            tcp_fastopen_queue_len,
            overload,
            ktls_enabled,
            io_uring_splice_enabled,
            record_mesh_mtls_metric,
            so_busy_poll_us,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
            0,
            Arc::new(HealthChecker::new()),
            crate::modes::mesh::outbound_enforcement::empty_slot(),
            None,
            trusted_proxies,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_epoch_and_mesh_enforcement(
        bind_addr: IpAddr,
        config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
        dns_cache: DnsCache,
        request_epoch: Arc<RequestEpochStore>,
        circuit_breaker_cache: Arc<CircuitBreakerCache>,
        frontend_tls_config: Option<Arc<rustls::ServerConfig>>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<String>,
        tcp_idle_timeout_seconds: u64,
        tcp_half_close_max_wait_seconds: u64,
        frontend_tls_handshake_timeout_seconds: u64,
        udp_max_sessions: usize,
        udp_cleanup_interval_seconds: u64,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        adaptive_buffer: Arc<crate::adaptive_buffer::AdaptiveBufferTracker>,
        udp_recvmmsg_batch_size: usize,
        tcp_fastopen_enabled: bool,
        tcp_listen_backlog: u32,
        accept_threads: usize,
        tcp_fastopen_queue_len: u16,
        overload: Arc<crate::overload::OverloadState>,
        ktls_enabled: bool,
        io_uring_splice_enabled: bool,
        record_mesh_mtls_metric: bool,
        so_busy_poll_us: u32,
        udp_gro_enabled: bool,
        udp_gso_enabled: bool,
        udp_pktinfo_enabled: bool,
        pool_shard_amount: usize,
        health_checker: Arc<HealthChecker>,
        mesh_outbound_enforcement:
            crate::modes::mesh::outbound_enforcement::SharedMeshOutboundEnforcement,
        stream_gateway_ref: Option<Arc<str>>,
        trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
    ) -> Self {
        Self {
            reconcile_serial: tokio::sync::Mutex::new(()),
            listeners: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            dtls_metrics: arc_swap::ArcSwap::new(Arc::new(Vec::new())),
            stream_backend_metrics: arc_swap::ArcSwap::new(Arc::new(Vec::new())),
            bind_failures: Arc::new(arc_swap::ArcSwap::new(Arc::new(Vec::new()))),
            async_bind_failures: Arc::new(arc_swap::ArcSwap::new(Arc::new(Vec::new()))),
            bind_addr,
            config,
            dns_cache,
            request_epoch,
            circuit_breaker_cache,
            health_checker,
            frontend_tls_config: Arc::new(arc_swap::ArcSwap::new(Arc::new(frontend_tls_config))),
            frontend_dtls_material: arc_swap::ArcSwap::new(Arc::new(None)),
            frontend_dtls_generation: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            frontend_dtls_generation_counter: AtomicU64::new(0),
            frontend_dtls_publish: Arc::new(tokio::sync::Mutex::new(())),
            frontend_dtls_reload_status: arc_swap::ArcSwap::new(Arc::new(
                FrontendDtlsReloadStatus::default(),
            )),
            mesh_node_waypoint_dtls_generation: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            mesh_node_waypoint_dtls_generation_counter: AtomicU64::new(0),
            mesh_node_waypoint_dtls_reload_status: arc_swap::ArcSwap::new(Arc::new(
                FrontendDtlsReloadStatus::default(),
            )),
            node_waypoint_udp_routers: std::sync::Mutex::new(std::collections::HashMap::new()),
            tls_no_verify,
            tls_ca_bundle_path,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            frontend_tls_handshake_timeout_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            tls_policy,
            crls: arc_swap::ArcSwapAny::new(crls),
            adaptive_buffer,
            udp_recvmmsg_batch_size,
            pool_shard_amount: crate::util::sharding::pool_shard_amount(pool_shard_amount),
            tcp_fastopen_enabled,
            tcp_listen_backlog,
            accept_threads,
            tcp_fastopen_queue_len,
            overload,
            ktls_enabled,
            io_uring_splice_enabled,
            record_mesh_mtls_metric,
            so_busy_poll_us,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
            global_shutdown_rx: arc_swap::ArcSwap::new(Arc::new(None)),
            backend_tls_reload_epoch: Arc::new(AtomicU64::new(0)),
            mesh_outbound_enforcement,
            stream_gateway_ref,
            node_waypoint_identity_resolver: arc_swap::ArcSwap::new(Arc::new(None)),
            node_waypoint_udp_source_index: arc_swap::ArcSwap::new(Arc::new(None)),
            node_waypoint_udp_steering: arc_swap::ArcSwap::new(Arc::new(None)),
            node_waypoint_udp_listener_generation: AtomicU64::new(0),
            node_waypoint_udp_steering_open: Arc::new(AtomicBool::new(true)),
            node_waypoint_udp_steer_before_map_hold: arc_swap::ArcSwap::new(Arc::new(None)),
            node_waypoint_udp_steer_before_install_hold: arc_swap::ArcSwap::new(Arc::new(None)),
            trusted_proxies,
            datagram_client_address_secret: arc_swap::ArcSwapOption::empty(),
            backend_conn_limit: std::sync::OnceLock::new(),
            stream_sni_plaintext_fallback: AtomicBool::new(false),
        }
    }

    /// Publish `FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK`.
    ///
    /// Call after [`Self::new`] and BEFORE the first `reconcile()`: each TCP
    /// listener snapshots the value at spawn, so a listener started earlier
    /// keeps the fail-closed default until it is rebound. Not calling it at all
    /// leaves every SNI listener fail-closed, which is the secure default.
    pub fn set_stream_sni_plaintext_fallback(&self, enabled: bool) {
        self.stream_sni_plaintext_fallback
            .store(enabled, Ordering::Release);
    }

    /// Publish the datagram client-address envelope's MAC key.
    ///
    /// Must be called after [`Self::new`] and BEFORE the first `reconcile()`, so
    /// no udp/dtls listener is spawned with a gate that would accept
    /// unauthenticated metadata this deployment configured a secret for.
    ///
    /// The configured bytes are published verbatim. Only an entirely empty
    /// value is unset: trimming would either key listeners with different bytes
    /// than `EnvConfig::validate_datagram_proxy_protocol_secret` accepted, or
    /// turn a whitespace-only secret into no authentication requirement at all.
    pub fn set_datagram_client_address_secret(&self, secret: Option<String>) {
        let secret = secret.filter(|value| !value.is_empty());
        self.datagram_client_address_secret
            .store(secret.map(Arc::new));
    }

    /// Install the ONE gateway-wide `connectionPool.tcp.maxConnections` counter
    /// so raw-TCP stream listeners admit backend sockets on the same
    /// per-destination lane as WebSocket, the pooled multiplexed transports and
    /// reqwest — rather than each listener enforcing its own private copy of the
    /// cap.
    ///
    /// Must be called after [`Self::new`] and BEFORE the first `reconcile()`, so
    /// no listener is ever spawned with the private fallback limiter. Idempotent
    /// and one-shot: a later call (config reload, listener restart) is ignored,
    /// which is what guarantees that live guards held by in-flight relays keep
    /// counting against the limiter that admitted them.
    pub fn attach_backend_conn_limit(&self, limiter: SharedBackendConnectionLimiter) {
        let _ = self.backend_conn_limit.set(limiter);
    }

    /// The limiter every spawned TCP listener's metrics share.
    ///
    /// Falls back to a lazily created private limiter when nothing was attached
    /// (focused tests, standalone callers). The fallback is created once and
    /// then reused, so even in that mode every listener under this manager still
    /// shares one ceiling.
    fn backend_conn_limit(&self) -> SharedBackendConnectionLimiter {
        self.backend_conn_limit
            .get_or_init(|| {
                let shards = self.pool_shard_amount;
                Arc::new(BackendConnectionLimiter::with_shard_amount(shards))
            })
            .clone()
    }

    /// Inject the gateway-wide shutdown receiver. Each subsequently spawned
    /// stream listener (TCP/UDP/DTLS) will observe SIGTERM/SIGINT through this
    /// receiver in addition to its private per-listener channel, so accept
    /// loops exit promptly during graceful drain.
    ///
    /// Must be called once per mode after [`Self::new`] and BEFORE the first
    /// `reconcile()` so listeners that bind on initial startup pick up the
    /// receiver. Listeners spawned by later reconciles also pick it up via
    /// the `ArcSwap` load.
    pub fn set_global_shutdown_rx(&self, rx: watch::Receiver<bool>) {
        self.global_shutdown_rx.store(Arc::new(Some(rx)));
    }

    /// Bump the backend TLS reload epoch shared with UDP/DTLS listeners.
    ///
    /// Called by `reload_backend_tls_material` after backend cert/key/CA
    /// bytes were validated and swapped, so listener-local backend DTLS
    /// config caches rebuild from the rotated material on the next session
    /// instead of serving stale params until restart.
    pub fn bump_backend_tls_reload_epoch(&self) {
        self.backend_tls_reload_epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Publish freshly loaded CRLs so subsequent reconciles fingerprint and
    /// rebuild against the rotated revocation list instead of the startup
    /// snapshot. Call BEFORE `reconcile()` — the reload key folds in the CRL
    /// content fingerprint, so the swap is what makes a CRL-only rotation
    /// register as backend-TLS drift and restart TCP+TLS listeners.
    pub fn set_crls(&self, crls: crate::tls::CrlList) {
        self.crls.store(crls);
    }

    /// Inject the node-waypoint identity resolver shared with `ProxyState`.
    ///
    /// Mesh `NodeWaypoint` runtime calls this once after building the resolver
    /// and BEFORE the first stream-listener `reconcile()`, so TCP listeners
    /// that bind on initial startup already see it; listeners spawned by later
    /// reconciles also pick it up via the `ArcSwap` load. Cloning the resolved
    /// `Arc` into each TCP accept loop lets that loop resolve the accepted
    /// connection's `SO_COOKIE` to a source pod identity and stamp the per-pod
    /// `PolicyScopeCache`, mirroring the HTTP/HBONE admit path.
    ///
    /// Scope is strictly `NodeWaypoint`: only that topology installs a
    /// resolver, so Sidecar/Ambient/east-west/egress and non-mesh stream
    /// proxies continue to pass `node_waypoint_policy_scope: None` and behave
    /// exactly as before.
    ///
    /// TCP consumes this resolver through the per-connection socket-cookie
    /// bridge. UDP/DTLS has no useful per-client cookie on its shared frontend
    /// socket, so it consumes the same resolver only after the separate
    /// ingress-interface/source-address index attributes a datagram to a pod;
    /// see [`Self::set_node_waypoint_udp_source_index`].
    pub fn set_node_waypoint_identity_resolver(&self, resolver: Arc<NodeWaypointIdentityResolver>) {
        self.node_waypoint_identity_resolver
            .store(Arc::new(Some(resolver)));
    }

    /// Install the NodeWaypoint UDP/DTLS source-attribution index (issue
    /// #3286).
    ///
    /// Called once by the mesh `NodeWaypoint` runtime before the first
    /// stream-listener `reconcile()`, alongside
    /// [`Self::set_node_waypoint_identity_resolver`]. UDP/DTLS listeners
    /// snapshot the slot at spawn and resolve every session's source pod from
    /// the kernel-provided ingress interface plus the node-agent-published
    /// source address, then stamp the pod's `PolicyScopeCache` so `mesh_authz`
    /// enforces namespace/selector-scoped policies per source workload. An
    /// unattributable datagram leaves the scope absent and `mesh_authz` denies
    /// the session — there is no mesh-wide fallback while scoped enforcement
    /// applies.
    ///
    /// Scope is strictly `NodeWaypoint`: every other topology and non-mesh UDP
    /// proxy keeps `None` and behaves exactly as before.
    pub fn set_node_waypoint_udp_source_index(
        &self,
        index: Arc<crate::proxy::node_waypoint_udp_identity::NodeWaypointUdpSourceIndex>,
    ) {
        self.node_waypoint_udp_source_index
            .store(Arc::new(Some(index)));
    }

    /// Install the NodeWaypoint UDP/DTLS Service-path steering instance.
    ///
    /// Must be called after [`Self::new`] and BEFORE the first `reconcile()`,
    /// alongside [`Self::set_node_waypoint_udp_source_index`]. `None` (the
    /// default) leaves the Service path unsteered.
    pub fn set_node_waypoint_udp_steering(
        &self,
        steering: Arc<crate::proxy::node_waypoint_udp_steering::NodeWaypointUdpSteering>,
    ) {
        self.node_waypoint_udp_steering
            .store(Arc::new(Some(steering)));
    }

    /// Recompute the serving steering plan from the accepted config and the
    /// listeners that are actually bound. Safe to call without a prior
    /// `reconcile()` — an empty listener set publishes nothing.
    pub async fn sync_node_waypoint_udp_steering(&self) {
        self.publish_serving_node_waypoint_udp_steering(&std::collections::HashSet::new())
            .await;
    }

    /// Test seam: pause bind-watch after `started` (before the map lock) and/or
    /// pause plan installation after eligibility so a concurrent failure or
    /// shutdown can be sequenced deterministically.
    #[allow(dead_code)] // External unit tests.
    pub fn set_node_waypoint_udp_steer_holds_for_test(
        &self,
        before_map: Option<Arc<NodeWaypointUdpSteerHold>>,
        before_install: Option<Arc<NodeWaypointUdpSteerHold>>,
    ) {
        self.node_waypoint_udp_steer_before_map_hold
            .store(Arc::new(before_map));
        self.node_waypoint_udp_steer_before_install_hold
            .store(Arc::new(before_install));
    }

    /// Test seam: `(runtime key, generation, started flag)` for each NodeWaypoint
    /// UDP owner currently in the listener map.
    #[allow(dead_code)] // External unit tests.
    pub async fn node_waypoint_udp_listener_owners_for_test(
        &self,
    ) -> Vec<(String, u64, Arc<AtomicBool>)> {
        let listeners = self.listeners.lock().await;
        listeners
            .iter()
            .filter(|(_, handle)| handle.node_waypoint_udp_owner)
            .map(|(key, handle)| (key.clone(), handle.generation, handle.started.clone()))
            .collect()
    }

    /// Test seam: accepted destination-table generation, destinations, and
    /// owners for one shared `__nwudp_{port}` router. `None` when that port is
    /// not currently a shared destination group.
    #[allow(dead_code)] // External unit tests.
    pub fn node_waypoint_udp_destination_snapshot_for_test(
        &self,
        port: u16,
    ) -> Option<(
        u64,
        Vec<std::net::IpAddr>,
        Vec<crate::config::db_backend::NamespacedResourceId>,
    )> {
        let routers = self
            .node_waypoint_udp_routers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        routers.get(&port).map(|router| {
            let snapshot = router.snapshot();
            (
                snapshot.generation(),
                snapshot.destinations(),
                snapshot.owners(),
            )
        })
    }

    /// Test seam: run the production listener-exit retraction for `generation`
    /// of `key`. A mismatched generation is a no-op so a failed predecessor
    /// cannot retract a replacement.
    #[allow(dead_code)] // External unit tests.
    pub async fn retract_node_waypoint_udp_listener_generation_for_test(
        &self,
        key: &str,
        generation: u64,
    ) {
        let Some(steering) = self.node_waypoint_udp_steering.load_full().as_ref().clone() else {
            return;
        };
        retract_owned_node_waypoint_udp_listener(
            &self.listeners,
            &self.node_waypoint_udp_steering_open,
            &steering,
            &self.config,
            self.node_waypoint_udp_source_index.load_full().as_ref(),
            key,
            generation,
        )
        .await;
    }

    /// Update the frontend TLS configuration used for TCP stream proxies with `frontend_tls: true`.
    ///
    /// After storing the config, automatically reconciles stream listeners so
    /// any previously deferred TCP listeners (waiting for TLS) are started.
    /// This is safe to call before the first `reconcile()` — the reconcile is
    /// a no-op when there are no stream proxies in the config yet.
    pub async fn set_frontend_tls_config(&self, tls_config: Option<Arc<rustls::ServerConfig>>) {
        let is_some = tls_config.is_some();
        self.frontend_tls_config.store(Arc::new(tls_config));
        // Reconcile to start any listeners that were deferred due to missing TLS config.
        if is_some {
            let failures = self.reconcile().await;
            for (proxy_id, port, err) in &failures {
                warn!(
                    proxy_id = %proxy_id,
                    port = port,
                    "Stream listener failed to bind after TLS config loaded: {}",
                    err
                );
            }
        }
    }

    /// Update the DTLS cert/key sources used for UDP stream proxies with
    /// `frontend_tls: true`.
    ///
    /// After storing the source identity, validates and publishes one immutable
    /// generation (when the material loads), then reconciles stream listeners so
    /// any previously deferred UDP/DTLS listeners start against that generation.
    /// `client_trust_reload_enabled` must match the process-wide frontend TLS
    /// live-reload opt-in. Static DTLS still publishes its crypto generation but
    /// leaves the retirement scope unarmed because no later trust generation can
    /// be accepted without a restart.
    pub async fn set_frontend_dtls_cert_key(
        &self,
        cert_path: String,
        key_path: String,
        client_ca_cert_path: Option<String>,
        client_trust_reload_enabled: bool,
    ) {
        self.frontend_dtls_material.store(Arc::new(Some((
            cert_path.clone(),
            key_path.clone(),
            client_ca_cert_path.clone(),
        ))));
        match crate::dtls::build_frontend_dtls_config(
            &cert_path,
            &key_path,
            client_ca_cert_path.as_deref(),
            &self.crls.load_full(),
        ) {
            Ok(config) => {
                let _ = self
                    .publish_frontend_dtls_generation(config, client_trust_reload_enabled)
                    .await;
            }
            Err(err) => {
                warn!(
                    "Failed to build initial frontend DTLS generation from configured sources: {}; \
                     listeners that need DTLS material remain deferred until a valid generation is published",
                    err
                );
                self.record_frontend_dtls_candidate_failure();
            }
        }
        // Reconcile to start any listeners that were deferred due to missing DTLS config.
        let failures = self.reconcile().await;
        for (proxy_id, port, err) in &failures {
            warn!(
                proxy_id = %proxy_id,
                port = port,
                "Stream listener failed to bind after DTLS config loaded: {}",
                err
            );
        }
    }

    /// Live-swap the frontend TLS `ServerConfig` used by mesh-shared TCP+TLS
    /// stream listeners.
    ///
    /// Unlike [`Self::set_frontend_tls_config`] this does NOT trigger a
    /// reconcile — the slot is shared with every active TCP+TLS accept loop,
    /// which snapshots it per accept. Existing connections keep the
    /// `ServerConfig` they handshake with until they end (rustls consults
    /// the config only at handshake time). New accepts use the swapped
    /// config on the next handshake.
    ///
    /// Used by mesh PeerAuthentication live reload. Ordinary HTTPS / non-mesh
    /// modes continue to use [`Self::set_frontend_tls_config`] at startup
    /// (followed by a static lifetime — those modes do not call swap).
    /// Mesh reload never live-swaps dedicated `FERRUM_DTLS_*` servers.
    pub fn swap_frontend_tls_config(&self, tls_config: Option<Arc<rustls::ServerConfig>>) {
        self.frontend_tls_config.store(Arc::new(tls_config));
    }

    /// Returns a snapshot of the current frontend TLS slot value. Tests use
    /// pointer-equality on the inner `Arc<ServerConfig>` to prove
    /// [`Self::swap_frontend_tls_config`] replaced the slot rather than
    /// mutated in place; non-test callers may also use this to observe the
    /// startup-set frontend TLS config.
    #[allow(dead_code)] // Test / introspection surface.
    pub fn snapshot_frontend_tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.frontend_tls_config.load().as_ref().clone()
    }

    /// Snapshot of the last accepted frontend DTLS generation (if any).
    #[allow(dead_code)] // Test / introspection surface.
    pub fn snapshot_frontend_dtls_generation(
        &self,
    ) -> Option<Arc<crate::dtls::FrontendDtlsGeneration>> {
        self.frontend_dtls_generation.load_full().as_ref().clone()
    }

    /// Test seam for deterministically fencing a collector against a concurrent
    /// generation publish. Production collectors use the same lock through
    /// [`with_current_frontend_dtls_generation`].
    #[doc(hidden)]
    #[allow(dead_code)] // External integration-test seam is unused by the bin test target.
    pub fn frontend_dtls_publish_lock_for_test(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.frontend_dtls_publish)
    }

    /// Test seam that observes the generation exactly as a newly collected
    /// DTLS server does, under the shared publication fence.
    #[doc(hidden)]
    #[allow(dead_code)] // External integration-test seam is unused by the bin test target.
    pub async fn collected_frontend_dtls_generation_for_test(&self) -> Option<u64> {
        with_current_frontend_dtls_generation(
            &self.frontend_dtls_publish,
            &self.frontend_dtls_generation,
            |generation| generation.map(|generation| generation.generation),
        )
        .await
    }

    /// Snapshot live DTLS servers' frontend-config identity for tests.
    ///
    /// Each entry is `(active_config Arc pointer, client certificate required)`.
    /// Pointer equality proves the dedicated `FERRUM_DTLS_*` slot was not
    /// replaced; the boolean is the client-CA policy bit. Established off the
    /// request/datagram hot path under the listener map lock.
    #[doc(hidden)]
    #[allow(dead_code)] // External unit/integration-test seam.
    pub async fn active_dtls_frontend_identities_for_test(&self) -> Vec<(usize, bool)> {
        let listeners = self.listeners.lock().await;
        listeners
            .values()
            .filter_map(|handle| {
                let slot = handle.dtls_server.as_ref()?;
                let snapshot = slot.load();
                let server = snapshot.as_ref().clone()?;
                Some(server.frontend_config_identity_for_test())
            })
            .collect()
    }

    /// Bounded redacted DTLS live-reload status (no secrets or source paths).
    pub fn frontend_dtls_reload_status(&self) -> FrontendDtlsReloadStatus {
        (**self.frontend_dtls_reload_status.load()).clone()
    }

    /// Record a rejected DTLS candidate without replacing the accepted generation.
    pub fn record_frontend_dtls_candidate_failure(&self) {
        self.frontend_dtls_reload_status.rcu(|current| {
            Arc::new(FrontendDtlsReloadStatus {
                generation: current.generation,
                last_swapped_listeners: current.last_swapped_listeners,
                last_success_unix: current.last_success_unix,
                last_failure_unix: unix_now_secs(),
                last_outcome: "rejected",
            })
        });
        // Issue #3857: a refused candidate keeps the last accepted DTLS
        // generation, its verifier and every live session; recording it against
        // the trust scope makes "retained, not silently ignored" observable.
        crate::tls::client_trust::record_rejected_candidate(
            crate::tls::ClientTrustScope::FrontendDtls,
        );
    }

    /// Publish one prevalidated immutable DTLS generation and live-swap it
    /// into every active DTLS server without rebinding sockets.
    ///
    /// The generation is stored first so listeners created or restarted after
    /// this call receive exactly the same material. Existing sessions keep
    /// their handshake snapshot, but the client-trust publication below
    /// retires authenticated sessions when the accepted generation narrows
    /// trust; new handshakes use the accepted generation. This method never
    /// rebuilds from sources — callers must validate the complete candidate
    /// before invoking it.
    ///
    /// `client_trust_reload_enabled=false` publishes and swaps the immutable
    /// DTLS crypto generation without arming per-session client-trust tracking.
    /// This preserves the documented zero-tracking static posture when frontend
    /// live reload is disabled. A real reload and its startup baseline pass
    /// `true`, so the first withdrawal compares against the material originally
    /// served and retires every older authenticated session.
    ///
    /// Returns `(generation, swapped_listener_count)`.
    pub async fn publish_frontend_dtls_generation(
        &self,
        config: crate::dtls::FrontendDtlsConfig,
        client_trust_reload_enabled: bool,
    ) -> (crate::dtls::FrontendDtlsGeneration, usize) {
        let _publish_guard = self.frontend_dtls_publish.lock().await;
        let generation = self
            .frontend_dtls_generation_counter
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let accepted = Arc::new(crate::dtls::FrontendDtlsGeneration { generation, config });
        self.frontend_dtls_generation
            .store(Arc::new(Some(Arc::clone(&accepted))));
        let swapped = self
            .swap_active_dtls_frontend_config(&accepted.config)
            .await;
        self.frontend_dtls_reload_status
            .store(Arc::new(FrontendDtlsReloadStatus {
                generation,
                last_swapped_listeners: swapped as u64,
                last_success_unix: unix_now_secs(),
                last_failure_unix: self.frontend_dtls_reload_status.load().last_failure_unix,
                last_outcome: "accepted",
            }));
        info!(
            dtls_generation = generation,
            swapped_dtls_listeners = swapped,
            "Published frontend DTLS material generation; new DTLS sessions use this generation"
        );
        // Issue #3857. When live reload is enabled, publish the client-trust
        // generation AFTER the material is live in every active `DtlsServer`, so
        // a session that reads the new generation provably snapshotted the new
        // verifier. Static DTLS and a generation with no client-certificate
        // verification leave this scope unarmed and publish no trust identity.
        if client_trust_reload_enabled && let Some(material) = accepted.config.client_trust.clone()
        {
            let publication = crate::tls::client_trust::publish_accepted_material(
                crate::tls::ClientTrustScope::FrontendDtls,
                material,
            );
            if publication.withdrew() {
                warn!(
                    dtls_generation = generation,
                    trust_generation = publication.generation,
                    reason = publication.reason.map(|reason| reason.label()),
                    retired_sessions = publication.retired_sessions,
                    "Frontend client-certificate trust was withdrawn; established DTLS client-certificate sessions were retired"
                );
            }
        }
        ((*accepted).clone(), swapped)
    }

    /// Live-swap a prevalidated `FrontendDtlsConfig` onto every active
    /// **operator-owned** DTLS server held by this manager (does not publish the
    /// shared generation slot — prefer
    /// [`Self::publish_frontend_dtls_generation`]).
    ///
    /// Generated `MeshNodeWaypoint` listeners are deliberately skipped: their
    /// posture is owned by the mesh slice, not by the `FERRUM_DTLS_*`
    /// generation (issue #3858).
    async fn swap_active_dtls_frontend_config(
        &self,
        config: &crate::dtls::FrontendDtlsConfig,
    ) -> usize {
        let mut swapped = 0usize;
        let listeners = self.listeners.lock().await;
        for handle in listeners.values() {
            if handle.dtls_owner.is_mesh_node_waypoint() {
                continue;
            }
            let Some(slot) = handle.dtls_server.as_ref() else {
                continue;
            };
            let snapshot = slot.load();
            let Some(server) = snapshot.as_ref().clone() else {
                // Collector task has not yet published the server (race with
                // bind). Skip — the collector applies the ordinary frontend
                // DTLS generation when the server arrives, and a later
                // ordinary publish re-converges.
                continue;
            };
            server.swap_frontend_config(config.clone());
            swapped += 1;
        }
        swapped
    }

    /// Publish one complete prevalidated **owner-scoped** DTLS generation for
    /// generated `MeshNodeWaypoint` listeners (issue #3858).
    ///
    /// `configs` is the whole accepted candidate set for one mesh slice, keyed
    /// by generated listener runtime key. It is stored first, so a listener
    /// created or restarted after this call receives exactly the same
    /// generation as its already-active peers, then swapped into the matching
    /// active servers. Ordinary operator listeners are never touched, and the
    /// ordinary `FERRUM_DTLS_*` generation slot is never written.
    ///
    /// Callers MUST have built and validated every candidate before invoking
    /// this: a failed build rejects the whole mesh slice upstream so both
    /// owners keep their complete last-good state.
    ///
    /// Returns `(generation, swapped_listener_count)`.
    pub async fn publish_mesh_node_waypoint_dtls_generation(
        &self,
        configs: std::collections::BTreeMap<String, crate::dtls::FrontendDtlsConfig>,
    ) -> (u64, usize) {
        let _publish_guard = self.frontend_dtls_publish.lock().await;
        let generation = self
            .mesh_node_waypoint_dtls_generation_counter
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let accepted = Arc::new(MeshNodeWaypointDtlsGeneration {
            generation,
            configs,
        });
        self.mesh_node_waypoint_dtls_generation
            .store(Arc::new(Some(Arc::clone(&accepted))));
        let mut swapped = 0usize;
        {
            let listeners = self.listeners.lock().await;
            for handle in listeners.values() {
                let DtlsListenerOwner::MeshNodeWaypoint { listener_key } = &handle.dtls_owner
                else {
                    continue;
                };
                let Some(config) = accepted.config_for(listener_key) else {
                    continue;
                };
                let Some(slot) = handle.dtls_server.as_ref() else {
                    continue;
                };
                let snapshot = slot.load();
                let Some(server) = snapshot.as_ref().clone() else {
                    // The collector has not published this server yet; it
                    // applies the accepted owner-scoped generation itself under
                    // this same publish lock when the server arrives.
                    continue;
                };
                server.swap_frontend_config(config.clone());
                swapped += 1;
            }
        }
        self.mesh_node_waypoint_dtls_reload_status
            .store(Arc::new(FrontendDtlsReloadStatus {
                generation,
                last_swapped_listeners: swapped as u64,
                last_success_unix: unix_now_secs(),
                last_failure_unix: self
                    .mesh_node_waypoint_dtls_reload_status
                    .load()
                    .last_failure_unix,
                last_outcome: "accepted",
            }));
        info!(
            mesh_node_waypoint_dtls_generation = generation,
            covered_listeners = accepted.configs.len(),
            swapped_dtls_listeners = swapped,
            "Published owner-scoped NodeWaypoint DTLS generation; ordinary operator DTLS \
             listeners are untouched"
        );
        (generation, swapped)
    }

    /// Snapshot of the last accepted owner-scoped NodeWaypoint DTLS generation.
    #[allow(dead_code)] // Test / introspection surface.
    pub fn snapshot_mesh_node_waypoint_dtls_generation(
        &self,
    ) -> Option<Arc<MeshNodeWaypointDtlsGeneration>> {
        self.mesh_node_waypoint_dtls_generation
            .load_full()
            .as_ref()
            .clone()
    }

    /// Bounded redacted owner-scoped DTLS reload status.
    #[allow(dead_code)] // Test / introspection surface.
    pub fn mesh_node_waypoint_dtls_reload_status(&self) -> FrontendDtlsReloadStatus {
        (**self.mesh_node_waypoint_dtls_reload_status.load()).clone()
    }

    /// Record a rejected owner-scoped DTLS candidate without replacing the
    /// accepted generation.
    pub fn record_mesh_node_waypoint_dtls_candidate_failure(&self) {
        self.mesh_node_waypoint_dtls_reload_status.rcu(|current| {
            Arc::new(FrontendDtlsReloadStatus {
                generation: current.generation,
                last_swapped_listeners: current.last_swapped_listeners,
                last_success_unix: current.last_success_unix,
                last_failure_unix: unix_now_secs(),
                last_outcome: "rejected",
            })
        });
    }

    /// Reconcile active listeners against the current config.
    ///
    /// - Starts listeners for new stream proxies (TCP and UDP)
    /// - Stops listeners for removed stream proxies
    /// - Restarts listeners whose port or protocol changed
    ///
    /// Returns a list of `(proxy_id, port, error_message)` for any listeners
    /// that failed to start due to port binding errors. An empty vec means all
    /// listeners started successfully.
    pub async fn reconcile(&self) -> Vec<(String, u16, String)> {
        let _reconcile_guard = self.reconcile_serial.lock().await;
        // Every configured stream listener that is not serving after this
        // reconcile — hard bind failures AND deferred/degraded skips — is
        // accumulated here and published to the `/overload` snapshot. The
        // startup path's hard-failure list is derived from this at the end
        // (deferred skips are excluded from the return value so a listener
        // merely waiting on TLS material never fails startup).
        let mut degraded: Vec<StreamBindFailure> = Vec::new();
        // Spawned listeners bind asynchronously after the pre-bind probe. A
        // task can therefore fail before this reconcile publishes its base
        // snapshot. The channel bridges that publication race; the task also
        // appends directly so failures that happen after reconcile returns
        // remain visible without requiring another config update.
        let (async_failure_tx, mut async_failure_rx) =
            tokio::sync::mpsc::unbounded_channel::<StreamBindFailure>();
        let current_config = self.config.load_full();
        // Fingerprint the active CRL list once per reconcile: it is folded
        // into every TCP+TLS reload key so a CRL rotation (published via
        // `set_crls`) registers as backend-TLS drift.
        let active_crl_fingerprint = crl_list_fingerprint(&self.crls.load_full());
        // Collect all desired stream proxies from config, keyed by the full
        // `(namespace, id)` identity. Two namespaces may reuse one proxy ID (IDs
        // are unique only per namespace), so a bare-ID key would silently drop
        // one tenant's listener and attach the survivor's runtime state to the
        // wrong namespace (issue #3094).
        let mut desired = std::collections::HashMap::new();
        for (declaration_order, proxy) in current_config.proxies.iter().enumerate() {
            if !proxy.dispatch_kind.is_stream() {
                continue;
            }
            let Some(port) = proxy.listen_port else {
                continue;
            };
            let prepares_backend_tls = proxy.dispatch_kind
                == crate::config::types::DispatchKind::TcpTls
                && !proxy.passthrough;
            let backend_tls_reload_key = if prepares_backend_tls {
                Some(
                    BackendTlsReloadKey::from_proxy(
                        proxy,
                        self.tls_ca_bundle_path.as_deref(),
                        active_crl_fingerprint.as_deref(),
                    )
                    .await,
                )
            } else {
                None
            };
            let backend_tls_validation_error = if prepares_backend_tls {
                self.prepare_backend_tls_config(proxy, port).await.err()
            } else {
                None
            };
            desired.insert(
                NamespacedResourceId::new(proxy.namespace.clone(), proxy.id.clone()),
                DesiredStreamProxy {
                    declaration_order,
                    port,
                    scheme: proxy.effective_scheme(),
                    frontend_tls: proxy.frontend_tls,
                    passthrough: proxy.passthrough,
                    stream_proxy_protocol: proxy.stream_proxy_protocol.unwrap_or(false),
                    has_hosts: !proxy.hosts.is_empty(),
                    has_stream_match: proxy
                        .stream_match
                        .as_ref()
                        .is_some_and(|matcher| !matcher.is_empty()),
                    node_waypoint_udp_destination_member: proxy
                        .joins_node_waypoint_udp_destination_plane(),
                    node_waypoint_udp_has_destination_route: current_config
                        .node_waypoint_udp_destination_routes
                        .iter()
                        .any(|route| {
                            route.proxy.namespace == proxy.namespace && route.proxy.id == proxy.id
                        }),
                    udp_amplification_factor_bits: proxy
                        .udp_max_response_amplification_factor
                        .map(f32::to_bits),
                    backend_tls_reload_key,
                    backend_tls_validation_error,
                },
            );
        }
        // `OwnedMutexGuard` is never used: this ordinary Tokio `MutexGuard` is
        // acquired only after every source await and prepared-config build.
        let listeners = self.listeners.lock().await;
        let listener_candidates_compatible = |ids: &[NamespacedResourceId]| {
            let Some(first) = ids.first().and_then(|id| desired.get(id)) else {
                return false;
            };
            ids.iter().all(|id| {
                desired.get(id).is_some_and(|entry| {
                    entry.scheme == first.scheme
                        && entry.frontend_tls == first.frontend_tls
                        && entry.stream_proxy_protocol == first.stream_proxy_protocol
                        && entry.backend_tls_reload_key == first.backend_tls_reload_key
                })
            })
        };
        let mut incompatible_shared_ids: std::collections::HashSet<NamespacedResourceId> =
            std::collections::HashSet::new();

        // Detect port groups that must be resolved by opaque-TLS SNI, keyed by
        // "__sni_{port}". Two triggers, matching `stream_listener_group_ports`:
        //
        //   * more than one `passthrough` proxy shares the port (historical), or
        //   * any SNI-plane candidate on the port declares `hosts` — including a
        //     lone one, so its host predicates are enforced instead of becoming
        //     a port-wide catch-all, and including an ordinary opaque `tcp`
        //     listener, which relays the ClientHello verbatim and can therefore
        //     be SNI-routed without terminating TLS (issue #3264).
        //
        // Grouping is by port because the OS port is the shared resource: a port
        // may legitimately be shared by proxies from different namespaces
        // (per-namespace uniqueness allows it). Candidates therefore stay
        // namespace-qualified so SNI resolution selects the right tenant.
        let mut sni_signal_by_port: std::collections::HashMap<u16, (usize, bool)> =
            std::collections::HashMap::new();
        for entry in desired.values() {
            if entry.passthrough {
                let signal = sni_signal_by_port.entry(entry.port).or_default();
                signal.0 += 1;
                signal.1 |= entry.has_hosts;
            } else if entry.has_hosts && entry.joins_sni_plane() {
                sni_signal_by_port.entry(entry.port).or_default().1 = true;
            }
        }
        let sni_ports: std::collections::HashMap<u16, bool> = sni_signal_by_port
            .into_iter()
            .filter(|(_, (passthrough_count, has_hosts))| *passthrough_count > 1 || *has_hosts)
            .map(|(port, (passthrough_count, _))| (port, passthrough_count > 0))
            .collect();
        // Every member candidate on an SNI port joins the shared listener,
        // hosts or not: a hostless candidate is the group's catch-all, and
        // leaving it outside would give it its own listener on an already-bound
        // port. Validation guarantees at most one such catch-all.
        let mut sni_groups: std::collections::HashMap<u16, Vec<NamespacedResourceId>> =
            std::collections::HashMap::new();
        for (identity, entry) in &desired {
            if sni_ports
                .get(&entry.port)
                .is_some_and(|port_has_passthrough| {
                    entry.is_sni_group_member(*port_has_passthrough)
                })
            {
                sni_groups
                    .entry(entry.port)
                    .or_default()
                    .push(identity.clone());
            }
        }
        for ids in sni_groups.values() {
            if ids.len() > 1 && !listener_candidates_compatible(ids) {
                incompatible_shared_ids.extend(ids.iter().cloned());
            }
        }
        sni_groups.retain(|_, ids| listener_candidates_compatible(ids));
        // Preserve config/translator declaration order for semantic
        // first-match-wins resolution. Identity is only a deterministic tie
        // breaker for synthetic/hand-authored inputs that somehow share a
        // declaration priority.
        for ids in sni_groups.values_mut() {
            ids.sort_by(|a, b| {
                let a_entry = desired.get(a);
                let b_entry = desired.get(b);
                a_entry
                    .map(|entry| entry.declaration_order)
                    .cmp(&b_entry.map(|entry| entry.declaration_order))
                    .then_with(|| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)))
            });
        }

        // Non-passthrough TCP L4 match groups: every compatible proxy on a port
        // participates once at least one candidate is constrained. This keeps
        // the single validated catch-all inside the shared listener instead of
        // letting it collide with the constrained listener at bind time.
        let mut l4_match_groups: std::collections::HashMap<u16, Vec<NamespacedResourceId>> =
            std::collections::HashMap::new();
        for (identity, entry) in &desired {
            if !entry.passthrough
                && matches!(entry.scheme, BackendScheme::Tcp | BackendScheme::Tcps)
            {
                l4_match_groups
                    .entry(entry.port)
                    .or_default()
                    .push(identity.clone());
            }
        }
        for ids in l4_match_groups.values() {
            let has_constrained = ids
                .iter()
                .any(|id| desired.get(id).is_some_and(|entry| entry.has_stream_match));
            if ids.len() > 1 && has_constrained && !listener_candidates_compatible(ids) {
                incompatible_shared_ids.extend(ids.iter().cloned());
            }
        }
        l4_match_groups.retain(|port, ids| {
            ids.len() > 1
                && ids
                    .iter()
                    .any(|id| desired.get(id).is_some_and(|entry| entry.has_stream_match))
                && listener_candidates_compatible(ids)
                && !sni_groups.contains_key(port)
        });
        for ids in l4_match_groups.values_mut() {
            ids.sort_by(|a, b| {
                let a_entry = desired.get(a);
                let b_entry = desired.get(b);
                // VirtualService tcp[] rules are evaluated in declaration
                // order. An unconstrained rule is normally authored last, but
                // if it is authored first it intentionally shadows later
                // rules; silently moving it behind constrained candidates
                // changes Istio's first-match semantics.
                a_entry
                    .map(|entry| entry.declaration_order)
                    .cmp(&b_entry.map(|entry| entry.declaration_order))
                    .then_with(|| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)))
            });
        }

        // NodeWaypoint UDP destination groups (issue #3861): several generated
        // plain-UDP Service listeners legitimately share one numeric port on a
        // `hostNetwork` node. They form one shared `__nwudp_{port}` listener and
        // are demultiplexed by exact local destination address.
        //
        // A port with exactly ONE claimant that has never been a shared group
        // stays an individual listener: that is the documented
        // direct-node-address boundary, where a datagram addressed to a node IP
        // (not to a ClusterIP) is still served because the port names exactly
        // one Service. Grouping it would refuse that traffic for lack of an
        // exact Service destination.
        //
        // A port already bound as `__nwudp_{port}` must stay on that key when
        // membership shrinks to one remaining VIP claimant. Dissolving the
        // group changes the listener key, stops the shared socket, and races a
        // rebind of the survivor — hosted NodeWaypoint eBPF live proved that
        // rebind can fail `EADDRINUSE` and leave Service B unbound after A is
        // retracted (`node_waypoint.udp.same_port_demux_retract_a_keeps_b`).
        let existing_shared_node_waypoint_udp_ports: std::collections::HashSet<u16> = listeners
            .iter()
            .filter(|(key, handle)| {
                *key == &node_waypoint_udp_listener_key(handle.listen_port)
                    && handle.scheme.is_udp()
                    && !handle.join_handle.is_finished()
            })
            .map(|(_, handle)| handle.listen_port)
            .collect();
        let mut node_waypoint_udp_groups: std::collections::HashMap<
            u16,
            Vec<NamespacedResourceId>,
        > = std::collections::HashMap::new();
        for (identity, entry) in &desired {
            if entry.node_waypoint_udp_destination_member {
                node_waypoint_udp_groups
                    .entry(entry.port)
                    .or_default()
                    .push(identity.clone());
            }
        }
        node_waypoint_udp_groups.retain(|port, ids| {
            let keep_shared = retain_shared_node_waypoint_udp_listener(
                ids.len(),
                existing_shared_node_waypoint_udp_ports.contains(port),
                ids.first().is_some_and(|id| {
                    desired
                        .get(id)
                        .is_some_and(|entry| entry.node_waypoint_udp_has_destination_route)
                }),
            );
            keep_shared
                && !sni_groups.contains_key(port)
                && !l4_match_groups.contains_key(port)
                && listener_candidates_compatible(ids)
        });
        for ids in node_waypoint_udp_groups.values_mut() {
            // Deterministic, order-independent membership: the representative is
            // only a label and a bind-address source. Every datagram's owner is
            // decided by the destination table, never by this ordering.
            ids.sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
        }

        // Build the effective desired map: individual proxies + SNI/L4 group entries.
        // Proxies in a group are replaced by a single shared-port entry.
        let grouped_proxy_ids: std::collections::HashSet<&NamespacedResourceId> = sni_groups
            .values()
            .chain(l4_match_groups.values())
            .chain(node_waypoint_udp_groups.values())
            .flatten()
            .chain(incompatible_shared_ids.iter())
            .collect();

        for identity in &incompatible_shared_ids {
            if let Some(entry) = desired.get(identity) {
                degraded.push(StreamBindFailure::new(
                    identity,
                    entry.port,
                    "Shared stream listener candidates disagree on pre-routing listener behavior; refusing the entire port",
                    StreamListenerDegradation::BindFailed,
                ));
            }
        }

        let mut effective_desired: std::collections::HashMap<String, DesiredStreamListener> =
            std::collections::HashMap::new();

        for (identity, entry) in &desired {
            if grouped_proxy_ids.contains(identity) {
                continue; // Handled as part of a group below
            }
            let udp_amplification_restart_key = if entry.scheme.is_udp() {
                vec![(identity.clone(), entry.udp_amplification_factor_bits)]
            } else {
                Vec::new()
            };
            effective_desired.insert(
                identity.runtime_key(),
                DesiredStreamListener {
                    identity: identity.clone(),
                    port: entry.port,
                    bind_addr: self.resolve_bind_addr(&current_config, entry.port),
                    scheme: entry.scheme,
                    frontend_tls: entry.frontend_tls,
                    passthrough: entry.passthrough,
                    datagram_client_address: entry.runs_datagram_client_address_gate(),
                    udp_amplification_restart_key,
                    backend_tls_reload_key: entry.backend_tls_reload_key.clone(),
                    backend_tls_validation_error: entry.backend_tls_validation_error.clone(),
                    sni_ids: None,
                    node_waypoint_udp_ids: None,
                },
            );
        }
        for (port, ids) in &node_waypoint_udp_groups {
            let key = node_waypoint_udp_listener_key(*port);
            let Some(representative) = ids.first() else {
                continue;
            };
            if let Some(entry) = desired.get(representative) {
                let udp_amplification_restart_key =
                    udp_amplification_restart_key_for_ids(ids, &desired);
                effective_desired.insert(
                    key,
                    DesiredStreamListener {
                        identity: representative.clone(),
                        port: entry.port,
                        bind_addr: self.resolve_bind_addr(&current_config, entry.port),
                        scheme: entry.scheme,
                        frontend_tls: entry.frontend_tls,
                        passthrough: false,
                        datagram_client_address: entry.runs_datagram_client_address_gate(),
                        udp_amplification_restart_key,
                        backend_tls_reload_key: entry.backend_tls_reload_key.clone(),
                        backend_tls_validation_error: entry.backend_tls_validation_error.clone(),
                        sni_ids: None,
                        // Deliberately NOT part of the restart key: membership
                        // changes republish the destination table in place, so
                        // adding Service B never withdraws Service A's socket
                        // and removing A never interrupts B — including when
                        // B is the last remaining claimant. Amplification
                        // factor changes on a still-present member still
                        // retire the shared session map (#3873).
                        node_waypoint_udp_ids: Some(ids.clone()),
                    },
                );
            }
        }
        for (port, ids) in &sni_groups {
            let key = format!("__sni_{}", port);
            // Use the first semantic-priority candidate as the listener's
            // representative; the accept path re-resolves the concrete tenant
            // per connection from `sni_ids`.
            let Some(representative) = ids.first() else {
                continue;
            };
            if let Some(entry) = desired.get(representative) {
                let udp_amplification_restart_key =
                    udp_amplification_restart_key_for_ids(ids, &desired);
                effective_desired.insert(
                    key,
                    DesiredStreamListener {
                        identity: representative.clone(),
                        port: entry.port,
                        bind_addr: self.resolve_bind_addr(&current_config, entry.port),
                        scheme: entry.scheme,
                        frontend_tls: entry.frontend_tls,
                        passthrough: entry.passthrough,
                        datagram_client_address: entry.runs_datagram_client_address_gate(),
                        udp_amplification_restart_key,
                        backend_tls_reload_key: entry.backend_tls_reload_key.clone(),
                        backend_tls_validation_error: entry.backend_tls_validation_error.clone(),
                        sni_ids: Some(ids.clone()),
                        node_waypoint_udp_ids: None,
                    },
                );
            }
        }
        for (port, ids) in &l4_match_groups {
            let key = format!("__l4_{}", port);
            let Some(representative) = ids.first() else {
                continue;
            };
            if let Some(entry) = desired.get(representative) {
                effective_desired.insert(
                    key,
                    DesiredStreamListener {
                        identity: representative.clone(),
                        port: entry.port,
                        bind_addr: self.resolve_bind_addr(&current_config, entry.port),
                        scheme: entry.scheme,
                        frontend_tls: entry.frontend_tls,
                        passthrough: false,
                        datagram_client_address: entry.runs_datagram_client_address_gate(),
                        udp_amplification_restart_key: Vec::new(),
                        backend_tls_reload_key: entry.backend_tls_reload_key.clone(),
                        backend_tls_validation_error: entry.backend_tls_validation_error.clone(),
                        // Reuse the candidate-id channel. `tcp_proxy`
                        // distinguishes an L4 match group from an SNI group by
                        // inspecting the candidates themselves: an L4 group is
                        // reachable only when the port carries no passthrough
                        // candidate and no candidate declares `hosts` (either
                        // would have promoted the port to `__sni_{port}` above),
                        // so "any candidate is passthrough or declares hosts"
                        // is exactly the SNI-group predicate.
                        sni_ids: Some(ids.clone()),
                        node_waypoint_udp_ids: None,
                    },
                );
            }
        }

        // Exact destination routes for shared same-port NodeWaypoint UDP
        // listeners (issue #3861). Published BEFORE any listener is started,
        // stopped or restarted, so a socket is never briefly serving from an
        // unpublished or stale table, and so an already-running listener picks
        // up an added/removed/updated Service by table republication instead of
        // a rebind. Ports that left the shared group entirely (no remaining
        // destination-plane member) are retracted and their routers dropped;
        // shrinking to one remaining claimant keeps the router and republishes.
        let shared_node_waypoint_udp_ports: std::collections::HashSet<u16> = effective_desired
            .values()
            .filter(|entry| entry.node_waypoint_udp_ids.is_some())
            .map(|entry| entry.port)
            .collect();
        self.retire_unused_node_waypoint_udp_routers(&shared_node_waypoint_udp_ports);
        for entry in effective_desired.values() {
            let Some(ids) = entry.node_waypoint_udp_ids.as_ref() else {
                continue;
            };
            let router = self.node_waypoint_udp_router(entry.port);
            self.publish_node_waypoint_udp_routes(&router, &current_config, ids);
        }

        // Drop durable task failures only when their configured proxy has
        // disappeared. Failures for still-desired proxies survive unrelated
        // reconciles until the listener is actually rebound below. Retention is
        // namespace-qualified so removing one tenant's proxy cannot keep (or
        // clear) another tenant's same-ID failure entry.
        self.async_bind_failures.rcu(|current| {
            Arc::new(
                current
                    .iter()
                    .filter(|failure| {
                        desired.contains_key(&NamespacedResourceId::new(
                            failure.namespace.clone(),
                            failure.proxy_id.clone(),
                        ))
                    })
                    .cloned()
                    .collect(),
            )
        });

        // Stop listeners for removed proxies or changed config
        let mut to_remove = Vec::new();
        for (key, handle) in listeners.iter() {
            // A listener task that already exited is dead capacity. The
            // spawned task's own TLS prebuild or socket bind can fail AFTER
            // reconcile's validation + port probe passed (TOCTOU: material
            // rotated away or the port was grabbed in the window), and the
            // accept loop itself can return an error. The handle's keys still
            // match the desired config, so without this check every later
            // reconcile would see no drift and never restart the dead
            // listener. Treat a finished task as drifted: drop the handle and
            // let the start loop below re-validate and re-bind. Failures
            // surface in the `degraded` snapshot and are retried on the next
            // reconcile; this never crashes reconcile.
            if handle.join_handle.is_finished() {
                warn!(
                    listener_key = %key,
                    port = handle.listen_port,
                    scheme = %handle.scheme,
                    "Stream listener task exited; scheduling restart on this reconcile"
                );
                to_remove.push(key.clone());
                continue;
            }

            let Some(DesiredStreamListener {
                identity,
                port,
                bind_addr,
                scheme,
                frontend_tls,
                passthrough,
                datagram_client_address,
                udp_amplification_restart_key,
                backend_tls_reload_key,
                backend_tls_validation_error,
                sni_ids,
                // Membership of a shared NodeWaypoint UDP destination group is
                // NOT part of the restart key (issue #3861): adding or removing
                // a same-port Service republishes the exact destination table
                // under the running socket instead of rebinding it. Factor
                // changes on a still-present member still restart (#3873).
                node_waypoint_udp_ids,
            }) = effective_desired.get(key)
            else {
                to_remove.push(key.clone());
                continue;
            };

            // Listener identity: a change here means the OLD listener must
            // stop serving regardless of whether its replacement can start
            // (e.g. a port move with broken TLS material must still release
            // the old port).
            let identity_changed = handle.listen_port != *port
                || handle.bind_addr != *bind_addr
                || handle.scheme != *scheme
                || handle.frontend_tls != *frontend_tls
                || handle.passthrough != *passthrough
                // The datagram client-address gate is captured at spawn, so
                // enabling or disabling it must restart the listener.
                || handle.datagram_client_address != *datagram_client_address
                // UDP sessions copy their amplification factor at admission.
                // Retire the whole listener/session map when any served
                // candidate's factor changes so policy tightening or deletion
                // applies to the next datagram even from an existing source.
                // Shared NodeWaypoint UDP groups ignore membership churn here.
                || udp_amplification_restart_required(
                    &handle.udp_amplification_restart_key,
                    udp_amplification_restart_key,
                    node_waypoint_udp_ids.is_some(),
                )
                // SNI-group membership change on a shared passthrough
                // port: the running listener captured the old candidate
                // ID list at spawn, so it must be restarted. IDs are
                // semantically ordered at group construction, making this a
                // stable comparison that preserves declaration priority.
                || handle.sni_ids != *sni_ids;
            let backend_tls_changed = handle.backend_tls_reload_key != *backend_tls_reload_key;

            if !identity_changed && !backend_tls_changed {
                continue;
            }

            // In-place backend TLS rotation on an otherwise unchanged TCP+TLS
            // listener: validate the replacement TLS config BEFORE stopping
            // the old listener. If the rotated material is unreadable or
            // invalid, keep the old listener serving with its cached config
            // instead of tearing it down and leaving the port closed. The
            // handle keeps its previous reload key, so every subsequent
            // reconcile re-detects the drift and retries once the material is
            // fixed.
            //
            // The keep-old path applies ONLY to a pure in-place content
            // rotation: the proxy's TLS *source configuration* (verify flag,
            // SAN allow-list, CA / client cert / client key source identity)
            // AND its backend routing fields must both be unchanged, i.e. the
            // only difference is rotated content under the same sources.
            // Decision matrix:
            //
            //   TLS sources | backend routing | new TLS valid | action
            //   ------------+-----------------+---------------+-----------------------------
            //   unchanged   | unchanged       | valid         | restart with fresh config
            //   unchanged   | unchanged       | invalid       | KEEP OLD listener, retry
            //   changed     | (any)           | (any)         | normal teardown + restart;
            //   unchanged   | changed         | (any)         |   invalid TLS -> port closed
            //                                                 |   + bind_failures visible
            //
            // Rationale for the fall-through rows: backend routing
            // (backend_host / backend_port / upstream) is read live per
            // connection from the request epoch, so a single config update can
            // change routing without changing listener identity. Keeping the
            // old listener in that case would pair its stale cached TLS (old
            // client cert / CA) with connections that now route to the NEW
            // backend — a silently persisting hybrid. A deliberate TLS source
            // change with broken material must likewise fail loudly (clean
            // teardown, port closed, failure reported) instead of serving
            // stale material from the previous sources.
            if !identity_changed && *scheme == BackendScheme::Tcps {
                let content_only_rotation =
                    match (&handle.backend_tls_reload_key, backend_tls_reload_key) {
                        (Some(old), Some(new)) => old.same_tls_sources(new),
                        _ => false,
                    };
                let current_routing_key = find_proxy_by_identity(&current_config, identity)
                    .map(|p| StreamBackendRoutingKey::from_proxy(p, &current_config));
                let routing_unchanged = handle.backend_routing_key.is_some()
                    && handle.backend_routing_key == current_routing_key;
                if content_only_rotation
                    && routing_unchanged
                    && let Some(msg) = backend_tls_validation_error.as_ref()
                {
                    error!(
                        namespace = %identity.namespace,
                        proxy_id = %identity.id,
                        port = *port,
                        "Backend TLS material rotated to invalid content; keeping the previous stream listener running: {}",
                        msg
                    );
                    degraded.push(StreamBindFailure::new(
                        identity,
                        *port,
                        format!("{} (kept previous listener running)", msg),
                        StreamListenerDegradation::BackendTlsRotationInvalid,
                    ));
                    continue;
                }
            }

            to_remove.push(key.clone());
        }

        // Retract steering for listeners about to stop BEFORE the sockets go
        // away, so an old rule cannot outlive its listener. New destinations
        // are not added here — they wait until bind succeeds below.
        let exclude: std::collections::HashSet<String> = to_remove.iter().cloned().collect();
        drop(listeners);
        self.publish_serving_node_waypoint_udp_steering(&exclude)
            .await;

        let removed_listeners = {
            let mut listeners = self.listeners.lock().await;
            let mut removed = Vec::new();
            for key in &to_remove {
                if let Some(handle) = listeners.remove(key) {
                    info!(
                        listener_key = %key,
                        port = handle.listen_port,
                        scheme = %handle.scheme,
                        "Stopping stream listener"
                    );
                    let _ = handle.shutdown_tx.send(true);
                    removed.push((key.clone(), handle));
                }
            }
            removed
        };
        for (key, handle) in removed_listeners {
            await_stream_listener_shutdown(&key, handle).await;
        }

        // Start listeners for new or restarted entries
        let mut newly_started_nw_udp: Vec<String> = Vec::new();
        for (key, desired_listener) in &effective_desired {
            if self.listeners.lock().await.contains_key(key) {
                continue;
            }
            let DesiredStreamListener {
                identity,
                port,
                bind_addr,
                scheme,
                frontend_tls,
                passthrough,
                datagram_client_address,
                udp_amplification_restart_key,
                backend_tls_reload_key,
                backend_tls_validation_error,
                sni_ids,
                node_waypoint_udp_ids,
            } = desired_listener;
            // Exact owning identity for this listener, carried from the config
            // entry that produced it (first SNI candidate for a shared group).
            // Never re-derived by scanning and never defaulted.
            let proxy_id = &identity.id;
            // Exact generated-listener ownership, decided from the accepted
            // identity before ANY DTLS material decision, so an operator and a
            // generated listener can never consult the other's generation
            // (issue #3858).
            let node_waypoint_udp_owner = node_waypoint_udp_listener_owner(
                identity,
                *scheme,
                sni_ids.as_ref(),
                node_waypoint_udp_ids.as_ref(),
            );
            let dtls_owner =
                DtlsListenerOwner::from_node_waypoint_flag(identity, node_waypoint_udp_owner);

            // Skip frontend_tls proxies when the required encryption config is not yet loaded.
            // For TCP: needs rustls ServerConfig. For UDP: needs DTLS cert/key paths.
            // The set_frontend_tls_config() / set_frontend_dtls_cert_key() methods
            // automatically call reconcile() after storing the config, so deferred
            // listeners will be started once TLS materials arrive.
            // Passthrough proxies never terminate TLS, so they skip this check entirely.
            if *frontend_tls && !*passthrough {
                if scheme.is_udp() {
                    // A generated NodeWaypoint DTLS listener is covered ONLY by
                    // the owner-scoped generation the accepted mesh slice
                    // published for its exact listener key. It must never fall
                    // back to the ordinary `FERRUM_DTLS_*` generation or
                    // sources: that would serve mesh traffic under an operator
                    // posture the mesh never accepted.
                    let (has_generation, has_sources) = match &dtls_owner {
                        DtlsListenerOwner::MeshNodeWaypoint { listener_key } => {
                            let accepted = self.mesh_node_waypoint_dtls_generation.load_full();
                            let covered = accepted.as_ref().as_ref().is_some_and(|generation| {
                                generation.config_for(listener_key).is_some()
                            });
                            (covered, false)
                        }
                        DtlsListenerOwner::Operator => (
                            self.frontend_dtls_generation.load().is_some(),
                            self.frontend_dtls_material.load().is_some(),
                        ),
                    };
                    if !has_generation && !has_sources {
                        info!(
                            proxy_id = %proxy_id,
                            port = port,
                            "Deferring UDP listener start: frontend_tls requires DTLS cert/key"
                        );
                        degraded.push(StreamBindFailure::new(
                            identity,
                            *port,
                            "Deferred: frontend_tls UDP listener requires DTLS cert/key material \
                             (not yet loaded)",
                            StreamListenerDegradation::FrontendDtlsDeferred,
                        ));
                        continue;
                    }
                } else if self.frontend_tls_config.load().is_none() {
                    info!(
                        proxy_id = %proxy_id,
                        port = port,
                        "Deferring TCP listener start: frontend_tls requires TLS config"
                    );
                    degraded.push(StreamBindFailure::new(
                        identity,
                        *port,
                        "Deferred: frontend_tls TCP listener requires a rustls ServerConfig \
                         (not yet loaded)",
                        StreamListenerDegradation::FrontendTlsDeferred,
                    ));
                    continue;
                }
            }

            // Passthrough listeners never originate backend TLS — raw bytes
            // are relayed — so unreadable backend TLS material (resolved,
            // upstream-supplied, or the global CA bundle) must not block them.
            if *scheme == BackendScheme::Tcps
                && !*passthrough
                && let Some(msg) = backend_tls_validation_error.as_ref()
            {
                error!(
                    namespace = %identity.namespace,
                    proxy_id = %proxy_id,
                    port = *port,
                    "Stream listener backend TLS validation failed: {}",
                    msg
                );
                degraded.push(StreamBindFailure::new(
                    identity,
                    *port,
                    msg,
                    StreamListenerDegradation::BackendTlsInvalid,
                ));
                continue;
            }

            // Pre-check port availability before spawning the listener task.
            // This catches EADDRINUSE early with a clear error rather than having
            // the spawned task fail silently in the background.
            // Use the bind carried on the desired listener — never reload config
            // for the address after desired-state construction.
            let port_val = *port;
            let bind_addr = *bind_addr;
            let probe_addr = std::net::SocketAddr::new(bind_addr, port_val);
            let probe_result = if scheme.is_udp() {
                tokio::net::UdpSocket::bind(probe_addr).await.map(drop)
            } else {
                tokio::net::TcpListener::bind(probe_addr).await.map(drop)
            };
            if let Err(e) = probe_result {
                let msg = format!(
                    "Port {} is already in use on {}: {}",
                    port_val, bind_addr, e
                );
                error!(
                    proxy_id = %proxy_id,
                    port = port_val,
                    "Stream listener bind failed: {}",
                    msg
                );
                degraded.extend(listener_failures(
                    identity,
                    // Shared groups carry their membership in exactly one of
                    // these: SNI groups in `sni_ids`, NodeWaypoint UDP groups
                    // in `node_waypoint_udp_ids`. The clearing side
                    // (`rebound_proxy_ids`) and the async task-failure side
                    // already fan out over both; this synchronous probe
                    // failure must too, or a shared-member bind failure is
                    // reported only for the representative.
                    sni_ids.as_deref().or(node_waypoint_udp_ids.as_deref()),
                    port_val,
                    &msg,
                    StreamListenerDegradation::BindFailed,
                ));
                continue;
            }

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let rebound_proxy_ids = sni_ids
                .clone()
                .or_else(|| node_waypoint_udp_ids.clone())
                .unwrap_or_else(|| vec![identity.clone()]);
            remove_bind_failures(&self.async_bind_failures, &rebound_proxy_ids);
            let proxy_id_owned = proxy_id.clone();
            // Owning namespace for this listener's proxy, carried verbatim from
            // the desired-listener identity built out of the config entry.
            // Runtime state keyed by proxy identity (the adaptive batch-limit
            // EWMA, lifecycle generations) must be namespace-qualified so a
            // same-id proxy in another tenant cannot share or prune it. There is
            // no scan and no default-namespace fallback: an inferred namespace
            // would silently attach one tenant's state to another's.
            let proxy_namespace_owned = identity.namespace.clone();
            let listener_identity = identity.clone();
            let config = self.config.clone();
            let dns_cache = self.dns_cache.clone();
            let request_epoch = self.request_epoch.clone();
            let health_checker = self.health_checker.clone();
            let tls_no_verify = self.tls_no_verify;
            let cb_cache = self.circuit_breaker_cache.clone();
            let started = Arc::new(AtomicBool::new(false));
            let generation = self
                .node_waypoint_udp_listener_generation
                .fetch_add(1, Ordering::Relaxed);
            // Clone the global shutdown receiver (if injected) so the spawned
            // listener observes both per-listener removal AND global SIGTERM.
            let global_shutdown = self.global_shutdown_rx.load().as_ref().clone();

            let (join_handle, tcp_metrics, udp_metrics, dtls_server) = if scheme.is_udp() {
                let started_for_listener = started.clone();
                // UDP or DTLS listener
                // Passthrough proxies forward raw encrypted datagrams — no DTLS termination.
                let frontend_dtls_config = if *frontend_tls && !*passthrough {
                    if let DtlsListenerOwner::MeshNodeWaypoint { listener_key } = &dtls_owner {
                        // Owner-scoped: the accepted mesh generation is the
                        // ONLY source for a generated listener. The deferral
                        // gate above already proved an entry exists; a race
                        // that removes it defers rather than borrowing the
                        // operator generation.
                        let accepted = self.mesh_node_waypoint_dtls_generation.load_full();
                        let owner_config = accepted
                            .as_ref()
                            .as_ref()
                            .and_then(|generation| generation.config_for(listener_key).cloned());
                        match owner_config {
                            Some(config) => Some(config),
                            None => {
                                degraded.push(StreamBindFailure::new(
                                    identity,
                                    *port,
                                    "Deferred: no accepted mesh NodeWaypoint DTLS generation \
                                     covers this generated listener",
                                    StreamListenerDegradation::FrontendDtlsDeferred,
                                ));
                                continue;
                            }
                        }
                    } else if let Some(generation) =
                        self.frontend_dtls_generation.load_full().as_ref()
                    {
                        // Prefer the last accepted immutable generation so a
                        // listener created/restarted after rotation converges
                        // on the same material already live-swapped into
                        // active DTLS servers — never re-read sources here.
                        Some(generation.config.clone())
                    } else {
                        let dtls_material = self.frontend_dtls_material.load();
                        match dtls_material.as_ref() {
                            Some((cert_path, key_path, client_ca_cert_path)) => {
                                match crate::dtls::build_frontend_dtls_config(
                                    cert_path,
                                    key_path,
                                    client_ca_cert_path.as_deref(),
                                    &self.crls.load_full(),
                                ) {
                                    Ok(cfg) => Some(cfg),
                                    Err(e) => {
                                        warn!(
                                            proxy_id = %proxy_id,
                                            "Failed to build frontend DTLS config: {}", e
                                        );
                                        degraded.push(StreamBindFailure::new(
                                            identity,
                                            *port,
                                            format!("Failed to build frontend DTLS config: {}", e),
                                            StreamListenerDegradation::FrontendDtlsBuildFailed,
                                        ));
                                        continue;
                                    }
                                }
                            }
                            None => {
                                // Should not happen — guarded above, but be safe
                                degraded.push(StreamBindFailure::new(
                                    identity,
                                    *port,
                                    "Deferred: frontend DTLS material unavailable at listener spawn",
                                    StreamListenerDegradation::FrontendDtlsDeferred,
                                ));
                                continue;
                            }
                        }
                    }
                } else {
                    None
                };
                let metrics = Arc::new(UdpProxyMetrics::default());
                // Datagram client-address metadata gate (issues #3289, #3856,
                // #3862), built once per listener from the process-wide trust
                // boundary, the optional MAC key, and this listener's exact
                // domain identity: receive-boundary protocol (DTLS-terminating
                // versus plain UDP), canonical bind address, and port. Every
                // component of that identity is already part of the listener
                // restart key, so a reload reconstructs the correct binding —
                // and a fresh replay window — instead of inheriting the
                // previous listener's. `None` unless this proxy opted in, so an
                // ordinary udp/dtls listener keeps its exact prior behavior.
                let datagram_client_address = datagram_client_address.then(|| {
                    use crate::proxy::datagram_client_address::{
                        DatagramClientAddressGate, DatagramListenerBinding,
                        DatagramListenerProtocol,
                    };
                    let protocol = if frontend_dtls_config.is_some() {
                        DatagramListenerProtocol::Dtls
                    } else {
                        DatagramListenerProtocol::Udp
                    };
                    let secret = self.datagram_client_address_secret.load();
                    let gate = DatagramClientAddressGate::new(
                        self.trusted_proxies.clone(),
                        secret.as_deref().map(String::as_str),
                        DatagramListenerBinding::new(protocol, bind_addr, port_val),
                        self.pool_shard_amount,
                    );
                    Arc::new(gate)
                });
                let udp_max_sessions = self.udp_max_sessions;
                let frontend_tls_handshake_timeout = self.frontend_tls_handshake_timeout_seconds;
                let udp_cleanup_interval = self.udp_cleanup_interval_seconds;
                let crls = self.crls.load_full();
                let backend_tls_reload_epoch = self.backend_tls_reload_epoch.clone();
                let tls_ca_bundle_path = self.tls_ca_bundle_path.clone();
                let sni_ids = sni_ids.clone();
                let adaptive_buf = self.adaptive_buffer.clone();
                let recvmmsg_batch = self.udp_recvmmsg_batch_size;
                let session_shards = self.pool_shard_amount;
                let overload = self.overload.clone();
                let so_busy_poll_us = self.so_busy_poll_us;
                let udp_gro_enabled = self.udp_gro_enabled;
                let udp_gso_enabled = self.udp_gso_enabled;
                let udp_pktinfo_enabled = self.udp_pktinfo_enabled;
                let listener_udp_metrics = Some(metrics.clone());
                let global_shutdown_for_listener = global_shutdown.clone();
                let mesh_outbound_enforcement = self.mesh_outbound_enforcement.clone();
                // Snapshot the NodeWaypoint UDP source-attribution slots once
                // per listener spawn (issue #3286). Both are `None` outside
                // NodeWaypoint topology; scoping is only enabled when BOTH are
                // present, because an index without the resolver could attribute
                // a pod but not resolve its per-pod policy scope.
                let node_waypoint_udp_source_index = self
                    .node_waypoint_udp_source_index
                    .load_full()
                    .as_ref()
                    .clone();
                let node_waypoint_identity_resolver_for_udp = self
                    .node_waypoint_identity_resolver
                    .load_full()
                    .as_ref()
                    .clone();
                let node_waypoint_udp_source_scoping = node_waypoint_udp_source_index
                    .zip(node_waypoint_identity_resolver_for_udp)
                    .map(|(index, resolver)| {
                        crate::proxy::node_waypoint_udp_identity::NodeWaypointUdpSourceScoping {
                            index,
                            resolver,
                        }
                    });
                let node_waypoint_udp_steering =
                    self.node_waypoint_udp_steering.load_full().as_ref().clone();
                // Shared same-port Service demultiplexing (issue #3861). The
                // router is created (or reused across a listener restart) and
                // seeded with THIS generation's exact routes before the socket
                // binds, so the very first datagram is already attributable and
                // nothing is ever served from an unpublished table.
                let node_waypoint_udp_destinations = node_waypoint_udp_ids
                    .as_ref()
                    .map(|_| self.node_waypoint_udp_router(*port));
                let bind_failures = Arc::clone(&self.bind_failures);
                let async_bind_failures = Arc::clone(&self.async_bind_failures);
                let async_failure_tx = async_failure_tx.clone();
                let failure_proxy_ids = sni_ids
                    .clone()
                    .or_else(|| node_waypoint_udp_ids.clone())
                    .unwrap_or_else(|| vec![listener_identity.clone()]);
                // Reserve a oneshot so the listener can publish the live
                // `Arc<DtlsServer>` back here once it has bound. Only meaningful
                // for actual DTLS listeners; plain UDP listeners drop the
                // sender unused.
                let (dtls_server_tx, dtls_server_rx) = tokio::sync::oneshot::channel();
                let dtls_server_tx = if *frontend_tls && !*passthrough {
                    Some(dtls_server_tx)
                } else {
                    None
                };
                let started_for_exit = started.clone();
                let listeners_for_exit = Arc::clone(&self.listeners);
                let steering_open_for_exit = Arc::clone(&self.node_waypoint_udp_steering_open);
                let config_for_exit = self.config.clone();
                let source_index_for_exit = self.node_waypoint_udp_source_index.load_full();
                let key_for_exit = key.clone();
                let generation_for_exit = generation;
                let owner_for_exit = node_waypoint_udp_owner;
                let join_handle = tokio::spawn(async move {
                    let result = super::udp_proxy::start_udp_listener(UdpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        proxy_namespace: proxy_namespace_owned,
                        dns_cache,
                        request_epoch,
                        health_checker,
                        shutdown: shutdown_rx,
                        global_shutdown: global_shutdown_for_listener,
                        metrics,
                        frontend_dtls_config,
                        dtls_server_tx,
                        tls_no_verify,
                        tls_ca_bundle_path,
                        max_sessions: udp_max_sessions,
                        frontend_tls_handshake_timeout_seconds: frontend_tls_handshake_timeout,
                        cleanup_interval_seconds: udp_cleanup_interval,
                        circuit_breaker_cache: cb_cache,
                        crls,
                        backend_tls_reload_epoch,
                        started: started_for_listener,
                        sni_proxy_ids: sni_ids,
                        adaptive_buffer: adaptive_buf,
                        recvmmsg_batch_size: recvmmsg_batch,
                        session_shard_amount: session_shards,
                        overload,
                        so_busy_poll_us,
                        udp_gro_enabled,
                        udp_gso_enabled,
                        udp_pktinfo_enabled,
                        mesh_outbound_enforcement,
                        node_waypoint_udp_source_scoping,
                        // Owner-scoped client-trust retirement domain for a
                        // terminating DTLS listener (issue #3858): the same bit
                        // that chose `dtls_owner` above, so the listener an
                        // operator publication deliberately does not
                        // reconfigure is also the listener whose sessions it
                        // cannot retire.
                        node_waypoint_udp_owner,
                        node_waypoint_udp_destinations,
                        datagram_client_address,
                    })
                    .await;
                    started_for_exit.store(false, Ordering::Release);
                    if let Err(e) = result {
                        let msg = format!("UDP stream listener task failed: {e}");
                        error!(
                            proxy_id = %proxy_id_owned,
                            port = port_val,
                            "{}",
                            msg
                        );
                        for failure_identity in &failure_proxy_ids {
                            let failure = StreamBindFailure::new(
                                failure_identity,
                                port_val,
                                msg.clone(),
                                StreamListenerDegradation::BindFailed,
                            );
                            append_bind_failure(&async_bind_failures, failure.clone());
                            append_bind_failure(&bind_failures, failure.clone());
                            let _ = async_failure_tx.send(failure);
                        }
                    }
                    if owner_for_exit && let Some(steering) = node_waypoint_udp_steering {
                        // Do not await the listener map here: reconcile joins this
                        // task while holding that lock. A helper observes the
                        // non-serving mark and generation fence once the owner
                        // releases.
                        tokio::spawn(async move {
                            retract_owned_node_waypoint_udp_listener(
                                &listeners_for_exit,
                                &steering_open_for_exit,
                                &steering,
                                &config_for_exit,
                                source_index_for_exit.as_ref(),
                                &key_for_exit,
                                generation_for_exit,
                            )
                            .await;
                        });
                    }
                });
                // The DTLS server `Arc` will be published shortly after the
                // listener task binds. Stash a shared slot here so the spawned
                // collector task can store it once `start_dtls_frontend_listener`
                // sends. Reconcile does not block waiting for the bind; if an
                // ordinary generation publish fires before the collector
                // resolves, the swap path finds an empty slot and skips it —
                // the collector then applies the accepted generation when the
                // server arrives.
                let dtls_server_slot: Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::DtlsServer>>>> =
                    Arc::new(arc_swap::ArcSwap::from_pointee(None));
                let dtls_server_slot_for_collector = Arc::clone(&dtls_server_slot);
                let generation_slot_for_collector = self.frontend_dtls_generation.clone();
                let mesh_generation_slot_for_collector =
                    self.mesh_node_waypoint_dtls_generation.clone();
                let publish_lock_for_collector = Arc::clone(&self.frontend_dtls_publish);
                let dtls_owner_for_collector = dtls_owner.clone();
                tokio::spawn(async move {
                    if let Ok(server) = dtls_server_rx.await {
                        // Converge a server that bound during a publish race and
                        // expose its handle in the same publication critical
                        // section. Without this fence a collector could snapshot
                        // generation A, a publisher could install B while the
                        // handle was still absent, and the collector could then
                        // expose the server after restoring stale A.
                        //
                        // The generation consulted is the one belonging to THIS
                        // listener's owner. A generated NodeWaypoint listener
                        // never reads the ordinary `FERRUM_DTLS_*` generation,
                        // and an operator listener never reads the mesh one.
                        match &dtls_owner_for_collector {
                            DtlsListenerOwner::MeshNodeWaypoint { listener_key } => {
                                let listener_key = listener_key.clone();
                                with_current_mesh_node_waypoint_dtls_generation(
                                    &publish_lock_for_collector,
                                    &mesh_generation_slot_for_collector,
                                    move |generation| {
                                        if let Some(config) = generation.and_then(|generation| {
                                            generation.config_for(&listener_key)
                                        }) {
                                            server.swap_frontend_config(config.clone());
                                        }
                                        dtls_server_slot_for_collector
                                            .store(Arc::new(Some(server)));
                                    },
                                )
                                .await;
                            }
                            DtlsListenerOwner::Operator => {
                                with_current_frontend_dtls_generation(
                                    &publish_lock_for_collector,
                                    &generation_slot_for_collector,
                                    |generation| {
                                        if let Some(generation) = generation {
                                            server.swap_frontend_config(generation.config.clone());
                                        }
                                        dtls_server_slot_for_collector
                                            .store(Arc::new(Some(server)));
                                    },
                                )
                                .await;
                            }
                        }
                    }
                });
                (
                    join_handle,
                    None,
                    listener_udp_metrics,
                    Some(dtls_server_slot),
                )
            } else {
                let started_for_listener = started.clone();
                // TCP or TcpTls listener
                // Passthrough proxies forward raw encrypted bytes — no TLS termination.
                // Hand the shared TLS slot to the listener so PeerAuth live reload
                // (mesh mode) can swap the inbound TLS config under a running
                // listener; the accept loop snapshots per accept. For listeners
                // that never terminate TLS (passthrough or non-TLS schemes) we
                // hand them a fresh per-listener empty slot so the listener task
                // is unconditionally typed and we don't fork the call path.
                let tls_slot = if *frontend_tls && !*passthrough {
                    Arc::clone(&self.frontend_tls_config)
                } else {
                    Arc::new(arc_swap::ArcSwap::new(Arc::new(None)))
                };
                // Observability counters are listener-local, but the
                // `maxConnections` admission counter is the ONE gateway-wide
                // limiter: a raw-TCP socket and a pooled/WebSocket socket to the
                // same destination must share the configured ceiling, and two
                // stream listeners must not each get their own copy of it.
                let conn_limit = self.backend_conn_limit();
                let metrics = Arc::new(TcpProxyMetrics::with_backend_conn_limit(conn_limit));
                let listener_tcp_metrics = Some(metrics.clone());
                let tcp_idle_timeout = self.tcp_idle_timeout_seconds;
                let tcp_half_close_max_wait = self.tcp_half_close_max_wait_seconds;
                let frontend_tls_handshake_timeout = self.frontend_tls_handshake_timeout_seconds;
                let tls_policy = self.tls_policy.clone();
                let crls = self.crls.load_full();
                let tls_ca_bundle_path = self.tls_ca_bundle_path.clone();
                let sni_ids = sni_ids.clone();
                let adaptive_buf = self.adaptive_buffer.clone();
                let tcp_fastopen = self.tcp_fastopen_enabled;
                let tcp_listen_backlog = self.tcp_listen_backlog;
                let accept_threads = self.accept_threads;
                let tcp_fastopen_queue_len = self.tcp_fastopen_queue_len;
                let overload = self.overload.clone();
                let ktls_enabled = self.ktls_enabled;
                let io_uring_splice_enabled = self.io_uring_splice_enabled;
                let record_mesh_mtls_metric = self.record_mesh_mtls_metric;
                let stream_sni_plaintext_fallback =
                    self.stream_sni_plaintext_fallback.load(Ordering::Acquire);
                let global_shutdown_for_listener = global_shutdown.clone();
                let mesh_outbound_enforcement = self.mesh_outbound_enforcement.clone();
                let stream_gateway_ref = self.stream_gateway_ref.clone();
                // Snapshot the node-waypoint resolver slot once per listener
                // spawn. `None` outside NodeWaypoint topology; when present the
                // accept loop resolves each connection's source pod identity to
                // stamp the per-pod policy scope (TCP only — see
                // `set_node_waypoint_identity_resolver`).
                let node_waypoint_identity_resolver = self
                    .node_waypoint_identity_resolver
                    .load_full()
                    .as_ref()
                    .clone();
                let trusted_proxies = self.trusted_proxies.clone();
                let bind_failures = Arc::clone(&self.bind_failures);
                let async_bind_failures = Arc::clone(&self.async_bind_failures);
                let async_failure_tx = async_failure_tx.clone();
                let failure_proxy_ids = sni_ids
                    .clone()
                    .unwrap_or_else(|| vec![listener_identity.clone()]);
                let join_handle = tokio::spawn(async move {
                    if let Err(e) = super::tcp_proxy::start_tcp_listener(TcpListenerConfig {
                        port: port_val,
                        bind_addr,
                        proxy_id: proxy_id_owned.clone(),
                        proxy_namespace: proxy_namespace_owned,
                        config,
                        dns_cache,
                        request_epoch,
                        health_checker,
                        frontend_tls_slot: tls_slot,
                        shutdown: shutdown_rx,
                        global_shutdown: global_shutdown_for_listener,
                        metrics,
                        tls_no_verify,
                        tls_ca_bundle_path,
                        tcp_idle_timeout_seconds: tcp_idle_timeout,
                        tcp_half_close_max_wait_seconds: tcp_half_close_max_wait,
                        frontend_tls_handshake_timeout_seconds: frontend_tls_handshake_timeout,
                        circuit_breaker_cache: cb_cache,
                        tls_policy,
                        crls,
                        started: started_for_listener,
                        sni_proxy_ids: sni_ids,
                        adaptive_buffer: adaptive_buf,
                        tcp_fastopen_enabled: tcp_fastopen,
                        tcp_listen_backlog,
                        accept_threads,
                        tcp_fastopen_queue_len,
                        overload,
                        ktls_enabled,
                        io_uring_splice_enabled,
                        record_mesh_mtls_metric,
                        stream_sni_plaintext_fallback,
                        mesh_outbound_enforcement,
                        stream_gateway_ref,
                        node_waypoint_identity_resolver,
                        trusted_proxies,
                    })
                    .await
                    {
                        let msg = format!("TCP stream listener task failed: {e}");
                        error!(
                            proxy_id = %proxy_id_owned,
                            port = port_val,
                            "{}",
                            msg
                        );
                        for failure_identity in &failure_proxy_ids {
                            let failure = StreamBindFailure::new(
                                failure_identity,
                                port_val,
                                msg.clone(),
                                StreamListenerDegradation::BindFailed,
                            );
                            append_bind_failure(&async_bind_failures, failure.clone());
                            append_bind_failure(&bind_failures, failure.clone());
                            let _ = async_failure_tx.send(failure);
                        }
                    }
                });
                (join_handle, listener_tcp_metrics, None, None)
            };

            info!(
                listener_key = %key,
                namespace = %identity.namespace,
                proxy_id = %proxy_id,
                port = port,
                scheme = %scheme,
                "Started stream listener"
            );

            // Snapshot routing identity for TCP+TLS listeners so the
            // keep-old-listener path on TLS rotation can verify routing has
            // not drifted since this listener's backend TLS cache was built.
            let backend_routing_key = if backend_tls_reload_key.is_some() {
                find_proxy_by_identity(&current_config, identity)
                    .map(|p| StreamBackendRoutingKey::from_proxy(p, &current_config))
            } else {
                None
            };

            let steer_bind_watch = if node_waypoint_udp_owner {
                self.node_waypoint_udp_steering
                    .load_full()
                    .as_ref()
                    .clone()
                    .map(|steering| (steering, started.clone(), shutdown_tx.subscribe()))
            } else {
                None
            };
            if node_waypoint_udp_owner {
                newly_started_nw_udp.push(key.clone());
            }

            self.listeners.lock().await.insert(
                key.clone(),
                ListenerHandle {
                    shutdown_tx,
                    join_handle,
                    listen_port: *port,
                    bind_addr,
                    scheme: *scheme,
                    frontend_tls: *frontend_tls,
                    passthrough: *passthrough,
                    datagram_client_address: *datagram_client_address,
                    udp_amplification_restart_key: udp_amplification_restart_key.clone(),
                    backend_tls_reload_key: backend_tls_reload_key.clone(),
                    backend_routing_key,
                    sni_ids: sni_ids.clone(),
                    started,
                    tcp_metrics,
                    udp_metrics,
                    dtls_server,
                    generation,
                    node_waypoint_udp_owner,
                    dtls_owner,
                },
            );
            if let Some((steering, started_for_watch, shutdown_rx_for_watch)) = steer_bind_watch {
                spawn_node_waypoint_udp_steer_bind_watch(
                    started_for_watch,
                    shutdown_rx_for_watch,
                    steering,
                    self.config.clone(),
                    self.node_waypoint_udp_source_index.load_full(),
                    Arc::clone(&self.listeners),
                    key.clone(),
                    generation,
                    Arc::clone(&self.node_waypoint_udp_steering_open),
                    self.node_waypoint_udp_steer_before_map_hold.load_full(),
                );
            }
        }

        for key in &newly_started_nw_udp {
            let started = self
                .listeners
                .lock()
                .await
                .get(key)
                .map(|handle| Arc::clone(&handle.started));
            if let Some(started) = started {
                wait_for_listener_started(started, NODE_WAYPOINT_UDP_STEER_BIND_WAIT).await;
            }
        }
        self.publish_serving_node_waypoint_udp_steering(&std::collections::HashSet::new())
            .await;

        let listeners = self.listeners.lock().await;

        let mut dtls_entries: Vec<DtlsDemuxMetricEntry> = listeners
            .iter()
            .filter(|(_, h)| h.frontend_tls)
            .filter_map(|(key, h)| {
                h.udp_metrics.as_ref().map(|m| DtlsDemuxMetricEntry {
                    listener_key: key.clone(),
                    listen_port: h.listen_port,
                    sessions: m.dtls_demux_sessions.clone(),
                })
            })
            .collect();
        dtls_entries.sort_by(|a, b| a.listener_key.cmp(&b.listener_key));
        self.dtls_metrics.store(Arc::new(dtls_entries));

        let stream_backend_entries: Vec<StreamBackendMetricEntry> = listeners
            .values()
            .filter_map(|h| match h.scheme {
                BackendScheme::Tcp | BackendScheme::Tcps => h
                    .tcp_metrics
                    .as_ref()
                    .map(|m| StreamBackendMetricEntry::Tcp(m.clone())),
                BackendScheme::Udp | BackendScheme::Dtls => h
                    .udp_metrics
                    .as_ref()
                    .map(|m| StreamBackendMetricEntry::Udp(m.clone())),
                BackendScheme::Http | BackendScheme::Https => None,
            })
            .collect();
        self.stream_backend_metrics
            .store(Arc::new(stream_backend_entries));
        drop(listeners);

        // Derive the hard bind-failure list returned to callers from the
        // degraded set. Only hard failures (port bind, backend TLS validation,
        // failed in-place rotation) are returned — deferred/skip reasons are
        // published to `/overload` but kept out of the return value so the
        // startup path (fatal in file/db mode) never trips on a listener that
        // is merely waiting for TLS material to arrive.
        let bind_failures: Vec<(String, u16, String)> = degraded
            .iter()
            .filter(|d| d.kind.is_hard_bind_failure())
            .map(|d| (d.proxy_id.clone(), d.listen_port, d.error.clone()))
            .collect();

        // Publish a structured snapshot of this reconcile's non-serving stream
        // listeners for the admin `/overload` surface. Overwrites the previous
        // snapshot so it always reflects the latest reconcile (a resource that
        // starts serving on a later reconcile clears its entry). Empty Vec
        // allocation is cheap and only happens on the cold reconcile path,
        // never per connection.
        merge_bind_failures(&mut degraded, &self.async_bind_failures.load_full());
        self.bind_failures.store(Arc::new(degraded));
        drop(async_failure_tx);
        while let Ok(failure) = async_failure_rx.try_recv() {
            append_bind_failure(&self.bind_failures, failure);
        }

        bind_failures
    }

    /// Get (or create) the exact destination router for one shared
    /// `__nwudp_{port}` listener (issue #3861).
    ///
    /// The router outlives an individual listener restart so a rebind cannot
    /// momentarily serve from an empty table; a port that loses every
    /// destination-plane member has its router retracted and dropped by
    /// [`Self::retire_unused_node_waypoint_udp_routers`]. Shrinking to one
    /// remaining claimant keeps this router and republishes.
    fn node_waypoint_udp_router(
        &self,
        port: u16,
    ) -> Arc<crate::proxy::node_waypoint_udp_destination::NodeWaypointUdpDestinationRouter> {
        let mut routers = self
            .node_waypoint_udp_routers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(routers.entry(port).or_insert_with(|| {
            crate::proxy::node_waypoint_udp_destination::NodeWaypointUdpDestinationRouter::new(port)
        }))
    }

    /// Publish this generation's exact destination routes for one shared
    /// listener.
    ///
    /// Only routes whose owning proxy is an accepted member of THIS listener's
    /// group are installed, so a candidate that materialization refused (mixed
    /// posture, duplicate exact claim, headless on a shared port) can never
    /// reach the datapath. A refused publication retracts the complete table:
    /// the config generation has already been accepted, so retaining its
    /// predecessor's ownership would serve stale routes under the new config.
    fn publish_node_waypoint_udp_routes(
        &self,
        router: &crate::proxy::node_waypoint_udp_destination::NodeWaypointUdpDestinationRouter,
        current_config: &GatewayConfig,
        members: &[NamespacedResourceId],
    ) {
        let port = router.listen_port();
        let member_set: std::collections::HashSet<(&str, &str)> =
            members.iter().map(|id| id.as_key()).collect();
        let routes: Vec<_> = current_config
            .node_waypoint_udp_destination_routes
            .iter()
            .filter(|route| route.listen_port == port && member_set.contains(&route.proxy.as_key()))
            .cloned()
            .collect();
        let route_count = routes.len();
        match router.publish(routes) {
            Ok(generation) => {
                info!(
                    listen_port = port,
                    destination_generation = generation,
                    destination_routes = route_count,
                    services = member_set.len(),
                    "Published exact NodeWaypoint UDP destination routes for a shared same-port \
                     listener; each datagram selects its owning Service from the kernel-reported \
                     local destination before any session, plugin or backend work"
                );
            }
            Err(err) => {
                // Materialization already refuses every ambiguous claimant, so
                // reaching this is a defect rather than operator input. The
                // candidate config is nevertheless already accepted; retract
                // every predecessor route so this generation fails closed
                // rather than retaining stale ownership under new policy.
                let generation = router.retract();
                error!(
                    listen_port = port,
                    destination_generation = generation,
                    "Refusing a NodeWaypoint UDP destination publication and retracting every \
                     exact route for this listener: {}",
                    err
                );
            }
        }
    }

    /// Retract and drop routers for ports that are no longer shared groups.
    ///
    /// Retraction happens BEFORE the router is forgotten, so any listener still
    /// holding it fails closed instead of serving a withdrawn generation.
    fn retire_unused_node_waypoint_udp_routers(&self, live_ports: &std::collections::HashSet<u16>) {
        let mut routers = self
            .node_waypoint_udp_routers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        routers.retain(|port, router| {
            if live_ports.contains(port) {
                return true;
            }
            router.retract();
            false
        });
    }

    /// Publish desired ∩ actually-bound NodeWaypoint UDP destinations into the
    /// serving steering instance, along with whether any owned UDP/DTLS
    /// listener is actually bound. `exclude` are listener keys about to stop,
    /// so their destinations are retracted before the sockets go away and they
    /// do not keep serving state live.
    async fn publish_serving_node_waypoint_udp_steering(
        &self,
        exclude: &std::collections::HashSet<String>,
    ) {
        if !self.node_waypoint_udp_steering_open.load(Ordering::Acquire) {
            return;
        }
        if let Some(hold) = self
            .node_waypoint_udp_steer_before_install_hold
            .load_full()
            .as_ref()
        {
            hold.wait().await;
            if !self.node_waypoint_udp_steering_open.load(Ordering::Acquire) {
                return;
            }
        }
        let Some(steering) = self.node_waypoint_udp_steering.load_full().as_ref().clone() else {
            return;
        };
        let listeners = self.listeners.lock().await;
        publish_bound_node_waypoint_udp_destinations(
            &steering,
            &self.config.load().node_waypoint_udp_steer_destinations,
            self.node_waypoint_udp_source_index.load_full().as_ref(),
            &listeners,
            exclude,
        );
    }

    /// Build-validate the cached backend TLS `ClientConfig` for a TCP+TLS
    /// stream proxy without installing it.
    ///
    /// Used in two places in [`Self::reconcile`]: (1) before tearing down a
    /// running listener whose backend TLS material rotated in place, so an
    /// invalid rotation keeps the old listener serving; (2) before spawning a
    /// new listener, so an invalid config never installs a listener that
    /// would fail every backend handshake. Returns the message to surface in
    /// `bind_failures` on failure.
    async fn prepare_backend_tls_config(&self, proxy: &Proxy, port: u16) -> Result<(), String> {
        let proxy = proxy.clone();
        let tls_no_verify = self.tls_no_verify;
        let tls_ca_bundle_path = self.tls_ca_bundle_path.clone();
        let tls_policy = self.tls_policy.clone();
        let crls = self.crls.load_full();
        match crate::tls::source::run_tls_source_blocking_result(move || {
            super::tcp_proxy::build_cached_backend_tls_config(
                &proxy,
                tls_no_verify,
                tls_ca_bundle_path.as_deref(),
                tls_policy.as_deref(),
                &crls,
            )
            .map(drop)
            .map_err(|error| error.to_string())
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!(
                "Backend TLS config failed for stream listener on port {}: {}",
                port, error
            )),
            Err(error) => Err(format!(
                "Backend TLS config preparation failed for stream listener on port {}: {}",
                port,
                error.failure_class()
            )),
        }
    }

    /// Lightweight stream-listener diagnostics included in the admin `/overload`
    /// response. Lock-free: reads pre-built metric references from an `ArcSwap`
    /// updated during reconciliation, so this never contends with config reloads.
    pub fn overload_snapshot(&self) -> StreamListenerOverloadSnapshot {
        let entries = self.dtls_metrics.load();
        let mut dtls_demux_sessions = Vec::with_capacity(entries.len());
        let mut dtls_demux_sessions_total = 0;

        for entry in entries.iter() {
            let sessions = entry.sessions.load(Ordering::Relaxed);
            dtls_demux_sessions_total += sessions;
            dtls_demux_sessions.push(DtlsDemuxSessionSnapshot {
                listener_key: entry.listener_key.clone(),
                listen_port: entry.listen_port,
                sessions,
            });
        }

        // Read through the public getter so it stays wired into the binary's
        // `/overload` response path (this is the sole non-test caller).
        let bind_failures = self.stream_bind_failures();
        StreamListenerOverloadSnapshot {
            dtls_demux_sessions_total,
            dtls_demux_sessions,
            frontend_dtls_reload: self.frontend_dtls_reload_status(),
            bind_failures_total: bind_failures.len(),
            bind_failures: bind_failures.as_ref().clone(),
        }
    }

    /// Structured snapshot of the most recent `reconcile()`'s non-serving
    /// stream listeners plus subsequent asynchronous listener-task failures
    /// (hard bind failures plus deferred/degraded skips, classified by
    /// [`StreamBindFailure::kind`]). Lock-free `ArcSwap` load; consumed by
    /// [`Self::overload_snapshot`] (the admin `/overload` surface) and by tests.
    /// Empty once every configured stream listener is serving.
    pub fn stream_bind_failures(&self) -> Arc<Vec<StreamBindFailure>> {
        self.bind_failures.load_full()
    }

    /// Estimate active stream backend sockets without including frontend HTTP/WebSocket sessions.
    pub fn active_backend_session_estimate(&self) -> u64 {
        let entries = self.stream_backend_metrics.load();
        active_backend_session_estimate_from_entries(&entries)
    }

    /// `(listener_key, bind_addr)` pairs currently owned by this manager.
    #[allow(dead_code)] // Test / introspection surface.
    pub async fn active_binds(&self) -> Vec<(String, IpAddr)> {
        let listeners = self.listeners.lock().await;
        let mut out: Vec<_> = listeners
            .iter()
            .map(|(key, handle)| (key.clone(), handle.bind_addr))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Resolve the OS bind address for `port` from the reconcile generation's
    /// config (dedicated Sidecar ingress override or the manager default).
    fn resolve_bind_addr(&self, config: &GatewayConfig, port: u16) -> IpAddr {
        config
            .mesh
            .as_ref()
            .and_then(|mesh| mesh.sidecar_ingress_bind_override(port))
            .unwrap_or(self.bind_addr)
    }

    /// Wait until all currently configured stream listeners have successfully
    /// bound and can accept traffic.
    pub async fn wait_until_started(&self, timeout: Duration) -> Result<(), anyhow::Error> {
        let deadline = Instant::now() + timeout;

        loop {
            let current_config = self.config.load();
            let candidates: Vec<StreamListenerKeyCandidate> = current_config
                .proxies
                .iter()
                .filter(|p| p.dispatch_kind.is_stream())
                .filter_map(|p| {
                    p.listen_port.map(|port| StreamListenerKeyCandidate {
                        identity: NamespacedResourceId::new(p.namespace.clone(), p.id.clone()),
                        port,
                        scheme: p.effective_scheme(),
                        frontend_tls: p.frontend_tls,
                        passthrough: p.passthrough,
                        has_hosts: !p.hosts.is_empty(),
                        has_stream_match: p.stream_match.as_ref().is_some_and(|m| !m.is_empty()),
                        node_waypoint_udp_destination_member: p
                            .joins_node_waypoint_udp_destination_plane(),
                    })
                })
                .collect();

            if candidates.is_empty() {
                return Ok(());
            }

            let (sni_ports, l4_ports) = stream_listener_group_ports(&candidates);

            let all_started = {
                let listeners = self.listeners.lock().await;
                candidates.iter().all(|candidate| {
                    // `reconcile()` collapses two or more generated
                    // NodeWaypoint UDP Service listeners onto one
                    // `__nwudp_{port}` handle and deliberately retains that
                    // handle when a VIP-backed group shrinks to one member.
                    // The live listener map is authoritative for that sticky
                    // decision; recomputing only the ordinary SNI/L4 key here
                    // would wait forever on per-proxy handles that reconcile
                    // intentionally did not create.
                    let shared_node_waypoint_udp_key =
                        node_waypoint_udp_listener_key(candidate.port);
                    let key = if candidate.node_waypoint_udp_destination_member
                        && listeners
                            .get(&shared_node_waypoint_udp_key)
                            .is_some_and(|handle| handle.node_waypoint_udp_owner)
                    {
                        shared_node_waypoint_udp_key
                    } else {
                        stream_listener_runtime_key(candidate, &sni_ports, &l4_ports)
                    };
                    listeners.get(&key).is_some_and(|handle| {
                        handle.listen_port == candidate.port
                            && handle.scheme == candidate.scheme
                            && handle.frontend_tls == candidate.frontend_tls
                            && handle.started.load(Ordering::Acquire)
                    })
                })
            };

            if all_started {
                return Ok(());
            }

            if Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "Timed out waiting for stream listeners to complete startup"
                ));
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Shut down all active stream listeners.
    ///
    /// Called from each mode's graceful-shutdown path AFTER HTTP listener
    /// handles have been awaited and BEFORE `wait_for_drain` runs. The
    /// per-listener watch channel fires alongside the global SIGTERM channel
    /// (see [`Self::set_global_shutdown_rx`]) so accept loops exit promptly
    /// regardless of which signal arrives first; calling this here also
    /// ensures the `JoinHandle` set is cleared even when the global channel
    /// is not injected (e.g. unit tests that build a manager standalone).
    pub async fn shutdown_all(&self) {
        let mut listeners = self.listeners.lock().await;
        // Fence watchers under the same ownership boundary as publication:
        // they cannot re-enter once `steering_open` is false and every
        // per-listener shutdown sender has fired. Retract the empty plan
        // while they cannot republish, and only then drop the sockets.
        self.node_waypoint_udp_steering_open
            .store(false, Ordering::Release);
        for handle in listeners.values() {
            let _ = handle.shutdown_tx.send(true);
        }
        if let Some(steering) = self.node_waypoint_udp_steering.load_full().as_ref() {
            steering.shutdown();
        }
        // Retract every exact destination table before the sockets drop, so a
        // datagram racing shutdown cannot still select a route whose serving
        // generation is gone (issue #3861).
        self.retire_unused_node_waypoint_udp_routers(&std::collections::HashSet::new());
        for (listener_key, handle) in listeners.drain() {
            info!(
                listener_key = %listener_key,
                port = handle.listen_port,
                "Shutting down stream listener"
            );
        }
    }
}

fn node_waypoint_udp_listener_owner(
    identity: &NamespacedResourceId,
    scheme: BackendScheme,
    sni_ids: Option<&Vec<NamespacedResourceId>>,
    node_waypoint_udp_ids: Option<&Vec<NamespacedResourceId>>,
) -> bool {
    if !scheme.is_udp() {
        return false;
    }
    // A shared `__nwudp_{port}` group is generated ownership by construction:
    // membership is derived from the reserved id prefix. An individual listener
    // proves ownership from its own identity, exactly as before. An SNI group
    // is never NodeWaypoint-generated.
    if node_waypoint_udp_ids.is_some() {
        return sni_ids.is_none();
    }
    sni_ids.is_none() && crate::modes::mesh::is_node_waypoint_udp_listener_id(&identity.id)
}

fn node_waypoint_udp_published_ifaces(
    source_index: &Option<
        Arc<crate::proxy::node_waypoint_udp_identity::NodeWaypointUdpSourceIndex>,
    >,
) -> Vec<String> {
    source_index
        .as_ref()
        .map(|index| index.published_ifaces())
        .unwrap_or_default()
}

fn publish_bound_node_waypoint_udp_destinations(
    steering: &crate::proxy::node_waypoint_udp_steering::NodeWaypointUdpSteering,
    desired: &[crate::capture::NodeWaypointUdpSteerDestination],
    source_index: &Option<
        Arc<crate::proxy::node_waypoint_udp_identity::NodeWaypointUdpSourceIndex>,
    >,
    listeners: &std::collections::HashMap<String, ListenerHandle>,
    exclude: &std::collections::HashSet<String>,
) {
    let serving_ports: std::collections::HashSet<u16> = listeners
        .iter()
        .filter(|(key, handle)| {
            !exclude.contains(*key)
                && handle.node_waypoint_udp_owner
                && handle.scheme.is_udp()
                && handle.started.load(Ordering::Acquire)
                && !handle.join_handle.is_finished()
        })
        .map(|(_, handle)| handle.listen_port)
        .collect();
    // Serving is bound-listener ownership, not ClusterIP inventory. An empty
    // destination set with `serving == true` is a headless/VIP-less listener
    // whose relay-cgroup sender proof must stay live.
    let serving = !serving_ports.is_empty();
    let destinations: Vec<crate::capture::NodeWaypointUdpSteerDestination> = if serving {
        desired
            .iter()
            .copied()
            .filter(|destination| serving_ports.contains(&destination.port))
            .collect()
    } else {
        Vec::new()
    };
    let ifaces = node_waypoint_udp_published_ifaces(source_index);
    steering.set_bound_destinations(destinations, Some(&ifaces), serving);
}

/// Mark this exact listener generation non-serving and republish the
/// desired ∩ still-owned intersection. A replacement on the same key is
/// left untouched.
async fn retract_owned_node_waypoint_udp_listener(
    listeners: &tokio::sync::Mutex<std::collections::HashMap<String, ListenerHandle>>,
    steering_open: &AtomicBool,
    steering: &crate::proxy::node_waypoint_udp_steering::NodeWaypointUdpSteering,
    config: &arc_swap::ArcSwap<GatewayConfig>,
    source_index: &Option<
        Arc<crate::proxy::node_waypoint_udp_identity::NodeWaypointUdpSourceIndex>,
    >,
    key: &str,
    generation: u64,
) {
    let guard = listeners.lock().await;
    if !steering_open.load(Ordering::Acquire) {
        return;
    }
    if let Some(handle) = guard.get(key) {
        if handle.generation != generation {
            return;
        }
        handle.started.store(false, Ordering::Release);
    }
    publish_bound_node_waypoint_udp_destinations(
        steering,
        &config.load().node_waypoint_udp_steer_destinations,
        source_index,
        &guard,
        &std::collections::HashSet::new(),
    );
}

/// Wait until this NodeWaypoint UDP/DTLS listener actually binds, then publish
/// desired ∩ currently-bound destinations. Taking the listener map lock after
/// `started` means a concurrent reconcile that already withdrew the key cannot
/// be raced into re-steering a socket that is gone. Bind failure / shutdown
/// exits without publishing. A mismatched generation is rejected so a stale
/// watcher cannot republish a replacement.
#[allow(clippy::too_many_arguments)]
fn spawn_node_waypoint_udp_steer_bind_watch(
    started: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
    steering: Arc<crate::proxy::node_waypoint_udp_steering::NodeWaypointUdpSteering>,
    config: Arc<arc_swap::ArcSwap<GatewayConfig>>,
    source_index: Arc<
        Option<Arc<crate::proxy::node_waypoint_udp_identity::NodeWaypointUdpSourceIndex>>,
    >,
    listeners: Arc<tokio::sync::Mutex<std::collections::HashMap<String, ListenerHandle>>>,
    key: String,
    generation: u64,
    steering_open: Arc<AtomicBool>,
    before_map: Arc<Option<Arc<NodeWaypointUdpSteerHold>>>,
) {
    tokio::spawn(async move {
        loop {
            if *shutdown_rx.borrow() {
                return;
            }
            if started.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                _ = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
        }
        if *shutdown_rx.borrow() {
            return;
        }
        if let Some(hold) = before_map.as_ref() {
            hold.wait().await;
        }
        if *shutdown_rx.borrow() || !steering_open.load(Ordering::Acquire) {
            return;
        }
        let guard = listeners.lock().await;
        if *shutdown_rx.borrow() || !steering_open.load(Ordering::Acquire) {
            return;
        }
        let Some(handle) = guard.get(&key) else {
            return;
        };
        if handle.generation != generation
            || !handle.node_waypoint_udp_owner
            || !handle.started.load(Ordering::Acquire)
            || handle.join_handle.is_finished()
        {
            return;
        }
        publish_bound_node_waypoint_udp_destinations(
            &steering,
            &config.load().node_waypoint_udp_steer_destinations,
            source_index.as_ref(),
            &guard,
            &std::collections::HashSet::new(),
        );
    });
}

async fn wait_for_listener_started(started: Arc<AtomicBool>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if started.load(Ordering::Acquire) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

async fn await_stream_listener_shutdown(listener_key: &str, handle: ListenerHandle) {
    let ListenerHandle {
        join_handle,
        listen_port,
        scheme,
        ..
    } = handle;
    let mut join_handle = join_handle;

    match tokio::time::timeout(STREAM_LISTENER_SHUTDOWN_WAIT, &mut join_handle).await {
        Ok(Ok(())) => {
            info!(
                listener_key = %listener_key,
                port = listen_port,
                scheme = %scheme,
                "Stopped stream listener"
            );
        }
        Ok(Err(err)) => {
            warn!(
                listener_key = %listener_key,
                port = listen_port,
                scheme = %scheme,
                "Stream listener task ended with error during restart: {}",
                err
            );
        }
        Err(_) => {
            warn!(
                listener_key = %listener_key,
                port = listen_port,
                scheme = %scheme,
                timeout_ms = STREAM_LISTENER_SHUTDOWN_WAIT.as_millis() as u64,
                "Timed out waiting for stream listener shutdown; aborting task before restart"
            );
            join_handle.abort();
            // Bound the post-abort join too. Abort only takes effect at the
            // task's next await point, so a task wedged in synchronous code
            // would otherwise hang this await — and reconcile holds the
            // listeners mutex, so a single wedged listener would deadlock
            // every future reconcile. Giving up here is safe: reconcile never
            // crashes, and if the old socket is still held the replacement's
            // bind probe fails and skips only the conflicting proxy until the
            // next reconcile.
            if tokio::time::timeout(STREAM_LISTENER_SHUTDOWN_WAIT, &mut join_handle)
                .await
                .is_err()
            {
                warn!(
                    listener_key = %listener_key,
                    port = listen_port,
                    scheme = %scheme,
                    "Stream listener task did not stop after abort; continuing reconcile — the replacement bind may fail until the old socket is released"
                );
            }
        }
    }
}

fn active_backend_session_estimate_from_entries(entries: &[StreamBackendMetricEntry]) -> u64 {
    entries.iter().fold(0u64, |total, entry| {
        let active = match entry {
            StreamBackendMetricEntry::Tcp(metrics) => {
                metrics.active_backend_connections.load(Ordering::Relaxed)
            }
            StreamBackendMetricEntry::Udp(metrics) => {
                metrics.active_sessions.load(Ordering::Relaxed)
            }
        };
        total.saturating_add(active)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    #[test]
    fn active_backend_session_estimate_sums_tcp_and_udp_stream_sessions() {
        let tcp_metrics = Arc::new(TcpProxyMetrics::default());
        let udp_metrics = Arc::new(UdpProxyMetrics::default());
        tcp_metrics.active_connections.store(99, Ordering::Relaxed);
        tcp_metrics
            .active_backend_connections
            .store(2, Ordering::Relaxed);
        udp_metrics.active_sessions.store(3, Ordering::Relaxed);
        let entries = vec![
            StreamBackendMetricEntry::Tcp(tcp_metrics),
            StreamBackendMetricEntry::Udp(udp_metrics),
        ];

        assert_eq!(active_backend_session_estimate_from_entries(&entries), 5);
    }

    #[tokio::test]
    async fn backend_tls_material_reload_key_changes_when_same_path_content_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, b"first-ca").expect("write first ca");
        let ca_path = ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config");

        let first =
            BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle).await;
        std::fs::write(ca_path, b"second-ca").expect("write second ca");
        let second =
            BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle).await;

        assert_eq!(first.source, second.source);
        assert_ne!(
            first.fingerprint, second.fingerprint,
            "same-path backend TLS material rotation must change the reload key"
        );
    }

    #[tokio::test]
    async fn backend_tls_material_reload_key_changes_when_missing_file_appears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        let ca_path = ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config");

        let missing =
            BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle).await;
        std::fs::write(ca_path, b"first-ca").expect("write ca");
        let present =
            BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle).await;

        assert_eq!(missing.source, present.source);
        assert!(
            missing.fingerprint.starts_with("error:"),
            "missing file fingerprint should preserve the load failure state"
        );
        assert!(
            present.fingerprint.starts_with("sha256:"),
            "present file fingerprint should hash the material"
        );
        assert_ne!(missing.fingerprint, present.fingerprint);
    }

    #[tokio::test]
    async fn backend_tls_material_reload_key_file_uri_rotation_changes_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, b"first-ca").expect("write first ca");
        let ca_uri = format!(
            "file://{}",
            ca_path
                .to_str()
                .expect("test temp path must be utf-8 for proxy config")
        );

        let first =
            BackendTlsMaterialReloadKey::from_source_value(&ca_uri, MaterialKind::CaBundle).await;
        std::fs::write(&ca_path, b"second-ca").expect("write second ca");
        let second =
            BackendTlsMaterialReloadKey::from_source_value(&ca_uri, MaterialKind::CaBundle).await;

        assert_eq!(first.source, second.source);
        assert!(
            first.fingerprint.starts_with("sha256:") && second.fingerprint.starts_with("sha256:"),
            "file:// URI sources must be fingerprinted by material content, not by raw fs::read of the URI string: {} / {}",
            first.fingerprint,
            second.fingerprint
        );
        assert_ne!(
            first.fingerprint, second.fingerprint,
            "file:// URI backend TLS material rotation must change the reload key"
        );
    }

    #[tokio::test]
    async fn backend_tls_material_reload_key_digests_inline_pem_without_leaking_it() {
        let inline_pem = "-----BEGIN CERTIFICATE-----\nMIIBsecret\n-----END CERTIFICATE-----\n";

        let key =
            BackendTlsMaterialReloadKey::from_source_value(inline_pem, MaterialKind::Cert).await;

        assert!(
            !key.source.contains("MIIBsecret"),
            "inline PEM must be digested in the reload key, never stored raw: {}",
            key.source
        );
        assert!(
            key.fingerprint.starts_with("sha256:"),
            "inline PEM should fingerprint its content: {}",
            key.fingerprint
        );
    }

    #[tokio::test]
    async fn same_tls_sources_distinguishes_content_rotation_from_source_or_policy_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, b"first-ca").expect("write first ca");
        let ca_path_str = ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config");
        let other_ca_path = dir.path().join("other-ca.pem");
        std::fs::write(&other_ca_path, b"other-ca").expect("write other ca");
        let other_ca_path_str = other_ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config");

        // Nested async helper: a sync closure cannot `.await` the reload-key
        // builder, so the key is resolved here before each comparison.
        async fn key(source: &str, san: Vec<String>) -> BackendTlsReloadKey {
            BackendTlsReloadKey {
                verify_server_cert: true,
                server_ca_cert: Some(
                    BackendTlsMaterialReloadKey::from_source_value(source, MaterialKind::CaBundle)
                        .await,
                ),
                client_cert: None,
                client_key: None,
                san_allow_list: san,
                crl_fingerprint: None,
            }
        }

        let original = key(ca_path_str, vec![]).await;

        // In-place content rotation: same source, new bytes -> same sources,
        // different key (eligible for the keep-old path).
        std::fs::write(&ca_path, b"second-ca").expect("rotate ca");
        let rotated = key(ca_path_str, vec![]).await;
        assert_ne!(original, rotated, "rotation must change the key");
        assert!(
            original.same_tls_sources(&rotated),
            "in-place rotation keeps the same source identity"
        );

        // Source path change -> NOT a content-only rotation.
        let new_source = key(other_ca_path_str, vec![]).await;
        assert!(
            !original.same_tls_sources(&new_source),
            "a different CA source must not count as an in-place rotation"
        );

        // SAN allow-list change -> NOT a content-only rotation.
        let san_changed = key(ca_path_str, vec!["backend.example".to_string()]).await;
        assert!(
            !original.same_tls_sources(&san_changed),
            "a SAN allow-list change must not count as an in-place rotation"
        );

        // Source removed entirely -> NOT a content-only rotation.
        let removed = BackendTlsReloadKey {
            verify_server_cert: true,
            server_ca_cert: None,
            client_cert: None,
            client_key: None,
            san_allow_list: vec![],
            crl_fingerprint: None,
        };
        assert!(
            !original.same_tls_sources(&removed),
            "removing a source must not count as an in-place rotation"
        );

        // CRL content rotation -> key changes, but it IS a content-only
        // rotation (same sources), so the keep-old path stays eligible.
        let crl_rotated = BackendTlsReloadKey {
            crl_fingerprint: Some("sha256:deadbeef".to_string()),
            ..original.clone()
        };
        assert_ne!(
            original, crl_rotated,
            "a CRL content rotation must change the reload key"
        );
        assert!(
            original.same_tls_sources(&crl_rotated),
            "a CRL content rotation keeps the same source identity"
        );
    }

    #[test]
    fn crl_list_fingerprint_tracks_content_and_is_none_when_empty() {
        use rustls::pki_types::CertificateRevocationListDer;

        let empty: crate::tls::CrlList = Arc::new(Vec::new());
        assert_eq!(crl_list_fingerprint(&empty), None);

        let first: crate::tls::CrlList = Arc::new(vec![CertificateRevocationListDer::from(
            b"crl-bytes-one".to_vec(),
        )]);
        let second: crate::tls::CrlList = Arc::new(vec![CertificateRevocationListDer::from(
            b"crl-bytes-two".to_vec(),
        )]);
        let first_fp = crl_list_fingerprint(&first).expect("fingerprint");
        let second_fp = crl_list_fingerprint(&second).expect("fingerprint");
        assert!(first_fp.starts_with("sha256:"));
        assert_ne!(
            first_fp, second_fp,
            "rotated CRL content must produce a different fingerprint"
        );
        assert_eq!(
            first_fp,
            crl_list_fingerprint(&first).expect("fingerprint"),
            "fingerprint must be deterministic for identical content"
        );
    }

    #[test]
    fn stream_backend_routing_key_tracks_upstream_target_set() {
        let config = |targets: serde_json::Value| -> GatewayConfig {
            serde_json::from_value(serde_json::json!({
                "version": "1",
                "proxies": [],
                "consumers": [],
                "plugin_configs": [],
                "upstreams": [{
                    "id": "up-1",
                    "targets": targets,
                }],
            }))
            .expect("config deserialize")
        };
        let proxy: Proxy = serde_json::from_value(serde_json::json!({
            "id": "tls-stream",
            "backend_host": "unused.example",
            "backend_port": 5000,
            "backend_scheme": "tcps",
            "listen_port": 6000,
            "upstream_id": "up-1",
        }))
        .expect("proxy deserialize");

        let one_target = config(serde_json::json!([{"host": "a.example", "port": 5001}]));
        let two_targets = config(serde_json::json!([
            {"host": "a.example", "port": 5001},
            {"host": "b.example", "port": 5002},
        ]));

        let key_one = StreamBackendRoutingKey::from_proxy(&proxy, &one_target);
        let key_one_again = StreamBackendRoutingKey::from_proxy(&proxy, &one_target);
        let key_two = StreamBackendRoutingKey::from_proxy(&proxy, &two_targets);

        assert_eq!(
            key_one, key_one_again,
            "an unchanged upstream target set must compare equal"
        );
        assert_ne!(
            key_one, key_two,
            "an upstream target-set change must register as routing drift even \
             though no proxy field changed"
        );
    }

    #[test]
    fn stream_backend_routing_key_tracks_subset_membership() {
        let config =
            |subset_labels: serde_json::Value, a_tags: serde_json::Value| -> GatewayConfig {
                serde_json::from_value(serde_json::json!({
                    "version": "1",
                    "proxies": [],
                    "consumers": [],
                    "plugin_configs": [],
                    "upstreams": [{
                        "id": "up-1",
                        "targets": [
                            {"host": "a.example", "port": 5001, "tags": a_tags},
                            {"host": "b.example", "port": 5002, "tags": {"version": "v2"}},
                        ],
                        "subsets": [{"name": "v1", "labels": subset_labels}],
                    }],
                }))
                .expect("config deserialize")
            };
        let proxy: Proxy = serde_json::from_value(serde_json::json!({
            "id": "tls-stream",
            "backend_host": "unused.example",
            "backend_port": 5000,
            "backend_scheme": "tcps",
            "listen_port": 6000,
            "upstream_id": "up-1",
            "upstream_subset": "v1",
        }))
        .expect("proxy deserialize");

        let v1_is_a = config(
            serde_json::json!({"version": "v1"}),
            serde_json::json!({"version": "v1"}),
        );
        // Subset label edit re-points "v1" at the v2 target — the upstream's
        // full endpoint list is unchanged.
        let v1_is_b = config(
            serde_json::json!({"version": "v2"}),
            serde_json::json!({"version": "v1"}),
        );
        // Target tag edit evicts a.example from the subset — again without
        // touching the endpoint list.
        let a_untagged = config(serde_json::json!({"version": "v1"}), serde_json::json!({}));

        let key_a = StreamBackendRoutingKey::from_proxy(&proxy, &v1_is_a);
        let key_b = StreamBackendRoutingKey::from_proxy(&proxy, &v1_is_b);
        let key_untagged = StreamBackendRoutingKey::from_proxy(&proxy, &a_untagged);

        assert_ne!(
            key_a, key_b,
            "a subset-label edit that changes effective membership must register as routing drift"
        );
        assert_ne!(
            key_a, key_untagged,
            "a target-tag edit that changes effective membership must register as routing drift"
        );
        assert_eq!(
            key_a,
            StreamBackendRoutingKey::from_proxy(&proxy, &v1_is_a),
            "unchanged subset membership must compare equal"
        );
    }

    #[test]
    fn stream_backend_routing_key_resolves_upstream_by_namespace() {
        // Same upstream id in two tenants must not latch TLS routing onto the
        // foreign tenant's targets (issue #3094).
        let proxy: Proxy = serde_json::from_value(serde_json::json!({
            "id": "p1",
            "namespace": "tenant-a",
            "listen_path": "/",
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": 9000,
            "listen_port": 9443,
            "upstream_id": "u1",
        }))
        .expect("proxy deserialize");

        // Insert the foreign upstream first so a bare-id find would wrongly
        // prefer it.
        let config_both = GatewayConfig {
            upstreams: vec![
                serde_json::from_value(serde_json::json!({
                    "id": "u1",
                    "namespace": "tenant-b",
                    "algorithm": "round_robin",
                    "targets": [{"host": "foreign.example", "port": 443}],
                }))
                .expect("upstream deserialize"),
                serde_json::from_value(serde_json::json!({
                    "id": "u1",
                    "namespace": "tenant-a",
                    "algorithm": "round_robin",
                    "targets": [{"host": "local.example", "port": 443}],
                }))
                .expect("upstream deserialize"),
            ],
            ..GatewayConfig::default()
        };

        let key = StreamBackendRoutingKey::from_proxy(&proxy, &config_both);
        assert_eq!(
            key.upstream_targets.as_deref(),
            Some(&[("local.example".to_string(), 443u16)][..]),
            "routing key must use the same-namespace upstream, not a same-id foreign one"
        );

        // Drop the local upstream: the foreign same-id entry must not fill in.
        let config_foreign_only = GatewayConfig {
            upstreams: vec![config_both.upstreams[0].clone()],
            ..GatewayConfig::default()
        };
        let missing = StreamBackendRoutingKey::from_proxy(&proxy, &config_foreign_only);
        assert_eq!(
            missing.upstream_targets.as_deref(),
            Some(&[][..]),
            "a dangling same-namespace upstream_id must yield an empty target set"
        );
    }
}
