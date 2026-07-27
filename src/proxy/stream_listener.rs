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

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::db_backend::NamespacedResourceId;
use crate::config::types::{BackendScheme, GatewayConfig, Proxy};
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;
use crate::request_epoch::RequestEpochStore;
use crate::tls::TlsPolicy;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

use super::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics};
use super::udp_proxy::{UdpListenerConfig, UdpProxyMetrics};

/// Live slot for a per-listener `DtlsServer`. The inner `Option<Arc<...>>` is
/// `None` until the listener task publishes the server (post-bind) and
/// becomes `Some` for the lifetime of the listener.
type DtlsServerSlot = Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::DtlsServer>>>>;

const STREAM_LISTENER_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);

/// Handle for a running stream listener — keeps the shutdown channel and task handle.
struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
    listen_port: u16,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
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
    /// mesh PeerAuth live reload can call
    /// [`crate::dtls::DtlsServer::swap_frontend_config`] on the same instance
    /// the recv loop is using. `None` for TCP/UDP-plain listeners.
    dtls_server: Option<DtlsServerSlot>,
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

    fn from_proxy(
        proxy: &Proxy,
        global_tls_ca_bundle_path: Option<&str>,
        crl_fingerprint: Option<&str>,
    ) -> Self {
        let server_ca_cert_source = proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .or(global_tls_ca_bundle_path);

        Self {
            verify_server_cert: proxy.resolved_tls.verify_server_cert,
            server_ca_cert: server_ca_cert_source.map(|source| {
                BackendTlsMaterialReloadKey::from_source_value(source, MaterialKind::CaBundle)
            }),
            client_cert: proxy
                .resolved_tls
                .client_cert_path
                .as_deref()
                .map(|source| {
                    BackendTlsMaterialReloadKey::from_source_value(source, MaterialKind::Cert)
                }),
            client_key: proxy.resolved_tls.client_key_path.as_deref().map(|source| {
                BackendTlsMaterialReloadKey::from_source_value(source, MaterialKind::Key)
            }),
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
    use sha2::{Digest, Sha256};
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
    /// Resolves through the same [`CertSource`] / [`load_material_blocking`]
    /// abstraction as `load_backend_material` in `src/tls/backend.rs`, so
    /// every supported source kind (plain path, inline PEM, `file://`,
    /// vault/aws/azure/gcp/k8s/acme/managed URIs) is fingerprinted by content.
    /// A raw `std::fs::read` of the config string would freeze the key for
    /// non-path sources: a `file:///x.pem` or stable secret URI rotation
    /// would never change the key and the cached config would go stale
    /// forever. Cold path only — runs during reconcile, never per connection.
    fn from_source_value(value: &str, kind: MaterialKind) -> Self {
        let source = CertSource::parse(value, kind);
        let fingerprint = match load_material_blocking(&source, kind) {
            Ok(material) => format!("sha256:{}", hex::encode(material.fingerprint)),
            Err(err) => format!("error:{}", err),
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
    port: u16,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
    /// Whether the proxy declares `hosts`; a lone passthrough proxy with hosts
    /// still needs SNI resolution so its host predicates are enforced.
    has_hosts: bool,
    backend_tls_reload_key: Option<BackendTlsReloadKey>,
}

/// One listener the reconcile pass wants running: either an individual proxy
/// (keyed `namespace|id`) or a shared SNI passthrough group (keyed
/// `__sni_{port}`).
struct DesiredStreamListener {
    /// Exact owning identity for this listener's representative proxy. For SNI
    /// groups this is the first (sorted) candidate; per-connection resolution
    /// picks the concrete tenant from [`Self::sni_ids`]. Never inferred and
    /// never defaulted — it is carried from the config entry that produced it.
    identity: NamespacedResourceId,
    port: u16,
    scheme: BackendScheme,
    frontend_tls: bool,
    passthrough: bool,
    backend_tls_reload_key: Option<BackendTlsReloadKey>,
    sni_ids: Option<Vec<NamespacedResourceId>>,
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
    listeners: tokio::sync::Mutex<std::collections::HashMap<String, ListenerHandle>>,
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
    /// DTLS frontend material for UDP stream proxies with `frontend_tls: true`.
    /// Stored as a single ArcSwap payload so cert/key and optional client-CA
    /// path are published atomically to reconcile() and listener startup.
    frontend_dtls_material: arc_swap::ArcSwap<Option<(String, String, Option<String>)>>,
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
    /// Number of SO_REUSEPORT TCP stream accept loops.
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
    /// Pre-parsed trusted proxy CIDR set (from `FERRUM_TRUSTED_PROXIES`).
    /// Shared with each spawned TCP stream accept loop that has
    /// `stream_proxy_protocol: true`. The accept loop honors the forwarded
    /// address from the PROXY header only when the socket peer belongs to
    /// this set; untrusted peers are rejected outright to prevent IP spoofing.
    /// Empty when `FERRUM_TRUSTED_PROXIES` is not set.
    trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
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
        trusted_proxies: Arc<crate::proxy::client_ip::TrustedProxies>,
    ) -> Self {
        Self {
            listeners: tokio::sync::Mutex::new(std::collections::HashMap::new()),
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
            node_waypoint_identity_resolver: arc_swap::ArcSwap::new(Arc::new(None)),
            trusted_proxies,
        }
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
    /// Deliberately TCP-only. Node-waypoint capture keys identity by the
    /// per-connection TCP socket cookie (`connect4`/`connect6` cgroup hooks
    /// stamp the source pod into `FERRUM_ORIG_DST4/6`, looked up at accept time
    /// via `getsockopt(SO_COOKIE)`). A UDP stream proxy has a single shared
    /// frontend socket with one cookie for every client, and there are no UDP
    /// capture hooks, so there is no per-source-pod cookie to resolve. UDP/DTLS
    /// node-waypoint streams therefore remain mesh-wide-only (the existing
    /// fail-closed default) — see `src/proxy/udp_proxy.rs` and `docs/mesh.md`.
    pub fn set_node_waypoint_identity_resolver(&self, resolver: Arc<NodeWaypointIdentityResolver>) {
        self.node_waypoint_identity_resolver
            .store(Arc::new(Some(resolver)));
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

    /// Update the DTLS cert/key paths used for UDP stream proxies with `frontend_tls: true`.
    ///
    /// After storing the config, automatically reconciles stream listeners so
    /// any previously deferred UDP/DTLS listeners are started.
    pub async fn set_frontend_dtls_cert_key(
        &self,
        cert_path: String,
        key_path: String,
        client_ca_cert_path: Option<String>,
    ) {
        self.frontend_dtls_material.store(Arc::new(Some((
            cert_path,
            key_path,
            client_ca_cert_path,
        ))));
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
    /// Used by mesh PeerAuthentication live reload alongside
    /// [`Self::swap_active_dtls_frontend_configs`]; ordinary HTTPS / non-mesh
    /// modes continue to use [`Self::set_frontend_tls_config`] at startup
    /// (followed by a static lifetime — those modes do not call swap).
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

    /// Live-swap the frontend DTLS crypto material on every active DTLS
    /// server held by this manager.
    ///
    /// `build_config` is invoked once per active DTLS listener so the caller
    /// can rebuild a fresh `FrontendDtlsConfig` for each (cloning the
    /// `DtlsCertificateChain` and verifier is cheap; the dimpl `Config` itself
    /// can be re-used since the build is symmetric). Existing in-flight
    /// DTLS sessions keep the snapshot they handshake with until they end;
    /// new sessions pick up the swapped material on the next ClientHello.
    ///
    /// Returns the number of listeners whose DTLS server was swapped.
    /// Listeners whose `dtls_server` slot has not yet been populated by the
    /// collector task (a brief race window post-bind) are skipped — the
    /// next slice apply re-runs this swap, and the in-flight session would
    /// have been rejected anyway since no peer can complete a handshake
    /// before the listener binds.
    pub async fn swap_active_dtls_frontend_configs<F>(&self, mut build_config: F) -> usize
    where
        F: FnMut() -> Result<crate::dtls::FrontendDtlsConfig, anyhow::Error>,
    {
        let mut swapped = 0usize;
        let listeners = self.listeners.lock().await;
        for handle in listeners.values() {
            let Some(slot) = handle.dtls_server.as_ref() else {
                continue;
            };
            let snapshot = slot.load();
            let Some(server) = snapshot.as_ref().clone() else {
                // Collector task has not yet published the server (race with
                // bind). Skip — the next live-reload swap will catch it.
                continue;
            };
            match build_config() {
                Ok(cfg) => {
                    server.swap_frontend_config(cfg);
                    swapped += 1;
                }
                Err(err) => {
                    warn!(
                        listen_port = handle.listen_port,
                        "Failed to rebuild frontend DTLS config for live swap: {}; \
                         keeping previous DTLS config on remaining listeners",
                        err
                    );
                    // `build_config` is invariant under iteration — the cert/key
                    // paths and CRL list it closes over do not change across
                    // listeners — so a failure on iteration N would have failed
                    // on iteration 0 as well. The only realistic divergence is
                    // a transient FS race (cert file briefly unreadable). Bail
                    // out so a stuttering FS does not produce a mix of new and
                    // old configs across long-lived listeners; the next slice
                    // apply re-runs the swap and converges everything to the
                    // newest material. Any listener already swapped this pass
                    // keeps the new config — that is the desired direction of
                    // travel.
                    return swapped;
                }
            }
        }
        swapped
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
        let current_config = self.config.load();
        // Fingerprint the active CRL list once per reconcile: it is folded
        // into every TCP+TLS reload key so a CRL rotation (published via
        // `set_crls`) registers as backend-TLS drift.
        let active_crl_fingerprint = crl_list_fingerprint(&self.crls.load_full());
        let mut listeners = self.listeners.lock().await;

        // Collect all desired stream proxies from config, keyed by the full
        // `(namespace, id)` identity. Two namespaces may reuse one proxy ID (IDs
        // are unique only per namespace), so a bare-ID key would silently drop
        // one tenant's listener and attach the survivor's runtime state to the
        // wrong namespace (issue #3094).
        let desired: std::collections::HashMap<NamespacedResourceId, DesiredStreamProxy> =
            current_config
                .proxies
                .iter()
                .filter(|p| p.dispatch_kind.is_stream())
                .filter_map(|p| {
                    p.listen_port.map(|port| {
                        // Passthrough proxies relay raw bytes and never build the
                        // cached backend TLS config, so they carry no reload key:
                        // backend TLS material (or its absence) must neither
                        // restart them nor block them from starting.
                        let backend_tls_reload_key = if p.dispatch_kind
                            == crate::config::types::DispatchKind::TcpTls
                            && !p.passthrough
                        {
                            Some(BackendTlsReloadKey::from_proxy(
                                p,
                                self.tls_ca_bundle_path.as_deref(),
                                active_crl_fingerprint.as_deref(),
                            ))
                        } else {
                            None
                        };
                        (
                            NamespacedResourceId::new(p.namespace.clone(), p.id.clone()),
                            DesiredStreamProxy {
                                port,
                                scheme: p.effective_scheme(),
                                frontend_tls: p.frontend_tls,
                                passthrough: p.passthrough,
                                has_hosts: !p.hosts.is_empty(),
                                backend_tls_reload_key,
                            },
                        )
                    })
                })
                .collect();

        // Detect passthrough port groups that must be resolved by SNI.
        // Multiple passthrough proxies sharing a port need one shared listener keyed by
        // "__sni_{port}". A single passthrough proxy with configured hosts also needs
        // SNI resolution so those host predicates are enforced instead of becoming a
        // port-wide catch-all.
        //
        // Grouping is by port because the OS port is the shared resource: a port
        // may legitimately be shared by passthrough proxies from different
        // namespaces (per-namespace uniqueness allows it). Candidates therefore
        // stay namespace-qualified so SNI resolution selects the right tenant.
        let mut passthrough_groups: std::collections::HashMap<u16, Vec<NamespacedResourceId>> =
            std::collections::HashMap::new();
        for (identity, entry) in &desired {
            if entry.passthrough {
                passthrough_groups
                    .entry(entry.port)
                    .or_default()
                    .push(identity.clone());
            }
        }
        passthrough_groups.retain(|_, ids| {
            ids.len() > 1
                || ids
                    .iter()
                    .any(|id| desired.get(id).is_some_and(|entry| entry.has_hosts))
        });
        // Sort identities for stable comparison on reconcile.
        for ids in passthrough_groups.values_mut() {
            ids.sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
        }

        // Build the effective desired map: individual proxies + SNI group entries.
        // Proxies in a group are replaced by a single "__sni_{port}" entry.
        let grouped_proxy_ids: std::collections::HashSet<&NamespacedResourceId> =
            passthrough_groups.values().flatten().collect();

        let mut effective_desired: std::collections::HashMap<String, DesiredStreamListener> =
            std::collections::HashMap::new();

        for (identity, entry) in &desired {
            if grouped_proxy_ids.contains(identity) {
                continue; // Handled as part of a group below
            }
            effective_desired.insert(
                identity.runtime_key(),
                DesiredStreamListener {
                    identity: identity.clone(),
                    port: entry.port,
                    scheme: entry.scheme,
                    frontend_tls: entry.frontend_tls,
                    passthrough: entry.passthrough,
                    backend_tls_reload_key: entry.backend_tls_reload_key.clone(),
                    sni_ids: None,
                },
            );
        }
        for (port, ids) in &passthrough_groups {
            let key = format!("__sni_{}", port);
            // Use the first proxy's scheme for the listener. `ids[0]` is also the
            // listener's *representative* identity: the accept path re-resolves
            // the concrete tenant per connection from `sni_ids`.
            if let Some(entry) = desired.get(&ids[0]) {
                effective_desired.insert(
                    key,
                    DesiredStreamListener {
                        identity: ids[0].clone(),
                        port: entry.port,
                        scheme: entry.scheme,
                        frontend_tls: entry.frontend_tls,
                        passthrough: entry.passthrough,
                        backend_tls_reload_key: entry.backend_tls_reload_key.clone(),
                        sni_ids: Some(ids.clone()),
                    },
                );
            }
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
                scheme,
                frontend_tls,
                passthrough,
                backend_tls_reload_key,
                sni_ids,
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
                || handle.scheme != *scheme
                || handle.frontend_tls != *frontend_tls
                || handle.passthrough != *passthrough
                // SNI-group membership change on a shared passthrough
                // port: the running listener captured the old candidate
                // ID list at spawn, so it must be restarted. IDs are
                // sorted at group construction, making this a stable
                // comparison.
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
                    && let Err(msg) =
                        self.validate_backend_tls_config(&current_config, identity, *port)
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

        let mut removed_listeners = Vec::new();
        for key in &to_remove {
            if let Some(handle) = listeners.remove(key) {
                info!(
                    listener_key = %key,
                    port = handle.listen_port,
                    scheme = %handle.scheme,
                    "Stopping stream listener"
                );
                let _ = handle.shutdown_tx.send(true);
                removed_listeners.push((key.clone(), handle));
            }
        }
        for (key, handle) in removed_listeners {
            await_stream_listener_shutdown(&key, handle).await;
        }

        // Start listeners for new or restarted entries
        for (key, desired_listener) in &effective_desired {
            if listeners.contains_key(key) {
                continue;
            }
            let DesiredStreamListener {
                identity,
                port,
                scheme,
                frontend_tls,
                passthrough,
                backend_tls_reload_key,
                sni_ids,
            } = desired_listener;
            // Exact owning identity for this listener, carried from the config
            // entry that produced it (first SNI candidate for a shared group).
            // Never re-derived by scanning and never defaulted.
            let proxy_id = &identity.id;

            // Skip frontend_tls proxies when the required encryption config is not yet loaded.
            // For TCP: needs rustls ServerConfig. For UDP: needs DTLS cert/key paths.
            // The set_frontend_tls_config() / set_frontend_dtls_cert_key() methods
            // automatically call reconcile() after storing the config, so deferred
            // listeners will be started once TLS materials arrive.
            // Passthrough proxies never terminate TLS, so they skip this check entirely.
            if *frontend_tls && !*passthrough {
                if scheme.is_udp() {
                    if self.frontend_dtls_material.load().is_none() {
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
                && let Err(msg) = self.validate_backend_tls_config(&current_config, identity, *port)
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
            let bind_addr = self.bind_addr;
            let port_val = *port;
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
                    sni_ids.as_deref(),
                    port_val,
                    &msg,
                    StreamListenerDegradation::BindFailed,
                ));
                continue;
            }

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let rebound_proxy_ids = sni_ids.clone().unwrap_or_else(|| vec![identity.clone()]);
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
            // Clone the global shutdown receiver (if injected) so the spawned
            // listener observes both per-listener removal AND global SIGTERM.
            let global_shutdown = self.global_shutdown_rx.load().as_ref().clone();

            let (join_handle, tcp_metrics, udp_metrics, dtls_server) = if scheme.is_udp() {
                let started_for_listener = started.clone();
                // UDP or DTLS listener
                // Passthrough proxies forward raw encrypted datagrams — no DTLS termination.
                let frontend_dtls_config = if *frontend_tls && !*passthrough {
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
                } else {
                    None
                };
                let metrics = Arc::new(UdpProxyMetrics::default());
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
                let bind_failures = Arc::clone(&self.bind_failures);
                let async_bind_failures = Arc::clone(&self.async_bind_failures);
                let async_failure_tx = async_failure_tx.clone();
                let failure_proxy_ids = sni_ids
                    .clone()
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
                let join_handle = tokio::spawn(async move {
                    if let Err(e) = super::udp_proxy::start_udp_listener(UdpListenerConfig {
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
                    })
                    .await
                    {
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
                });
                // The DTLS server `Arc` will be published shortly after the
                // listener task binds. Stash a shared slot here so the spawned
                // collector task can store it once `start_dtls_frontend_listener`
                // sends. Reconcile does not block waiting for the bind; if the
                // first PeerAuth live-reload swap fires before the collector
                // resolves, the swap path simply finds an empty slot for that
                // listener and skips it (re-reconcile or the next swap picks
                // it up — the swap is idempotent over slice apply).
                let dtls_server_slot: Arc<arc_swap::ArcSwap<Option<Arc<crate::dtls::DtlsServer>>>> =
                    Arc::new(arc_swap::ArcSwap::from_pointee(None));
                let dtls_server_slot_for_collector = Arc::clone(&dtls_server_slot);
                tokio::spawn(async move {
                    if let Ok(server) = dtls_server_rx.await {
                        dtls_server_slot_for_collector.store(Arc::new(Some(server)));
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
                let metrics = Arc::new(TcpProxyMetrics::default());
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
                let global_shutdown_for_listener = global_shutdown.clone();
                let mesh_outbound_enforcement = self.mesh_outbound_enforcement.clone();
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
                        mesh_outbound_enforcement,
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

            listeners.insert(
                key.clone(),
                ListenerHandle {
                    shutdown_tx,
                    join_handle,
                    listen_port: *port,
                    scheme: *scheme,
                    frontend_tls: *frontend_tls,
                    passthrough: *passthrough,
                    backend_tls_reload_key: backend_tls_reload_key.clone(),
                    backend_routing_key,
                    sni_ids: sni_ids.clone(),
                    started,
                    tcp_metrics,
                    udp_metrics,
                    dtls_server,
                },
            );
        }

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

    /// Build-validate the cached backend TLS `ClientConfig` for a TCP+TLS
    /// stream proxy without installing it.
    ///
    /// Used in two places in [`Self::reconcile`]: (1) before tearing down a
    /// running listener whose backend TLS material rotated in place, so an
    /// invalid rotation keeps the old listener serving; (2) before spawning a
    /// new listener, so an invalid config never installs a listener that
    /// would fail every backend handshake. Returns the message to surface in
    /// `bind_failures` on failure.
    fn validate_backend_tls_config(
        &self,
        current_config: &GatewayConfig,
        identity: &NamespacedResourceId,
        port: u16,
    ) -> Result<(), String> {
        let Some(proxy) = find_proxy_by_identity(current_config, identity) else {
            return Err(format!(
                "Backend TLS config failed for stream listener on port {}: proxy {}/{} not found",
                port, identity.namespace, identity.id
            ));
        };
        super::tcp_proxy::build_cached_backend_tls_config(
            proxy,
            self.tls_no_verify,
            self.tls_ca_bundle_path.as_deref(),
            self.tls_policy.as_deref(),
            &self.crls.load_full(),
        )
        .map(drop)
        .map_err(|err| {
            format!(
                "Backend TLS config failed for stream listener on port {}: {}",
                port, err
            )
        })
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

    /// Wait until all currently configured stream listeners have successfully
    /// bound and can accept traffic.
    pub async fn wait_until_started(&self, timeout: Duration) -> Result<(), anyhow::Error> {
        let deadline = Instant::now() + timeout;

        loop {
            let current_config = self.config.load();
            let desired: Vec<(NamespacedResourceId, u16, BackendScheme, bool, bool, bool)> =
                current_config
                    .proxies
                    .iter()
                    .filter(|p| p.dispatch_kind.is_stream())
                    .filter_map(|p| {
                        p.listen_port.map(|port| {
                            (
                                NamespacedResourceId::new(p.namespace.clone(), p.id.clone()),
                                port,
                                p.effective_scheme(),
                                p.frontend_tls,
                                p.passthrough,
                                !p.hosts.is_empty(),
                            )
                        })
                    })
                    .collect();

            if desired.is_empty() {
                return Ok(());
            }

            // Detect SNI port groups to map proxy_ids to their listener key.
            let mut pt_ports: std::collections::HashMap<u16, (usize, bool)> =
                std::collections::HashMap::new();
            for (_, port, _, _, passthrough, has_hosts) in &desired {
                if *passthrough {
                    let entry = pt_ports.entry(*port).or_default();
                    entry.0 += 1;
                    entry.1 |= *has_hosts;
                }
            }

            let all_started = {
                let listeners = self.listeners.lock().await;
                desired
                    .iter()
                    .all(|(identity, port, scheme, frontend_tls, passthrough, _)| {
                        // For SNI groups the listener key is "__sni_{port}";
                        // individual listeners are keyed by the namespace-
                        // qualified `namespace|id` runtime key, matching
                        // `reconcile`'s `effective_desired`.
                        let key = if *passthrough
                            && pt_ports
                                .get(port)
                                .is_some_and(|(count, has_hosts)| *count > 1 || *has_hosts)
                        {
                            format!("__sni_{}", port)
                        } else {
                            identity.runtime_key()
                        };
                        listeners.get(&key).is_some_and(|handle| {
                            handle.listen_port == *port
                                && handle.scheme == *scheme
                                && handle.frontend_tls == *frontend_tls
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
        for (listener_key, handle) in listeners.drain() {
            info!(
                listener_key = %listener_key,
                port = handle.listen_port,
                "Shutting down stream listener"
            );
            let _ = handle.shutdown_tx.send(true);
        }
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

    #[test]
    fn backend_tls_material_reload_key_changes_when_same_path_content_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, b"first-ca").expect("write first ca");
        let ca_path = ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config");

        let first = BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle);
        std::fs::write(ca_path, b"second-ca").expect("write second ca");
        let second =
            BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle);

        assert_eq!(first.source, second.source);
        assert_ne!(
            first.fingerprint, second.fingerprint,
            "same-path backend TLS material rotation must change the reload key"
        );
    }

    #[test]
    fn backend_tls_material_reload_key_changes_when_missing_file_appears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        let ca_path = ca_path
            .to_str()
            .expect("test temp path must be utf-8 for proxy config");

        let missing =
            BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle);
        std::fs::write(ca_path, b"first-ca").expect("write ca");
        let present =
            BackendTlsMaterialReloadKey::from_source_value(ca_path, MaterialKind::CaBundle);

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

    #[test]
    fn backend_tls_material_reload_key_file_uri_rotation_changes_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, b"first-ca").expect("write first ca");
        let ca_uri = format!(
            "file://{}",
            ca_path
                .to_str()
                .expect("test temp path must be utf-8 for proxy config")
        );

        let first = BackendTlsMaterialReloadKey::from_source_value(&ca_uri, MaterialKind::CaBundle);
        std::fs::write(&ca_path, b"second-ca").expect("write second ca");
        let second =
            BackendTlsMaterialReloadKey::from_source_value(&ca_uri, MaterialKind::CaBundle);

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

    #[test]
    fn backend_tls_material_reload_key_digests_inline_pem_without_leaking_it() {
        let inline_pem = "-----BEGIN CERTIFICATE-----\nMIIBsecret\n-----END CERTIFICATE-----\n";

        let key = BackendTlsMaterialReloadKey::from_source_value(inline_pem, MaterialKind::Cert);

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

    #[test]
    fn same_tls_sources_distinguishes_content_rotation_from_source_or_policy_change() {
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

        let key = |source: &str, san: Vec<String>| BackendTlsReloadKey {
            verify_server_cert: true,
            server_ca_cert: Some(BackendTlsMaterialReloadKey::from_source_value(
                source,
                MaterialKind::CaBundle,
            )),
            client_cert: None,
            client_key: None,
            san_allow_list: san,
            crl_fingerprint: None,
        };

        let original = key(ca_path_str, vec![]);

        // In-place content rotation: same source, new bytes -> same sources,
        // different key (eligible for the keep-old path).
        std::fs::write(&ca_path, b"second-ca").expect("rotate ca");
        let rotated = key(ca_path_str, vec![]);
        assert_ne!(original, rotated, "rotation must change the key");
        assert!(
            original.same_tls_sources(&rotated),
            "in-place rotation keeps the same source identity"
        );

        // Source path change -> NOT a content-only rotation.
        let new_source = key(other_ca_path_str, vec![]);
        assert!(
            !original.same_tls_sources(&new_source),
            "a different CA source must not count as an in-place rotation"
        );

        // SAN allow-list change -> NOT a content-only rotation.
        let san_changed = key(ca_path_str, vec!["backend.example".to_string()]);
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
