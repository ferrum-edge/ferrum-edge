//! SPIFFE trust-bundle federation poller (GAP-3C).
//!
//! Today the mesh slice carries [`TrustBundleSet.federated`](crate::modes::mesh::config::TrustBundleSet)
//! only when a control plane pushes it. This module adds a runtime poller that
//! fetches remote-cluster trust bundles from
//! `MultiClusterConfig.remote_clusters[].federation_endpoint` URLs and stores
//! the validated result in an `ArcSwap`-held map. The slice apply path merges
//! that snapshot with whatever the control plane provided so cross-cluster
//! mTLS can verify federated peers without a CP push for every rotation.
//!
//! Design notes:
//!
//! - **Lock-free hot path**: readers (slice apply, verifier) load the snapshot
//!   via [`FederationStore::snapshot`], which dereferences a single `ArcSwap`.
//! - **Validated swap**: each polled bundle is validated through the same
//!   trust-bundle invariants as a slice-provided bundle before being stored.
//!   A failed poll bumps the failure metric and keeps the last-good entry.
//!   `FERRUM_MESH_FEDERATION_FAIL_OPEN` controls only bootstrap fallback for
//!   remotes with no last-good polled bundle yet; once a bundle has been
//!   fetched, transient poll failures never delete it.
//! - **Backoff**: each remote endpoint runs in its own tokio task with
//!   jittered exponential backoff matching `src/grpc/dp_client.rs`
//!   (1s → 30s cap, ±25% jitter). On success the per-target backoff resets to
//!   the configured poll interval.
//! - **Shutdown**: every loop watches the gateway's shutdown channel; SIGTERM
//!   drains the poller cleanly.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::Deserialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::identity::TrustDomain;
use crate::modes::mesh::config::{
    JwtAuthority, MAX_MESH_REMOTE_CLUSTERS, MultiClusterConfig, TrustBundle, TrustBundleSet,
};
use crate::modes::mesh::config_consumer::common::{
    BACKOFF_INITIAL_SECS, jittered_backoff, next_backoff_secs as common_next_backoff_secs,
};
use crate::plugins::utils::http_client::PluginHttpClient;
#[cfg(test)]
use crate::util::backoff::{
    BACKOFF_MAX_SECS, jittered_backoff_with_entropy as common_jittered_backoff_with_entropy,
};

/// Initial backoff bound shared with `src/grpc/dp_client.rs`. The federation
/// poller intentionally mirrors the CP-reconnect cadence so an operator-tuned
/// cluster has only one cross-cluster backoff curve to reason about.
pub(crate) const FEDERATION_BACKOFF_INITIAL_SECS: u64 = BACKOFF_INITIAL_SECS;
#[cfg(test)]
const FEDERATION_BACKOFF_MAX_SECS: u64 = BACKOFF_MAX_SECS;

/// Hard cap on federation response body size. A real SPIFFE bundle is
/// kilobytes — even a generous JWKS with several authorities fits well
/// below 256 KiB. The 2 MiB cap leaves vast headroom while preventing a
/// malicious or runaway endpoint from streaming gigabytes into a single
/// `Bytes` allocation inside the timeout window.
const FEDERATION_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Defense-in-depth bounds on parsed bundle sizes. SPIFFE bundles in the
/// wild carry a handful of certs at most; 256 entries is orders of
/// magnitude above realistic. Stops a small JSON document with millions of
/// empty-string keys from allocating millions of `JwtAuthority` structs.
const FEDERATION_MAX_X509_AUTHORITIES: usize = 256;
const FEDERATION_MAX_JWT_AUTHORITIES: usize = 256;

/// Snapshot the federation store hands out to slice apply and the admin API.
/// Keyed by trust domain so two `RemoteCluster` entries with overlapping trust
/// domains would dedupe at install time (last writer wins; the poller only
/// installs a target's own trust domain).
#[derive(Debug, Default, Clone)]
pub struct FederationSnapshot {
    pub bundles: HashMap<TrustDomain, FederatedBundle>,
}

#[derive(Debug, Clone)]
pub struct FederatedBundle {
    pub bundle: TrustBundle,
    pub fetched_at_unix_seconds: u64,
    pub endpoint: String,
    pub cluster_name: String,
}

/// Lock-free shared state populated by the poller and consumed by both the
/// slice-apply path and `GET /mesh/federation`.
#[derive(Clone)]
pub struct FederationStore {
    inner: Arc<ArcSwap<FederationSnapshot>>,
    first_ready: Arc<std::sync::atomic::AtomicBool>,
    /// Bumped on every successful install. The slice-apply task subscribes to
    /// it so a freshly polled bundle re-runs the slice-apply pipeline even
    /// when the live mesh slice itself is unchanged. Without this, a stable
    /// CP config would never pick up a rotated federated trust bundle until
    /// the next CP push.
    revision_tx: Arc<watch::Sender<u64>>,
    /// Monotonic generation counter. [`FederationPollerManager`] stamps each
    /// poll task with the generation registered at launch; `install` commits
    /// only when the task's generation still matches the cluster's registered
    /// generation. This closes the abort→install race without forcing a single
    /// generation slot per trust domain: multiple remote clusters can share a
    /// trust domain, but retiring one cluster must not stale every other
    /// cluster polling the same bundle.
    generation: Arc<AtomicU64>,
    /// Generation at which each cluster was last registered, in an
    /// `ArcSwap` so `install` can re-check it atomically inside its rcu.
    cluster_generation: Arc<ArcSwap<HashMap<String, u64>>>,
}

impl Default for FederationStore {
    fn default() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(FederationSnapshot::default()))),
            first_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
            generation: Arc::new(AtomicU64::new(0)),
            cluster_generation: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
        }
    }
}

impl FederationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock-free read.
    pub fn snapshot(&self) -> Arc<FederationSnapshot> {
        self.inner.load_full()
    }

    /// `true` after at least one trust domain has been successfully polled.
    pub fn has_first_success(&self) -> bool {
        self.first_ready.load(Ordering::Acquire)
    }

    /// Subscribe to install events. Mirrors `MeshRuntimeState::subscribe()`.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    /// Register a poll task for `cluster_name` and return its generation token.
    /// The task passes the token back to `install`; if it no longer matches the
    /// cluster's current generation (the cluster was removed, or removed +
    /// re-registered) the install is silently dropped.
    pub(crate) fn register(&self, cluster_name: &str) -> u64 {
        let new_gen = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.cluster_generation.rcu(|current| {
            let mut next = (**current).clone();
            next.insert(cluster_name.to_string(), new_gen);
            Arc::new(next)
        });
        new_gen
    }

    fn cluster_generation_matches(&self, cluster_name: &str, task_generation: u64) -> bool {
        self.cluster_generation
            .load()
            .get(cluster_name)
            .is_some_and(|&g| g == task_generation)
    }

    /// Install a polled bundle, but ONLY when `task_generation` still matches the
    /// cluster's registered generation — so an in-flight poll cannot reinstall
    /// after the manager withdrew the cluster (the abort→install race). Returns
    /// `true` only when the bundle actually commits.
    fn install(
        &self,
        cluster_name: &str,
        trust_domain: TrustDomain,
        bundle: FederatedBundle,
        task_generation: u64,
    ) -> bool {
        // Fast-path generation check (re-validated atomically in the rcu below).
        if !self.cluster_generation_matches(cluster_name, task_generation) {
            return false;
        }
        // CAS loop so two concurrent successful polls (different trust domains)
        // cannot stomp each other. The generation is re-checked INSIDE the
        // closure so check-and-insert is atomic w.r.t. cluster removal, which
        // retires the generation (in `cluster_generation`) BEFORE clearing or
        // republishing the bundle snapshot (in
        // `inner`): a racing `remove` either commits before this rcu (and its
        // subsequent clear drops the bundle) or wins the CAS, forcing this
        // closure to retry, observe the retired generation, and skip — never
        // resurrecting a withdrawn trust anchor.
        let mut installed = false;
        self.inner.rcu(|current| {
            if !self.cluster_generation_matches(cluster_name, task_generation) {
                installed = false;
                return Arc::clone(current);
            }
            let mut next = (**current).clone();
            next.bundles.insert(trust_domain.clone(), bundle.clone());
            installed = true;
            Arc::new(next)
        });
        if installed {
            self.first_ready.store(true, Ordering::Release);
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
        installed
    }

    /// Test helper: register + install in one step. Production code registers in
    /// the manager and threads the token through the poll task.
    #[cfg(test)]
    fn install_for_test(&self, trust_domain: TrustDomain, bundle: FederatedBundle) {
        let cluster_name = bundle.cluster_name.clone();
        let task_generation = self.register(&cluster_name);
        self.install(&cluster_name, trust_domain, bundle, task_generation);
    }

    /// Retire a cluster generation when its `RemoteCluster` is removed from the
    /// slice (or its trust is withdrawn). When `remove_bundle` is true, remove
    /// the trust domain from the federated bundle map unconditionally. When it
    /// is false, still remove the bundle if this cluster was the source of the
    /// currently cached trust-domain entry.
    ///
    /// Called by [`FederationPollerManager`] so a once-fetched federated bundle
    /// stops being overlaid onto slice applies and the decommissioned peer
    /// stops being dial-eligible — without requiring a gateway restart. Bumps
    /// the revision so the slice-apply task re-applies. Even when no bundle has
    /// been cached yet, retiring a registered generation republishes `inner` so
    /// any in-flight first-poll RCU based on the old snapshot loses its CAS,
    /// retries, observes the retired generation, and drops the install.
    pub fn remove_cluster(
        &self,
        cluster_name: &str,
        trust_domain: &TrustDomain,
        remove_bundle: bool,
    ) {
        // Retire the generation FIRST so any in-flight poll task for this
        // cluster sees a mismatch in `install` and cannot reinstall after
        // removal.
        let mut retired_generation = false;
        self.cluster_generation.rcu(|current| {
            if current.contains_key(cluster_name) {
                let mut next = (**current).clone();
                next.remove(cluster_name);
                retired_generation = true;
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });

        let mut published_snapshot = false;
        self.inner.rcu(|current| {
            let cached_bundle = current.bundles.get(trust_domain);
            let has_cached_bundle = cached_bundle.is_some();
            let cached_from_removed_cluster =
                cached_bundle.is_some_and(|bundle| bundle.cluster_name == cluster_name);
            if retired_generation
                || (remove_bundle && has_cached_bundle)
                || cached_from_removed_cluster
            {
                let mut next = (**current).clone();
                if remove_bundle || cached_from_removed_cluster {
                    next.bundles.remove(trust_domain);
                }
                published_snapshot = true;
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
        if published_snapshot {
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
    }
}

/// Wire-format the federation endpoint serves.
///
/// Two shapes are accepted, validated through a single `serde(untagged)` enum:
///
/// 1. **Ferrum-native** (`{"trust_domain": "...", "x509_authorities": [...]}`):
///    a direct serialization of [`TrustBundle`] from `src/modes/mesh/config.rs`.
///    This is the canonical shape and round-trips through `serde_json` with
///    zero mapping. A Ferrum control plane serving its local trust material
///    over HTTPS would emit this format directly.
///
/// 2. **SPIFFE JWKS** (`{"keys": [{"kty": "RSA", "use": "x509-svid",
///    "x5c": ["..."]}], "spiffe_sequence": 1, "spiffe_refresh_hint": 60}`):
///    the SPIFFE Trust Domain and Bundle JWKS profile. We translate the
///    `keys` array to `TrustBundle` at decode time using the `use` claim
///    (`x509-svid` → `x509_authorities[]`; `jwt-svid` → `jwt_authorities[]`
///    with `kid` + a PEM-wrapped JWK key). The trust domain is supplied by
///    the surrounding [`RemoteCluster`](crate::modes::mesh::config::RemoteCluster)
///    entry because SPIFFE bundles do not carry it inside the document.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FederationDocument {
    /// SPIFFE JWKS is tried first because it has a required `keys` field —
    /// only matches when the wire document actually carries a JWKS. The
    /// native variant has every field defaulted, so without this ordering an
    /// untagged enum would silently accept a JWKS document as an empty
    /// Native bundle.
    SpiffeJwks(SpiffeJwksDocument),
    Native(NativeFederationBundle),
}

#[derive(Debug, Deserialize)]
struct NativeFederationBundle {
    #[serde(default)]
    trust_domain: Option<String>,
    #[serde(default)]
    x509_authorities: Vec<String>,
    #[serde(default)]
    jwt_authorities: Vec<JwtAuthority>,
    #[serde(default)]
    refresh_hint_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SpiffeJwksDocument {
    keys: Vec<SpiffeJwksKey>,
    #[serde(default)]
    spiffe_refresh_hint: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SpiffeJwksKey {
    #[serde(rename = "use", default)]
    key_use: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    x5c: Vec<String>,
    /// SPIFFE JWKS includes the full JWK (`kty`, `n`, `e`, `crv`, `x`, `y`).
    /// We preserve it as-is in `jwt_authorities[].public_key_pem` so callers
    /// can hand it to a JWK consumer; the consumer is responsible for
    /// converting JWK → PEM as needed. This intentionally keeps the poller
    /// free of crypto-format conversion code.
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

/// Parse the wire document into a [`TrustBundle`] keyed under
/// `expected_trust_domain`. SPIFFE federation responses do not carry their
/// trust domain inline; native responses may include it but the value MUST
/// match the configured remote-cluster trust domain.
pub(crate) fn parse_federation_document(
    body: &[u8],
    expected_trust_domain: &TrustDomain,
) -> Result<TrustBundle, String> {
    let doc: FederationDocument =
        serde_json::from_slice(body).map_err(|e| format!("invalid federation bundle JSON: {e}"))?;
    match doc {
        FederationDocument::Native(native) => {
            if let Some(ref td) = native.trust_domain
                && td.as_str() != expected_trust_domain.as_str()
            {
                return Err(format!(
                    "federation bundle trust_domain '{td}' does not match remote cluster trust domain '{expected_trust_domain}'"
                ));
            }
            if native.x509_authorities.len() > FEDERATION_MAX_X509_AUTHORITIES {
                return Err(format!(
                    "federation bundle for '{expected_trust_domain}' has {} x509 authorities (max {})",
                    native.x509_authorities.len(),
                    FEDERATION_MAX_X509_AUTHORITIES
                ));
            }
            if native.jwt_authorities.len() > FEDERATION_MAX_JWT_AUTHORITIES {
                return Err(format!(
                    "federation bundle for '{expected_trust_domain}' has {} JWT authorities (max {})",
                    native.jwt_authorities.len(),
                    FEDERATION_MAX_JWT_AUTHORITIES
                ));
            }
            Ok(TrustBundle {
                trust_domain: expected_trust_domain.clone(),
                x509_authorities: native.x509_authorities,
                jwt_authorities: native.jwt_authorities,
                refresh_hint_seconds: native.refresh_hint_seconds,
            })
        }
        FederationDocument::SpiffeJwks(jwks) => {
            if jwks.keys.len() > FEDERATION_MAX_X509_AUTHORITIES + FEDERATION_MAX_JWT_AUTHORITIES {
                return Err(format!(
                    "federation JWKS for '{expected_trust_domain}' has {} keys (max {})",
                    jwks.keys.len(),
                    FEDERATION_MAX_X509_AUTHORITIES + FEDERATION_MAX_JWT_AUTHORITIES
                ));
            }
            let mut x509 = Vec::new();
            let mut jwts = Vec::new();
            for key in jwks.keys {
                match key.key_use.as_deref() {
                    Some("x509-svid") => {
                        // Per SPIFFE Federation §4.2.1, `x5c` carries
                        // base64-DER X.509 certs (the standard JWK form,
                        // *not* JWS-style URL-safe base64).
                        x509.extend(key.x5c);
                    }
                    Some("jwt-svid") => {
                        let kid = key.kid.unwrap_or_default();
                        if kid.is_empty() {
                            return Err("federation bundle jwt-svid key missing 'kid'".to_string());
                        }
                        // Re-serialise the JWK fields back to JSON so downstream
                        // JWT consumers can parse it as a JWK. We intentionally
                        // do not convert to PEM here: see field doc above.
                        let json = serde_json::Value::Object(key.rest);
                        let serialised = serde_json::to_string(&json)
                            .map_err(|e| format!("re-serialising JWT JWK: {e}"))?;
                        jwts.push(JwtAuthority {
                            key_id: kid,
                            public_key_pem: serialised,
                        });
                    }
                    Some(other) => {
                        // Unknown SPIFFE `use` claim — skip with a warning so a
                        // newer SPIFFE spec key type does not break the
                        // existing keys.
                        debug!(unsupported_use = %other, "Skipping SPIFFE JWKS key with unsupported 'use'");
                    }
                    None => {
                        return Err("federation bundle JWKS key missing 'use' claim".to_string());
                    }
                }
            }
            Ok(TrustBundle {
                trust_domain: expected_trust_domain.clone(),
                x509_authorities: x509,
                jwt_authorities: jwts,
                refresh_hint_seconds: jwks.spiffe_refresh_hint,
            })
        }
    }
}

/// Validate a federation-fetched bundle through the same invariants the slice
/// validator applies to [`TrustBundleSet::federated`]. Centralised here so the
/// poller stays in lock-step with `validate_mesh_config_internal`.
pub(crate) fn validate_polled_bundle(bundle: &TrustBundle) -> Result<(), String> {
    if bundle.x509_authorities.is_empty() && bundle.jwt_authorities.is_empty() {
        return Err(format!(
            "federation bundle for trust domain '{}' has no authorities",
            bundle.trust_domain
        ));
    }
    bundle
        .decode_x509_authorities()
        .map(|_| ())
        .map_err(|e| format!("federation bundle for '{}': {}", bundle.trust_domain, e))
}

/// One polling task per [`RemoteCluster.federation_endpoint`].
#[derive(Clone, PartialEq, Eq)]
struct RemoteClusterPollTarget {
    cluster_name: String,
    trust_domain: TrustDomain,
    endpoint: String,
}

/// Configuration knobs derived from `EnvConfig` / `MultiClusterConfig`.
#[derive(Debug, Clone)]
pub struct FederationPollerConfig {
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    /// Federation bootstrap policy. When true, a remote trust domain with a
    /// configured federation endpoint may use a CP-supplied fallback bundle
    /// before the first successful poll. When false, that remote trust domain
    /// stays inactive until the poller installs a last-good bundle.
    pub fail_open: bool,
}

impl FederationPollerConfig {
    /// Returns `None` when the poller should be disabled (interval 0 or no
    /// federated remote clusters configured).
    pub fn from_env(interval_seconds: u64, timeout_seconds: u64, fail_open: bool) -> Option<Self> {
        if interval_seconds == 0 {
            return None;
        }
        Some(Self {
            poll_interval: Duration::from_secs(interval_seconds),
            request_timeout: Duration::from_secs(timeout_seconds.max(1)),
            fail_open,
        })
    }
}

/// Holds the spawned tasks so callers can join during graceful shutdown.
#[allow(dead_code)] // Integration tests call this through the lib crate; the bin target does not.
pub struct FederationPollerHandles {
    pub tasks: Vec<JoinHandle<()>>,
}

/// Resolve the polling-target list from a [`MultiClusterConfig`]. Remote
/// clusters without a federation endpoint are silently skipped (the operator
/// is allowed to leave that field unset for east-west-only federation).
fn poll_targets_for_multi_cluster(
    multi_cluster: &MultiClusterConfig,
) -> Vec<RemoteClusterPollTarget> {
    let mut targets = Vec::with_capacity(
        multi_cluster
            .remote_clusters
            .len()
            .min(MAX_MESH_REMOTE_CLUSTERS),
    );
    for remote in &multi_cluster.remote_clusters {
        let Some(endpoint) = remote.federation_endpoint.as_deref().map(str::trim) else {
            continue;
        };
        if endpoint.is_empty() {
            continue;
        }
        // SSRF + plaintext defense: reject endpoints pointing at link-
        // local / loopback / cloud-metadata / non-https hosts at slice
        // apply time so a misconfigured (or compromised) CP cannot
        // weaponize the poller. Bad targets are dropped with a warn;
        // the rest of the federation surface continues to function.
        if let Err(err) = validate_federation_endpoint(endpoint) {
            warn!(
                cluster = %remote.name,
                trust_domain = %remote.trust_domain,
                error = %err,
                "Dropping federation_endpoint that failed SSRF/scheme validation"
            );
            continue;
        }
        if targets.len() >= MAX_MESH_REMOTE_CLUSTERS {
            warn!(
                cluster = %remote.name,
                max_remote_clusters = MAX_MESH_REMOTE_CLUSTERS,
                "Skipping federation_endpoint beyond remote-cluster target cap"
            );
            continue;
        }
        targets.push(RemoteClusterPollTarget {
            cluster_name: remote.name.clone(),
            trust_domain: remote.trust_domain.clone(),
            endpoint: endpoint.to_string(),
        });
    }
    targets
}

/// Spawn the federation poller. Returns `None` when the poller is disabled or
/// there are no configured federation endpoints; otherwise returns the spawned
/// task handles. The caller-supplied `store` is shared with the mesh runtime
/// so successful polls are observable by the slice-apply path immediately.
#[allow(dead_code)] // Integration tests call this through the lib crate; the bin target does not.
pub fn spawn_federation_poller(
    multi_cluster: Option<&MultiClusterConfig>,
    config: Option<FederationPollerConfig>,
    http_client: PluginHttpClient,
    store: FederationStore,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<FederationPollerHandles> {
    let config = config?;
    let multi_cluster = multi_cluster?;
    let targets = poll_targets_for_multi_cluster(multi_cluster);
    if targets.is_empty() {
        debug!(
            "No remote clusters with federation_endpoint configured; federation poller disabled"
        );
        return None;
    }
    let mut tasks = Vec::with_capacity(targets.len());
    for target in targets {
        let task_store = store.clone();
        let task_config = config.clone();
        let task_client = http_client.clone();
        let task_shutdown = shutdown_rx.clone();
        let cluster_name = target.cluster_name.clone();
        let trust_domain = target.trust_domain.clone();
        let endpoint = target.endpoint.clone();
        let endpoint_for_logs = sanitize_endpoint_for_logging(&endpoint);
        info!(
            cluster = %cluster_name,
            trust_domain = %trust_domain,
            endpoint = %endpoint_for_logs,
            poll_interval_seconds = task_config.poll_interval.as_secs(),
            fail_open = task_config.fail_open,
            "Spawning SPIFFE federation poller"
        );
        // Register a generation token so the poll task's install is gated by it
        // (parity with the manager / RemoteEndpointStore). This one-shot startup
        // path never calls remove(), so the token simply stays current.
        let task_generation = store.register(&cluster_name);
        let handle = tokio::spawn(async move {
            poll_federation_loop(
                target,
                task_store,
                task_config,
                task_client,
                task_shutdown,
                task_generation,
            )
            .await;
        });
        tasks.push(handle);
    }
    Some(FederationPollerHandles { tasks })
}

/// One running federation poller tracked by [`FederationPollerManager`].
struct RunningFederationPoller {
    target: RemoteClusterPollTarget,
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

/// Reconciles SPIFFE federation pollers against the latest mesh slice.
///
/// The one-shot [`spawn_federation_poller`] starts pollers from a single startup
/// slice and never sees later changes. This manager instead reconciles on every
/// slice update (mirroring `RemoteDiscoveryManager` for endpoint discovery): it
/// starts pollers for federation endpoints **added** after startup, aborts
/// pollers for clusters that are **removed** (or whose endpoint changed), and —
/// critically — calls [`FederationStore::remove_cluster`] for a withdrawn
/// cluster so a once-fetched federated bundle stops being overlaid onto every
/// slice apply once the last poller for that trust domain is gone (and stops
/// keeping the decommissioned peer dial-eligible), without requiring a gateway
/// restart.
pub struct FederationPollerManager {
    config: Option<FederationPollerConfig>,
    http_client: PluginHttpClient,
    store: FederationStore,
    /// Keyed by cluster name (the poller-lifecycle identity), matching
    /// `RemoteDiscoveryManager`. Bundle removal is keyed by the cluster's trust
    /// domain via `stop_cluster`.
    running: HashMap<String, RunningFederationPoller>,
}

impl FederationPollerManager {
    pub fn new(
        config: Option<FederationPollerConfig>,
        http_client: PluginHttpClient,
        store: FederationStore,
    ) -> Self {
        Self {
            config,
            http_client,
            store,
            running: HashMap::new(),
        }
    }

    /// Start/stop per-cluster pollers to match the latest slice. A cluster that
    /// disappears (or whose target changed) is stopped and its federated bundle
    /// removed so a stale trust anchor cannot persist after withdrawal.
    pub fn reconcile(&mut self, multi_cluster: Option<&MultiClusterConfig>) {
        let (Some(config), Some(multi_cluster)) = (self.config.clone(), multi_cluster) else {
            self.stop_all(true);
            return;
        };
        let targets = poll_targets_for_multi_cluster(multi_cluster);
        if targets.is_empty() {
            self.stop_all(true);
            debug!(
                "No remote clusters with federation_endpoint configured; federation pollers stopped"
            );
            return;
        }

        let targets_by_name: HashMap<String, RemoteClusterPollTarget> = targets
            .into_iter()
            .map(|target| (target.cluster_name.clone(), target))
            .collect();

        let stale: Vec<String> = self
            .running
            .iter()
            .filter_map(|(name, running)| {
                let desired = targets_by_name.get(name)?;
                (&running.target != desired).then(|| name.clone())
            })
            .collect();
        let removed: Vec<String> = self
            .running
            .keys()
            .filter(|name| !targets_by_name.contains_key(*name))
            .cloned()
            .collect();
        for name in stale.into_iter().chain(removed) {
            self.stop_cluster(&name, true);
        }

        for target in targets_by_name.into_values() {
            if !self.running.contains_key(&target.cluster_name) {
                self.start_cluster(target, config.clone());
            }
        }
    }

    /// Abort all running pollers WITHOUT removing their bundles. Used on
    /// graceful shutdown — the process is exiting, so trust state is moot and we
    /// avoid a spurious revision storm.
    pub fn shutdown(&mut self) {
        self.stop_all(false);
    }

    fn start_cluster(&mut self, target: RemoteClusterPollTarget, config: FederationPollerConfig) {
        let task_store = self.store.clone();
        let task_client = self.http_client.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let endpoint_for_logs = sanitize_endpoint_for_logging(&target.endpoint);
        info!(
            cluster = %target.cluster_name,
            trust_domain = %target.trust_domain,
            endpoint = %endpoint_for_logs,
            poll_interval_seconds = config.poll_interval.as_secs(),
            fail_open = config.fail_open,
            "Spawning SPIFFE federation poller"
        );
        // Register a generation token BEFORE spawning so the poll task's install
        // is gated by it; stop_cluster retires the token, so a poll that
        // completes its synchronous install after withdrawal cannot resurrect
        // the bundle (mirrors RemoteEndpointStore's F6 guard).
        let task_generation = self.store.register(&target.cluster_name);
        let loop_target = target.clone();
        let handle = tokio::spawn(async move {
            poll_federation_loop(
                loop_target,
                task_store,
                config,
                task_client,
                shutdown_rx,
                task_generation,
            )
            .await;
        });
        self.running.insert(
            target.cluster_name.clone(),
            RunningFederationPoller {
                target,
                shutdown_tx,
                handle,
            },
        );
    }

    fn stop_cluster(&mut self, cluster_name: &str, remove_bundle: bool) {
        if let Some(running) = self.running.remove(cluster_name) {
            let _ = running.shutdown_tx.send(true);
            running.handle.abort();
            if remove_bundle {
                let remove_trust_domain_bundle = !self
                    .running
                    .values()
                    .any(|other| other.target.trust_domain == running.target.trust_domain);
                self.store.remove_cluster(
                    &running.target.cluster_name,
                    &running.target.trust_domain,
                    remove_trust_domain_bundle,
                );
            }
        }
    }

    fn stop_all(&mut self, remove_bundle: bool) {
        let names: Vec<String> = self.running.keys().cloned().collect();
        for name in names {
            self.stop_cluster(&name, remove_bundle);
        }
    }

    #[cfg(test)]
    fn running_cluster_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.running.keys().cloned().collect();
        names.sort();
        names
    }
}

async fn poll_federation_loop(
    target: RemoteClusterPollTarget,
    store: FederationStore,
    config: FederationPollerConfig,
    http_client: PluginHttpClient,
    mut shutdown_rx: watch::Receiver<bool>,
    task_generation: u64,
) {
    let mut backoff_secs = FEDERATION_BACKOFF_INITIAL_SECS;
    let cluster_name = target.cluster_name;
    let trust_domain = target.trust_domain;
    let endpoint = target.endpoint;
    let endpoint_for_logs = sanitize_endpoint_for_logging(&endpoint);

    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        let attempt_started_at = std::time::Instant::now();
        let result = fetch_and_install_bundle(
            &cluster_name,
            &trust_domain,
            &endpoint,
            &config,
            &http_client,
            &store,
            task_generation,
        )
        .await;

        let (succeeded, sleep_duration) = match result {
            Ok(true) => {
                backoff_secs = FEDERATION_BACKOFF_INITIAL_SECS;
                // After a success we wait at least one full poll interval —
                // `attempt_started_at` lets a long round-trip eat into the
                // interval so a 30s poll on a 60s interval still wakes at the
                // 60s mark, not 90s.
                let elapsed = attempt_started_at.elapsed();
                (true, config.poll_interval.saturating_sub(elapsed))
            }
            Ok(false) => {
                debug!(
                    cluster = %cluster_name,
                    trust_domain = %trust_domain,
                    endpoint = %endpoint_for_logs,
                    "SPIFFE federation poll result was discarded because the poller generation is stale"
                );
                return;
            }
            Err(err) => {
                warn!(
                    cluster = %cluster_name,
                    trust_domain = %trust_domain,
                    endpoint = %endpoint_for_logs,
                    error = %err,
                    fail_open = config.fail_open,
                    "SPIFFE federation poll failed; keeping last-good bundle if any"
                );
                crate::plugins::mesh::prometheus_helpers::increment_mesh_federation_poll_failure(
                    trust_domain.as_str(),
                    &endpoint_for_logs,
                );
                (false, jittered_backoff(backoff_secs))
            }
        };

        if !succeeded {
            backoff_secs = next_backoff_secs(backoff_secs);
        }

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_federation_shutdown(&mut shutdown_rx) => return,
        }
    }
}

async fn wait_for_federation_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

async fn fetch_and_install_bundle(
    cluster_name: &str,
    trust_domain: &TrustDomain,
    endpoint: &str,
    config: &FederationPollerConfig,
    http_client: &PluginHttpClient,
    store: &FederationStore,
    task_generation: u64,
) -> Result<bool, String> {
    // Strip userinfo from the URL we use for logs / metrics so a
    // credentialed endpoint (`https://user:token@host/...`) does not leak
    // its token. The request itself still goes to the original URL via
    // reqwest's normal handling.
    let endpoint_for_logs = sanitize_endpoint_for_logging(endpoint);
    let request = http_client
        .get()
        .get(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(config.request_timeout);
    let response = http_client
        .execute_redacted(request, "mesh_federation_poll", &endpoint_for_logs)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {} from federation endpoint", status.as_u16()));
    }
    // Reject early when the server advertises a Content-Length larger than
    // our cap, so we don't even start streaming a multi-gigabyte body.
    if let Some(cl_value) = response.content_length()
        && cl_value as usize > FEDERATION_MAX_BODY_BYTES
    {
        return Err(format!(
            "federation response Content-Length {} exceeds {} byte cap",
            cl_value, FEDERATION_MAX_BODY_BYTES
        ));
    }
    // Size-bounded streaming read. `response.bytes()` would allocate an
    // unbounded `Bytes` from a hostile endpoint within the request timeout
    // and OOM the gateway. The cap is enforced frame-by-frame so a
    // streaming response that ignores Content-Length is also caught.
    let body = read_bounded_body(response, FEDERATION_MAX_BODY_BYTES, &endpoint_for_logs).await?;
    let bundle = parse_federation_document(&body, trust_domain)?;
    validate_polled_bundle(&bundle)?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let federated = FederatedBundle {
        bundle,
        fetched_at_unix_seconds: now,
        endpoint: endpoint.to_string(),
        cluster_name: cluster_name.to_string(),
    };
    let installed = store.install(
        cluster_name,
        trust_domain.clone(),
        federated,
        task_generation,
    );
    if !installed {
        return Ok(false);
    }
    crate::plugins::mesh::prometheus_helpers::record_mesh_federation_poll_success(
        trust_domain.as_str(),
        now,
    );
    info!(
        cluster = %cluster_name,
        trust_domain = %trust_domain,
        endpoint = %endpoint_for_logs,
        "Installed federated trust bundle"
    );
    Ok(true)
}

/// Read the response body frame-by-frame and abort if it exceeds
/// `max_bytes`. Returns `Vec<u8>` rather than `Bytes` because callers feed
/// it straight to `serde_json::from_slice`.
async fn read_bounded_body(
    response: reqwest::Response,
    max_bytes: usize,
    endpoint_for_logs: &str,
) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            let error_class = crate::retry::classify_reqwest_error(&e);
            format!("{error_class} reading federation response body from {endpoint_for_logs}")
        })?;
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!(
                "federation response body exceeded {max_bytes} bytes; aborting"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Strip userinfo (`user:password@`) from the URL when logging. Falls back
/// to a placeholder string if parsing fails — never returns the raw input
/// for logs.
fn sanitize_endpoint_for_logging(endpoint: &str) -> String {
    match reqwest::Url::parse(endpoint) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.to_string()
        }
        Err(_) => "<unparseable>".to_string(),
    }
}

/// SSRF defense for federation endpoints. Cloud metadata services
/// (`169.254.169.254`, AWS IMDS) and link-local addresses are rejected to
/// keep a compromised control plane from pivoting through the poller into
/// node-local infrastructure. Loopback is allowed because legitimate
/// local-development and integration-test setups use it; loopback offers
/// no new attack surface that the local process doesn't already have.
///
/// HTTPS is recommended (a `warn!` fires on plain `http://`) but not
/// enforced, so existing CP-supplied configurations that pre-date this
/// validator keep working. Operators should treat the warn as a strong
/// hint to migrate.
pub(crate) fn validate_federation_endpoint(endpoint: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(endpoint).map_err(|e| {
        format!(
            "federation_endpoint '{}' is not a valid URL: {e}",
            sanitize_endpoint_for_logging(endpoint)
        )
    })?;
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(format!(
            "federation_endpoint must use 'http' or 'https' scheme (got '{scheme}')"
        ));
    }
    if scheme == "http" {
        warn!(
            endpoint = %sanitize_endpoint_for_logging(endpoint),
            "federation_endpoint uses plain http; trust-bundle traffic should use https"
        );
    }
    let Some(host) = url.host() else {
        return Err(format!(
            "federation_endpoint '{}' has no host component",
            sanitize_endpoint_for_logging(endpoint)
        ));
    };
    match host {
        url::Host::Ipv4(ip) => reject_unsafe_ipv4(&ip)?,
        url::Host::Ipv6(ip) => reject_unsafe_ipv6(&ip)?,
        url::Host::Domain(_) => {
            // Hostnames are resolved at request time. We accept any
            // syntactically valid host; the DNS-resolver layer enforces
            // `BackendAllowIps` if configured by the operator.
        }
    }
    Ok(())
}

fn reject_unsafe_ipv4(ip: &std::net::Ipv4Addr) -> Result<(), String> {
    // Loopback is allowed for local development / integration test setups.
    if ip.is_loopback() {
        return Ok(());
    }
    if ip.is_link_local() {
        return Err(format!(
            "federation_endpoint refuses link-local host {ip} (defends against cloud metadata SSRF)"
        ));
    }
    // 169.254.169.254 is link-local already, but call it out explicitly for
    // the operator-readable error message.
    if ip.octets() == [169, 254, 169, 254] {
        return Err(format!(
            "federation_endpoint refuses cloud metadata IP {ip}"
        ));
    }
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return Err(format!(
            "federation_endpoint refuses non-unicast IPv4 host {ip}"
        ));
    }
    Ok(())
}

fn reject_unsafe_ipv6(ip: &std::net::Ipv6Addr) -> Result<(), String> {
    if ip.is_loopback() {
        return Ok(());
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!(
            "federation_endpoint refuses non-unicast IPv6 host {ip}"
        ));
    }
    // RFC 4291 link-local fe80::/10
    let segs = ip.segments();
    if segs[0] & 0xffc0 == 0xfe80 {
        return Err(format!(
            "federation_endpoint refuses link-local IPv6 host {ip}"
        ));
    }
    Ok(())
}

#[cfg(test)]
fn jittered_backoff_with_entropy(backoff_secs: u64, entropy: u64) -> Duration {
    common_jittered_backoff_with_entropy(backoff_secs, entropy)
}

pub(crate) fn next_backoff_secs(current_secs: u64) -> u64 {
    common_next_backoff_secs(current_secs, true)
}

fn dynamic_federation_trust_domains(
    multi_cluster: Option<&MultiClusterConfig>,
    poll_enabled: bool,
) -> HashSet<TrustDomain> {
    if !poll_enabled {
        return HashSet::new();
    }
    multi_cluster
        .map(|mc| {
            mc.remote_clusters
                .iter()
                .filter(|remote| {
                    remote
                        .federation_endpoint
                        .as_deref()
                        .is_some_and(|endpoint| !endpoint.trim().is_empty())
                })
                .map(|remote| remote.trust_domain.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Merge the live federation snapshot into the static [`TrustBundleSet`] the
/// control plane handed us. Used by the slice-apply path so the dispatched
/// [`crate::config::types::GatewayConfig`] sees the currently active
/// cross-cluster authorities.
///
/// Merge precedence: the live snapshot (polled) wins on conflict because the
/// poller signals a fresh trust-domain rotation. When
/// `FERRUM_MESH_FEDERATION_FAIL_OPEN=false` and federation polling is enabled,
/// a remote cluster that declares a `federation_endpoint` must have a last-good
/// polled bundle before its trust domain is activated. CP-supplied bundles for
/// such domains are treated as bootstrap fallback only when
/// `FERRUM_MESH_FEDERATION_FAIL_OPEN=true` (or polling is disabled entirely).
/// This makes the fail-open setting observable while still preserving
/// last-good polled bundles across transient poll failures.
pub fn merge_federation_into_trust_bundles(
    trust_bundles: Option<TrustBundleSet>,
    snapshot: &FederationSnapshot,
    multi_cluster: Option<&MultiClusterConfig>,
    fail_open: bool,
    poll_enabled: bool,
) -> Option<TrustBundleSet> {
    let mut set = trust_bundles?;

    if !fail_open {
        let dynamic_domains = dynamic_federation_trust_domains(multi_cluster, poll_enabled);
        if !dynamic_domains.is_empty() {
            set.federated.retain(|fed| {
                !dynamic_domains.contains(&fed.trust_domain)
                    || snapshot.bundles.contains_key(&fed.trust_domain)
            });
        }
    }

    if snapshot.bundles.is_empty() {
        return Some(set);
    }
    // Dedupe by trust domain: drop any existing federated entries whose trust
    // domain the poller has fetched, then append the fresh polled bundles.
    set.federated
        .retain(|fed| !snapshot.bundles.contains_key(&fed.trust_domain));
    for (_td, federated) in snapshot.bundles.iter() {
        set.federated.push(federated.bundle.clone());
    }
    Some(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TrustDomain;
    use crate::modes::mesh::config::TrustBundle;

    fn td(s: &str) -> TrustDomain {
        TrustDomain::new(s).expect("valid trust domain")
    }

    fn sample_cert_base64() -> String {
        // Minimal valid base64 for a "DER" blob — the poller validator only
        // checks that base64 decode succeeds, not that the inner bytes are a
        // real X.509 cert. The slice validator behaves identically.
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0xde, 0xad, 0xbe, 0xef])
    }

    #[test]
    fn parse_native_format_round_trips() {
        let body = serde_json::json!({
            "trust_domain": "remote.example.com",
            "x509_authorities": [sample_cert_base64()],
            "refresh_hint_seconds": 60u64,
        })
        .to_string();
        let trust_domain = td("remote.example.com");
        let bundle = parse_federation_document(body.as_bytes(), &trust_domain)
            .expect("native parse should succeed");
        assert_eq!(bundle.trust_domain, trust_domain);
        assert_eq!(bundle.x509_authorities.len(), 1);
        assert_eq!(bundle.refresh_hint_seconds, Some(60));
    }

    #[test]
    fn parse_native_format_rejects_trust_domain_mismatch() {
        let body = serde_json::json!({
            "trust_domain": "other.example.com",
            "x509_authorities": [sample_cert_base64()],
        })
        .to_string();
        let err = parse_federation_document(body.as_bytes(), &td("remote.example.com"))
            .expect_err("mismatch should reject");
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn parse_spiffe_jwks_format() {
        let body = serde_json::json!({
            "keys": [
                {"use": "x509-svid", "x5c": [sample_cert_base64()]},
                {"use": "jwt-svid", "kid": "kid1", "kty": "RSA", "n": "abc", "e": "AQAB"},
            ],
            "spiffe_refresh_hint": 120u64,
        })
        .to_string();
        let bundle = parse_federation_document(body.as_bytes(), &td("remote.example.com"))
            .expect("jwks parse should succeed");
        assert_eq!(bundle.x509_authorities.len(), 1);
        assert_eq!(bundle.jwt_authorities.len(), 1);
        assert_eq!(bundle.jwt_authorities[0].key_id, "kid1");
        assert!(bundle.jwt_authorities[0].public_key_pem.contains("\"kty\""));
        assert_eq!(bundle.refresh_hint_seconds, Some(120));
    }

    #[test]
    fn parse_rejects_invalid_json() {
        let err = parse_federation_document(b"not json", &td("td"))
            .expect_err("invalid JSON should reject");
        assert!(err.contains("invalid federation bundle JSON"), "{err}");
    }

    #[test]
    fn validate_rejects_empty_bundle() {
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: Vec::new(),
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        let err = validate_polled_bundle(&bundle).expect_err("empty bundle should reject");
        assert!(err.contains("has no authorities"), "{err}");
    }

    #[test]
    fn validate_rejects_bad_base64() {
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: vec!["!!!not base64!!!".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        let err = validate_polled_bundle(&bundle).expect_err("bad base64 should reject");
        assert!(err.contains("invalid base64"), "{err}");
    }

    #[test]
    fn validate_accepts_valid_bundle() {
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: vec![sample_cert_base64()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        validate_polled_bundle(&bundle).expect("valid bundle should accept");
    }

    #[test]
    fn backoff_matches_dp_client_cap_and_jitter() {
        // Cap behaviour mirrors src/grpc/dp_client.rs.
        assert_eq!(next_backoff_secs(1), 2);
        assert_eq!(next_backoff_secs(2), 4);
        assert_eq!(next_backoff_secs(16), FEDERATION_BACKOFF_MAX_SECS);
        assert_eq!(next_backoff_secs(30), FEDERATION_BACKOFF_MAX_SECS);
        assert_eq!(
            next_backoff_secs(FEDERATION_BACKOFF_MAX_SECS),
            FEDERATION_BACKOFF_MAX_SECS
        );

        // Jitter window: ±25%.
        for entropy in 0..256u64 {
            let duration = jittered_backoff_with_entropy(1, entropy);
            assert!(duration >= Duration::from_millis(750));
            assert!(duration <= Duration::from_millis(1250));
        }

        // Floor of 100ms even when base is zero.
        assert_eq!(
            jittered_backoff_with_entropy(0, 0),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn store_install_makes_first_ready() {
        let store = FederationStore::new();
        assert!(!store.has_first_success());
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: vec![sample_cert_base64()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        store.install_for_test(
            td("remote.example.com"),
            FederatedBundle {
                bundle,
                fetched_at_unix_seconds: 1234,
                endpoint: "https://example/.well-known/spiffe".to_string(),
                cluster_name: "remote".to_string(),
            },
        );
        assert!(store.has_first_success());
        let snap = store.snapshot();
        assert_eq!(snap.bundles.len(), 1);
        let entry = snap.bundles.get(&td("remote.example.com")).expect("entry");
        assert_eq!(entry.fetched_at_unix_seconds, 1234);
    }

    #[test]
    fn merge_overlays_polled_bundles() {
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![TrustBundle {
                trust_domain: td("remote.example.com"),
                x509_authorities: vec!["cp_value".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }],
        };
        let mut polled = FederationSnapshot::default();
        polled.bundles.insert(
            td("remote.example.com"),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: td("remote.example.com"),
                    x509_authorities: vec![sample_cert_base64()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://example".to_string(),
                cluster_name: "remote".to_string(),
            },
        );

        let merged =
            merge_federation_into_trust_bundles(Some(cp_bundle), &polled, None, false, false)
                .expect("merge result");
        assert_eq!(merged.federated.len(), 1);
        assert_eq!(
            merged.federated[0].x509_authorities[0],
            sample_cert_base64()
        );
    }

    #[test]
    fn merge_keeps_disjoint_cp_bundles() {
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![TrustBundle {
                trust_domain: td("kept.example.com"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }],
        };
        let mut polled = FederationSnapshot::default();
        polled.bundles.insert(
            td("remote.example.com"),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: td("remote.example.com"),
                    x509_authorities: vec![sample_cert_base64()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://example".to_string(),
                cluster_name: "remote".to_string(),
            },
        );

        let merged =
            merge_federation_into_trust_bundles(Some(cp_bundle), &polled, None, false, false)
                .expect("merge result");
        let domains: Vec<_> = merged
            .federated
            .iter()
            .map(|tb| tb.trust_domain.as_str().to_string())
            .collect();
        assert!(domains.contains(&"kept.example.com".to_string()));
        assert!(domains.contains(&"remote.example.com".to_string()));
    }

    #[test]
    fn merge_returns_none_without_cp_or_polled() {
        let polled = FederationSnapshot::default();
        assert!(merge_federation_into_trust_bundles(None, &polled, None, false, false).is_none());
    }

    #[test]
    fn merge_returns_cp_only_when_polled_empty() {
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        };
        let polled = FederationSnapshot::default();
        let merged = merge_federation_into_trust_bundles(
            Some(cp_bundle.clone()),
            &polled,
            None,
            false,
            false,
        )
        .expect("kept");
        assert_eq!(merged.federated.len(), 0);
        assert_eq!(merged.local.trust_domain, td("local"));
    }

    #[test]
    fn merge_fail_closed_blocks_cp_fallback_until_first_poll() {
        use crate::modes::mesh::config::RemoteCluster;

        let remote_td = td("remote.example.com");
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![TrustBundle {
                trust_domain: remote_td.clone(),
                x509_authorities: vec!["cp_value".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }],
        };
        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "remote".to_string(),
                trust_domain: remote_td.clone(),
                network: None,
                control_plane_url: None,
                federation_endpoint: Some("https://remote/.well-known/spiffe".to_string()),
            }],
            ..MultiClusterConfig::default()
        };

        let merged = merge_federation_into_trust_bundles(
            Some(cp_bundle),
            &FederationSnapshot::default(),
            Some(&mc),
            false,
            true,
        )
        .expect("merge result");

        assert!(
            merged.federated.is_empty(),
            "fail-closed mode must not activate a CP fallback for a dynamic federation endpoint before a poll succeeds"
        );
    }

    #[test]
    fn merge_fail_open_uses_cp_fallback_until_first_poll() {
        use crate::modes::mesh::config::RemoteCluster;

        let remote_td = td("remote.example.com");
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![TrustBundle {
                trust_domain: remote_td.clone(),
                x509_authorities: vec!["cp_value".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }],
        };
        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "remote".to_string(),
                trust_domain: remote_td.clone(),
                network: None,
                control_plane_url: None,
                federation_endpoint: Some("https://remote/.well-known/spiffe".to_string()),
            }],
            ..MultiClusterConfig::default()
        };

        let merged = merge_federation_into_trust_bundles(
            Some(cp_bundle),
            &FederationSnapshot::default(),
            Some(&mc),
            true,
            true,
        )
        .expect("merge result");

        assert_eq!(merged.federated.len(), 1);
        assert_eq!(merged.federated[0].trust_domain, remote_td);
        assert_eq!(merged.federated[0].x509_authorities[0], "cp_value");
    }

    #[test]
    fn merge_polled_bundle_wins_in_fail_closed_mode() {
        use crate::modes::mesh::config::RemoteCluster;

        let remote_td = td("remote.example.com");
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![TrustBundle {
                trust_domain: remote_td.clone(),
                x509_authorities: vec!["cp_value".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }],
        };
        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "remote".to_string(),
                trust_domain: remote_td.clone(),
                network: None,
                control_plane_url: None,
                federation_endpoint: Some("https://remote/.well-known/spiffe".to_string()),
            }],
            ..MultiClusterConfig::default()
        };
        let mut polled = FederationSnapshot::default();
        polled.bundles.insert(
            remote_td.clone(),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: remote_td.clone(),
                    x509_authorities: vec![sample_cert_base64()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://remote/.well-known/spiffe".to_string(),
                cluster_name: "remote".to_string(),
            },
        );

        let merged =
            merge_federation_into_trust_bundles(Some(cp_bundle), &polled, Some(&mc), false, true)
                .expect("merge result");

        assert_eq!(merged.federated.len(), 1);
        assert_eq!(merged.federated[0].trust_domain, remote_td);
        assert_eq!(
            merged.federated[0].x509_authorities[0],
            sample_cert_base64()
        );
    }

    #[test]
    fn poll_targets_skip_blank_or_missing_endpoints() {
        use crate::modes::mesh::config::RemoteCluster;
        let mc = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![
                RemoteCluster {
                    name: "with-endpoint".to_string(),
                    trust_domain: td("a"),
                    network: None,
                    control_plane_url: None,
                    federation_endpoint: Some("https://a/.well-known/spiffe".to_string()),
                },
                RemoteCluster {
                    name: "no-endpoint".to_string(),
                    trust_domain: td("b"),
                    network: None,
                    control_plane_url: None,
                    federation_endpoint: None,
                },
                RemoteCluster {
                    name: "blank-endpoint".to_string(),
                    trust_domain: td("c"),
                    network: None,
                    control_plane_url: None,
                    federation_endpoint: Some("   ".to_string()),
                },
            ],
            east_west_gateways: Vec::new(),
        };
        let targets = poll_targets_for_multi_cluster(&mc);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].cluster_name, "with-endpoint");
    }

    #[test]
    fn poll_targets_cap_federation_endpoints() {
        use crate::modes::mesh::config::RemoteCluster;
        let mc = MultiClusterConfig {
            remote_clusters: (0..=MAX_MESH_REMOTE_CLUSTERS)
                .map(|index| RemoteCluster {
                    name: format!("cluster-{index}"),
                    trust_domain: td(&format!("remote-{index}.test")),
                    network: None,
                    control_plane_url: None,
                    federation_endpoint: Some(format!(
                        "https://remote-{index}.example/.well-known/spiffe"
                    )),
                })
                .collect(),
            ..MultiClusterConfig::default()
        };

        let targets = poll_targets_for_multi_cluster(&mc);

        assert_eq!(targets.len(), MAX_MESH_REMOTE_CLUSTERS);
        assert!(
            targets
                .iter()
                .all(|target| target.cluster_name != format!("cluster-{MAX_MESH_REMOTE_CLUSTERS}"))
        );
    }

    #[test]
    fn config_from_env_disables_when_interval_zero() {
        assert!(FederationPollerConfig::from_env(0, 30, false).is_none());
        let cfg = FederationPollerConfig::from_env(60, 10, true).expect("enabled");
        assert_eq!(cfg.poll_interval, Duration::from_secs(60));
        assert_eq!(cfg.request_timeout, Duration::from_secs(10));
        assert!(cfg.fail_open);
    }

    #[test]
    fn validate_federation_endpoint_rejects_cloud_metadata() {
        let err = validate_federation_endpoint("https://169.254.169.254/x")
            .expect_err("cloud metadata IP must be rejected");
        assert!(err.contains("link-local") || err.contains("metadata"));
    }

    #[test]
    fn validate_federation_endpoint_rejects_link_local_v6() {
        let err = validate_federation_endpoint("https://[fe80::1]/x")
            .expect_err("IPv6 link-local must be rejected");
        assert!(err.contains("link-local"));
    }

    #[test]
    fn validate_federation_endpoint_allows_loopback_for_tests() {
        validate_federation_endpoint("http://127.0.0.1:9090/x")
            .expect("loopback http is allowed for test scaffolding");
        validate_federation_endpoint("http://[::1]:9090/x").expect("loopback IPv6 is allowed");
    }

    #[test]
    fn validate_federation_endpoint_accepts_https_hostname() {
        validate_federation_endpoint("https://federation.cluster-2.example.com/.well-known/spiffe")
            .expect("valid https hostname endpoint must be accepted");
    }

    #[test]
    fn validate_federation_endpoint_rejects_ftp_scheme() {
        let err = validate_federation_endpoint("ftp://example.com/")
            .expect_err("non-http(s) schemes must be rejected");
        assert!(err.contains("http"));
    }

    #[test]
    fn sanitize_endpoint_strips_userinfo() {
        let safe = sanitize_endpoint_for_logging("https://user:token@host.example/path");
        assert!(!safe.contains("user"), "userinfo must be stripped: {safe}");
        assert!(!safe.contains("token"), "password must be stripped: {safe}");
        assert!(safe.contains("host.example"), "host preserved: {safe}");
    }

    #[test]
    fn validate_federation_endpoint_errors_do_not_echo_userinfo() {
        let err = validate_federation_endpoint("https://user:token@")
            .expect_err("invalid credentialed endpoints must be rejected");
        assert!(!err.contains("user"), "username must be stripped: {err}");
        assert!(!err.contains("token"), "password must be stripped: {err}");
    }

    #[test]
    fn parse_native_rejects_too_many_x509_authorities() {
        let mut authorities = Vec::with_capacity(FEDERATION_MAX_X509_AUTHORITIES + 1);
        for _ in 0..(FEDERATION_MAX_X509_AUTHORITIES + 1) {
            authorities.push("ZGVhZGJlZWY=".to_string()); // base64 "deadbeef"
        }
        let doc = serde_json::json!({
            "trust_domain": "cluster-2.local",
            "x509_authorities": authorities,
        });
        let body = serde_json::to_vec(&doc).unwrap();
        let td = TrustDomain::new("cluster-2.local").unwrap();
        let err = parse_federation_document(&body, &td)
            .expect_err("exceeding the x509 cap must be rejected");
        assert!(err.contains("max"));
    }

    #[tokio::test]
    async fn install_is_atomic_across_concurrent_polls() {
        // Two concurrent successful polls (different trust domains) must
        // not stomp each other. Without RCU the second store would discard
        // the first.
        let store = FederationStore::new();
        let td_a = TrustDomain::new("cluster-a.local").unwrap();
        let td_b = TrustDomain::new("cluster-b.local").unwrap();
        let bundle_a = FederatedBundle {
            bundle: TrustBundle {
                trust_domain: td_a.clone(),
                x509_authorities: vec!["a".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            fetched_at_unix_seconds: 1,
            endpoint: "https://a/".to_string(),
            cluster_name: "a".to_string(),
        };
        let bundle_b = FederatedBundle {
            bundle: TrustBundle {
                trust_domain: td_b.clone(),
                x509_authorities: vec!["b".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            fetched_at_unix_seconds: 2,
            endpoint: "https://b/".to_string(),
            cluster_name: "b".to_string(),
        };

        // Register each cluster once and reuse its generation token across
        // all 50 concurrent installs, so this test exercises the RCU's
        // cross-trust-domain atomicity rather than generation churn.
        let gen_a = store.register("cluster-a");
        let gen_b = store.register("cluster-b");
        let store_a = store.clone();
        let store_b = store.clone();
        let h1 = tokio::spawn(async move {
            for _ in 0..50 {
                store_a.install("cluster-a", td_a.clone(), bundle_a.clone(), gen_a);
            }
        });
        let h2 = tokio::spawn(async move {
            for _ in 0..50 {
                store_b.install("cluster-b", td_b.clone(), bundle_b.clone(), gen_b);
            }
        });
        let _ = h1.await;
        let _ = h2.await;

        let snap = store.snapshot();
        assert_eq!(
            snap.bundles.len(),
            2,
            "both trust domains must survive concurrent installs: {:?}",
            snap.bundles.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn install_with_stale_generation_after_remove_is_dropped() {
        // Mirrors the abort->install race: a poll task registered at generation
        // G is withdrawn (remove_cluster() retires G), then completes its in-flight
        // install with the now-stale G. That install MUST be dropped — it must
        // not resurrect the withdrawn trust anchor.
        let store = FederationStore::new();
        let domain = td("eu.example.com");
        let federated = |ts: u64| FederatedBundle {
            bundle: TrustBundle {
                trust_domain: domain.clone(),
                x509_authorities: vec!["a".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            fetched_at_unix_seconds: ts,
            endpoint: "https://eu/.well-known/spiffe".to_string(),
            cluster_name: "eu".to_string(),
        };

        let stale_gen = store.register("eu");
        store.remove_cluster("eu", &domain, true); // withdrawal retires the generation
        assert!(
            !store.install("eu", domain.clone(), federated(1), stale_gen),
            "stale-generation install must report that it did not commit"
        );
        assert!(
            !store.snapshot().bundles.contains_key(&domain),
            "a stale-generation install after withdrawal must be dropped (no resurrection)"
        );

        // A fresh registration (cluster re-added) installs normally.
        let fresh_gen = store.register("eu");
        assert!(store.install("eu", domain.clone(), federated(2), fresh_gen));
        assert!(
            store.snapshot().bundles.contains_key(&domain),
            "a current-generation install after re-registration must commit"
        );
    }

    #[test]
    fn remove_without_cached_bundle_retires_generation_and_bumps_revision() {
        let store = FederationStore::new();
        let domain = td("first-poll-race.example.com");
        let revision_rx = store.subscribe();
        let stale_gen = store.register("race-cluster");

        store.remove_cluster("race-cluster", &domain, true);

        assert_eq!(
            *revision_rx.borrow(),
            1,
            "removing a registered cluster without a cached bundle still republishes the snapshot"
        );
        let federated = FederatedBundle {
            bundle: TrustBundle {
                trust_domain: domain.clone(),
                x509_authorities: vec!["a".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            fetched_at_unix_seconds: 1,
            endpoint: "https://race/.well-known/spiffe".to_string(),
            cluster_name: "race-cluster".to_string(),
        };
        assert!(
            !store.install("race-cluster", domain.clone(), federated, stale_gen),
            "first poll racing a remove must not commit after generation retirement"
        );
        assert!(!store.snapshot().bundles.contains_key(&domain));
    }

    #[tokio::test]
    async fn manager_reconcile_starts_poller_and_removes_bundle_on_withdrawal() {
        use crate::modes::mesh::config::RemoteCluster;

        let store = FederationStore::new();
        let td_a = td("cluster-a.local");
        // Pre-install a federated bundle as if a poll had already succeeded.
        store.install_for_test(
            td_a.clone(),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: td_a.clone(),
                    x509_authorities: vec!["a".to_string()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://remote-a/.well-known/spiffe".to_string(),
                cluster_name: "cluster-a".to_string(),
            },
        );
        assert!(store.snapshot().bundles.contains_key(&td_a));

        let config = FederationPollerConfig {
            poll_interval: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
            fail_open: false,
        };
        let mut manager =
            FederationPollerManager::new(Some(config), PluginHttpClient::default(), store.clone());

        let cluster_a = RemoteCluster {
            name: "cluster-a".to_string(),
            trust_domain: td_a.clone(),
            network: None,
            control_plane_url: None,
            federation_endpoint: Some("https://remote-a/.well-known/spiffe".to_string()),
        };
        let slice_with_a = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![cluster_a],
            east_west_gateways: Vec::new(),
        };

        // Reconcile in: a poller is tracked and the bundle stays.
        manager.reconcile(Some(&slice_with_a));
        assert_eq!(
            manager.running_cluster_names(),
            vec!["cluster-a".to_string()]
        );
        assert!(store.snapshot().bundles.contains_key(&td_a));

        // Reconcile out: cluster removed from the slice → poller stopped AND its
        // stale federated bundle dropped (no restart needed).
        let empty_slice = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: Vec::new(),
            east_west_gateways: Vec::new(),
        };
        manager.reconcile(Some(&empty_slice));
        assert!(manager.running_cluster_names().is_empty());
        assert!(
            !store.snapshot().bundles.contains_key(&td_a),
            "withdrawn cluster's federated bundle must be removed"
        );
    }

    #[tokio::test]
    async fn manager_reconcile_keeps_shared_trust_domain_bundle_from_remaining_cluster() {
        use crate::modes::mesh::config::RemoteCluster;

        let store = FederationStore::new();
        let shared_td = td("shared.local");
        let config = FederationPollerConfig {
            poll_interval: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
            fail_open: false,
        };
        let mut manager =
            FederationPollerManager::new(Some(config), PluginHttpClient::default(), store.clone());

        let cluster = |name: &str, endpoint: &str| RemoteCluster {
            name: name.to_string(),
            trust_domain: shared_td.clone(),
            network: None,
            control_plane_url: None,
            federation_endpoint: Some(endpoint.to_string()),
        };
        let slice_with_both = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![
                cluster("cluster-a", "https://remote-a/.well-known/spiffe"),
                cluster("cluster-b", "https://remote-b/.well-known/spiffe"),
            ],
            east_west_gateways: Vec::new(),
        };

        manager.reconcile(Some(&slice_with_both));
        assert_eq!(
            manager.running_cluster_names(),
            vec!["cluster-a".to_string(), "cluster-b".to_string()]
        );

        store.install_for_test(
            shared_td.clone(),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: shared_td.clone(),
                    x509_authorities: vec!["shared".to_string()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://remote-b/.well-known/spiffe".to_string(),
                cluster_name: "cluster-b".to_string(),
            },
        );
        assert!(store.snapshot().bundles.contains_key(&shared_td));

        let slice_with_b = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![cluster("cluster-b", "https://remote-b/.well-known/spiffe")],
            east_west_gateways: Vec::new(),
        };
        manager.reconcile(Some(&slice_with_b));
        assert_eq!(
            manager.running_cluster_names(),
            vec!["cluster-b".to_string()]
        );
        assert!(
            store.snapshot().bundles.contains_key(&shared_td),
            "removing one poller must keep a bundle installed by a remaining same-domain cluster"
        );

        let empty_slice = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: Vec::new(),
            east_west_gateways: Vec::new(),
        };
        manager.reconcile(Some(&empty_slice));
        assert!(manager.running_cluster_names().is_empty());
        assert!(
            !store.snapshot().bundles.contains_key(&shared_td),
            "the shared trust-domain bundle is removed only after the last poller is gone"
        );
    }

    #[tokio::test]
    async fn manager_reconcile_removes_shared_trust_domain_bundle_from_removed_cluster() {
        use crate::modes::mesh::config::RemoteCluster;

        let store = FederationStore::new();
        let shared_td = td("shared-source.local");
        let config = FederationPollerConfig {
            poll_interval: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
            fail_open: false,
        };
        let mut manager =
            FederationPollerManager::new(Some(config), PluginHttpClient::default(), store.clone());

        let cluster = |name: &str, endpoint: &str| RemoteCluster {
            name: name.to_string(),
            trust_domain: shared_td.clone(),
            network: None,
            control_plane_url: None,
            federation_endpoint: Some(endpoint.to_string()),
        };
        let slice_with_both = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![
                cluster("cluster-a", "https://remote-a/.well-known/spiffe"),
                cluster("cluster-b", "https://remote-b/.well-known/spiffe"),
            ],
            east_west_gateways: Vec::new(),
        };
        manager.reconcile(Some(&slice_with_both));

        store.install_for_test(
            shared_td.clone(),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: shared_td.clone(),
                    x509_authorities: vec!["old-a".to_string()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://remote-a/.well-known/spiffe".to_string(),
                cluster_name: "cluster-a".to_string(),
            },
        );
        assert!(store.snapshot().bundles.contains_key(&shared_td));

        let slice_with_b = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![cluster("cluster-b", "https://remote-b/.well-known/spiffe")],
            east_west_gateways: Vec::new(),
        };
        manager.reconcile(Some(&slice_with_b));
        assert_eq!(
            manager.running_cluster_names(),
            vec!["cluster-b".to_string()]
        );
        assert!(
            !store.snapshot().bundles.contains_key(&shared_td),
            "bundle installed by the removed cluster must be withdrawn even while a same-domain sibling remains"
        );
    }

    #[tokio::test]
    async fn manager_reconcile_restarts_poller_on_endpoint_change() {
        use crate::modes::mesh::config::RemoteCluster;

        let store = FederationStore::new();
        let td_a = td("cluster-a.local");
        let config = FederationPollerConfig {
            poll_interval: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
            fail_open: false,
        };
        let mut manager =
            FederationPollerManager::new(Some(config), PluginHttpClient::default(), store.clone());

        let slice = |endpoint: &str| MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![RemoteCluster {
                name: "cluster-a".to_string(),
                trust_domain: td_a.clone(),
                network: None,
                control_plane_url: None,
                federation_endpoint: Some(endpoint.to_string()),
            }],
            east_west_gateways: Vec::new(),
        };

        manager.reconcile(Some(&slice("https://remote-a-v1/.well-known/spiffe")));
        assert_eq!(
            manager.running_cluster_names(),
            vec!["cluster-a".to_string()]
        );

        // Simulate a successful poll having installed a bundle.
        store.install_for_test(
            td_a.clone(),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: td_a.clone(),
                    x509_authorities: vec!["a".to_string()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://remote-a-v1/.well-known/spiffe".to_string(),
                cluster_name: "cluster-a".to_string(),
            },
        );
        assert!(store.snapshot().bundles.contains_key(&td_a));

        // A federation_endpoint change makes the target stale → the poller is
        // stopped and restarted against the new endpoint. The cluster stays
        // tracked; its bundle is transiently dropped (the restarted poller
        // re-fetches from the new endpoint), matching RemoteDiscoveryManager's
        // stale-restart semantics — a fail-closed blip, never a stale anchor.
        manager.reconcile(Some(&slice("https://remote-a-v2/.well-known/spiffe")));
        assert_eq!(
            manager.running_cluster_names(),
            vec!["cluster-a".to_string()],
            "cluster stays tracked across an endpoint change (poller restarted)"
        );
        assert!(
            !store.snapshot().bundles.contains_key(&td_a),
            "endpoint change transiently drops the bundle until the restarted poller re-fetches"
        );
    }
}
