//! Cross-cluster endpoint discovery (Tier 3b).
//!
//! Today "multi-cluster" in Ferrum is east-west SNI passthrough
//! ([`materialize_east_west_gateway_proxies`](super::materialize_east_west_gateway_proxies))
//! plus federated trust bundles ([`super::federation`]). The
//! [`RemoteCluster.control_plane_url`](crate::modes::mesh::config::RemoteCluster)
//! field was inert — referenced only by a non-empty validation, never dialed.
//! This module makes it functional: it dials each remote cluster's control
//! plane, fetches that cluster's service endpoints (workloads + services), and
//! stores them in an `ArcSwap`-held snapshot. The slice-apply path merges that
//! snapshot into the local mesh `workloads` / `services` (see
//! [`merge_remote_endpoints_into_mesh`]), tagging remote workloads with a
//! distinct locality so the existing **locality-aware priority-tier load
//! balancer** fails over local → remote at the endpoint level: local targets
//! sit in the source region/zone tier, and remote targets only receive traffic
//! once the local tier has no healthy endpoints.
//!
//! Design notes (kept in lock-step with [`super::federation`]):
//!
//! - **Lock-free hot path**: the slice-apply reader loads the snapshot via
//!   [`RemoteEndpointStore::snapshot`] (one `ArcSwap` deref). The request hot
//!   path is unchanged — remote endpoints become ordinary `Upstream` targets.
//! - **Mockable source**: [`RemoteServiceSource`] abstracts the remote fetch.
//!   The production implementation ([`NativeRemoteSource`]) dials the remote CP
//!   over the native `MeshSubscribe` gRPC stream and reuses the DP gRPC TLS /
//!   JWT machinery; tests inject a deterministic mock. This lets the full
//!   discovery + aggregation + failover path be verified without a live remote
//!   control plane.
//! - **Fail-closed mTLS**: a remote cluster is only polled when cross-cluster
//!   trust is established (a federated trust bundle for the remote trust domain
//!   exists, matching the fail-closed posture of [`super::federation`]). A
//!   failed poll keeps the last-good endpoints and bumps a failure metric;
//!   once-and-only-once failures never delete previously fetched endpoints.
//! - **Backoff**: each remote cluster runs its own task with jittered
//!   exponential backoff (1s → 30s, ±25%) matching the federation poller and
//!   `src/grpc/dp_client.rs`.
//! - **Shutdown**: every loop watches the gateway shutdown channel.
//!
//! ## Live-verification status
//!
//! The aggregation + failover path and the poll loop are covered by unit tests
//! with a mock [`RemoteServiceSource`]. The [`NativeRemoteSource`] gRPC dialer
//! is additionally covered by an in-process two-CP round trip: tests stand up a
//! real `MeshSubscribe` gRPC server on a loopback port and drive the production
//! dialer against it — channel dial, DP-JWT mint + server-side verification,
//! heartbeat skipping, slice decode, endpoint extraction, and a full
//! discovery-loop install (see `mod tests`). The remaining live-verification
//! step is a true cross-cluster deployment — two mesh control planes on
//! separate networks — exercising the dialer under real network churn / loss /
//! latency. This is documented for operators in `docs/mesh.md` "Cross-Cluster
//! Endpoint Discovery".

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::grpc::dp_client::{DpGrpcTlsConfig, GrpcJwtSecret};
use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::config::{
    AppProtocol, MAX_MESH_REMOTE_CLUSTERS, MeshService, MultiClusterConfig, Workload,
};
use crate::modes::mesh::config_consumer::common::{
    BACKOFF_INITIAL_SECS, MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE, jittered_backoff,
    next_backoff_secs as common_next_backoff_secs,
};

/// Backoff bounds shared with [`super::federation`] and
/// `src/grpc/dp_client.rs`. One cross-cluster backoff curve for operators to
/// reason about.
pub(crate) const REMOTE_BACKOFF_INITIAL_SECS: u64 = BACKOFF_INITIAL_SECS;
#[allow(dead_code)]
pub(crate) const DEFAULT_REMOTE_DISCOVERY_MAX_STALE_SECONDS: u64 = 300;

/// Defense-in-depth cap on the number of workloads / services a single remote
/// cluster may contribute. A misbehaving (or compromised) remote CP cannot
/// balloon local memory or the load-balancer target lists. Realistic clusters
/// are far below this.
const REMOTE_MAX_WORKLOADS_PER_CLUSTER: usize = 50_000;
const REMOTE_MAX_SERVICES_PER_CLUSTER: usize = 10_000;

/// The endpoints one remote cluster contributes: its `workloads` (carrying
/// addresses, ports, and locality) and `services` (name/namespace/ports +
/// workload refs). These are merged into the local mesh registry at slice
/// apply.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RemoteClusterEndpoints {
    pub workloads: Vec<Workload>,
    pub services: Vec<MeshService>,
}

/// One installed remote cluster's endpoints plus provenance.
///
/// `fetched_at` is a shared [`AtomicU64`] (not a plain `u64`) so a no-op poll —
/// identical endpoints, only a newer poll timestamp — can refresh the age in
/// place via a single relaxed store, WITHOUT cloning the snapshot or this
/// entry's [`RemoteClusterEndpoints`] payload (which can hold tens of thousands
/// of workloads/services near the per-cluster caps). The atomic is published
/// inside the live `ArcSwap` snapshot, so the lock-free admin/apply readers
/// observe the refreshed value without a swap. A *changed* endpoint set still
/// goes through the full `inner.rcu` install, which mints a fresh `fetched_at`
/// for the new entry. See [`RemoteEndpointStore::install`].
#[derive(Debug, Clone)]
pub struct RemoteClusterEntry {
    pub cluster_name: String,
    pub trust_domain: TrustDomain,
    /// Network label of the remote cluster, used to default workload locality
    /// when the remote workload carries none.
    pub network: Option<String>,
    /// **Normalized** control-plane URL these endpoints were polled from (the
    /// value the poll task dialed, i.e. [`normalize_control_plane_url`] applied
    /// to the trimmed operator URL). Stored so the FULL poll identity — not just
    /// (name, trust_domain, network) — can be matched against an about-to-be-
    /// applied / accepted slice (codex F7.2 round-5): a slice that changes ONLY
    /// `control_plane_url` for the same name keeps a stale store entry until the
    /// discovery reconciler stops the old poller, and without the URL here the
    /// same-generation admission filter and the admin `discovered` filter cannot
    /// tell the old endpoints (fetched from the previous CP) apart from the
    /// newly-declared identity. `None` only for entries staged without a poll
    /// URL (test seeders); production entries always carry the polled URL.
    pub control_plane_url: Option<String>,
    /// Credential reference (`RemoteCluster.discovery_credential_ref`) the
    /// endpoints were polled UNDER. Part of the poll identity: `matches_declared`
    /// compares it so a slice that rotates or withdraws a cluster's discovery
    /// credential — even with name/trust_domain/network/url unchanged — does NOT
    /// admit endpoints fetched with the old credential. Without it, a credential
    /// change (including to an unresolvable ref that must fail closed) would let
    /// the slice-apply merge keep serving the stale endpoints for a generation,
    /// until the discovery reconciler stops the old poller.
    pub credential_ref: Option<String>,
    pub endpoints: RemoteClusterEndpoints,
    /// Unix-seconds timestamp of the last successful poll for this cluster.
    /// Shared (`Arc<AtomicU64>`) so a no-op poll refreshes it without a clone;
    /// read through [`RemoteClusterEntry::fetched_at_unix_seconds`].
    pub fetched_at: Arc<AtomicU64>,
}

impl RemoteClusterEntry {
    /// Construct an entry, wrapping the poll timestamp in a fresh shared atomic.
    #[allow(dead_code)]
    pub fn new(
        cluster_name: String,
        trust_domain: TrustDomain,
        network: Option<String>,
        control_plane_url: Option<String>,
        credential_ref: Option<String>,
        endpoints: RemoteClusterEndpoints,
        fetched_at_unix_seconds: u64,
    ) -> Self {
        Self {
            cluster_name,
            trust_domain,
            network,
            control_plane_url,
            credential_ref,
            endpoints,
            fetched_at: Arc::new(AtomicU64::new(fetched_at_unix_seconds)),
        }
    }

    /// Last-successful-poll timestamp (Unix seconds). Lock-free relaxed read of
    /// the shared atomic; ordering does not matter (a single scalar refreshed by
    /// one poll task and read for human-facing age reporting).
    pub fn fetched_at_unix_seconds(&self) -> u64 {
        self.fetched_at.load(Ordering::Relaxed)
    }

    /// Whether this stored entry's FULL poll identity matches a `RemoteCluster`
    /// declared in a candidate / accepted slice. The poll identity is
    /// (name, trust_domain, network, **normalized control_plane_url**,
    /// **discovery_credential_ref**): two clusters that share a name but differ
    /// on any of those resolve / dial / **authenticate** differently and must
    /// not be conflated. The credential ref is included so rotating or
    /// withdrawing a cluster's discovery credential (even to an unresolvable ref
    /// that must fail closed) immediately stops admitting endpoints fetched with
    /// the old credential, rather than serving them until the reconciler stops
    /// the old poller.
    ///
    /// The declared URL is normalized + trimmed the SAME way the poll target is
    /// ([`poll_targets_for_multi_cluster`] → [`normalize_control_plane_url`])
    /// before comparison, so an operator-written `grpcs://` declaration matches a
    /// stored `https://` poll URL and trailing whitespace never causes a false
    /// mismatch. A declaration with no usable `control_plane_url` is never a
    /// match for a stored (polled) entry — such a cluster is federation-only and
    /// is never polled, so it cannot legitimately own discovered endpoints.
    ///
    /// Centralizing this here keeps the same-generation merge filter
    /// ([`cluster_admitted_by_candidate`]) and the admin `discovered` filter
    /// (`admin::mesh_remote_clusters::build_response`) from drifting: both ask
    /// the SAME "is this stored entry the one this slice declares?" question.
    pub fn matches_declared(&self, declared: &crate::modes::mesh::config::RemoteCluster) -> bool {
        if declared.name != self.cluster_name
            || declared.trust_domain != self.trust_domain
            || declared.network != self.network
            || declared.discovery_credential_ref != self.credential_ref
        {
            return false;
        }
        match declared.control_plane_url.as_deref().map(str::trim) {
            Some(url) if !url.is_empty() => {
                self.control_plane_url.as_deref() == Some(normalize_control_plane_url(url).as_str())
            }
            // Federation-only (or empty) declaration: never owns polled endpoints.
            _ => false,
        }
    }
}

/// Snapshot the store hands out to slice apply and the admin API. Keyed by
/// remote cluster name (`RemoteCluster.name` is validated unique).
#[derive(Debug, Default, Clone)]
pub struct RemoteEndpointSnapshot {
    pub clusters: HashMap<String, RemoteClusterEntry>,
}

impl RemoteEndpointSnapshot {
    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty()
    }
}

/// Outcome of a [`RemoteEndpointStore::install`] call.
///
/// `install` returns more than a simple `bool` so the poll loop can tell a
/// *live* poll (endpoints changed, or an unchanged-but-still-registered dedup
/// whose `fetched_at` was refreshed) apart from a poll that landed after the
/// cluster's generation was retired (removed / trust withdrawn). Only the first
/// two are a genuinely successful poll worth recording in the success / age
/// metrics; a [`RemoteInstallOutcome::Retired`] no-op must NOT mark the cluster
/// freshly-polled, or `/metrics` would advertise a healthy remote cluster whose
/// endpoints were intentionally dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteInstallOutcome {
    /// Endpoints changed and were committed (the apply task was woken).
    Installed,
    /// Generation still matches but the endpoints were identical to what is
    /// stored, so only the poll timestamp was refreshed (F2 dedup). Still a
    /// successful live poll.
    Deduped,
    /// The task's cluster generation was retired mid-flight (the cluster was
    /// removed or its trust was withdrawn): a true no-op. Nothing was installed
    /// and the cluster is no longer live.
    Retired,
}

impl RemoteInstallOutcome {
    /// Whether endpoints were actually committed (used for "installed" logging
    /// and revision/first-ready bookkeeping).
    fn installed(self) -> bool {
        matches!(self, RemoteInstallOutcome::Installed)
    }

    /// Whether this poll reflects a live, registered cluster — i.e. it should
    /// refresh the success / last-success / endpoint-age metrics. A retired
    /// generation is excluded.
    fn is_live_poll(self) -> bool {
        matches!(
            self,
            RemoteInstallOutcome::Installed | RemoteInstallOutcome::Deduped
        )
    }
}

/// Lock-free shared state populated by the discovery poller and consumed by the
/// slice-apply path. Mirrors [`super::federation::FederationStore`].
#[derive(Clone)]
pub struct RemoteEndpointStore {
    inner: Arc<ArcSwap<RemoteEndpointSnapshot>>,
    first_ready: Arc<AtomicBool>,
    /// Bumped on every successful install/remove so the slice-apply task
    /// re-runs even when the local CP config is unchanged (a remote cluster
    /// scaling up/down must re-materialize the aggregated upstream targets).
    revision_tx: Arc<watch::Sender<u64>>,
    /// Monotonically-increasing generation counter. `RemoteDiscoveryManager`
    /// stamps each poll task with the generation at launch; `install` checks
    /// that the task's generation is still current before committing an update.
    /// This prevents a task that was aborted during a mid-flight `fetch()` from
    /// installing its (now stale) result after `remove()` has already cleared
    /// the cluster — closing the abort→install race (F6).
    generation: Arc<AtomicU64>,
    /// Generation at which each cluster was last registered. Stored alongside
    /// the snapshot so `install` can compare atomically.
    cluster_generation: Arc<ArcSwap<HashMap<String, u64>>>,
    /// Serializes the remote-discovery success-metric *record* (in the poll
    /// task) against the success-metric *clear* + generation retire (in the
    /// reconcile task). The generation check that authorizes a metric record is
    /// lock-free inside `install`, but the metric write itself lands in a
    /// separate `DashMap` from `cluster_generation`, so without this lock a poll
    /// that observed a live generation could resurrect the success / last-success
    /// / endpoint-age series *after* a concurrent `remove` cleared it — leaving a
    /// freshly-polled, endpoint-less cluster visible on unauthenticated
    /// `/metrics`. Holding this lock across the generation-retire+clear and the
    /// generation-check+record makes the two mutually exclusive, so removal can
    /// never lose the race. This is the multi-second discovery/reconcile control
    /// path, never the request hot path, so a mutex here is fine.
    metrics_ordering: Arc<std::sync::Mutex<()>>,
}

impl Default for RemoteEndpointStore {
    fn default() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(RemoteEndpointSnapshot::default()))),
            first_ready: Arc::new(AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
            generation: Arc::new(AtomicU64::new(0)),
            cluster_generation: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            metrics_ordering: Arc::new(std::sync::Mutex::new(())),
        }
    }
}

impl RemoteEndpointStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock-free read.
    pub fn snapshot(&self) -> Arc<RemoteEndpointSnapshot> {
        self.inner.load_full()
    }

    /// `true` after at least one remote cluster has been successfully polled.
    #[cfg(test)]
    pub fn has_first_success(&self) -> bool {
        self.first_ready.load(Ordering::Acquire)
    }

    /// Subscribe to install events. Mirrors `MeshRuntimeState::subscribe()`.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    /// Test helper: register a cluster and immediately install its entry in one
    /// step. Production code must use `register_cluster` + `install` so the
    /// generation token is passed through the poll task.
    ///
    /// `#[cfg(test)]` so this seeder is NEVER compiled into production builds and
    /// can never be reached through the public `MeshRuntimeState` API — staging
    /// a discovered snapshot is exclusively an in-crate test concern. It is
    /// `pub(crate)` (not module-private) so the mesh apply-loop tests in
    /// `super::mod` can seed the store to exercise the rejected-received-slice
    /// re-apply path (codex F7.2 round-4); it remains test-only and unreachable
    /// from production code.
    #[cfg(test)]
    pub(crate) fn install_for_test(&self, entry: RemoteClusterEntry) {
        let new_gen = self.register_cluster(&entry.cluster_name);
        self.install(entry, new_gen);
    }

    /// Register a newly-started poll task for `cluster_name` and return its
    /// generation token. The task must pass this token back to `install`; if the
    /// token no longer matches the cluster's current generation (because the
    /// cluster was removed and re-added, or removed and not re-added) the
    /// install is silently dropped, preventing the abort→install race (F6).
    pub(crate) fn register_cluster(&self, cluster_name: &str) -> u64 {
        let new_gen = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.cluster_generation.rcu(|current| {
            let mut next = (**current).clone();
            next.insert(cluster_name.to_string(), new_gen);
            Arc::new(next)
        });
        new_gen
    }

    /// Install remote endpoints for a cluster **only** when `task_generation`
    /// still matches the cluster's registered generation. A task whose cluster
    /// was removed (or removed + re-started at a newer generation) while the
    /// task was mid-`fetch` will find a mismatched generation and its result
    /// is discarded — closing the abort→install race (F6).
    ///
    /// When the endpoints are byte-identical to what is already stored, the
    /// apply task is NOT woken and the revision is NOT bumped (F2) — but the
    /// stored `fetched_at` IS refreshed to this poll's timestamp. That keeps the
    /// admin endpoint's `age_seconds` measuring time-since-last-successful-POLL
    /// rather than time-since-last-endpoint-CHANGE, so a healthy but stable
    /// remote cluster does not look stale to operator alerting. The refresh is a
    /// single relaxed store into the entry's **shared** `fetched_at` atomic — it
    /// does NOT clone the snapshot or the (potentially huge) endpoint payload,
    /// and it does NOT touch `revision_tx`/`first_ready`, preserving the
    /// "no reconcile on unchanged endpoints" optimization without the
    /// steady-state per-poll deep-clone the previous in-`rcu` refresh incurred.
    ///
    /// Returns a [`RemoteInstallOutcome`] distinguishing a real install, a
    /// dedup (timestamp-only refresh of a still-registered cluster), and a
    /// retired-generation no-op (cluster removed / trust withdrawn). Callers use
    /// this both to avoid logging "installed" on a no-op and to avoid recording
    /// a successful-poll metric for a cluster whose endpoints were dropped.
    fn install(&self, entry: RemoteClusterEntry, task_generation: u64) -> RemoteInstallOutcome {
        let name = entry.cluster_name.clone();
        // Fast-path generation check: bail out early if the task's cluster slot
        // was already retired, avoiding the swap for stale tasks. This is
        // re-validated below — it is only an optimization, not the authoritative
        // check.
        if !self.cluster_generation_matches(&name, task_generation) {
            return RemoteInstallOutcome::Retired;
        }
        // No-op dedup: endpoints identical to what is stored. Refresh only the
        // poll timestamp (so `age_seconds` tracks polls) via the entry's shared
        // atomic — NO snapshot/endpoint clone — and do NOT wake the apply task.
        //
        // Concurrency: the atomic lives inside the currently-published snapshot
        // (`current`), so the store is visible to lock-free readers without an
        // `ArcSwap` swap. The generation is RE-CHECKED immediately before the
        // store so a stale task (whose cluster was removed, or removed and
        // re-registered at a newer generation) cannot refresh a live entry's
        // age: `remove()` retires the generation BEFORE clearing `inner`, so
        // either the recheck fails (skip) or `remove` has not yet cleared the
        // entry and a harmless store lands on an entry about to be dropped from
        // the snapshot (the next published snapshot — without this cluster, or
        // with the re-registered cluster's own fresh atomic — is what readers
        // see). It can therefore never resurrect a removed cluster (the entry is
        // already present; we add nothing) nor mis-age a re-registered one.
        {
            let current = self.inner.load();
            if let Some(existing) = current.clusters.get(&name)
                && existing.endpoints == entry.endpoints
            {
                // Re-check the generation immediately before the timestamp
                // refresh: if the cluster was retired between the fast-path
                // check and here, this poll lands on an entry about to be
                // dropped and is NOT a live refresh — report it as retired so
                // the success metric is not bumped for a removed cluster.
                if self.cluster_generation_matches(&name, task_generation) {
                    existing
                        .fetched_at
                        .store(entry.fetched_at_unix_seconds(), Ordering::Relaxed);
                    return RemoteInstallOutcome::Deduped;
                }
                return RemoteInstallOutcome::Retired;
            }
        }
        // First sight or CHANGED endpoints: full install via a CAS loop so two
        // concurrent successful polls (different clusters) cannot stomp each
        // other's snapshot clone. The generation is re-checked INSIDE the
        // closure so the check-and-insert is atomic with respect to `remove()`:
        // `remove` retires the generation (in `cluster_generation`) BEFORE
        // clearing endpoints (in `inner`). So if a `remove` races this
        // mid-flight install, either (a) this rcu commits first and `remove`'s
        // subsequent `inner` clear drops the endpoints, or (b) `remove`'s `inner`
        // clear wins the CAS, this closure retries, re-reads the now-retired
        // generation, and skips — never reintroducing endpoints for a removed
        // cluster. Without the in-closure recheck, a stale task could insert
        // after `remove` had already cleared the cluster (the F6 race, widened
        // to the trust-withdrawal case). `outcome` is computed fresh on every
        // closure iteration so a CAS retry never carries a stale verdict.
        let mut outcome = RemoteInstallOutcome::Retired;
        self.inner.rcu(|current| {
            if !self.cluster_generation_matches(&name, task_generation) {
                outcome = RemoteInstallOutcome::Retired;
                return Arc::clone(current);
            }
            // Re-confirm the endpoints still differ: a concurrent poll for the
            // same cluster may have installed identical endpoints between our
            // pre-check above and this CAS attempt. If so, this is a no-op (the
            // timestamp refresh raced ahead) — do not wake the apply task, but
            // it is still a live (deduped) poll since the generation matches.
            if current
                .clusters
                .get(&name)
                .is_some_and(|existing| existing.endpoints == entry.endpoints)
            {
                outcome = RemoteInstallOutcome::Deduped;
                return Arc::clone(current);
            }
            let mut next = (**current).clone();
            next.clusters.insert(name.clone(), entry.clone());
            outcome = RemoteInstallOutcome::Installed;
            Arc::new(next)
        });
        if outcome.installed() {
            self.first_ready.store(true, Ordering::Release);
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
        outcome
    }

    /// Whether `task_generation` still matches the cluster's registered
    /// generation slot. Returns `false` once `remove()` has retired the slot (or
    /// it was re-registered at a newer generation), which is how an in-flight
    /// poll task for a removed/untrusted cluster is prevented from installing.
    fn cluster_generation_matches(&self, cluster_name: &str, task_generation: u64) -> bool {
        self.cluster_generation
            .load()
            .get(cluster_name)
            .is_some_and(|&g| g == task_generation)
    }

    /// Remove a remote cluster's endpoints (slice no longer lists it or trust was
    /// withdrawn). Also retires the generation slot so any in-flight poll task
    /// for this cluster sees a stale generation and cannot reinstall after removal.
    /// No-op if untracked.
    pub fn remove(&self, cluster_name: &str) {
        // Retire the cluster's generation so any in-flight task sees mismatch.
        self.cluster_generation.rcu(|current| {
            if current.contains_key(cluster_name) {
                let mut next = (**current).clone();
                next.remove(cluster_name);
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
        let mut changed = false;
        self.inner.rcu(|current| {
            if current.clusters.contains_key(cluster_name) {
                let mut next = (**current).clone();
                next.clusters.remove(cluster_name);
                changed = true;
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
        if changed {
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
    }

    /// Expire last-good endpoints after a bounded staleness window without
    /// retiring the cluster's generation. The poller remains live and can
    /// reinstall endpoints on a later successful poll.
    pub(crate) fn expire_stale_endpoints_and_clear_metrics(
        &self,
        cluster_name: &str,
        trust_domain: &str,
        now_unix_seconds: u64,
        max_stale_age: Duration,
    ) -> bool {
        let max_stale_seconds = max_stale_age.as_secs();
        if max_stale_seconds == 0 {
            return false;
        }
        let _guard = self
            .metrics_ordering
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.cluster_generation.load().contains_key(cluster_name) {
            return false;
        }
        let mut expired = false;
        self.inner.rcu(|current| {
            // Recompute the outcome on every CAS attempt: a lost CAS (e.g. an old
            // poller failure racing a re-registered cluster installing fresh
            // endpoints) retries the closure against a newer snapshot, so a stale
            // `true` must not survive a retry that removes nothing and then
            // withdraw a fresh cluster's freshness gauges (mirrors `install`'s
            // per-attempt reset of `installed`).
            expired = false;
            let Some(entry) = current.clusters.get(cluster_name) else {
                return Arc::clone(current);
            };
            let age_seconds = now_unix_seconds.saturating_sub(entry.fetched_at_unix_seconds());
            if age_seconds <= max_stale_seconds {
                return Arc::clone(current);
            }
            let mut next = (**current).clone();
            next.clusters.remove(cluster_name);
            expired = true;
            Arc::new(next)
        });
        if expired {
            self.revision_tx.send_modify(|revision| *revision += 1);
            // Withdraw only the freshness gauges. Staleness expiry is transient —
            // the poller stays live and can reinstall endpoints — so the
            // monotonic `ferrum_mesh_remote_discovery_poll_successes_total`
            // counter must be preserved to avoid a counter reset; only the
            // cluster-removal path (`remove_and_clear_metrics`) clears it.
            crate::plugins::mesh::prometheus_helpers::withdraw_mesh_remote_discovery_freshness(
                cluster_name,
                trust_domain,
            );
        }
        expired
    }

    /// Record a successful, still-live remote-discovery poll's success /
    /// last-success / endpoint-age metrics — but only while holding the metrics
    /// ordering lock and re-confirming the cluster's generation under it.
    ///
    /// The poll task computes its live/retired verdict inside `install`, but the
    /// metric write happens in a separate `DashMap` from `cluster_generation`,
    /// so a bare post-`install` record could resurrect the series *after* a
    /// concurrent reconcile already retired the generation and cleared the
    /// metrics (see [`Self::remove_and_clear_metrics`]). Taking the same lock
    /// and re-checking the generation here makes the record mutually exclusive
    /// with the retire+clear: either this record observes a live generation
    /// (and any later clear removes it) or it observes the retired generation
    /// (and skips), so removal can never lose the race and leave a
    /// freshly-polled, endpoint-less cluster on unauthenticated `/metrics`.
    fn record_remote_discovery_success_if_live(
        &self,
        cluster: &str,
        trust_domain: &str,
        fetched_at_unix_seconds: u64,
        task_generation: u64,
    ) {
        // Poison is impossible: the critical sections are panic-free (atomic
        // map ops + an ArcSwap load). Recover the guard either way rather than
        // propagating, since a poisoned ordering lock must not wedge polling.
        let _guard = self
            .metrics_ordering
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.cluster_generation_matches(cluster, task_generation) {
            crate::plugins::mesh::prometheus_helpers::record_mesh_remote_discovery_poll_success(
                cluster,
                trust_domain,
                fetched_at_unix_seconds,
            );
        }
    }

    /// Remove a remote cluster's endpoints **and** prune its discovery metric
    /// series, retiring the generation and clearing the metrics under the
    /// metrics ordering lock so the clear cannot race a concurrent
    /// [`Self::record_remote_discovery_success_if_live`].
    pub(crate) fn remove_and_clear_metrics(&self, cluster_name: &str, trust_domain: &str) {
        let _guard = self
            .metrics_ordering
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Retire the generation + drop the endpoints first, then clear the
        // metric series — all while holding the lock, so a poll task's
        // generation-checked record (which takes the same lock) is serialized
        // against this clear and cannot re-create the cleared series.
        self.remove(cluster_name);
        crate::plugins::mesh::prometheus_helpers::clear_mesh_remote_discovery_metrics(
            cluster_name,
            trust_domain,
        );
    }
}

/// Abstracts the remote-cluster endpoint fetch so the discovery loop is
/// testable without a live remote control plane. The production implementation
/// is [`NativeRemoteSource`]; tests inject a deterministic mock.
#[async_trait]
pub trait RemoteServiceSource: Send + Sync {
    /// Fetch the remote cluster's current service endpoints. Returns `Err` on
    /// any transport / auth / decode failure so the poll loop keeps the
    /// last-good snapshot and backs off.
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String>;
}

/// Locality tag applied to a remote workload that carries no locality of its
/// own, so it still tiers BELOW the local source region in the priority-tier
/// load balancer. Format is `region/zone` where the region is a synthetic
/// `remote-<cluster>` that can never collide with a real local region.
fn default_remote_locality(cluster_name: &str, network: Option<&str>) -> String {
    match network {
        Some(network) if !network.is_empty() => {
            format!("{REMOTE_LOCALITY_PREFIX}{cluster_name}/{network}")
        }
        _ => format!("{REMOTE_LOCALITY_PREFIX}{cluster_name}"),
    }
}

/// Region prefix stamped on remote-cluster endpoints by
/// [`default_remote_locality`] so a remote workload that carries no locality of
/// its own still tiers BELOW the local source region in the priority-tier load
/// balancer. This is a LOCALITY fallback only — it is NOT used to decide whether
/// a target is remote (a real local region could legitimately be named
/// `remote-foo`). Remote provenance is keyed on the explicit [`MESH_REMOTE_TAG`]
/// stamped from the workload's cross-cluster identity.
pub(crate) const REMOTE_LOCALITY_PREFIX: &str = "remote-";

/// Per-target tag key marking a target as a REMOTE-cluster-discovered endpoint —
/// a RESERVED provenance marker the data plane sets and trusts. Stamped
/// (`= "true"`) at materialization time in [`crate::service_discovery::mesh`] from
/// the workload's [`Workload::remote_provenance`] flag ([`workload_is_remote`]),
/// which `tag_remote_workloads` set at remote-poll INGESTION (so it reflects real
/// cross-cluster provenance, NOT `cluster`-name equality or a locality string).
/// It is UN-SPOOFABLE: it never rides a wire/file payload (`#[serde(skip)]` on the
/// flag), and every target builder that copies operator/workload labels into tags
/// strips the reserved `mesh.*` namespace first ([`strip_reserved_mesh_tags`]), so
/// a hand-authored `mesh.remote: "true"` label can never reach a target.
/// Strict local-first locality LB (`Upstream.locality_lb_strict`) keys local vs.
/// remote on the ABSENCE of this tag (checking the exact value), so a real local
/// Kubernetes region whose name happens to begin with `remote-` is never
/// misclassified as remote. Absent on local-cluster and non-mesh targets.
pub(crate) const MESH_REMOTE_TAG: &str = "mesh.remote";

/// The EXACT value the discoverer stamps for [`MESH_REMOTE_TAG`] when a target
/// is a remote-cluster endpoint. Strict local-first locality LB classifies a
/// target as remote ONLY when the tag equals this value, NOT on mere key
/// presence. Single source of truth shared by the stamp site
/// ([`crate::service_discovery::mesh`]) and the check site
/// ([`crate::load_balancer`]) so they can never drift.
pub(crate) const MESH_REMOTE_TAG_VALUE: &str = "true";

/// RESERVED tag-key namespace owned exclusively by Ferrum mesh internals
/// (`mesh.remote`, `mesh.hbone`, `mesh.mtls`, `mesh.spiffe_id`, …). These tags
/// are PROVENANCE / transport markers the data plane sets and trusts; an operator
/// or workload label must never be able to forge one. Any target builder that
/// COPIES workload/operator labels wholesale into `UpstreamTarget.tags` (e.g. the
/// east-west `workload.selector.labels` copy, the egress ServiceEntry endpoint
/// `labels` copy) must strip this namespace first via
/// [`strip_reserved_mesh_tags`] so a user label literally named `mesh.remote:
/// "true"` can never make a LOCAL target masquerade as remote (and so no copied
/// label collides with a transport marker).
pub(crate) const RESERVED_MESH_TAG_PREFIX: &str = "mesh.";

/// Drop every reserved `mesh.*` key (see [`RESERVED_MESH_TAG_PREFIX`]) from a
/// label map copied from operator/workload-controlled input, in place. Mesh
/// internals re-stamp the legitimate `mesh.*` provenance/transport tags
/// themselves (e.g. the discoverer's `mesh.remote`, the egress tag builders'
/// `mesh.hbone`/`mesh.mtls`), so this only removes forge attempts, never a real
/// marker.
pub(crate) fn strip_reserved_mesh_tags(tags: &mut std::collections::HashMap<String, String>) {
    tags.retain(|key, _| !key.starts_with(RESERVED_MESH_TAG_PREFIX));
}

/// Whether a workload is a REMOTE-cluster endpoint.
///
/// Classification is by **discovery provenance**, NOT a locality string prefix:
///
/// 1. **Authoritative signal — [`Workload::remote_provenance`]**: set `true` by
///    [`tag_remote_workloads`] at the DP-side remote-poll ingestion point, which
///    KNOWS the endpoint came from a remote discovery slice. This is checked FIRST
///    and is independent of any `cluster`-name matching, so a genuinely-remote
///    endpoint whose Istio WorkloadEntry translation stamped a `cluster` that does
///    NOT equal the configured [`RemoteCluster::name`] is STILL classified remote
///    (the former cluster-name-equality-only path misclassified it LOCAL, so
///    strict local-first LB kept sending to it while locals were healthy).
///
/// 2. **Fallback — `cluster`-name vs [`MultiClusterConfig`]** (cannot cause a
///    false-LOCAL for a genuinely-remote endpoint, since provenance already
///    covers those): retained so a workload carrying a cross-cluster `cluster`
///    identity is still classified remote even on a code path that did not run
///    `tag_remote_workloads` (defense in depth). Depends on `local_cluster`:
///    - `local_cluster` set: remote iff `workload.cluster` differs from it.
///    - `local_cluster` UNSET: remote iff `workload.cluster` matches a configured
///      `remote_clusters[].name`.
///    - No workload cluster, or no `MultiClusterConfig`: LOCAL.
///
/// Single source of truth shared by the materialization path
/// ([`crate::service_discovery::mesh`]) and the east-west / outbound local-only
/// filters ([`super::matched_local_service_workloads`]) so they never drift on
/// what "remote" means.
#[inline]
pub(crate) fn workload_is_remote(
    workload: &Workload,
    multi_cluster: Option<&MultiClusterConfig>,
) -> bool {
    // Authoritative: the reserved provenance marker stamped at remote ingestion.
    if workload.remote_provenance {
        return true;
    }
    // Fallback (defense in depth): cluster-name vs configured clusters. Can only
    // promote LOCAL→REMOTE, never the reverse, so it cannot misclassify a
    // genuinely-remote (provenance-marked) endpoint as local.
    let Some(workload_cluster) = workload.cluster.as_deref() else {
        // A workload with no cluster identity is always local.
        return false;
    };
    let Some(multi_cluster) = multi_cluster else {
        // No multi-cluster config: single-cluster posture, treat as local.
        return false;
    };
    match multi_cluster.local_cluster.as_deref() {
        // Relative to a known local cluster: remote iff it differs.
        Some(local_cluster) => workload_cluster != local_cluster,
        // No local cluster name: classify by discovery provenance — the workload
        // is remote iff its stamped cluster is a configured remote cluster.
        None => multi_cluster
            .remote_clusters
            .iter()
            .any(|remote| remote.name == workload_cluster),
    }
}

/// Tag a remote cluster's workloads with provenance and a fail-safe locality.
///
/// - `remote_provenance` is set `true` — the RESERVED, un-spoofable remote marker.
///   This is the AUTHORITATIVE remote signal: it is stamped HERE, at the DP-side
///   remote-poll ingestion point that KNOWS the source is the remote slice, so a
///   genuinely-remote endpoint is marked regardless of what `cluster` name an
///   Istio WorkloadEntry translation may have stamped on it. The discoverer copies
///   this into the `mesh.remote=true` target tag strict local-first LB keys on; it
///   never crosses a wire/file boundary (`#[serde(skip)]`), so it cannot be forged.
/// - `cluster` is stamped (only when absent) so introspection / metrics can
///   attribute the target.
/// - `network` is preserved (multi-network routing).
/// - `locality` is always rewritten to a synthetic `remote-<cluster>` locality.
///   A remote CP can legitimately report the same region/zone strings as the
///   local cluster, but remote endpoints must stay below the local priority tier
///   until local endpoints are exhausted.
///
/// Workloads are NOT renamed or re-keyed: a remote workload keeps its SPIFFE
/// id, service_name, addresses, and ports so [`MeshServiceDiscoverer`] resolves
/// it against the same `MeshService` the local cluster advertises.
fn tag_remote_workloads(
    endpoints: &mut RemoteClusterEndpoints,
    cluster_name: &str,
    network: Option<&str>,
) {
    for workload in &mut endpoints.workloads {
        // RESERVED provenance: this workload came from the remote discovery slice.
        // Independent of `cluster`-name matching so a WorkloadEntry-translated
        // `cluster` that diverges from the configured `RemoteCluster.name` still
        // marks the endpoint remote.
        workload.remote_provenance = true;
        // Fill cluster/network only when the remote payload omitted them: the
        // payload value is the workload's OWN identity (e.g. a WorkloadEntry's
        // real cluster, which may legitimately diverge from this entry's alias)
        // and `remote_provenance` above — not the cluster field — is what
        // classifies the endpoint as remote, so it must be preserved. The
        // merge-layer registry dedup (`WorkloadEndpointKey`) includes
        // cluster/network, so two same-address endpoints on distinct networks
        // stay as distinct WORKLOADS for provenance/introspection. The runtime
        // target dedup in `service_discovery::mesh` deliberately collapses them
        // back on `host:port` (they are not independently dial-able until a
        // network-gateway address rewrite exists — issue #1719 — and the
        // health/CB/LB keys are `host:port`).
        if workload.cluster.is_none() {
            workload.cluster = Some(cluster_name.to_string());
        }
        if workload.network.is_none()
            && let Some(network) = network
            && !network.is_empty()
        {
            workload.network = Some(network.to_string());
        }
        workload.locality = Some(default_remote_locality(cluster_name, network));
    }
}

fn workload_endpoint_key(workload: &Workload) -> WorkloadEndpointKey {
    let mut addresses = workload.addresses.clone();
    addresses.sort();
    let mut ports: Vec<(u16, AppProtocol, Option<String>)> = workload
        .ports
        .iter()
        .map(|port| (port.port, port.protocol, port.name.clone()))
        .collect();
    ports.sort_by(|left, right| {
        (left.0, app_protocol_sort_key(left.1), left.2.as_deref()).cmp(&(
            right.0,
            app_protocol_sort_key(right.1),
            right.2.as_deref(),
        ))
    });
    WorkloadEndpointKey {
        spiffe_id: workload.spiffe_id.as_str().to_string(),
        namespace: workload.namespace.clone(),
        service_name: workload.service_name.clone(),
        cluster: workload.cluster.clone(),
        network: workload.network.clone(),
        addresses,
        ports,
    }
}

fn app_protocol_sort_key(protocol: AppProtocol) -> u8 {
    match protocol {
        AppProtocol::Http => 0,
        AppProtocol::Http2 => 1,
        AppProtocol::Grpc => 2,
        AppProtocol::Tcp => 3,
        AppProtocol::Tls => 4,
        AppProtocol::Udp => 5,
        AppProtocol::Mongo => 6,
        AppProtocol::Redis => 7,
        AppProtocol::Mysql => 8,
        AppProtocol::Postgres => 9,
        AppProtocol::Unknown => 10,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WorkloadEndpointKey {
    spiffe_id: String,
    namespace: String,
    service_name: String,
    cluster: Option<String>,
    network: Option<String>,
    addresses: Vec<String>,
    ports: Vec<(u16, AppProtocol, Option<String>)>,
}

/// Whether a stored remote-cluster entry is admitted by the candidate (about-to-
/// be-applied) slice's [`MultiClusterConfig`]. The store is reconciled from the
/// ACCEPTED slice, but the apply loop reads the store snapshot a generation
/// before the discovery reconciler can react to a just-accepted slice that
/// removed (or re-identified) a cluster. Filtering the merge against the
/// candidate slice closes that one-generation window: a cluster the candidate
/// does NOT declare (removal), or declares under a divergent identity,
/// contributes NO endpoints to this generation. Fail-closed: a candidate slice
/// with no `MultiClusterConfig` admits nothing, so a stale store can never leak
/// endpoints into a slice that dropped multi-cluster entirely.
///
/// The match is the FULL poll identity — name, trust_domain, network, AND the
/// normalized `control_plane_url` — via [`RemoteClusterEntry::matches_declared`].
/// Storing the polled URL on the entry (codex F7.2 round-5) closes the former
/// URL-only-divergence gap: when an accepted slice changes ONLY
/// `control_plane_url` for an existing cluster name, the stored entry (still
/// holding the OLD CP's endpoints) no longer matches the candidate, so the
/// generation that accepts the new config serves NO endpoints from the previous
/// control plane while the discovery reconciler spins up the new poller. It is
/// no longer the case that a URL-only change leaks for a generation.
fn cluster_admitted_by_candidate(
    entry: &RemoteClusterEntry,
    candidate: Option<&MultiClusterConfig>,
) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    candidate
        .remote_clusters
        .iter()
        .any(|declared| entry.matches_declared(declared))
}

/// Merge the remote-endpoint snapshot into a slice's local `workloads` /
/// `services`. Returns the merged vectors; the slice-apply path uses these to
/// build `GatewayConfig.mesh` so [`MeshServiceDiscoverer`] resolves both local
/// and remote endpoints for a service.
///
/// Only remote clusters admitted by `candidate_multi_cluster` (the about-to-be-
/// applied slice's [`MultiClusterConfig`]) contribute endpoints — see
/// [`cluster_admitted_by_candidate`]. This makes cluster removal / control-plane
/// identity changes fail-closed within the SAME generation rather than leaking
/// stale endpoints for one generation until the discovery reconciler evicts the
/// store entry.
///
/// Merge rules (for admitted clusters):
/// - Remote workloads are appended after local ones. Exact endpoint duplicates
///   are skipped, but workloads with the same SPIFFE ID and different addresses
///   are retained; multi-cluster services can legitimately expose replicas with
///   the same service account identity in multiple clusters.
/// - Remote services are merged by `(namespace, name)`: a service the local
///   cluster already advertises keeps the local definition (ports / overrides);
///   only the remote `workloads` refs are unioned in so the local service can
///   resolve the remote endpoints. A service that exists ONLY remotely is added
///   wholesale only when `allow_remote_service_append` is true. Callers that
///   pass an already Sidecar-egress-narrowed service list must set it false so
///   the discovery merge cannot widen the outbound authorization boundary.
///
/// `local_workloads` / `local_services` are cloned and extended; callers pass
/// the slice's own vectors.
pub fn merge_remote_endpoints_into_mesh(
    local_workloads: &[Workload],
    local_services: &[MeshService],
    snapshot: &RemoteEndpointSnapshot,
    candidate_multi_cluster: Option<&MultiClusterConfig>,
    allow_remote_service_append: bool,
) -> (Vec<Workload>, Vec<MeshService>) {
    if snapshot.is_empty() {
        return (local_workloads.to_vec(), local_services.to_vec());
    }

    let mut workloads = local_workloads.to_vec();
    let mut seen_workloads: std::collections::HashSet<WorkloadEndpointKey> =
        workloads.iter().map(workload_endpoint_key).collect();

    let mut services = local_services.to_vec();
    // Index local services by (namespace, name) for ref-union.
    let mut service_index: HashMap<(String, String), usize> = services
        .iter()
        .enumerate()
        .map(|(idx, svc)| ((svc.namespace.clone(), svc.name.clone()), idx))
        .collect();

    // Deterministic order: iterate clusters by name so the merged target list
    // is stable across snapshots (avoids LB hash-ring churn from HashMap order).
    let mut cluster_names: Vec<&String> = snapshot.clusters.keys().collect();
    cluster_names.sort();

    for cluster_name in cluster_names {
        let Some(entry) = snapshot.clusters.get(cluster_name) else {
            continue;
        };
        // Fail-closed same-generation filter: drop endpoints for any cluster the
        // candidate slice does not declare (or declares under a divergent
        // identity). The store may still hold them for one generation until the
        // discovery reconciler (sourced from the accepted slice) evicts them.
        if !cluster_admitted_by_candidate(entry, candidate_multi_cluster) {
            continue;
        }
        for workload in &entry.endpoints.workloads {
            if seen_workloads.insert(workload_endpoint_key(workload)) {
                workloads.push(workload.clone());
            }
        }
        for remote_svc in &entry.endpoints.services {
            let key = (remote_svc.namespace.clone(), remote_svc.name.clone());
            if let Some(&idx) = service_index.get(&key) {
                // Local service wins on ports/overrides; union remote refs so
                // the local service resolves the remote workloads too.
                let local = &mut services[idx];
                for wref in &remote_svc.workloads {
                    if !local
                        .workloads
                        .iter()
                        .any(|w| w.spiffe_id == wref.spiffe_id)
                    {
                        local.workloads.push(wref.clone());
                    }
                }
            } else if allow_remote_service_append {
                let new_idx = services.len();
                services.push(remote_svc.clone());
                service_index.insert(key, new_idx);
            } else {
                tracing::debug!(
                    namespace = %remote_svc.namespace,
                    service = %remote_svc.name,
                    "skipping poller-discovered remote service absent from Sidecar-narrowed slice"
                );
            }
        }
    }

    (workloads, services)
}

/// Per-cluster poll target derived from a [`MultiClusterConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteClusterPollTarget {
    cluster_name: String,
    trust_domain: TrustDomain,
    network: Option<String>,
    control_plane_url: String,
    /// Reference naming the per-remote discovery credential (resolved against
    /// the installed credential map). `None` falls back to the shared CP-DP
    /// JWT secret. Kept in `PartialEq` so a changed reference re-rolls the
    /// poller in `reconcile`.
    credential_ref: Option<String>,
}

struct RunningRemoteDiscovery {
    target: RemoteClusterPollTarget,
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

type RemoteSourceFactory =
    Arc<dyn Fn(&RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource> + Send + Sync>;

/// Manager that reconciles remote-cluster discovery tasks against the latest
/// mesh slice and trust-bundle state.
pub struct RemoteDiscoveryManager {
    config: Option<RemoteDiscoveryConfig>,
    store: RemoteEndpointStore,
    source_factory: RemoteSourceFactory,
    running: HashMap<String, RunningRemoteDiscovery>,
    /// Resolved per-RemoteCluster discovery credentials (reference -> secret).
    /// Matched against `RemoteCluster.discovery_credential_ref` in
    /// `start_cluster`; an empty map keeps shared-secret behavior.
    credentials: std::sync::Arc<std::collections::HashMap<String, GrpcJwtSecret>>,
}

impl RemoteDiscoveryManager {
    pub fn new<F>(
        config: Option<RemoteDiscoveryConfig>,
        store: RemoteEndpointStore,
        source_factory: F,
    ) -> Self
    where
        F: Fn(&RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource> + Send + Sync + 'static,
    {
        Self {
            config,
            store,
            source_factory: Arc::new(source_factory),
            running: HashMap::new(),
            credentials: std::sync::Arc::new(std::collections::HashMap::new()),
        }
    }

    /// Install the resolved per-RemoteCluster discovery credential map
    /// (reference -> secret). References are matched against
    /// `RemoteCluster.discovery_credential_ref`; an unmatched reference fails
    /// closed (the cluster is not polled). Empty map = shared-secret behavior.
    pub fn with_credentials(
        mut self,
        credentials: std::sync::Arc<std::collections::HashMap<String, GrpcJwtSecret>>,
    ) -> Self {
        self.credentials = credentials;
        self
    }

    /// Start/stop per-cluster pollers to match the latest slice and trust state.
    /// Removing an ineligible cluster also removes its last-good endpoints so a
    /// stale snapshot cannot keep serving a cluster after trust or config is
    /// withdrawn.
    pub fn reconcile(
        &mut self,
        multi_cluster: Option<&MultiClusterConfig>,
        trust_bundle_domains: std::collections::HashSet<TrustDomain>,
    ) {
        let (Some(config), Some(multi_cluster)) = (self.config.clone(), multi_cluster) else {
            self.stop_all(true);
            return;
        };
        let targets = poll_targets_for_multi_cluster_with_posture(
            multi_cluster,
            &trust_bundle_domains,
            config.production_mode,
        );
        if targets.is_empty() {
            self.stop_all(true);
            debug!("No remote clusters eligible for endpoint discovery; pollers stopped");
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

    pub fn shutdown(&mut self) {
        self.stop_all(false);
    }

    #[cfg(test)]
    fn running_cluster_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.running.keys().cloned().collect();
        names.sort();
        names
    }

    fn start_cluster(
        &mut self,
        target: RemoteClusterPollTarget,
        mut config: RemoteDiscoveryConfig,
    ) {
        // Resolve the per-RemoteCluster discovery credential. A configured
        // reference that does not resolve fails closed (do NOT silently fall
        // back to the shared secret — that could authenticate with the wrong
        // credential): skip the cluster with a warning.
        match &target.credential_ref {
            Some(reference) => match self.credentials.get(reference) {
                Some(secret) => {
                    config.jwt_secret = Some(secret.clone());
                }
                None => {
                    warn!(
                        cluster = %target.cluster_name,
                        "RemoteCluster references an unknown discovery credential; \
                         skipping discovery (configure FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS)"
                    );
                    return;
                }
            },
            None => {
                // No per-remote reference: shared CP-DP secret fallback. In
                // production multi-cluster this shared-secret posture is
                // deprecated — warn loudly but keep working (migration path).
                if config.production_mode && config.jwt_secret.is_some() {
                    warn!(
                        cluster = %target.cluster_name,
                        "Remote-cluster discovery is using the shared CP-DP JWT secret in \
                         production mode; configure a per-RemoteCluster discovery_credential_ref \
                         + FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS so a credential for one cluster \
                         cannot authenticate to another (deprecated shared-secret posture)"
                    );
                }
            }
        }
        let ctx = RemoteClusterPollContext {
            cluster_name: target.cluster_name.clone(),
            trust_domain: target.trust_domain.clone(),
            network: target.network.clone(),
            control_plane_url: target.control_plane_url.clone(),
            credential_ref: target.credential_ref.clone(),
            config,
        };
        let source = (self.source_factory)(&ctx);
        let task_store = self.store.clone();
        // Register a generation token *before* spawning so the task's first
        // install can be validated. The generation is bumped again in `remove`,
        // so a task aborted mid-fetch cannot reinstall after its cluster is
        // removed (F6).
        let task_generation = self.store.register_cluster(&target.cluster_name);
        let (cluster_shutdown_tx, cluster_shutdown_rx) = watch::channel(false);
        let url_for_logs = sanitize_url_for_logging(&target.control_plane_url);
        info!(
            cluster = %target.cluster_name,
            trust_domain = %target.trust_domain,
            control_plane = %url_for_logs,
            poll_interval_seconds = ctx.config.poll_interval.as_secs(),
            max_stale_seconds = ctx.config.max_stale_age.map(|age| age.as_secs()),
            production_mode = ctx.config.production_mode,
            "Spawning remote-cluster endpoint discovery"
        );
        let handle = tokio::spawn(async move {
            remote_discovery_loop(
                ctx,
                source,
                task_store,
                cluster_shutdown_rx,
                task_generation,
            )
            .await;
        });
        self.running.insert(
            target.cluster_name.clone(),
            RunningRemoteDiscovery {
                target,
                shutdown_tx: cluster_shutdown_tx,
                handle,
            },
        );
    }

    fn stop_cluster(&mut self, cluster_name: &str, remove_endpoints: bool) {
        if let Some(running) = self.running.remove(cluster_name) {
            let _ = running.shutdown_tx.send(true);
            running.handle.abort();
            if remove_endpoints {
                // Drop the endpoints (retiring the generation) AND prune the
                // success / last-success / endpoint-age series so a removed (or
                // trust-withdrawn) cluster does not linger as a freshly-polled,
                // endpoint-less entry on `/metrics`. Keyed by
                // (cluster, trust_domain) to match the metric maps. The retire +
                // clear run under the store's metrics ordering lock so an
                // in-flight poll's generation-checked success record cannot race
                // this clear and re-create the series.
                self.store
                    .remove_and_clear_metrics(cluster_name, running.target.trust_domain.as_str());
            }
        }
    }

    fn stop_all(&mut self, remove_endpoints: bool) {
        let names: Vec<String> = self.running.keys().cloned().collect();
        for name in names {
            self.stop_cluster(&name, remove_endpoints);
        }
    }
}

#[derive(Clone, Default)]
pub struct RemoteDiscoveryTlsConfig {
    pub tls_urls: Option<DpGrpcTlsConfig>,
    pub plain_urls: Option<DpGrpcTlsConfig>,
}

impl RemoteDiscoveryTlsConfig {
    fn for_control_plane_url(&self, url: &str) -> Option<DpGrpcTlsConfig> {
        // URLs reaching this method are already normalized by
        // `normalize_control_plane_url` (grpcs→https, grpc→http), so matching
        // on `https` is sufficient. The `grpcs` arm is retained as belt-and-
        // suspenders for any caller that passes a non-normalized URL.
        match reqwest::Url::parse(url)
            .ok()
            .map(|parsed| parsed.scheme().to_string())
        {
            Some(scheme) if scheme == "https" || scheme == "grpcs" => self.tls_urls.clone(),
            _ => self.plain_urls.clone(),
        }
    }
}

/// Knobs derived from `EnvConfig`. Not `Debug` because `DpGrpcTlsConfig`
/// carries key material and is intentionally not `Debug`.
#[derive(Clone)]
pub struct RemoteDiscoveryConfig {
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    /// Maximum age for last-good endpoints after poll failures. `None` keeps
    /// last-good endpoints indefinitely (dev/test only in production
    /// validation).
    pub max_stale_age: Option<Duration>,
    /// Production posture rejects plaintext remote-control-plane URLs.
    pub production_mode: bool,
    /// JWT secret + issuer for the remote CP gRPC handshake (reuses the
    /// CP→DP secret). `None` disables discovery (no secret → cannot dial).
    pub jwt_secret: Option<GrpcJwtSecret>,
    /// This DP's node id, sent in the remote subscribe request.
    pub node_id: String,
    /// Namespace scope requested from the remote CP.
    pub namespace: String,
    /// Optional DP gRPC client TLS material, split by remote CP URL scheme so an
    /// HTTPS remote is not affected by the local CP URL scheme.
    pub tls_config: RemoteDiscoveryTlsConfig,
}

impl RemoteDiscoveryConfig {
    /// Returns `None` when discovery should be disabled (interval 0 or no JWT
    /// secret available to authenticate to the remote CP).
    #[allow(dead_code)]
    pub fn new(
        interval_seconds: u64,
        timeout_seconds: u64,
        jwt_secret: Option<GrpcJwtSecret>,
        node_id: String,
        namespace: String,
        tls_config: RemoteDiscoveryTlsConfig,
    ) -> Option<Self> {
        Self::new_with_max_stale(
            interval_seconds,
            timeout_seconds,
            DEFAULT_REMOTE_DISCOVERY_MAX_STALE_SECONDS,
            jwt_secret,
            node_id,
            namespace,
            tls_config,
        )
    }

    pub fn new_with_max_stale(
        interval_seconds: u64,
        timeout_seconds: u64,
        max_stale_seconds: u64,
        jwt_secret: Option<GrpcJwtSecret>,
        node_id: String,
        namespace: String,
        tls_config: RemoteDiscoveryTlsConfig,
    ) -> Option<Self> {
        if interval_seconds == 0 {
            return None;
        }
        Some(Self {
            poll_interval: Duration::from_secs(interval_seconds),
            request_timeout: Duration::from_secs(timeout_seconds.max(1)),
            max_stale_age: (max_stale_seconds > 0).then(|| Duration::from_secs(max_stale_seconds)),
            production_mode: crate::identity::production_mode(),
            jwt_secret,
            node_id,
            namespace,
            tls_config,
        })
    }
}

/// Parse the `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` JSON object (a map of
/// credential-reference -> raw JWT secret) into resolved `GrpcJwtSecret`s. The
/// secret values are minted with the local CP-DP issuer (the remote CP pins
/// issuer, not a per-remote one), passed in as `issuer` so it matches the
/// shared-secret remote-discovery path (`FERRUM_CP_DP_GRPC_JWT_ISSUER`).
/// Returns an empty map for `None`/empty input; returns an error string on
/// malformed JSON or an empty secret value.
pub(crate) fn parse_remote_discovery_credentials(
    raw: Option<&str>,
    issuer: &str,
) -> Result<std::collections::HashMap<String, GrpcJwtSecret>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(std::collections::HashMap::new());
    };
    let parsed: std::collections::HashMap<String, String> = serde_json::from_str(raw)
        .map_err(|e| {
            format!(
                "FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS is not a valid JSON object of ref->secret: {e}"
            )
        })?;
    let mut out = std::collections::HashMap::with_capacity(parsed.len());
    for (reference, secret) in parsed {
        if reference.trim().is_empty() {
            return Err(
                "FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS has an empty credential reference"
                    .to_string(),
            );
        }
        // Enforce the same minimum HS256 key strength the shared
        // FERRUM_CP_DP_GRPC_JWT_SECRET path applies (env_config `min_len`), so a
        // per-remote entry cannot mint tokens with a trivially weak key — and the
        // failure surfaces here at parse time, not later at the remote CP.
        if secret.len() < crate::config::types::MIN_JWT_SECRET_LENGTH {
            // `reference` is a JSON object key parsed *out of* the variable, so
            // no whole-value or segment candidate covers it at any length —
            // and the variable is credential material by definition.
            return Err(format!(
                "FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS reference {} secret must be at \
                 least {} characters (matching FERRUM_CP_DP_GRPC_JWT_SECRET); got {}",
                crate::secrets::quoted_env_value(
                    "FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS",
                    reference.trim()
                ),
                crate::config::types::MIN_JWT_SECRET_LENGTH,
                secret.len()
            ));
        }
        out.insert(
            reference,
            GrpcJwtSecret::with_issuer(secret, issuer.to_string()),
        );
    }
    Ok(out)
}

/// Resolve the poll-target list from a [`MultiClusterConfig`].
///
/// A remote cluster is polled only when it BOTH declares a `control_plane_url`
/// AND has cross-cluster trust established — i.e. a federated trust bundle for
/// its trust domain is present in `trust_bundle_domains`. This keeps
/// cross-cluster discovery fail-closed: Ferrum will not dial (and merge
/// endpoints from) a cluster it cannot mutually authenticate, mirroring the
/// federation poller's posture.
#[cfg(test)]
fn poll_targets_for_multi_cluster(
    multi_cluster: &MultiClusterConfig,
    trust_bundle_domains: &std::collections::HashSet<TrustDomain>,
) -> Vec<RemoteClusterPollTarget> {
    poll_targets_for_multi_cluster_with_posture(multi_cluster, trust_bundle_domains, false)
}

fn poll_targets_for_multi_cluster_with_posture(
    multi_cluster: &MultiClusterConfig,
    trust_bundle_domains: &std::collections::HashSet<TrustDomain>,
    production_mode: bool,
) -> Vec<RemoteClusterPollTarget> {
    let mut targets = Vec::with_capacity(
        multi_cluster
            .remote_clusters
            .len()
            .min(MAX_MESH_REMOTE_CLUSTERS),
    );
    for remote in &multi_cluster.remote_clusters {
        let Some(url) = remote.control_plane_url.as_deref().map(str::trim) else {
            continue;
        };
        if url.is_empty() {
            continue;
        }
        if !trust_bundle_domains.contains(&remote.trust_domain) {
            warn!(
                cluster = %remote.name,
                trust_domain = %remote.trust_domain,
                "Skipping remote-cluster discovery: no federated trust bundle for the remote \
                 trust domain (cross-cluster discovery is fail-closed). Configure trust \
                 federation for this cluster first."
            );
            continue;
        }
        if let Err(err) = validate_control_plane_url_with_posture(url, production_mode) {
            warn!(
                cluster = %remote.name,
                error = %err,
                "Dropping remote-cluster control_plane_url that failed validation"
            );
            continue;
        }
        if targets.len() >= MAX_MESH_REMOTE_CLUSTERS {
            warn!(
                cluster = %remote.name,
                max_remote_clusters = MAX_MESH_REMOTE_CLUSTERS,
                "Skipping remote-cluster discovery beyond remote-cluster target cap"
            );
            continue;
        }
        targets.push(RemoteClusterPollTarget {
            cluster_name: remote.name.clone(),
            trust_domain: remote.trust_domain.clone(),
            network: remote.network.clone(),
            // Normalize grpc:// → http:// and grpcs:// → https:// so the
            // dialer and TLS-selection logic always see canonical schemes.
            control_plane_url: normalize_control_plane_url(url),
            credential_ref: remote.discovery_credential_ref.clone(),
        });
    }
    targets
}

/// Normalize a `control_plane_url` for dialing.
///
/// `grpc://` is normalized to `http://` and `grpcs://` to `https://` so that:
/// - `tonic::Channel::from_shared` receives a scheme it understands (`http`/`https`).
/// - TLS selection in [`RemoteDiscoveryTlsConfig::for_control_plane_url`] keys off
///   `https` correctly: a `grpcs://` CP gets TLS; a `grpc://` CP gets plaintext.
///
/// `http`/`https` URLs are returned unchanged.
pub(crate) fn normalize_control_plane_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("grpcs://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("grpc://") {
        format!("http://{rest}")
    } else {
        url.to_string()
    }
}

/// Validate a `control_plane_url`: must parse, must be
/// `http`/`https`/`grpc`/`grpcs`, and must carry a host. Cloud-metadata /
/// link-local hosts are rejected (SSRF defense), mirroring
/// [`super::federation::validate_federation_endpoint`]. Loopback is allowed
/// for local development / integration-test control planes.
///
/// `grpc://` and `grpcs://` are accepted and normalized to `http://` /
/// `https://` by [`normalize_control_plane_url`] before dialing so that
/// `tonic::Channel::from_shared` receives a scheme it understands.
#[cfg(test)]
pub(crate) fn validate_control_plane_url(url: &str) -> Result<(), String> {
    validate_control_plane_url_with_posture(url, false)
}

pub(crate) fn validate_control_plane_url_with_posture(
    url: &str,
    production_mode: bool,
) -> Result<(), String> {
    // Normalise before parsing so the scheme check is on the canonical form.
    let normalized = normalize_control_plane_url(url);
    let parsed =
        reqwest::Url::parse(&normalized).map_err(|e| format!("invalid control_plane_url: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("unsupported control_plane_url scheme '{other}'")),
    }
    if production_mode && parsed.scheme() != "https" {
        return Err(
            "production remote-cluster discovery requires an authenticated TLS control_plane_url \
             (use https:// or grpcs://; plaintext http:// and grpc:// are dev/test only)"
                .to_string(),
        );
    }
    let Some(host) = parsed.host() else {
        return Err("control_plane_url has no host".to_string());
    };
    match host {
        url::Host::Ipv4(ip) => {
            if ip.is_loopback() {
                return Ok(());
            }
            if ip.is_link_local() || ip.octets() == [169, 254, 169, 254] {
                return Err(format!(
                    "control_plane_url refuses link-local / cloud-metadata host {ip} (SSRF defense)"
                ));
            }
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                return Err(format!(
                    "control_plane_url refuses non-unicast IPv4 host {ip}"
                ));
            }
        }
        url::Host::Ipv6(ip) => {
            if ip.is_loopback() {
                return Ok(());
            }
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(format!(
                    "control_plane_url refuses non-unicast IPv6 host {ip}"
                ));
            }
            if ip.segments()[0] & 0xffc0 == 0xfe80 {
                return Err(format!(
                    "control_plane_url refuses link-local IPv6 host {ip}"
                ));
            }
        }
        url::Host::Domain(_) => {
            // Hostnames resolve at dial time. Domain-based SSRF defense relies
            // on operator network controls; Ferrum does not resolve or validate
            // the resulting IP for tonic-dialed remote CPs (see F5).
        }
    }
    Ok(())
}

/// Build the trust-domain set from a slice's federated + live-polled trust
/// bundles. Used to gate which remote clusters may be dialed.
pub fn trust_domains_from_bundles(
    slice_bundles: Option<&crate::modes::mesh::config::TrustBundleSet>,
    federation: &super::federation::FederationSnapshot,
) -> std::collections::HashSet<TrustDomain> {
    let mut domains = std::collections::HashSet::new();
    if let Some(bundles) = slice_bundles {
        domains.insert(bundles.local.trust_domain.clone());
        for tb in &bundles.federated {
            domains.insert(tb.trust_domain.clone());
        }
    }
    for td in federation.bundles.keys() {
        domains.insert(td.clone());
    }
    domains
}

/// Context passed to the source factory and the poll loop.
#[derive(Clone)]
pub struct RemoteClusterPollContext {
    pub cluster_name: String,
    pub trust_domain: TrustDomain,
    pub network: Option<String>,
    pub control_plane_url: String,
    /// Credential reference this poll authenticates with, stamped onto stored
    /// entries so `matches_declared` treats it as part of the poll identity.
    pub credential_ref: Option<String>,
    pub config: RemoteDiscoveryConfig,
}

async fn remote_discovery_loop(
    ctx: RemoteClusterPollContext,
    source: Arc<dyn RemoteServiceSource>,
    store: RemoteEndpointStore,
    mut shutdown_rx: watch::Receiver<bool>,
    task_generation: u64,
) {
    let mut backoff_secs = REMOTE_BACKOFF_INITIAL_SECS;
    let url_for_logs = sanitize_url_for_logging(&ctx.control_plane_url);

    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        let attempt_started_at = std::time::Instant::now();
        let result = source.fetch().await.and_then(|mut endpoints| {
            validate_remote_endpoints(&ctx.cluster_name, &endpoints)?;
            enforce_remote_trust_domain(&mut endpoints, &ctx.trust_domain, &ctx.cluster_name);
            tag_remote_workloads(&mut endpoints, &ctx.cluster_name, ctx.network.as_deref());
            Ok(endpoints)
        });

        let (succeeded, sleep_duration) = match result {
            Ok(endpoints) => {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                let workload_count = endpoints.workloads.len();
                let entry = RemoteClusterEntry::new(
                    ctx.cluster_name.clone(),
                    ctx.trust_domain.clone(),
                    ctx.network.clone(),
                    // `ctx.control_plane_url` is already normalized by
                    // `poll_targets_for_multi_cluster`; store it so a later
                    // URL-only slice change fails the membership filter closed.
                    Some(ctx.control_plane_url.clone()),
                    // Stamp the credential ref so a credential rotation /
                    // withdrawal also fails the membership filter closed.
                    ctx.credential_ref.clone(),
                    endpoints,
                    now,
                );
                // Capture the summary fields before moving `entry` into
                // `install`, so the log can fire on the actual install result.
                let log_trust_domain = entry.trust_domain.clone();
                let log_network = entry.network.clone();
                let log_fetched_at = entry.fetched_at_unix_seconds();
                let outcome = store.install(entry, task_generation);
                if outcome.installed() {
                    info!(
                        cluster = %ctx.cluster_name,
                        trust_domain = %log_trust_domain,
                        network = log_network.as_deref().unwrap_or(""),
                        fetched_at_unix_seconds = log_fetched_at,
                        control_plane = %url_for_logs,
                        workloads = workload_count,
                        "Installed remote-cluster endpoints"
                    );
                } else {
                    // Poll succeeded but the snapshot was unchanged — endpoints
                    // identical (F2 dedup) or the cluster's generation was
                    // retired mid-flight (removed / trust withdrawn). Not an
                    // "installed" event; keep it at debug to avoid steady-state
                    // INFO spam every poll interval.
                    debug!(
                        cluster = %ctx.cluster_name,
                        control_plane = %url_for_logs,
                        workloads = workload_count,
                        "Remote-cluster poll succeeded with no endpoint change; not re-installing"
                    );
                }
                // Only mark the cluster freshly-polled when the poll reflects a
                // live, still-registered cluster. A retired-generation no-op
                // (the cluster was removed / trust withdrawn while this poll was
                // in flight) must not refresh the success / last-success /
                // endpoint-age gauges, or `/metrics` would advertise a healthy
                // remote cluster whose endpoints were intentionally dropped.
                //
                // `install`'s live/retired verdict is computed lock-free, but the
                // metric write lands in a separate map; recording through the
                // store re-checks the generation under the metrics ordering lock
                // so this record cannot resurrect the series after a concurrent
                // reconcile retired the generation and cleared the metrics.
                if outcome.is_live_poll() {
                    store.record_remote_discovery_success_if_live(
                        &ctx.cluster_name,
                        ctx.trust_domain.as_str(),
                        now,
                        task_generation,
                    );
                }
                backoff_secs = REMOTE_BACKOFF_INITIAL_SECS;
                let elapsed = attempt_started_at.elapsed();
                (true, ctx.config.poll_interval.saturating_sub(elapsed))
            }
            Err(err) => {
                warn!(
                    cluster = %ctx.cluster_name,
                    control_plane = %url_for_logs,
                    error = %err,
                    "Remote-cluster endpoint discovery failed; keeping last-good endpoints if any"
                );
                crate::plugins::mesh::prometheus_helpers::increment_mesh_remote_discovery_poll_failure(
                    &ctx.cluster_name,
                    ctx.trust_domain.as_str(),
                    &url_for_logs,
                );
                expire_stale_endpoints_after_failure(&store, &ctx, task_generation, &url_for_logs);
                (false, jittered_backoff(backoff_secs))
            }
        };

        if !succeeded {
            backoff_secs = next_backoff_secs(backoff_secs);
        }

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_shutdown(&mut shutdown_rx) => return,
        }
    }
}

fn expire_stale_endpoints_after_failure(
    store: &RemoteEndpointStore,
    ctx: &RemoteClusterPollContext,
    task_generation: u64,
    url_for_logs: &str,
) {
    let Some(max_stale_age) = ctx.config.max_stale_age else {
        return;
    };
    if !store.cluster_generation_matches(&ctx.cluster_name, task_generation) {
        return;
    }
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if store.expire_stale_endpoints_and_clear_metrics(
        &ctx.cluster_name,
        ctx.trust_domain.as_str(),
        now,
        max_stale_age,
    ) {
        warn!(
            cluster = %ctx.cluster_name,
            trust_domain = %ctx.trust_domain,
            control_plane = %url_for_logs,
            max_stale_seconds = max_stale_age.as_secs(),
            "Expired last-good remote-cluster endpoints after bounded staleness window"
        );
    }
}

/// Drop any remote-cluster endpoints whose identity falls outside the cluster's
/// **declared** trust domain.
///
/// Cross-cluster discovery is gated only on a federated trust bundle existing
/// for the remote's declared trust domain; the remote CP's response is otherwise
/// trusted verbatim ([`tag_remote_workloads`] rewrites only provenance/locality,
/// never identity). Without this filter a federated peer (which may be a
/// lower-trust partner, or compromised) could return a workload claiming a
/// `spiffe_id`/`trust_domain` in the LOCAL domain (`cluster.local`) or any other
/// domain, with attacker-chosen `addresses`. Because the merge keys services by
/// `(namespace, name)` and matches workloads to services by namespace +
/// `service_name`/`spiffe_id` (never by trust domain — see
/// [`crate::service_discovery::mesh`]), and the outbound mTLS dial only verifies
/// the backend cert chains to *some* trusted domain (not the claimed identity),
/// those addresses would silently become backend endpoints for a local service
/// — a cross-trust-domain confused-deputy hijack.
///
/// Enforcing that every contributed workload carries the declared trust domain,
/// and that every service workload-ref still points at a surviving workload in
/// that service namespace, makes ingestion fail closed: a peer under
/// `eu-west-1.example.com` may only contribute `eu-west-1.example.com`
/// identities and can no longer impersonate another domain's workloads.
/// Mismatches are dropped (not fatal — one bad endpoint must not blackhole the
/// whole snapshot) and surfaced via a structured `warn!` so the drops are
/// observable. If an explicitly-refed service loses all refs, the service is
/// dropped instead of being converted into an empty-ref same-name selector.
fn enforce_remote_trust_domain(
    endpoints: &mut RemoteClusterEndpoints,
    declared: &TrustDomain,
    cluster_name: &str,
) {
    let mut dropped_workloads = 0usize;
    let mut dropped_service_refs = 0usize;
    let mut dropped_services = 0usize;
    let mut example_offender: Option<String> = None;
    let mut note_offender = |spiffe_id: &SpiffeId| {
        if example_offender.is_none() {
            example_offender = Some(spiffe_id.as_str().to_string());
        }
    };

    endpoints.workloads.retain(|workload| {
        // A workload must carry the declared trust domain in BOTH its
        // `trust_domain` field and the trust domain embedded in its SPIFFE id —
        // a mismatch in either is treated as foreign and dropped.
        let belongs =
            workload.trust_domain == *declared && workload.spiffe_id.trust_domain() == declared;
        if !belongs {
            dropped_workloads += 1;
            note_offender(&workload.spiffe_id);
        }
        belongs
    });

    let surviving_workload_refs: HashSet<(String, String)> = endpoints
        .workloads
        .iter()
        .map(|workload| {
            (
                workload.namespace.clone(),
                workload.spiffe_id.as_str().to_string(),
            )
        })
        .collect();

    endpoints.services.retain_mut(|service| {
        let had_explicit_refs = !service.workloads.is_empty();
        service.workloads.retain(|workload_ref| {
            let belongs = workload_ref.spiffe_id.trust_domain() == declared
                && surviving_workload_refs.contains(&(
                    service.namespace.clone(),
                    workload_ref.spiffe_id.as_str().to_string(),
                ));
            if !belongs {
                dropped_service_refs += 1;
                note_offender(&workload_ref.spiffe_id);
            }
            belongs
        });
        if had_explicit_refs && service.workloads.is_empty() {
            dropped_services += 1;
            return false;
        }
        true
    });

    if dropped_workloads > 0 || dropped_service_refs > 0 || dropped_services > 0 {
        warn!(
            cluster = %cluster_name,
            declared_trust_domain = %declared,
            dropped_workloads,
            dropped_service_refs,
            dropped_services,
            example_offending_spiffe_id = example_offender.as_deref().unwrap_or(""),
            "Dropped remote-cluster endpoints whose identity is outside the cluster's declared trust domain (cross-trust-domain confusion guard)"
        );
    }
}

fn validate_remote_endpoints(
    cluster_name: &str,
    endpoints: &RemoteClusterEndpoints,
) -> Result<(), String> {
    if endpoints.workloads.len() > REMOTE_MAX_WORKLOADS_PER_CLUSTER {
        return Err(format!(
            "remote cluster '{cluster_name}' returned {} workloads (max {REMOTE_MAX_WORKLOADS_PER_CLUSTER})",
            endpoints.workloads.len()
        ));
    }
    if endpoints.services.len() > REMOTE_MAX_SERVICES_PER_CLUSTER {
        return Err(format!(
            "remote cluster '{cluster_name}' returned {} services (max {REMOTE_MAX_SERVICES_PER_CLUSTER})",
            endpoints.services.len()
        ));
    }
    Ok(())
}

async fn wait_for_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn next_backoff_secs(current: u64) -> u64 {
    common_next_backoff_secs(current, true)
}

fn sanitize_url_for_logging(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.to_string()
        }
        Err(_) => "<unparseable>".to_string(),
    }
}

// ── Native gRPC remote source ─────────────────────────────────────────────

/// Production [`RemoteServiceSource`]: dials the remote CP's native
/// `MeshSubscribe` gRPC stream, takes the first non-heartbeat slice, and
/// extracts its `workloads` / `services` as the remote cluster's endpoints.
///
/// The subscribe is one-shot per poll: connect, read the first applicable
/// slice, drop the stream. The poll cadence (re-dialing on the configured
/// interval) gives eventual consistency without holding a long-lived stream per
/// remote cluster — keeping the failure model identical to the federation
/// poller (each poll is independent; a failure keeps the last-good snapshot).
pub struct NativeRemoteSource {
    control_plane_url: String,
    node_id: String,
    namespace: String,
    jwt_secret: GrpcJwtSecret,
    /// Target-cluster JWT audience this poller mints into every discovery
    /// token (issue #2475). Derived from the STABLE, operator-visible
    /// `RemoteCluster.name` — never from `control_plane_url`, which is mutable
    /// and would rebind the credential every time an endpoint moved. The
    /// receiving control plane compares it against its own
    /// `FERRUM_MESH_CLUSTER_AUDIENCE`, so a token minted for cluster B is
    /// refused by cluster C even when B and C share a JWT secret and issuer.
    audience: String,
    tls_config: Option<DpGrpcTlsConfig>,
    request_timeout: Duration,
}

impl NativeRemoteSource {
    pub fn new(ctx: &RemoteClusterPollContext, jwt_secret: GrpcJwtSecret) -> Self {
        Self {
            control_plane_url: ctx.control_plane_url.clone(),
            node_id: ctx.config.node_id.clone(),
            namespace: ctx.config.namespace.clone(),
            jwt_secret,
            audience: crate::grpc::auth::remote_discovery_audience(&ctx.cluster_name),
            tls_config: ctx
                .config
                .tls_config
                .for_control_plane_url(&ctx.control_plane_url),
            request_timeout: ctx.config.request_timeout,
        }
    }
}

#[async_trait]
impl RemoteServiceSource for NativeRemoteSource {
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
        fetch_remote_slice_endpoints(
            &self.control_plane_url,
            &self.node_id,
            &self.namespace,
            &self.jwt_secret,
            &self.audience,
            self.tls_config.as_ref(),
            self.request_timeout,
        )
        .await
    }
}

/// Factory wiring [`NativeRemoteSource`] for production use. Requires a JWT
/// secret; returns a source that always fails (logged) when none is configured
/// so the poll loop simply backs off rather than panicking.
pub fn native_source_factory(ctx: &RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource> {
    match ctx.config.jwt_secret.clone() {
        Some(secret) => Arc::new(NativeRemoteSource::new(ctx, secret)),
        None => Arc::new(MissingSecretSource {
            cluster_name: ctx.cluster_name.clone(),
        }),
    }
}

/// Sentinel source used when no gRPC JWT secret is configured. Always errors so
/// the poll loop logs + backs off instead of dialing unauthenticated.
struct MissingSecretSource {
    cluster_name: String,
}

#[async_trait]
impl RemoteServiceSource for MissingSecretSource {
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
        Err(format!(
            "remote cluster '{}' has no CP↔DP gRPC JWT secret configured; cannot authenticate to \
             the remote control plane (set FERRUM_CP_DP_GRPC_JWT_SECRET)",
            self.cluster_name
        ))
    }
}

/// One-shot remote MeshSubscribe: connect, read the first non-heartbeat slice,
/// return its workloads/services. Bounded by `request_timeout`.
///
/// The response is validated against the exact subscription request through the
/// SAME centralized rules the local native consumer applies
/// (`config_consumer::update_validation`) — present + compatible
/// `ferrum_version`, envelope/slice version agreement, and node/namespace/scope
/// binding — before any endpoint is imported. Any rejection fails the whole
/// poll, so `remote_discovery_loop` keeps the cluster's last-good endpoints,
/// backs off, and never installs wrong-cluster or wrong-namespace endpoints.
async fn fetch_remote_slice_endpoints(
    control_plane_url: &str,
    node_id: &str,
    namespace: &str,
    jwt_secret: &GrpcJwtSecret,
    audience: &str,
    tls_config: Option<&DpGrpcTlsConfig>,
    request_timeout: Duration,
) -> Result<RemoteClusterEndpoints, String> {
    use crate::grpc::dp_client::generate_dp_jwt_full;
    use crate::grpc::proto::MeshSubscribeRequest;
    use crate::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient;
    use crate::modes::mesh::config_consumer::common::tonic_tls_config;
    use crate::modes::mesh::config_consumer::update_validation::{
        MeshUpdateConsumer, MeshUpdateExpectation, validate_mesh_config_update,
        validate_update_ferrum_version,
    };
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let attempt = async {
        let mut endpoint = Channel::from_shared(control_plane_url.to_string())
            .map_err(|e| format!("invalid control_plane_url: {e}"))?
            .connect_timeout(Duration::from_secs(10));
        if let Some(tls) = tls_config {
            let mut client_tls = tonic_tls_config(tls);
            if let Ok(uri) = control_plane_url.parse::<http::Uri>()
                && let Some(host) = uri.host()
            {
                client_tls = client_tls.domain_name(host);
            }
            endpoint = endpoint
                .tls_config(client_tls)
                .map_err(|e| format!("remote CP TLS config: {e}"))?;
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| format!("connect to remote CP: {e}"))?;
        // Bind the token to the TARGET CLUSTER, not just to the credential:
        // issuer + expiry + signature cannot express "this token is for
        // cluster B", so a shared secret used by B and C made B's token valid
        // at C. The `aud` closes that (issue #2475).
        let auth_token = generate_dp_jwt_full(
            jwt_secret.as_str(),
            node_id,
            jwt_secret.issuer(),
            Some(namespace),
            Some(audience),
        )
        .map_err(|e| format!("mint remote CP JWT: {e}"))?;
        let token: MetadataValue<_> = format!("Bearer {auth_token}")
            .parse()
            .map_err(|e| format!("build auth metadata: {e}"))?;
        #[allow(clippy::result_large_err)]
        let mut client =
            MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert("authorization", token.clone());
                Ok(req)
            })
            .max_decoding_message_size(MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE);
        let subscribe_request = MeshSubscribeRequest {
            node_id: node_id.to_string(),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            namespace: namespace.to_string(),
            workload_spiffe_id: String::new(),
            labels: HashMap::new(),
            waypoint_name: String::new(),
            ambient_udp_source_scoping: false,
            // Declares the CROSS-CLUSTER subscription class, selecting the
            // remote-discovery audience policy on the receiving CP. Both
            // classes fail closed there, so this flag widens nothing.
            remote_discovery: true,
        };
        // Derive the expectation from the request actually sent, so the two can
        // never drift apart.
        let expected = MeshUpdateExpectation::from_subscribe_request(&subscribe_request);
        let consumer = MeshUpdateConsumer::RemoteDiscovery;
        let request = tonic::Request::new(subscribe_request);
        let mut stream = client
            .mesh_subscribe(request)
            .await
            .map_err(|e| format!("remote MeshSubscribe failed: {e}"))?
            .into_inner();
        while let Some(update) = stream
            .message()
            .await
            .map_err(|e| format!("remote MeshSubscribe stream error: {e}"))?
        {
            if update.heartbeat {
                // Heartbeats carry no slice, but they still ride the CP
                // compatibility contract — the same gate the local native
                // consumer applies to every frame.
                validate_update_ferrum_version(&update.ferrum_version, consumer)
                    .map_err(|rejection| format!("remote MeshSubscribe rejected: {rejection}"))?;
                continue;
            }
            let slice = validate_mesh_config_update(&update, &expected, consumer)
                .map_err(|rejection| format!("remote MeshSubscribe rejected: {rejection}"))?;
            return Ok(RemoteClusterEndpoints {
                workloads: slice.workloads,
                services: slice.services,
            });
        }
        Err("remote MeshSubscribe stream closed before delivering a slice".to_string())
    };

    tokio::time::timeout(request_timeout, attempt)
        .await
        .map_err(|_| "remote MeshSubscribe timed out".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::LocalityPreference;
    use crate::identity::spiffe::SpiffeId;
    use crate::modes::mesh::config::{RemoteCluster, ServicePort, WorkloadRef, WorkloadSelector};
    use std::sync::Mutex;

    fn td(raw: &str) -> TrustDomain {
        TrustDomain::new(raw).expect("trust domain")
    }

    fn spiffe(raw: &str) -> SpiffeId {
        SpiffeId::new(raw.to_string()).expect("spiffe id")
    }

    fn workload(spiffe_id: &str, service: &str, address: &str, locality: Option<&str>) -> Workload {
        // Derive `trust_domain` from the SPIFFE id so fixtures stay
        // self-consistent (a real workload's `trust_domain` always matches its
        // identity). Tests that need a deliberate split-identity / impersonation
        // workload override `trust_domain` via struct-update syntax.
        let spiffe_id = spiffe(spiffe_id);
        let trust_domain = spiffe_id.trust_domain().clone();
        Workload {
            spiffe_id,
            selector: WorkloadSelector::default(),
            service_name: service.to_string(),
            addresses: vec![address.to_string()],
            ports: vec![],
            trust_domain,
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: locality.map(str::to_string),
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }
    }

    /// Local-cluster-relative `MultiClusterConfig` fixture: `local_cluster`
    /// set, plus `west` declared as a remote cluster (so the provenance branch
    /// has something to match when `local_cluster` is later cleared).
    fn relative_to(local: &str) -> MultiClusterConfig {
        MultiClusterConfig {
            local_cluster: Some(local.to_string()),
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("west.local"),
                network: None,
                control_plane_url: None,
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        }
    }

    #[test]
    fn workload_is_remote_keys_on_cross_cluster_identity_not_locality() {
        let east_local = relative_to("east");
        let mut local = workload("spiffe://cluster.local/ns/d/sa/a", "svc", "10.0.0.1", None);
        local.cluster = Some("east".to_string());
        // A workload whose cluster matches the local cluster is LOCAL.
        assert!(!workload_is_remote(&local, Some(&east_local)));
        // A workload whose cluster differs from the local cluster is REMOTE.
        let mut from_west = local.clone();
        from_west.cluster = Some("west".to_string());
        assert!(workload_is_remote(&from_west, Some(&east_local)));

        // No `cluster` on the workload → local regardless of config.
        let no_cluster = workload("spiffe://cluster.local/ns/d/sa/b", "svc", "10.0.0.2", None);
        assert!(!workload_is_remote(&no_cluster, Some(&east_local)));

        // No `MultiClusterConfig` at all → nothing is classified remote
        // (single-cluster posture).
        assert!(!workload_is_remote(&local, None));

        // Regression guard for the codex finding: a LOCAL workload whose region
        // is literally named `remote-us` (carrying NO foreign cluster) must NOT
        // be classified remote — provenance is the cluster identity, not the
        // locality string prefix.
        let local_named_remote = workload(
            "spiffe://cluster.local/ns/d/sa/c",
            "svc",
            "10.0.0.3",
            Some("remote-us/zone-a"),
        );
        assert!(!workload_is_remote(&local_named_remote, Some(&east_local)));
        assert!(!workload_is_remote(&local_named_remote, None));
    }

    /// codex r2 finding #1: remote provenance must NOT require
    /// `MultiClusterConfig.local_cluster`. When `local_cluster` is omitted, a
    /// workload is remote iff its stamped cluster matches a configured remote
    /// cluster — so remote-discovered endpoints are still classified remote and
    /// the egress local-only filter / strict locality LB still fail over
    /// local→remote correctly.
    #[test]
    fn workload_is_remote_provenance_without_local_cluster() {
        // `local_cluster` UNSET, `west` declared remote.
        let no_local = MultiClusterConfig {
            local_cluster: None,
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("west.local"),
                network: None,
                control_plane_url: None,
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };

        // A workload stamped with a configured remote cluster's name is REMOTE
        // even though no `local_cluster` is set.
        let mut from_west = workload("spiffe://cluster.local/ns/d/sa/a", "svc", "10.0.0.1", None);
        from_west.cluster = Some("west".to_string());
        assert!(
            workload_is_remote(&from_west, Some(&no_local)),
            "a workload from a configured remote cluster must be REMOTE even with local_cluster unset"
        );

        // A workload stamped with a cluster the config does NOT list as remote
        // stays LOCAL (single-cluster / local-tagged posture).
        let mut from_other = from_west.clone();
        from_other.cluster = Some("east".to_string());
        assert!(
            !workload_is_remote(&from_other, Some(&no_local)),
            "a cluster not declared remote stays LOCAL when local_cluster is unset"
        );

        // No `cluster` on the workload → still LOCAL.
        let no_cluster = workload("spiffe://cluster.local/ns/d/sa/b", "svc", "10.0.0.2", None);
        assert!(!workload_is_remote(&no_cluster, Some(&no_local)));
    }

    fn service(name: &str, refs: &[&str]) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: Default::default(),
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: refs
                .iter()
                .map(|r| WorkloadRef {
                    spiffe_id: spiffe(r),
                })
                .collect(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn snapshot_with(cluster: &str, endpoints: RemoteClusterEndpoints) -> RemoteEndpointSnapshot {
        let mut clusters = HashMap::new();
        clusters.insert(
            cluster.to_string(),
            RemoteClusterEntry::new(
                cluster.to_string(),
                td("remote.local"),
                Some("net2".to_string()),
                // Matches the URL `candidate_admitting` declares (already
                // normalized form), so the full-poll-identity filter admits it.
                Some("https://cp.remote.example:15010".to_string()),
                None,
                endpoints,
                1,
            ),
        );
        RemoteEndpointSnapshot { clusters }
    }

    /// A candidate `MultiClusterConfig` that admits the `snapshot_with` cluster
    /// identity (`name` / `remote.local` / `net2`) so the merge tests below see
    /// the same-generation candidate filter pass. Tests asserting the filter
    /// REJECTS a divergent/absent cluster build their own candidate.
    fn candidate_admitting(cluster: &str) -> MultiClusterConfig {
        MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: cluster.to_string(),
                trust_domain: td("remote.local"),
                network: Some("net2".to_string()),
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        }
    }

    #[test]
    fn enforce_remote_trust_domain_drops_foreign_identities() {
        let declared = td("eu-west-1.example.com");

        // Fully in-domain: survives.
        let in_domain = Workload {
            trust_domain: declared.clone(),
            ..workload(
                "spiffe://eu-west-1.example.com/ns/default/sa/reviews",
                "reviews",
                "10.9.0.1",
                None,
            )
        };
        // Impersonator: claims the LOCAL trust domain in both spiffe_id and
        // trust_domain — exactly the confused-deputy hijack the filter blocks.
        let impersonator = Workload {
            trust_domain: td("cluster.local"),
            ..workload(
                "spiffe://cluster.local/ns/default/sa/reviews",
                "reviews",
                "10.6.6.6",
                None,
            )
        };
        // Split identity: spiffe domain matches declared but the trust_domain
        // field is foreign — must also be dropped (both must match).
        let split = Workload {
            trust_domain: td("cluster.local"),
            ..workload(
                "spiffe://eu-west-1.example.com/ns/default/sa/api",
                "api",
                "10.9.0.2",
                None,
            )
        };

        let mut endpoints = RemoteClusterEndpoints {
            workloads: vec![in_domain, impersonator, split],
            services: vec![service(
                "reviews",
                &[
                    "spiffe://eu-west-1.example.com/ns/default/sa/reviews",
                    "spiffe://cluster.local/ns/default/sa/reviews",
                ],
            )],
        };

        enforce_remote_trust_domain(&mut endpoints, &declared, "eu-west-1");

        assert_eq!(
            endpoints.workloads.len(),
            1,
            "only the fully in-domain workload survives"
        );
        assert_eq!(
            endpoints.workloads[0].spiffe_id.as_str(),
            "spiffe://eu-west-1.example.com/ns/default/sa/reviews"
        );
        assert_eq!(
            endpoints.services[0].workloads.len(),
            1,
            "the foreign service workload-ref is dropped"
        );
        assert_eq!(
            endpoints.services[0].workloads[0].spiffe_id.as_str(),
            "spiffe://eu-west-1.example.com/ns/default/sa/reviews"
        );
    }

    #[test]
    fn enforce_remote_trust_domain_drops_orphaned_refs_and_empty_services() {
        let declared = td("eu-west-1.example.com");
        let shared_spiffe = "spiffe://eu-west-1.example.com/ns/default/sa/shared";
        let orphan_spiffe = "spiffe://eu-west-1.example.com/ns/default/sa/orphan";
        let surviving_different_service = Workload {
            trust_domain: declared.clone(),
            ..workload(shared_spiffe, "payments", "10.9.0.3", None)
        };
        let dropped_split_identity = Workload {
            trust_domain: td("cluster.local"),
            ..workload(orphan_spiffe, "api", "10.9.0.4", None)
        };

        let mut endpoints = RemoteClusterEndpoints {
            workloads: vec![surviving_different_service, dropped_split_identity],
            services: vec![
                service("api", &[shared_spiffe]),
                service("payments", &[shared_spiffe]),
                service("orphaned", &[orphan_spiffe]),
            ],
        };

        enforce_remote_trust_domain(&mut endpoints, &declared, "eu-west-1");

        assert_eq!(
            endpoints.workloads.len(),
            1,
            "the split-identity workload is dropped"
        );
        assert_eq!(
            endpoints.services.len(),
            2,
            "the orphaned service is dropped, while legacy refs to surviving in-domain workloads stay explicit"
        );
        let service_names: Vec<_> = endpoints
            .services
            .iter()
            .map(|service| service.name.as_str())
            .collect();
        assert!(service_names.contains(&"api"));
        assert!(service_names.contains(&"payments"));
        assert!(!service_names.contains(&"orphaned"));
        assert_eq!(endpoints.services[0].workloads.len(), 1);
    }

    #[test]
    fn enforce_remote_trust_domain_keeps_all_in_domain() {
        let declared = td("eu-west-1.example.com");
        let in_domain = Workload {
            trust_domain: declared.clone(),
            ..workload(
                "spiffe://eu-west-1.example.com/ns/default/sa/reviews",
                "reviews",
                "10.9.0.1",
                None,
            )
        };
        let mut endpoints = RemoteClusterEndpoints {
            workloads: vec![in_domain],
            services: vec![service(
                "reviews",
                &["spiffe://eu-west-1.example.com/ns/default/sa/reviews"],
            )],
        };
        enforce_remote_trust_domain(&mut endpoints, &declared, "eu-west-1");
        assert_eq!(endpoints.workloads.len(), 1);
        assert_eq!(endpoints.services[0].workloads.len(), 1);
    }

    #[test]
    fn default_remote_locality_distinguishes_region() {
        assert_eq!(
            default_remote_locality("west", Some("net2")),
            "remote-west/net2"
        );
        assert_eq!(default_remote_locality("west", None), "remote-west");
        // The synthetic region differs from any plausible local region, so a
        // remote target never lands in the local source-region tier.
        let local = LocalityPreference::parse("us-east-1/zone-a").unwrap();
        let remote = LocalityPreference::parse(&default_remote_locality("west", None)).unwrap();
        assert!(!local.same_region(&remote));
    }

    /// codex r3 Finding C: the reserved-namespace stripper drops every `mesh.*`
    /// key from a label map copied from operator/workload-controlled input so a
    /// forged provenance/transport marker can never reach an `UpstreamTarget`.
    #[test]
    fn strip_reserved_mesh_tags_drops_mesh_namespace_only() {
        let mut tags: std::collections::HashMap<String, String> = [
            ("app", "reviews"),
            ("version", "v2"),
            (MESH_REMOTE_TAG, MESH_REMOTE_TAG_VALUE), // forged provenance marker
            ("mesh.hbone", "true"),                   // forged transport marker
            ("mesh.anything", "x"),                   // any reserved key
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        strip_reserved_mesh_tags(&mut tags);
        // Operator labels survive.
        assert_eq!(tags.get("app").map(String::as_str), Some("reviews"));
        assert_eq!(tags.get("version").map(String::as_str), Some("v2"));
        // Every reserved `mesh.*` key is gone.
        assert!(!tags.contains_key(MESH_REMOTE_TAG));
        assert!(!tags.contains_key("mesh.hbone"));
        assert!(!tags.contains_key("mesh.anything"));
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn tag_remote_workloads_applies_locality_and_cluster() {
        let mut endpoints = RemoteClusterEndpoints {
            workloads: vec![
                workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                ),
                workload(
                    "spiffe://remote.local/ns/default/sa/b",
                    "reviews",
                    "10.2.0.2",
                    Some("us-west-2/zone-c"),
                ),
            ],
            services: vec![],
        };
        tag_remote_workloads(&mut endpoints, "west", Some("net2"));
        // Remote workloads always get the synthetic remote locality, even when
        // the remote CP supplied a real locality that could collide with local.
        assert_eq!(
            endpoints.workloads[0].locality.as_deref(),
            Some("remote-west/net2")
        );
        assert_eq!(endpoints.workloads[0].cluster.as_deref(), Some("west"));
        assert_eq!(endpoints.workloads[0].network.as_deref(), Some("net2"));
        assert_eq!(
            endpoints.workloads[1].locality.as_deref(),
            Some("remote-west/net2")
        );
        // codex r3 Finding B: ingestion stamps the RESERVED provenance marker on
        // every remote-discovered workload.
        assert!(endpoints.workloads[0].remote_provenance);
        assert!(endpoints.workloads[1].remote_provenance);
    }

    /// codex r3 Finding B: a genuinely-remote endpoint whose PRESERVED
    /// `workload.cluster` does NOT equal the configured `RemoteCluster.name` (an
    /// Istio WorkloadEntry translation can stamp such a `cluster`) must STILL be
    /// classified remote. Before the fix, `workload_is_remote` keyed solely on
    /// cluster-name equality, so this endpoint was misclassified LOCAL and strict
    /// locality LB kept sending to it while locals were healthy. The reserved
    /// `remote_provenance` marker — stamped at ingestion, independent of the
    /// cluster name — fixes it.
    #[test]
    fn remote_provenance_overrides_divergent_cluster_name() {
        // Workload pre-stamped (e.g. by WorkloadEntry translation) with a cluster
        // name that does NOT match the configured remote alias `west`.
        let mut diverged = workload(
            "spiffe://remote.local/ns/default/sa/a",
            "reviews",
            "10.2.0.1",
            None,
        );
        diverged.cluster = Some("some-other-cluster-id".to_string());
        let mut endpoints = RemoteClusterEndpoints {
            workloads: vec![diverged],
            services: vec![],
        };
        // Ingest from the remote slice for configured cluster `west`.
        tag_remote_workloads(&mut endpoints, "west", None);
        let ingested = &endpoints.workloads[0];

        // Provenance is stamped; the divergent cluster name is preserved.
        assert!(ingested.remote_provenance);
        assert_eq!(ingested.cluster.as_deref(), Some("some-other-cluster-id"));

        // Config declares `west` as remote with NO local_cluster; the workload's
        // cluster name does not match it, so the cluster-name fallback alone would
        // say LOCAL. Provenance must win → REMOTE.
        let cfg = MultiClusterConfig {
            local_cluster: None,
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: None,
                control_plane_url: None,
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        assert!(
            workload_is_remote(ingested, Some(&cfg)),
            "a provenance-marked remote endpoint must classify remote even when its \
             cluster name diverges from the configured alias"
        );
        // Sanity: the SAME divergent-cluster workload WITHOUT the provenance marker
        // (never ingested from the remote slice) falls back to cluster-name match
        // and is LOCAL — proving the provenance flag, not the cluster name, is what
        // flips classification here.
        let mut not_ingested = ingested.clone();
        not_ingested.remote_provenance = false;
        assert!(!workload_is_remote(&not_ingested, Some(&cfg)));
    }

    #[test]
    fn merge_appends_remote_workloads_and_unions_service_refs() {
        let local_workloads = vec![workload(
            "spiffe://cluster.local/ns/default/sa/local",
            "reviews",
            "10.1.0.1",
            Some("us-east-1/zone-a"),
        )];
        let local_services = vec![service(
            "reviews",
            &["spiffe://cluster.local/ns/default/sa/local"],
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/remote",
                "reviews",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![service(
                "reviews",
                &["spiffe://remote.local/ns/default/sa/remote"],
            )],
        };
        let snapshot = snapshot_with("west", remote);

        let (workloads, services) = merge_remote_endpoints_into_mesh(
            &local_workloads,
            &local_services,
            &snapshot,
            Some(&candidate_admitting("west")),
            true,
        );

        assert_eq!(workloads.len(), 2, "remote workload appended");
        // Single merged `reviews` service with BOTH refs so the discoverer
        // resolves local + remote endpoints.
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].workloads.len(), 2);
    }

    #[test]
    fn merge_does_not_append_remote_only_service_when_append_disabled() {
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/forbidden",
                "forbidden",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![service(
                "forbidden",
                &["spiffe://remote.local/ns/default/sa/forbidden"],
            )],
        };
        let snapshot = snapshot_with("west", remote);

        let (workloads, services) = merge_remote_endpoints_into_mesh(
            &[],
            &[],
            &snapshot,
            Some(&candidate_admitting("west")),
            false,
        );

        assert_eq!(workloads.len(), 1, "remote workload inventory is retained");
        assert!(
            services.is_empty(),
            "a poller-discovered remote-only service must not widen a Sidecar-narrowed service list"
        );
    }

    #[test]
    fn merge_keeps_same_spiffe_remote_workload_with_distinct_endpoint() {
        // The same service account identity can legitimately appear in multiple
        // clusters. Only exact endpoint duplicates are collapsed.
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/shared",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://cluster.local/ns/default/sa/shared",
                "reviews",
                "10.9.9.9",
                None,
            )],
            services: vec![],
        };
        let snapshot = snapshot_with("west", remote);
        let (workloads, _) = merge_remote_endpoints_into_mesh(
            &local,
            &[],
            &snapshot,
            Some(&candidate_admitting("west")),
            true,
        );
        assert_eq!(workloads.len(), 2);
        assert_eq!(workloads[0].addresses, vec!["10.1.0.1".to_string()]);
        assert_eq!(workloads[1].addresses, vec!["10.9.9.9".to_string()]);
    }

    #[test]
    fn merge_keeps_same_remote_endpoint_on_distinct_networks() {
        let remote_spiffe = "spiffe://remote.local/ns/default/sa/shared";
        let remote_workload = |cluster: &str, network: &str| Workload {
            cluster: Some(cluster.to_string()),
            network: Some(network.to_string()),
            locality: Some(default_remote_locality(cluster, Some(network))),
            ..workload(remote_spiffe, "reviews", "10.9.9.9", None)
        };
        let mut clusters = HashMap::new();
        clusters.insert(
            "east".to_string(),
            RemoteClusterEntry::new(
                "east".to_string(),
                td("remote.local"),
                Some("net-a".to_string()),
                Some("https://cp-east.remote.example:15010".to_string()),
                None,
                RemoteClusterEndpoints {
                    workloads: vec![remote_workload("east", "net-a")],
                    services: vec![],
                },
                1,
            ),
        );
        clusters.insert(
            "west".to_string(),
            RemoteClusterEntry::new(
                "west".to_string(),
                td("remote.local"),
                Some("net-b".to_string()),
                Some("https://cp-west.remote.example:15010".to_string()),
                None,
                RemoteClusterEndpoints {
                    workloads: vec![remote_workload("west", "net-b")],
                    services: vec![],
                },
                1,
            ),
        );
        let snapshot = RemoteEndpointSnapshot { clusters };
        let candidate = MultiClusterConfig {
            remote_clusters: vec![
                RemoteCluster {
                    name: "east".to_string(),
                    trust_domain: td("remote.local"),
                    network: Some("net-a".to_string()),
                    control_plane_url: Some("https://cp-east.remote.example:15010".to_string()),
                    federation_endpoint: None,
                    discovery_credential_ref: None,
                },
                RemoteCluster {
                    name: "west".to_string(),
                    trust_domain: td("remote.local"),
                    network: Some("net-b".to_string()),
                    control_plane_url: Some("https://cp-west.remote.example:15010".to_string()),
                    federation_endpoint: None,
                    discovery_credential_ref: None,
                },
            ],
            ..MultiClusterConfig::default()
        };

        let (workloads, _) =
            merge_remote_endpoints_into_mesh(&[], &[], &snapshot, Some(&candidate), true);

        assert_eq!(
            workloads.len(),
            2,
            "same address/SPIFFE endpoints from distinct networks must not collapse"
        );
        let networks: HashSet<_> = workloads
            .iter()
            .filter_map(|workload| workload.network.as_deref())
            .collect();
        assert!(networks.contains("net-a"));
        assert!(networks.contains("net-b"));
    }

    #[test]
    fn merge_skips_exact_remote_workload_duplicate() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/shared",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://cluster.local/ns/default/sa/shared",
                "reviews",
                "10.1.0.1",
                None,
            )],
            services: vec![],
        };
        let snapshot = snapshot_with("west", remote);
        let (workloads, _) = merge_remote_endpoints_into_mesh(
            &local,
            &[],
            &snapshot,
            Some(&candidate_admitting("west")),
            true,
        );
        assert_eq!(workloads.len(), 1);
    }

    #[test]
    fn merge_empty_snapshot_is_identity() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/a",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let (workloads, services) = merge_remote_endpoints_into_mesh(
            &local,
            &[service(
                "reviews",
                &["spiffe://cluster.local/ns/default/sa/a"],
            )],
            &RemoteEndpointSnapshot::default(),
            None,
            true,
        );
        assert_eq!(workloads.len(), 1);
        assert_eq!(services.len(), 1);
    }

    /// Finding 1 (same-generation fail-closed): a stored remote cluster that the
    /// CANDIDATE slice does not declare contributes NO endpoints, even though the
    /// store still holds it (the discovery reconciler, sourced from the accepted
    /// slice, evicts it only on the next generation). Cluster removal must be
    /// fail-closed within the generation that removed it.
    #[test]
    fn merge_drops_cluster_absent_from_candidate_slice() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/local",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/remote",
                "reviews",
                "10.2.0.1",
                None,
            )],
            services: vec![service(
                "reviews",
                &["spiffe://remote.local/ns/default/sa/remote"],
            )],
        };
        let snapshot = snapshot_with("west", remote);

        // Candidate declares NO multi-cluster at all → fail closed, no remote
        // endpoints contributed.
        let (workloads, services) =
            merge_remote_endpoints_into_mesh(&local, &[], &snapshot, None, true);
        assert_eq!(
            workloads.len(),
            1,
            "no remote workload when candidate is None"
        );
        assert!(services.is_empty());

        // Candidate declares a DIFFERENT cluster name → the stored `west` is not
        // admitted.
        let other = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "east".to_string(),
                trust_domain: td("remote.local"),
                network: Some("net2".to_string()),
                control_plane_url: Some("https://cp.east.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let (workloads, _) =
            merge_remote_endpoints_into_mesh(&local, &[], &snapshot, Some(&other), true);
        assert_eq!(
            workloads.len(),
            1,
            "a cluster absent from the candidate contributes nothing"
        );
    }

    /// Finding 1 (identity divergence): a candidate that keeps the cluster NAME
    /// but diverges on a poll-identity field the entry carries (`network` here,
    /// `trust_domain` likewise) does NOT admit the stored entry — the
    /// same-generation guard for the fields the snapshot exposes.
    #[test]
    fn merge_drops_cluster_with_diverged_identity_in_candidate() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/local",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/remote",
                "reviews",
                "10.2.0.1",
                None,
            )],
            services: vec![],
        };
        // Stored entry carries network `net2` (from `snapshot_with`).
        let snapshot = snapshot_with("west", remote);

        // Candidate declares `west` but on a DIFFERENT network.
        let diverged_network = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: Some("net-other".to_string()),
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let (workloads, _) =
            merge_remote_endpoints_into_mesh(&local, &[], &snapshot, Some(&diverged_network), true);
        assert_eq!(workloads.len(), 1, "diverged network is not admitted");

        // Candidate declares `west`/`net2` but a DIFFERENT trust domain.
        let diverged_td = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("other.local"),
                network: Some("net2".to_string()),
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let (workloads, _) =
            merge_remote_endpoints_into_mesh(&local, &[], &snapshot, Some(&diverged_td), true);
        assert_eq!(workloads.len(), 1, "diverged trust domain is not admitted");

        // Matching identity admits it.
        let (workloads, _) = merge_remote_endpoints_into_mesh(
            &local,
            &[],
            &snapshot,
            Some(&candidate_admitting("west")),
            true,
        );
        assert_eq!(
            workloads.len(),
            2,
            "matching identity admits the remote workload"
        );
    }

    /// Codex F7.2 round-5, finding 1: a candidate slice that changes ONLY the
    /// `control_plane_url` (same name + trust domain + network) must NOT admit
    /// the stored entry — those endpoints were fetched from the PREVIOUS control
    /// plane, so the generation that accepts the new URL must serve none of them
    /// until the discovery reconciler starts the new poller. The stored entry
    /// carries the normalized polled URL, so the filter can tell them apart.
    #[test]
    fn merge_drops_cluster_with_url_only_divergence() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/local",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/remote",
                "reviews",
                "10.2.0.1",
                None,
            )],
            services: vec![],
        };
        // `snapshot_with` stores URL `https://cp.remote.example:15010`.
        let snapshot = snapshot_with("west", remote);

        // Candidate keeps name + trust domain + network but moves the CP to v2.
        let url_only_change = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: Some("net2".to_string()),
                control_plane_url: Some("https://cp-v2.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let (workloads, _) =
            merge_remote_endpoints_into_mesh(&local, &[], &snapshot, Some(&url_only_change), true);
        assert_eq!(
            workloads.len(),
            1,
            "a URL-only change must not serve endpoints fetched from the previous control plane"
        );

        // The operator-written `grpcs://` form of the SAME URL still admits it
        // (normalization matches it to the stored `https://` poll URL).
        let grpcs_same = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: Some("net2".to_string()),
                control_plane_url: Some("grpcs://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let (workloads, _) =
            merge_remote_endpoints_into_mesh(&local, &[], &snapshot, Some(&grpcs_same), true);
        assert_eq!(
            workloads.len(),
            2,
            "a grpcs:// declaration of the same URL normalizes to the stored https:// and admits"
        );
    }

    /// `matches_declared` is the single source of truth shared by the merge
    /// filter and the admin `discovered` filter; pin its identity rules.
    #[test]
    fn matches_declared_compares_full_poll_identity() {
        let entry = RemoteClusterEntry::new(
            "west".to_string(),
            td("remote.local"),
            Some("net2".to_string()),
            Some("https://cp.remote.example:15010".to_string()),
            None,
            RemoteClusterEndpoints::default(),
            1,
        );
        let base = RemoteCluster {
            name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: Some("net2".to_string()),
            control_plane_url: Some("https://cp.remote.example:15010".to_string()),
            federation_endpoint: None,
            discovery_credential_ref: None,
        };
        assert!(entry.matches_declared(&base), "exact identity matches");
        // grpcs:// normalizes to the stored https:// → matches.
        assert!(entry.matches_declared(&RemoteCluster {
            control_plane_url: Some("grpcs://cp.remote.example:15010".to_string()),
            ..base.clone()
        }));
        // Surrounding whitespace is trimmed before normalization.
        assert!(entry.matches_declared(&RemoteCluster {
            control_plane_url: Some("  https://cp.remote.example:15010  ".to_string()),
            ..base.clone()
        }));
        // Each identity field, diverged in isolation, fails the match.
        assert!(!entry.matches_declared(&RemoteCluster {
            name: "east".to_string(),
            ..base.clone()
        }));
        assert!(!entry.matches_declared(&RemoteCluster {
            trust_domain: td("other.local"),
            ..base.clone()
        }));
        assert!(!entry.matches_declared(&RemoteCluster {
            network: Some("net-other".to_string()),
            ..base.clone()
        }));
        assert!(!entry.matches_declared(&RemoteCluster {
            control_plane_url: Some("https://cp-v2.remote.example:15010".to_string()),
            ..base.clone()
        }));
        // A federation-only (no URL) or blank-URL declaration never owns polled
        // endpoints, even with otherwise-matching identity.
        assert!(!entry.matches_declared(&RemoteCluster {
            control_plane_url: None,
            ..base.clone()
        }));
        assert!(!entry.matches_declared(&RemoteCluster {
            control_plane_url: Some("   ".to_string()),
            ..base.clone()
        }));
        // An entry with no stored URL (test seeder shape) never matches a
        // URL-bearing declaration.
        let urlless = RemoteClusterEntry::new(
            "west".to_string(),
            td("remote.local"),
            Some("net2".to_string()),
            None,
            None,
            RemoteClusterEndpoints::default(),
            1,
        );
        assert!(!urlless.matches_declared(&base));
    }

    /// The discovery credential ref is part of the poll identity:
    /// `matches_declared` must reject a declaration whose
    /// `discovery_credential_ref` differs from the credential the stored
    /// endpoints were polled UNDER, so a credential rotation / withdrawal stops
    /// admitting stale endpoints fetched with the old credential.
    #[test]
    fn matches_declared_includes_credential_ref() {
        let entry = RemoteClusterEntry::new(
            "west".to_string(),
            td("remote.local"),
            Some("net2".to_string()),
            Some("https://cp.remote.example:15010".to_string()),
            Some("credA".to_string()),
            RemoteClusterEndpoints::default(),
            1,
        );
        // Identical poll identity INCLUDING the credential ref → matches.
        let base = RemoteCluster {
            name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: Some("net2".to_string()),
            control_plane_url: Some("https://cp.remote.example:15010".to_string()),
            federation_endpoint: None,
            discovery_credential_ref: Some("credA".to_string()),
        };
        assert!(
            entry.matches_declared(&base),
            "an entry polled under credA matches a credA declaration"
        );
        // A rotated credential (different ref) → no match.
        assert!(
            !entry.matches_declared(&RemoteCluster {
                discovery_credential_ref: Some("credB".to_string()),
                ..base.clone()
            }),
            "rotating the discovery credential must stop admitting the old endpoints"
        );
        // A withdrawn credential (now None) → no match.
        assert!(
            !entry.matches_declared(&RemoteCluster {
                discovery_credential_ref: None,
                ..base.clone()
            }),
            "withdrawing the discovery credential must stop admitting the old endpoints"
        );
        // Symmetric case: an entry polled WITHOUT a credential must not match a
        // declaration that has since ADDED one.
        let uncredentialed = RemoteClusterEntry::new(
            "west".to_string(),
            td("remote.local"),
            Some("net2".to_string()),
            Some("https://cp.remote.example:15010".to_string()),
            None,
            RemoteClusterEndpoints::default(),
            1,
        );
        assert!(
            !uncredentialed.matches_declared(&base),
            "adding a discovery credential must stop admitting endpoints polled without one"
        );
    }

    #[test]
    fn store_install_and_snapshot_round_trip() {
        let store = RemoteEndpointStore::new();
        assert!(!store.has_first_success());
        assert!(store.snapshot().is_empty());

        store.install_for_test(RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: None,
            credential_ref: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                )],
                services: vec![],
            },
            fetched_at: Arc::new(AtomicU64::new(1)),
        });
        assert!(store.has_first_success());
        let snapshot = store.snapshot();
        let entry = snapshot.clusters.get("west").expect("installed entry");
        assert_eq!(entry.trust_domain.as_str(), "remote.local");
        assert_eq!(entry.endpoints.workloads.len(), 1);
        assert_eq!(entry.fetched_at_unix_seconds(), 1);

        store.remove("west");
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn poll_targets_require_federated_trust() {
        let mc = MultiClusterConfig {
            remote_clusters: vec![
                RemoteCluster {
                    name: "trusted".to_string(),
                    trust_domain: td("trusted.local"),
                    network: None,
                    control_plane_url: Some("https://cp.trusted.example:15010".to_string()),
                    federation_endpoint: None,
                    discovery_credential_ref: None,
                },
                RemoteCluster {
                    name: "untrusted".to_string(),
                    trust_domain: td("untrusted.local"),
                    network: None,
                    control_plane_url: Some("https://cp.untrusted.example:15010".to_string()),
                    federation_endpoint: None,
                    discovery_credential_ref: None,
                },
            ],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("trusted.local"));

        let targets = poll_targets_for_multi_cluster(&mc, &trusted);
        assert_eq!(targets.len(), 1, "only the federated cluster is dialed");
        assert_eq!(targets[0].cluster_name, "trusted");
    }

    #[test]
    fn poll_targets_cap_remote_discovery_clusters() {
        let remote_clusters: Vec<RemoteCluster> = (0..=MAX_MESH_REMOTE_CLUSTERS)
            .map(|index| RemoteCluster {
                name: format!("cluster-{index}"),
                trust_domain: td(&format!("remote-{index}.test")),
                network: None,
                control_plane_url: Some(format!("https://cp-{index}.remote.example:15010")),
                federation_endpoint: None,
                discovery_credential_ref: None,
            })
            .collect();
        let trusted: std::collections::HashSet<TrustDomain> = remote_clusters
            .iter()
            .map(|remote| remote.trust_domain.clone())
            .collect();
        let mc = MultiClusterConfig {
            remote_clusters,
            ..MultiClusterConfig::default()
        };

        let targets = poll_targets_for_multi_cluster(&mc, &trusted);

        assert_eq!(targets.len(), MAX_MESH_REMOTE_CLUSTERS);
        assert!(
            targets
                .iter()
                .all(|target| target.cluster_name != format!("cluster-{MAX_MESH_REMOTE_CLUSTERS}"))
        );
    }

    #[tokio::test]
    async fn manager_reconciles_trust_changes_and_removes_stale_endpoints() {
        let store = RemoteEndpointStore::new();
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            max_stale_age: None,
            production_mode: false,
            jwt_secret: None,
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig::default(),
        };
        let mut manager = RemoteDiscoveryManager::new(Some(config), store.clone(), |ctx| {
            Arc::new(MissingSecretSource {
                cluster_name: ctx.cluster_name.clone(),
            })
        });
        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: None,
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("remote.local"));

        manager.reconcile(Some(&mc), trusted);
        assert_eq!(manager.running_cluster_names(), vec!["west"]);
        store.install_for_test(RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: None,
            credential_ref: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                )],
                services: vec![],
            },
            fetched_at: Arc::new(AtomicU64::new(1)),
        });
        assert!(!store.snapshot().is_empty());

        manager.reconcile(Some(&mc), std::collections::HashSet::new());
        assert!(manager.running_cluster_names().is_empty());
        assert!(
            store.snapshot().is_empty(),
            "trust withdrawal removes stale remote endpoints"
        );
        manager.shutdown();
    }

    #[test]
    fn parse_remote_discovery_credentials_parses_map() {
        let issuer = crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER;
        // Secrets must meet MIN_JWT_SECRET_LENGTH (32), like the shared
        // FERRUM_CP_DP_GRPC_JWT_SECRET path enforces.
        let secret_b = "b".repeat(40);
        let secret_c = "c".repeat(40);
        let raw = format!(r#"{{"b":"{secret_b}","c":"{secret_c}"}}"#);
        let parsed = parse_remote_discovery_credentials(Some(&raw), issuer)
            .expect("valid credential map parses");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("b").map(|s| s.as_str()), Some(secret_b.as_str()));
        assert_eq!(parsed.get("c").map(|s| s.as_str()), Some(secret_c.as_str()));
        // Each resolved secret carries the supplied (shared CP-DP) issuer so the
        // remote CP accepts a token minted with it.
        assert_eq!(parsed.get("b").map(|s| s.issuer()), Some(issuer));
    }

    #[test]
    fn parse_remote_discovery_credentials_none_and_empty_are_empty() {
        let issuer = crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER;
        assert!(
            parse_remote_discovery_credentials(None, issuer)
                .expect("None is ok")
                .is_empty()
        );
        assert!(
            parse_remote_discovery_credentials(Some(""), issuer)
                .expect("empty is ok")
                .is_empty()
        );
        assert!(
            parse_remote_discovery_credentials(Some("  "), issuer)
                .expect("whitespace is ok")
                .is_empty()
        );
    }

    #[test]
    fn parse_remote_discovery_credentials_rejects_malformed_and_empty_secret() {
        let issuer = crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER;
        assert!(
            parse_remote_discovery_credentials(Some("not json"), issuer).is_err(),
            "malformed JSON is rejected"
        );
        assert!(
            parse_remote_discovery_credentials(Some(r#"{"b":""}"#), issuer).is_err(),
            "empty secret value is rejected"
        );
        assert!(
            parse_remote_discovery_credentials(Some(r#"{"b":"short"}"#), issuer).is_err(),
            "a secret below MIN_JWT_SECRET_LENGTH is rejected"
        );
        assert!(
            parse_remote_discovery_credentials(
                Some(r#"{"":"a-32-char-secret-aaaaaaaaaaaaaaaaa"}"#),
                issuer
            )
            .is_err(),
            "empty credential reference is rejected"
        );
    }

    /// A RemoteCluster that references an installed credential starts a poller
    /// (the per-remote secret resolves and is threaded into discovery config).
    #[tokio::test]
    async fn manager_starts_poller_for_resolved_credential_ref() {
        let store = RemoteEndpointStore::new();
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            max_stale_age: None,
            production_mode: false,
            jwt_secret: None,
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig::default(),
        };
        let mut credentials = std::collections::HashMap::new();
        credentials.insert(
            "credB".to_string(),
            GrpcJwtSecret::new("per-remote-secret-padding-32-chars".to_string()),
        );
        let mut manager = RemoteDiscoveryManager::new(Some(config), store.clone(), |ctx| {
            Arc::new(MissingSecretSource {
                cluster_name: ctx.cluster_name.clone(),
            })
        })
        .with_credentials(std::sync::Arc::new(credentials));

        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: None,
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: Some("credB".to_string()),
            }],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("remote.local"));

        manager.reconcile(Some(&mc), trusted);
        assert_eq!(manager.running_cluster_names(), vec!["west"]);
        manager.shutdown();
    }

    /// A RemoteCluster that references an UNKNOWN credential fails closed: no
    /// poller is started (and discovery never falls back to the shared secret).
    #[tokio::test]
    async fn manager_fails_closed_for_unresolved_credential_ref() {
        let store = RemoteEndpointStore::new();
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            max_stale_age: None,
            production_mode: false,
            // A shared secret IS present; the unresolved ref must still fail
            // closed rather than silently borrow it.
            jwt_secret: Some(GrpcJwtSecret::new(
                "shared-secret-padding-32-chars!!".to_string(),
            )),
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig::default(),
        };
        // Empty credential map: the referenced "missing" ref cannot resolve.
        let mut manager = RemoteDiscoveryManager::new(Some(config), store.clone(), |ctx| {
            Arc::new(MissingSecretSource {
                cluster_name: ctx.cluster_name.clone(),
            })
        })
        .with_credentials(std::sync::Arc::new(std::collections::HashMap::new()));

        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: None,
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: Some("missing".to_string()),
            }],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("remote.local"));

        manager.reconcile(Some(&mc), trusted);
        assert!(
            manager.running_cluster_names().is_empty(),
            "an unresolved discovery credential reference must not start a poller"
        );
        manager.shutdown();
    }

    /// codex finding: removing a cluster (trust withdrawal / reconcile drop)
    /// must also prune its remote-discovery success / last-success / endpoint-age
    /// metrics, not just its cached endpoints — otherwise a stale, endpoint-less
    /// cluster keeps advertising a fresh poll on unauthenticated `/metrics`.
    #[tokio::test]
    async fn manager_clears_remote_discovery_metrics_on_removal() {
        // Unique cluster/trust-domain so the shared global metric maps don't
        // collide with other tests rendering the same output.
        let suffix = format!("{}-{}", std::process::id(), line!());
        let cluster = format!("metricclear-{suffix}");
        let trust_domain_str = format!("td-{suffix}.example");
        let trust_domain = td(&trust_domain_str);

        let store = RemoteEndpointStore::new();
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            max_stale_age: None,
            production_mode: false,
            jwt_secret: None,
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig::default(),
        };
        let mut manager = RemoteDiscoveryManager::new(Some(config), store.clone(), |ctx| {
            Arc::new(MissingSecretSource {
                cluster_name: ctx.cluster_name.clone(),
            })
        });
        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: cluster.clone(),
                trust_domain: trust_domain.clone(),
                network: None,
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(trust_domain.clone());

        manager.reconcile(Some(&mc), trusted);
        assert_eq!(manager.running_cluster_names(), vec![cluster.clone()]);

        // Simulate a successful poll having recorded the cluster's metrics.
        crate::plugins::mesh::prometheus_helpers::record_mesh_remote_discovery_poll_success(
            &cluster,
            &trust_domain_str,
            1,
        );
        let mut before = String::new();
        crate::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics(&mut before);
        assert!(
            before.contains(&format!("cluster=\"{cluster}\"")),
            "precondition: success metric should be present before removal: {before}"
        );

        // Withdraw trust → reconcile removes the cluster (stop_cluster with
        // remove_endpoints = true), which must also clear the metric series.
        manager.reconcile(Some(&mc), std::collections::HashSet::new());
        assert!(manager.running_cluster_names().is_empty());

        let mut after = String::new();
        crate::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics(&mut after);
        assert!(
            !after.contains(&format!("cluster=\"{cluster}\"")),
            "removing a cluster must prune its remote-discovery metric series: {after}"
        );
        manager.shutdown();
    }

    /// Codex F7.2 round-3: a target that keeps the same cluster name + trust
    /// domain but changes its poll identity (`network` AND `control_plane_url`)
    /// is a DIFFERENT poll target. `reconcile` must stop the old poller and
    /// evict its endpoints rather than keep serving them — otherwise a rejected
    /// slice that only diverged on those fields could leave stale endpoints in
    /// the store (and thus under `/mesh/remote-clusters`'s `discovered`, which
    /// the name+trust-domain admin filter would NOT catch). Combined with
    /// sourcing the reconcile from the *accepted* slice, this guarantees the
    /// store only ever holds endpoints from the proxy-applied multicluster
    /// config. Trust eligibility is held constant here to isolate the
    /// poll-identity-change path from the trust-withdrawal path above.
    #[tokio::test]
    async fn manager_evicts_endpoints_when_poll_identity_diverges() {
        let store = RemoteEndpointStore::new();
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            max_stale_age: None,
            production_mode: false,
            jwt_secret: None,
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig::default(),
        };
        let mut manager = RemoteDiscoveryManager::new(Some(config), store.clone(), |ctx| {
            Arc::new(MissingSecretSource {
                cluster_name: ctx.cluster_name.clone(),
            })
        });

        // Accepted slice declares `west` with network `net-a` reachable at v1.
        let accepted = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: Some("net-a".to_string()),
                control_plane_url: Some("https://cp-v1.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("remote.local"));

        manager.reconcile(Some(&accepted), trusted.clone());
        assert_eq!(manager.running_cluster_names(), vec!["west"]);
        store.install_for_test(RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: Some("net-a".to_string()),
            control_plane_url: Some("https://cp-v1.remote.example:15010".to_string()),
            credential_ref: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                )],
                services: vec![],
            },
            fetched_at: Arc::new(AtomicU64::new(1)),
        });
        assert!(!store.snapshot().is_empty());

        // A divergent target: SAME cluster name + trust domain, but a changed
        // network AND control_plane_url (the exact shape a rejected slice could
        // carry past a name+trust-domain-only filter). The old poller must be
        // stopped and its endpoints evicted before the new poller starts.
        let divergent = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: Some("net-b".to_string()),
                control_plane_url: Some("https://cp-v2.remote.example:15010".to_string()),
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        };
        manager.reconcile(Some(&divergent), trusted);
        assert!(
            store.snapshot().is_empty(),
            "a changed network/control_plane_url evicts the prior cluster's endpoints"
        );
        // The cluster is still eligible, so a fresh poller for the new identity
        // is started (it just hasn't fetched anything yet via the stub source).
        assert_eq!(manager.running_cluster_names(), vec!["west"]);
        manager.shutdown();
    }

    #[test]
    fn validate_control_plane_url_rejects_metadata_and_bad_scheme() {
        assert!(validate_control_plane_url("https://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("http://cp.example:15010").is_ok());
        // grpc:// and grpcs:// are normalized to http:// / https:// before
        // validation (F3), so they must be accepted.
        assert!(validate_control_plane_url("grpc://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("grpcs://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("ftp://cp.example").is_err());
        assert!(validate_control_plane_url("https://169.254.169.254/").is_err());
        assert!(validate_control_plane_url("not a url").is_err());
    }

    #[test]
    fn production_control_plane_url_rejects_plaintext() {
        assert!(validate_control_plane_url_with_posture("https://cp.example:15010", true).is_ok());
        assert!(validate_control_plane_url_with_posture("grpcs://cp.example:15010", true).is_ok());
        let err = validate_control_plane_url_with_posture("http://cp.example:15010", true)
            .expect_err("production remote discovery must reject plaintext HTTP");
        assert!(err.contains("production"), "{err}");
        let err = validate_control_plane_url_with_posture("grpc://cp.example:15010", true)
            .expect_err("production remote discovery must reject plaintext gRPC");
        assert!(err.contains("plaintext"), "{err}");
    }

    #[test]
    fn normalize_control_plane_url_translates_grpc_schemes() {
        assert_eq!(
            normalize_control_plane_url("grpc://cp.example:15010"),
            "http://cp.example:15010"
        );
        assert_eq!(
            normalize_control_plane_url("grpcs://cp.example:15010"),
            "https://cp.example:15010"
        );
        // http/https pass through unchanged.
        assert_eq!(
            normalize_control_plane_url("https://cp.example:15010"),
            "https://cp.example:15010"
        );
        assert_eq!(
            normalize_control_plane_url("http://cp.example:15010"),
            "http://cp.example:15010"
        );
    }

    #[test]
    fn tls_selection_respects_grpcs_scheme() {
        let tls_cfg = RemoteDiscoveryTlsConfig {
            tls_urls: Some(DpGrpcTlsConfig::default()),
            plain_urls: None,
        };
        // grpcs normalizes to https — must pick TLS config.
        assert!(
            tls_cfg
                .for_control_plane_url("grpcs://cp.example:15010")
                .is_some()
        );
        // grpc normalizes to http — must pick plain config (None here).
        assert!(
            tls_cfg
                .for_control_plane_url("grpc://cp.example:15010")
                .is_none()
        );
    }

    #[test]
    fn native_source_tls_selection_follows_remote_url_scheme() {
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            max_stale_age: None,
            production_mode: false,
            jwt_secret: None,
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig {
                tls_urls: Some(DpGrpcTlsConfig::default()),
                plain_urls: None,
            },
        };
        let https_ctx = RemoteClusterPollContext {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: "https://cp.remote.example:15010".to_string(),
            credential_ref: None,
            config: config.clone(),
        };
        let http_ctx = RemoteClusterPollContext {
            control_plane_url: "http://cp.remote.example:15010".to_string(),
            ..https_ctx.clone()
        };

        let secret = GrpcJwtSecret::new("secret-padding-for-32-char-min!!".to_string());
        assert!(
            NativeRemoteSource::new(&https_ctx, secret.clone())
                .tls_config
                .is_some()
        );
        assert!(
            NativeRemoteSource::new(&http_ctx, secret)
                .tls_config
                .is_none()
        );
    }

    struct MockSource {
        responses: Mutex<Vec<Result<RemoteClusterEndpoints, String>>>,
    }

    #[async_trait]
    impl RemoteServiceSource for MockSource {
        async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
            let mut responses = self.responses.lock().expect("lock");
            if responses.is_empty() {
                return Err("no more mock responses".to_string());
            }
            responses.remove(0)
        }
    }

    #[tokio::test]
    async fn discovery_loop_installs_then_keeps_last_good_on_failure() {
        let store = RemoteEndpointStore::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let source = Arc::new(MockSource {
            responses: Mutex::new(vec![
                Ok(RemoteClusterEndpoints {
                    workloads: vec![workload(
                        "spiffe://remote.local/ns/default/sa/a",
                        "reviews",
                        "10.2.0.1",
                        None,
                    )],
                    services: vec![],
                }),
                Err("transient".to_string()),
            ]),
        });

        let ctx = RemoteClusterPollContext {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: Some("net2".to_string()),
            control_plane_url: "https://cp.remote.example:15010".to_string(),
            credential_ref: None,
            config: RemoteDiscoveryConfig {
                // Tiny interval so the loop reaches the second (failing) poll
                // quickly; the test shuts it down right after.
                poll_interval: Duration::from_millis(20),
                request_timeout: Duration::from_secs(1),
                max_stale_age: None,
                production_mode: false,
                jwt_secret: None,
                node_id: "dp-1".to_string(),
                namespace: "default".to_string(),
                tls_config: RemoteDiscoveryTlsConfig::default(),
            },
        };

        let task_store = store.clone();
        let task_gen = store.register_cluster("west");
        let handle = tokio::spawn(async move {
            remote_discovery_loop(ctx, source, task_store, shutdown_rx, task_gen).await
        });

        // Wait for the first successful install.
        let mut rx = store.subscribe();
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("install event")
            .expect("revision channel open");
        assert_eq!(
            store
                .snapshot()
                .clusters
                .values()
                .map(|entry| entry.endpoints.workloads.len())
                .sum::<usize>(),
            1
        );

        // The remote workload was tagged with the synthetic locality.
        let snap = store.snapshot();
        let entry = snap.clusters.get("west").expect("west entry");
        assert_eq!(
            entry.endpoints.workloads[0].locality.as_deref(),
            Some("remote-west/net2")
        );

        // Let the second (failing) poll run; the last-good snapshot survives.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            store
                .snapshot()
                .clusters
                .values()
                .map(|entry| entry.endpoints.workloads.len())
                .sum::<usize>(),
            1,
            "a failed poll must keep the last-good endpoints"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// F6: a stale task whose cluster was removed (generation retired) cannot
    /// reinstall endpoints after removal. Simulates the abort→install race:
    /// task fetches successfully but `remove` runs before the task calls
    /// `install`. With the generation guard the install must be a no-op.
    #[test]
    fn install_after_remove_is_blocked_by_generation_check() {
        let store = RemoteEndpointStore::new();
        // Register "west" and grab its generation (simulates start_cluster).
        let stale_gen = store.register_cluster("west");
        // Now remove the cluster (simulates trust withdrawal / reconcile remove).
        store.remove("west");
        // The stale task completes its fetch and tries to install.
        let entry = RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: None,
            credential_ref: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/stale",
                    "reviews",
                    "10.2.0.99",
                    None,
                )],
                services: vec![],
            },
            fetched_at: Arc::new(AtomicU64::new(1)),
        };
        // The install must be silently dropped — the generation slot is gone.
        store.install(entry, stale_gen);
        assert!(
            store.snapshot().is_empty(),
            "install with retired generation must not reinstate removed cluster"
        );
        assert!(
            !store.has_first_success(),
            "first_ready must not be set by a generation-blocked install"
        );
    }

    /// F2: no-op polls (identical endpoints) must not bump the revision or
    /// wake the slice-apply task.
    #[test]
    fn install_with_identical_endpoints_does_not_bump_revision() {
        let store = RemoteEndpointStore::new();
        let mut rx = store.subscribe();
        let endpoints = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/a",
                "reviews",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![],
        };
        let entry = || RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: None,
            credential_ref: None,
            endpoints: endpoints.clone(),
            fetched_at: Arc::new(AtomicU64::new(1)),
        };
        // First install: should bump the revision.
        store.install_for_test(entry());
        assert!(
            rx.has_changed().unwrap(),
            "first install must bump revision"
        );
        rx.mark_unchanged();
        // Re-register to match the generation tracking (simulates the same
        // task running its next poll with identical results).
        let same_gen = store.register_cluster("west");
        store.install(entry(), same_gen);
        assert!(
            !rx.has_changed().unwrap(),
            "no-op poll with identical endpoints must not bump revision"
        );
    }

    /// Finding 1: a no-op poll (identical endpoints) with a NEWER fetch
    /// timestamp must refresh the stored `fetched_at_unix_seconds` so the admin
    /// endpoint's `age_seconds` tracks the last successful POLL — not the last
    /// endpoint CHANGE — WITHOUT waking the apply task. A healthy-but-stable
    /// remote cluster otherwise looks stale to operator alerting.
    #[test]
    fn no_op_poll_refreshes_fetch_timestamp_without_bumping_revision() {
        let store = RemoteEndpointStore::new();
        let mut rx = store.subscribe();
        let endpoints = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/a",
                "reviews",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![],
        };
        let entry_at = |fetched_at: u64| RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: None,
            credential_ref: None,
            endpoints: endpoints.clone(),
            fetched_at: Arc::new(AtomicU64::new(fetched_at)),
        };

        // First poll at t=100 installs and bumps the revision.
        let gen1 = store.register_cluster("west");
        assert_eq!(
            store.install(entry_at(100), gen1),
            RemoteInstallOutcome::Installed,
            "first install changes endpoints → Installed"
        );
        assert!(rx.has_changed().unwrap(), "first install bumps revision");
        rx.mark_unchanged();
        assert_eq!(
            store
                .snapshot()
                .clusters
                .get("west")
                .map(|e| e.fetched_at_unix_seconds()),
            Some(100)
        );

        // Second poll at t=160: SAME endpoints, NEWER timestamp. Must refresh
        // the stored timestamp but NOT wake the apply task and NOT report a
        // change. Still a live (deduped) poll, not a retired no-op.
        let gen2 = store.register_cluster("west");
        assert_eq!(
            store.install(entry_at(160), gen2),
            RemoteInstallOutcome::Deduped,
            "no-op poll (same endpoints) is Deduped even though it refreshed the timestamp"
        );
        assert!(
            !rx.has_changed().unwrap(),
            "timestamp-only refresh must not bump revision / wake apply"
        );
        assert_eq!(
            store
                .snapshot()
                .clusters
                .get("west")
                .map(|e| e.fetched_at_unix_seconds()),
            Some(160),
            "age must track the latest successful poll, not the last endpoint change"
        );
    }

    /// Finding 2 (perf): a no-op poll must refresh the fetch timestamp WITHOUT
    /// deep-cloning the snapshot or the endpoint payload. We prove it two ways:
    /// (1) the published `inner` snapshot `Arc` is byte-for-byte the SAME pointer
    /// before and after the no-op refresh (a deep clone would `ArcSwap::store` a
    /// new snapshot, changing the pointer); (2) an `Arc` handle to the entry's
    /// shared `fetched_at` atomic captured BEFORE the poll observes the NEW value
    /// after it (the in-place store targets the live entry, not a clone). With
    /// the previous in-`rcu` refresh both would fail (new snapshot pointer; the
    /// old atomic handle, copied into the clone, would be stale).
    #[test]
    fn no_op_poll_refreshes_timestamp_in_place_without_cloning_snapshot() {
        let store = RemoteEndpointStore::new();
        let endpoints = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/a",
                "reviews",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![],
        };
        let entry_at = |fetched_at: u64| {
            RemoteClusterEntry::new(
                "west".to_string(),
                td("remote.local"),
                None,
                None,
                None,
                endpoints.clone(),
                fetched_at,
            )
        };

        let gen1 = store.register_cluster("west");
        assert!(store.install(entry_at(100), gen1).installed());

        // Capture the live snapshot Arc and a handle to the shared atomic.
        let snapshot_before = store.snapshot();
        let shared_atomic = Arc::clone(&snapshot_before.clusters.get("west").unwrap().fetched_at);
        assert_eq!(shared_atomic.load(Ordering::Relaxed), 100);

        // No-op poll: identical endpoints, newer timestamp.
        let gen2 = store.register_cluster("west");
        assert_eq!(
            store.install(entry_at(160), gen2),
            RemoteInstallOutcome::Deduped
        );

        // (1) The published snapshot Arc is unchanged → no clone+swap happened.
        let snapshot_after = store.snapshot();
        assert!(
            Arc::ptr_eq(&snapshot_before, &snapshot_after),
            "a no-op timestamp refresh must NOT swap a freshly-cloned snapshot"
        );
        // (2) The pre-captured shared atomic observes the new value in place.
        assert_eq!(
            shared_atomic.load(Ordering::Relaxed),
            160,
            "the shared fetched_at atomic is refreshed in place (no payload clone)"
        );
    }

    /// Finding 1 (fail-closed): the timestamp refresh on a no-op poll must
    /// respect the generation guard. A retired cluster (removed / trust
    /// withdrawn) whose in-flight task lands a no-op poll must NOT have its age
    /// refreshed or its endpoints reinstated — the cluster is gone.
    #[test]
    fn no_op_refresh_is_blocked_for_retired_cluster() {
        let store = RemoteEndpointStore::new();
        let endpoints = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/a",
                "reviews",
                "10.2.0.1",
                None,
            )],
            services: vec![],
        };
        let entry_at = |fetched_at: u64| RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: None,
            credential_ref: None,
            endpoints: endpoints.clone(),
            fetched_at: Arc::new(AtomicU64::new(fetched_at)),
        };
        // Install once, then retire the cluster.
        let stale_gen = store.register_cluster("west");
        assert!(store.install(entry_at(100), stale_gen).installed());
        store.remove("west");
        assert!(store.snapshot().is_empty(), "remove clears the cluster");
        // The stale task's next (no-op) poll must be dropped, not refresh a
        // resurrected entry, and must report Retired (NOT Deduped) so the
        // success metric is not bumped for a removed cluster.
        assert_eq!(
            store.install(entry_at(160), stale_gen),
            RemoteInstallOutcome::Retired,
            "a no-op poll on a retired generation must report Retired, not Deduped"
        );
        assert!(
            store.snapshot().is_empty(),
            "retired cluster must not be reinstated by a no-op timestamp refresh"
        );
    }

    /// codex finding (removal race): a poll task's success-metric record must be
    /// dropped when its cluster's generation has been retired — so a poll that
    /// completed `install` as live, but whose reconcile concurrently removed the
    /// cluster and cleared the metric series, cannot RESURRECT the
    /// success / last-success / endpoint-age series on unauthenticated
    /// `/metrics`. The store re-checks the generation under the metrics ordering
    /// lock before writing.
    #[test]
    fn success_metric_record_is_blocked_for_retired_cluster() {
        // Unique cluster/trust-domain so the shared global metric maps don't
        // collide with other tests rendering the same output.
        let suffix = format!("{}-{}", std::process::id(), line!());
        let cluster = format!("recordrace-{suffix}");
        let trust_domain = format!("td-{suffix}.example");

        let store = RemoteEndpointStore::new();
        // Register the cluster, then retire it (reconcile remove + metric clear).
        let stale_gen = store.register_cluster(&cluster);
        store.remove_and_clear_metrics(&cluster, &trust_domain);

        // The stale poll task — which observed a live generation inside
        // `install` before the removal landed — now tries to record success with
        // its (now retired) generation. The store must drop it.
        store.record_remote_discovery_success_if_live(&cluster, &trust_domain, 1234, stale_gen);
        let mut after_retired = String::new();
        crate::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics(
            &mut after_retired,
        );
        assert!(
            !after_retired.contains(&format!("cluster=\"{cluster}\"")),
            "a retired-generation success record must NOT resurrect the metric series: {after_retired}"
        );

        // Sanity: a record on a freshly-registered (live) generation DOES write,
        // proving the guard rejects only the retired case (not all records).
        let live_gen = store.register_cluster(&cluster);
        store.record_remote_discovery_success_if_live(&cluster, &trust_domain, 5678, live_gen);
        let mut after_live = String::new();
        crate::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics(
            &mut after_live,
        );
        assert!(
            after_live.contains(&format!(
                "ferrum_mesh_remote_discovery_last_success_timestamp_seconds{{cluster=\"{cluster}\",trust_domain=\"{trust_domain}\"}} 5678"
            )),
            "a live-generation success record must write the last-success gauge: {after_live}"
        );

        // Clean up the global metric maps so this test leaves no residue.
        crate::plugins::mesh::prometheus_helpers::clear_mesh_remote_discovery_metrics(
            &cluster,
            &trust_domain,
        );
    }

    #[test]
    fn expire_stale_endpoints_clears_cache_and_metrics_without_retiring_generation() {
        let suffix = format!("{}-{}", std::process::id(), line!());
        let cluster = format!("stale-endpoints-{suffix}");
        let trust_domain = format!("stale-{suffix}.example");
        let trust = td(&trust_domain);

        let store = RemoteEndpointStore::new();
        let mut rx = store.subscribe();
        let task_generation = store.register_cluster(&cluster);
        let endpoints = RemoteClusterEndpoints {
            workloads: vec![workload(
                &format!("spiffe://{trust_domain}/ns/default/sa/a"),
                "reviews",
                "10.2.0.1",
                None,
            )],
            services: vec![],
        };
        let entry_at = |fetched_at: u64| {
            RemoteClusterEntry::new(
                cluster.clone(),
                trust.clone(),
                None,
                Some("https://cp.remote.example:15010".to_string()),
                None,
                endpoints.clone(),
                fetched_at,
            )
        };

        assert!(
            store.install(entry_at(100), task_generation).installed(),
            "precondition: first poll installs endpoints"
        );
        store.record_remote_discovery_success_if_live(
            &cluster,
            &trust_domain,
            100,
            task_generation,
        );
        rx.mark_unchanged();

        assert!(
            !store.expire_stale_endpoints_and_clear_metrics(
                &cluster,
                &trust_domain,
                120,
                Duration::from_secs(20),
            ),
            "age equal to max stale remains usable"
        );
        assert!(store.snapshot().clusters.contains_key(&cluster));

        assert!(store.expire_stale_endpoints_and_clear_metrics(
            &cluster,
            &trust_domain,
            121,
            Duration::from_secs(20),
        ));
        assert!(
            !store.snapshot().clusters.contains_key(&cluster),
            "expired endpoints are withdrawn from the active snapshot"
        );
        assert!(
            rx.has_changed().unwrap(),
            "expiration wakes the apply loop so upstream targets are recomputed"
        );
        let mut rendered = String::new();
        crate::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics(&mut rendered);
        let cluster_label = format!("cluster=\"{cluster}\"");
        assert!(
            !rendered.lines().any(|line| line
                .starts_with("ferrum_mesh_remote_discovery_last_success_timestamp_seconds")
                && line.contains(&cluster_label)),
            "expiration withdraws the last-success freshness gauge for stale endpoints: {rendered}"
        );
        assert!(
            !rendered.lines().any(|line| line
                .starts_with("ferrum_mesh_remote_discovery_endpoint_age_seconds")
                && line.contains(&cluster_label)),
            "expiration withdraws the derived endpoint-age gauge for stale endpoints: {rendered}"
        );
        assert!(
            rendered.lines().any(|line| line
                .starts_with("ferrum_mesh_remote_discovery_poll_successes_total")
                && line.contains(&cluster_label)),
            "staleness expiry preserves the monotonic poll-success counter (no counter reset): {rendered}"
        );

        assert!(
            store.install(entry_at(130), task_generation).installed(),
            "staleness expiration must not retire the poll generation; a later successful poll can reinstall"
        );
        assert!(store.snapshot().clusters.contains_key(&cluster));
        crate::plugins::mesh::prometheus_helpers::clear_mesh_remote_discovery_metrics(
            &cluster,
            &trust_domain,
        );
    }

    // ── Real two-CP gRPC round trip ────────────────────────────────────────
    //
    // The tests above stub `RemoteServiceSource::fetch` with `MockSource`. The
    // ones below stand up an in-process `MeshConfigSync` gRPC server on a
    // loopback port and point the *production* dialer
    // ([`NativeRemoteSource`] -> `fetch_remote_slice_endpoints`) at it, so the
    // real wire path is exercised end to end: channel dial, DP-JWT mint +
    // server-side verification (the same `verify_grpc_jwt_metadata` the real
    // `MeshGrpcServer` uses), `MeshSubscribe` streaming, heartbeat skipping,
    // slice-JSON decode, and workload/service extraction. This is the
    // in-process stand-in for a two-control-plane round trip; a true
    // cross-cluster deployment under network churn/loss stays an infra-level
    // verification step.

    use crate::grpc::auth::{
        GrpcAudiencePolicy, remote_discovery_audience, verify_grpc_jwt_metadata_with_audience,
    };
    use crate::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
    use crate::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
    use crate::modes::mesh::slice::MeshSlice;
    use chrono::Utc;
    use std::pin::Pin;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    /// Cluster name every `remote_ctx` poll context uses, and therefore the
    /// identity the stub CP expects in the discovery token's `aud`.
    const STUB_CLUSTER_NAME: &str = "west";

    /// What the stub remote CP emits on a `MeshSubscribe`.
    #[derive(Clone, Copy)]
    enum StubBehavior {
        /// A single non-heartbeat slice, then the stream ends.
        SliceOnly,
        /// A heartbeat first, then the slice: the dialer must skip the
        /// heartbeat and return the slice's endpoints.
        HeartbeatThenSlice,
        /// Only a heartbeat, then the stream closes without ever delivering a
        /// slice: the dialer must surface a "closed before slice" error.
        HeartbeatThenClose,
        /// Never emit anything: the dialer must hit its request timeout.
        Stall,
        /// A slice whose envelope `version` is desynced from the embedded
        /// slice version (issue #2457).
        SliceWithEnvelopeVersion(&'static str),
        /// A slice whose response `ferrum_version` is overridden; `""` models a
        /// control plane that sends none at all (issue #2457).
        SliceWithFerrumVersion(&'static str),
    }

    #[derive(Clone)]
    struct StubRemoteCp {
        slice: Arc<MeshSlice>,
        /// When `Some`, the stub verifies the bearer JWT exactly as the real
        /// CP does, proving the minted DP token is acceptable on the wire.
        verify_secret: Option<GrpcJwtSecret>,
        behavior: StubBehavior,
    }

    #[tonic::async_trait]
    impl MeshConfigSync for StubRemoteCp {
        type MeshSubscribeStream =
            Pin<Box<dyn tokio_stream::Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

        async fn mesh_subscribe(
            &self,
            request: Request<MeshSubscribeRequest>,
        ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
            if let Some(secret) = &self.verify_secret {
                // Mirror the real `MeshGrpcServer` policy selection: a
                // cross-cluster poll must present this cluster's discovery
                // audience; anything else must not carry a reserved one.
                let expected = remote_discovery_audience(STUB_CLUSTER_NAME);
                let policy = if request.get_ref().remote_discovery {
                    GrpcAudiencePolicy::Required(&expected)
                } else {
                    GrpcAudiencePolicy::ReservedForbidden
                };
                verify_grpc_jwt_metadata_with_audience(
                    request.metadata(),
                    secret.as_str(),
                    secret.issuer(),
                    policy,
                )
                .map_err(|(status, _)| status)?;
            }

            let slice_update = MeshConfigUpdate {
                version: self.slice.version.clone(),
                timestamp: Utc::now().timestamp(),
                mesh_slice_json: serde_json::to_string(self.slice.as_ref())
                    .map_err(|e| Status::internal(format!("serialize slice: {e}")))?,
                ferrum_version: crate::FERRUM_VERSION.to_string(),
                heartbeat: false,
            };
            let heartbeat = MeshConfigUpdate {
                version: self.slice.version.clone(),
                timestamp: Utc::now().timestamp(),
                mesh_slice_json: String::new(),
                ferrum_version: crate::FERRUM_VERSION.to_string(),
                heartbeat: true,
            };

            let items: Vec<Result<MeshConfigUpdate, Status>> = match self.behavior {
                StubBehavior::SliceOnly => vec![Ok(slice_update)],
                StubBehavior::HeartbeatThenSlice => vec![Ok(heartbeat), Ok(slice_update)],
                StubBehavior::HeartbeatThenClose => vec![Ok(heartbeat)],
                StubBehavior::SliceWithEnvelopeVersion(version) => {
                    let update = MeshConfigUpdate {
                        version: version.to_string(),
                        ..slice_update
                    };
                    vec![Ok(update)]
                }
                StubBehavior::SliceWithFerrumVersion(version) => {
                    let update = MeshConfigUpdate {
                        ferrum_version: version.to_string(),
                        ..slice_update
                    };
                    vec![Ok(update)]
                }
                StubBehavior::Stall => {
                    let stream: Self::MeshSubscribeStream = Box::pin(tokio_stream::pending());
                    return Ok(Response::new(stream));
                }
            };
            let stream: Self::MeshSubscribeStream = Box::pin(tokio_stream::iter(items));
            Ok(Response::new(stream))
        }
    }

    struct StubCpHandle {
        url: String,
        shutdown_tx: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    }

    impl StubCpHandle {
        async fn shutdown(mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
        }
    }

    async fn start_stub_cp(stub: StubRemoteCp) -> StubCpHandle {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub CP");
        let addr = listener.local_addr().expect("stub CP local addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let incoming = TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(MeshConfigSyncServer::new(stub))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        StubCpHandle {
            url: format!("http://{addr}"),
            shutdown_tx: Some(shutdown_tx),
            task,
        }
    }

    /// A remote slice carrying two `reviews` workloads and one `reviews`
    /// service, so the dialer has real endpoints to extract.
    ///
    /// `node_id` / `namespace` echo the subscription [`remote_ctx`] builds: a
    /// real CP derives the returned slice from the request, and the dialer now
    /// rejects any response that is not bound to it (issue #2457).
    fn remote_slice_with_endpoints() -> MeshSlice {
        MeshSlice {
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            version: "v-remote-1".to_string(),
            workloads: vec![
                workload(
                    "spiffe://remote.local/ns/default/sa/reviews-1",
                    "reviews",
                    "10.2.0.1",
                    None,
                ),
                workload(
                    "spiffe://remote.local/ns/default/sa/reviews-2",
                    "reviews",
                    "10.2.0.2",
                    None,
                ),
            ],
            services: vec![service(
                "reviews",
                &["spiffe://remote.local/ns/default/sa/reviews-1"],
            )],
            ..MeshSlice::default()
        }
    }

    fn remote_ctx(
        url: &str,
        jwt_secret: Option<GrpcJwtSecret>,
        request_timeout: Duration,
    ) -> RemoteClusterPollContext {
        RemoteClusterPollContext {
            cluster_name: STUB_CLUSTER_NAME.to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: url.to_string(),
            credential_ref: None,
            config: RemoteDiscoveryConfig {
                poll_interval: Duration::from_millis(20),
                request_timeout,
                max_stale_age: None,
                production_mode: false,
                jwt_secret,
                node_id: "dp-1".to_string(),
                namespace: "default".to_string(),
                tls_config: RemoteDiscoveryTlsConfig::default(),
            },
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_round_trip_returns_remote_endpoints() {
        let secret = GrpcJwtSecret::new("multicluster-roundtrip-secret-0000".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceOnly,
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let endpoints = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect("real gRPC round trip returns the remote slice's endpoints");

        assert_eq!(endpoints.workloads.len(), 2);
        assert_eq!(endpoints.services.len(), 1);
        assert_eq!(endpoints.services[0].name, "reviews");
        assert!(
            endpoints
                .workloads
                .iter()
                .any(|w| w.addresses == vec!["10.2.0.1".to_string()]),
            "decoded workloads must carry the remote addresses"
        );

        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_skips_heartbeat_and_returns_first_slice() {
        let secret = GrpcJwtSecret::new("multicluster-heartbeat-secret-000".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::HeartbeatThenSlice,
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let endpoints = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect("the heartbeat is skipped and the slice is returned");
        assert_eq!(endpoints.workloads.len(), 2);

        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_rejects_mismatched_jwt() {
        let server_secret = GrpcJwtSecret::new("server-side-secret-aaaaaaaaaaaa".to_string());
        let client_secret = GrpcJwtSecret::new("client-side-secret-bbbbbbbbbbbb".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(server_secret),
            behavior: StubBehavior::SliceOnly,
        })
        .await;

        let ctx = remote_ctx(
            &handle.url,
            Some(client_secret.clone()),
            Duration::from_secs(5),
        );
        let err = NativeRemoteSource::new(&ctx, client_secret)
            .fetch()
            .await
            .expect_err("a token signed with the wrong secret must be rejected by the remote CP");
        assert!(
            err.contains("MeshSubscribe failed"),
            "expected a remote-rejection error, got: {err}"
        );

        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_errors_when_stream_closes_without_slice() {
        let secret = GrpcJwtSecret::new("multicluster-noslice-secret-00000".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::HeartbeatThenClose,
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let err = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect_err("a stream that closes after only a heartbeat must error");
        assert!(
            err.contains("closed before delivering a slice"),
            "expected a stream-closed error, got: {err}"
        );

        handle.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_times_out_when_remote_withholds_slice() {
        let secret = GrpcJwtSecret::new("multicluster-timeout-secret-00000".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::Stall,
        })
        .await;

        let ctx = remote_ctx(
            &handle.url,
            Some(secret.clone()),
            Duration::from_millis(300),
        );
        let err = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect_err("a remote that never sends a slice must time out");
        assert!(
            err.contains("timed out"),
            "expected a timeout error, got: {err}"
        );

        handle.shutdown().await;
    }

    /// Issue #2457: a remote CP answering with a slice scoped to a DIFFERENT
    /// node than the subscription is refused before its endpoints are imported.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_rejects_wrong_node_response() {
        let secret = GrpcJwtSecret::new("multicluster-wrongnode-secret-000".to_string());
        let slice = MeshSlice {
            node_id: "some-other-dp".to_string(),
            ..remote_slice_with_endpoints()
        };
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(slice),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceOnly,
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let err = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect_err("a slice bound to another node must not be imported");
        assert!(
            err.contains("node_id_mismatch"),
            "expected a node-binding rejection, got: {err}"
        );

        handle.shutdown().await;
    }

    /// Issue #2457: a remote CP answering for another namespace is refused, so
    /// wrong-tenant endpoints never land under this cluster's entry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_rejects_wrong_namespace_response() {
        let secret = GrpcJwtSecret::new("multicluster-wrongns-secret-00000".to_string());
        let slice = MeshSlice {
            namespace: "beta".to_string(),
            ..remote_slice_with_endpoints()
        };
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(slice),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceOnly,
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let err = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect_err("a slice for another namespace must not be imported");
        assert!(
            err.contains("namespace_mismatch"),
            "expected a namespace-binding rejection, got: {err}"
        );

        handle.shutdown().await;
    }

    /// Issue #2457: the envelope version must equal the embedded slice version.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_rejects_envelope_version_mismatch() {
        let secret = GrpcJwtSecret::new("multicluster-envversion-secret-00".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceWithEnvelopeVersion("v-desynced"),
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let err = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect_err("a desynced version envelope must not be imported");
        assert!(
            err.contains("envelope_version_mismatch"),
            "expected an envelope-version rejection, got: {err}"
        );

        handle.shutdown().await;
    }

    /// Issue #2457: remote discovery now requires a present `ferrum_version`,
    /// matching the local native client's long-standing gate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_rejects_missing_ferrum_version() {
        let secret = GrpcJwtSecret::new("multicluster-noversion-secret-000".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceWithFerrumVersion(""),
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let err = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect_err("an unversioned remote response must not be imported");
        assert!(
            err.contains("missing_ferrum_version"),
            "expected a missing-version rejection, got: {err}"
        );

        handle.shutdown().await;
    }

    /// Issue #2457: an incompatible CP version is refused with the same
    /// major/minor contract the local native consumer applies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_source_rejects_incompatible_ferrum_version() {
        let secret = GrpcJwtSecret::new("multicluster-badversion-secret-00".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceWithFerrumVersion("999.999.0"),
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret.clone()), Duration::from_secs(5));
        let err = NativeRemoteSource::new(&ctx, secret)
            .fetch()
            .await
            .expect_err("an incompatible remote CP must not be imported from");
        assert!(
            err.contains("incompatible_ferrum_version"),
            "expected an incompatible-version rejection, got: {err}"
        );

        handle.shutdown().await;
    }

    /// Issue #2457: a rejected response leaves the cluster's last-good
    /// endpoints in place — the poll fails and backs off exactly like any other
    /// transport failure, rather than clobbering the store with foreign
    /// endpoints or emptying it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovery_loop_keeps_last_good_endpoints_when_response_is_unbound() {
        let secret = GrpcJwtSecret::new("multicluster-lastgood-secret-0000".to_string());
        let slice = MeshSlice {
            node_id: "some-other-dp".to_string(),
            ..remote_slice_with_endpoints()
        };
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(slice),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceOnly,
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret), Duration::from_secs(5));
        let source = native_source_factory(&ctx);

        let store = RemoteEndpointStore::new();
        let task_gen = store.register_cluster("west");
        // Seed a last-good snapshot the way a previous successful poll would.
        let last_good = RemoteClusterEntry::new(
            "west".to_string(),
            td("remote.local"),
            None,
            Some(ctx.control_plane_url.clone()),
            None,
            RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/reviews-1",
                    "reviews",
                    "10.2.0.1",
                    None,
                )],
                services: vec![],
            },
            1_700_000_000,
        );
        store.install(last_good, task_gen);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task_store = store.clone();
        let loop_ctx = ctx;
        let loop_handle = tokio::spawn(async move {
            remote_discovery_loop(loop_ctx, source, task_store, shutdown_rx, task_gen).await
        });

        // The first poll runs immediately; give it room to complete and be
        // rejected before inspecting the store.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let snap = store.snapshot();
        let entry = snap.clusters.get("west").expect("west entry retained");
        assert_eq!(
            entry.endpoints.workloads.len(),
            1,
            "a rejected response must not replace last-good endpoints"
        );
        assert_eq!(
            entry.endpoints.workloads[0].addresses,
            vec!["10.2.0.1".to_string()],
            "the retained endpoints must be the last-good ones"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
        handle.shutdown().await;
    }

    /// End-to-end: the discovery loop, driven by the production
    /// [`native_source_factory`] dialer against a live (loopback) CP, installs
    /// the remote endpoints into the store tagged with the synthetic remote
    /// locality. This is the closest in-process analogue to a two-CP round
    /// trip installing remote endpoints.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovery_loop_installs_remote_endpoints_via_real_grpc() {
        let secret = GrpcJwtSecret::new("multicluster-loop-secret-0000000".to_string());
        let handle = start_stub_cp(StubRemoteCp {
            slice: Arc::new(remote_slice_with_endpoints()),
            verify_secret: Some(secret.clone()),
            behavior: StubBehavior::SliceOnly,
        })
        .await;

        let ctx = remote_ctx(&handle.url, Some(secret), Duration::from_secs(5));
        let source = native_source_factory(&ctx);

        let store = RemoteEndpointStore::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task_store = store.clone();
        let task_gen = store.register_cluster("west");
        let loop_handle = tokio::spawn(async move {
            remote_discovery_loop(ctx, source, task_store, shutdown_rx, task_gen).await
        });

        let mut rx = store.subscribe();
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("remote install event within timeout")
            .expect("revision channel open");

        let snap = store.snapshot();
        let entry = snap.clusters.get("west").expect("west entry installed");
        assert_eq!(entry.endpoints.workloads.len(), 2);
        // Remote workloads carry the synthetic remote locality so the
        // priority-tier LB tiers them below local endpoints.
        assert_eq!(
            entry.endpoints.workloads[0].locality.as_deref(),
            Some("remote-west")
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
        handle.shutdown().await;
    }
}
