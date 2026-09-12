use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::audit::{self, AuditActor, AuditEvent};
use crate::admin::jwt_auth::AdminRole;
use crate::config::db_backend::{
    BatchConfigWriteMode, DatabaseBackend, MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE,
    PROXY_ROUTE_CONFLICT_ERROR, PaginatedResult, is_mtls_dns_admission_unavailable,
    is_mtls_dns_identity_conflict, mark_mtls_dns_admission_unavailable, mtls_dns_identity_conflict,
    tcp_connection_throttle_attachment_conflict, validate_api_spec_proxy_plugin_association,
    validate_api_spec_restore_inputs,
};
use crate::config::db_loader::{is_proxy_plugin_association_load_error, is_row_decode_rejection};
use crate::config::gateway_trust::GatewayTrustBundleRecord;
use crate::config::runtime_config_apply::LiveApplyMode;
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream, validate_resource_id,
};
use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;

pub(crate) type DbResult<T> = Result<T, anyhow::Error>;

pub(crate) struct ValidationCtx<'a> {
    pub reserved_ports: &'a HashSet<u16>,
    pub stream_bind_address: &'a str,
    pub mode: &'a str,
    /// Backend egress policy, so per-resource admin writes screen literal-IP
    /// backend targets the same way the file/db/restore loaders do.
    pub backend_allow_ips: &'a crate::config::BackendEgressPolicy,
}

impl<'a> ValidationCtx<'a> {
    pub(crate) fn from_state(state: &'a AdminState) -> Self {
        Self {
            reserved_ports: &state.reserved_ports,
            stream_bind_address: &state.stream_proxy_bind_address,
            mode: &state.mode,
            backend_allow_ips: &state.backend_allow_ips,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum WriteAction<'a> {
    Create,
    Update { id: &'a str },
}

enum LateResourceWrite<'a> {
    Create,
    Update { id: &'a str },
    Delete { id: &'a str },
}

pub(crate) enum InterveningWriteRecovery {
    Compensate,
    KeepCurrent,
}

pub(crate) struct ApiSpecDeleteSnapshot {
    spec: crate::config::types::ApiSpec,
    upstream: Option<Upstream>,
    plugins: Vec<PluginConfig>,
    additional_upstreams: Vec<Upstream>,
    additional_plugins: Vec<PluginConfig>,
}

#[derive(Debug)]
struct ApiSpecRestoreSnapshotValidation(String);

impl std::fmt::Display for ApiSpecRestoreSnapshotValidation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ApiSpecRestoreSnapshotValidation {}

fn api_spec_restore_snapshot_validation(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ApiSpecRestoreSnapshotValidation(message.into()))
}

#[derive(Clone, Copy)]
struct LateDeleteSnapshots<'a> {
    config: &'a GatewayConfig,
    api_spec: Option<&'a ApiSpecDeleteSnapshot>,
}

struct LateResourceRecovery<'a, R> {
    written: Option<&'a R>,
    previous: Option<&'a R>,
    delete_snapshots: Option<LateDeleteSnapshots<'a>>,
}

struct OwnedLateDeleteRecovery<R> {
    previous: R,
    config: Option<GatewayConfig>,
    api_spec: Option<ApiSpecDeleteSnapshot>,
}

pub(crate) enum AfterValidateError {
    BadRequest(Vec<String>),
    Conflict(Vec<String>),
    Db(anyhow::Error),
    Response(Box<Response<Full<Bytes>>>),
}

/// Validation outcomes for resource-specific checks and generic field validation.
pub(crate) enum ValidationError {
    Fields(Vec<String>),
    Message(String),
}

/// A write-preparation failure whose origin determines the HTTP status.
pub(crate) enum PrepareWriteError {
    InvalidRequest(String),
    Internal(String),
}

impl PrepareWriteError {
    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::InvalidRequest(message) | Self::Internal(message) => message,
        }
    }
}

pub(crate) enum BatchPreparationError {
    Validation(Vec<String>),
    Internal(String),
}

const NAMESPACE_CONFIG_ADMISSION_LOCK_SHARDS: usize = 64;
static NAMESPACE_CONFIG_ADMISSION_LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
const CONFIG_ADMISSION_LEASE_DURATION: Duration = Duration::from_secs(120);
const CONFIG_ADMISSION_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(30);
const CONFIG_ADMISSION_LEASE_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Budget for a detached, best-effort lease release.
///
/// The release runs in a task nothing awaits, so it can afford to ride out the
/// same congestion the renewer rides out. One retry interval was not enough:
/// under the datastore stall this machinery exists to survive, a one-second
/// release almost always times out and leaves the namespace's lease held for
/// its full remaining TTL, which serializes every later writer behind an owner
/// that is already gone.
const CONFIG_ADMISSION_LEASE_RELEASE_TIMEOUT: Duration = CONFIG_ADMISSION_LEASE_RENEW_INTERVAL;

/// Longest a caller waits for a contended namespace admission lease before the
/// request is refused as retryable congestion.
///
/// An incumbent lease is at most one lease duration from expiry, so a healthy
/// datastore always frees the row inside this window. Waiting longer does not
/// help: it only adds another stalled writer to a pileup that is already the
/// reason nothing is completing, which is exactly the self-amplifying retry
/// storm issue #4146 describes. Beyond this bound the caller gets the standard
/// retryable admission-unavailable failure (503) instead.
const CONFIG_ADMISSION_LEASE_ACQUIRE_MAX_WAIT: Duration = CONFIG_ADMISSION_LEASE_DURATION;

/// Timing envelope for one admission lease renewer.
///
/// Production uses [`Self::PRODUCTION`]. Tests scale the same ratios down so
/// the stall and expiry boundaries can be crossed in milliseconds instead of
/// minutes; every derived bound below is computed from these three fields, so
/// a scaled envelope exercises the identical arithmetic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LeaseRenewalTiming {
    pub(crate) lease_duration: Duration,
    pub(crate) renew_interval: Duration,
    pub(crate) retry_interval: Duration,
}

impl LeaseRenewalTiming {
    pub(crate) const PRODUCTION: Self = Self {
        lease_duration: CONFIG_ADMISSION_LEASE_DURATION,
        renew_interval: CONFIG_ADMISSION_LEASE_RENEW_INTERVAL,
        retry_interval: CONFIG_ADMISSION_LEASE_RETRY_INTERVAL,
    };

    /// How long a single renewal round trip may block before it is abandoned
    /// and re-issued.
    ///
    /// Capped at one renew interval. The cap is what makes
    /// retry-before-invalidate possible at all: without it a datastore stall is
    /// absorbed by ONE `await` that returns only after the lease has already
    /// expired on the datastore clock — the observed failure. With it, a
    /// renewal due at `T`, whose window closes at
    /// `T + (lease_duration - renew_interval)` (production: `T + 90s`, because
    /// the previous deadline was anchored one renew interval ago), gets three
    /// bounded attempts plus retry gaps inside that window instead of one
    /// unbounded attempt that spans it.
    fn attempt_budget(self) -> Duration {
        self.renew_interval
    }
}

/// Terminal state of one admission lease renewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseRenewalOutcome {
    /// The guard was dropped, or the stop signal fired, while the lease was
    /// still held.
    Stopped,
    /// Ownership provably changed hands: the row is held by another owner, or
    /// came back at a generation this guard never acquired.
    Lost,
    /// The lease window closed without a successful renewal or reclaim. Fails
    /// closed — the guard invalidates rather than assume it still holds a row
    /// it could not prove.
    Expired,
}

/// What one renewer did over its lifetime. Returned by the renew task so tests
/// can assert on the path taken, not only on the terminal state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LeaseRenewalCounters {
    /// Conditional renewal `UPDATE`s that matched the row.
    pub(crate) renewals: u32,
    /// Attempts abandoned on a datastore error or the per-attempt timeout and
    /// re-issued inside the same window.
    pub(crate) retries: u32,
    /// Windows recovered by a generation-preserving re-acquisition after the
    /// datastore refused the conditional renewal.
    pub(crate) reclaims: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LeaseRenewalReport {
    // Read by the external lease-renewal tests through
    // `run_namespace_config_admission_renewal_for_test`; the binary target
    // never inspects the report, so both fields are dead there.
    #[allow(dead_code)]
    pub(crate) outcome: LeaseRenewalOutcome,
    #[allow(dead_code)]
    pub(crate) counters: LeaseRenewalCounters,
}

/// Shared, lock-free view of one lease's local deadline.
struct LeaseRenewalState {
    valid: Arc<AtomicBool>,
    valid_until_millis: Arc<AtomicU64>,
    lease_state_tx: tokio::sync::watch::Sender<u64>,
    lease_started_at: Instant,
    lease_duration_millis: u64,
}

impl LeaseRenewalState {
    /// Publish a new local deadline derived from `anchor`.
    ///
    /// `anchor` is the instant the successful datastore write was **issued**,
    /// never the instant it returned. The datastore stamps
    /// `expires_at = <datastore now> + lease_duration` when the statement
    /// actually executes, which is at or after `anchor`, so the local deadline
    /// is always at or before the true one. That one-sided rounding is the
    /// safety property this whole module rests on: the guard may believe it
    /// holds the lease for LESS time than it really has, never more.
    fn publish_deadline(&self, anchor: Instant) -> Instant {
        let elapsed = anchor.duration_since(self.lease_started_at);
        let elapsed_millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let valid_until_millis = elapsed_millis.saturating_add(self.lease_duration_millis);
        self.valid_until_millis
            .store(valid_until_millis, Ordering::Release);
        let _ = self.lease_state_tx.send(valid_until_millis);
        anchor + Duration::from_millis(self.lease_duration_millis)
    }

    /// Fail closed. Both the flag and the deadline are cleared so every
    /// observer — `ensure_held` reading the atomics and
    /// `run_to_completion_while_held` watching the channel — sees the loss.
    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
        self.valid_until_millis.store(0, Ordering::Release);
        let _ = self.lease_state_tx.send(0);
    }
}

/// Outcome of a generation-preserving reclaim attempt.
enum LeaseReclaim {
    /// The row is still this owner's, at the generation this guard acquired,
    /// so no other writer was ever admitted.
    SameGeneration(Instant),
    /// Ownership provably changed hands.
    Taken,
    /// The reclaim itself could not be completed. Proof of nothing; the caller
    /// retries while the window still allows it.
    Unavailable,
}

/// Time one renewal attempt may block, or `None` when the window has closed.
///
/// The arithmetic, spelled out, because the safety property lives here:
///
/// * `valid_until` mirrors the datastore's `expires_at` and is always at or
///   before it (see [`LeaseRenewalState::publish_deadline`]).
/// * An attempt may therefore run until `valid_until` and no further. Past
///   that instant a success could not be trusted: the row it updated may
///   already have been claimed by another owner.
/// * Attempts are additionally capped at one renew interval so a stalled
///   datastore yields several attempts inside one window rather than a single
///   attempt that spans it.
/// * A window with one retry interval or less remaining counts as closed.
///   Issuing an attempt that cannot be followed up only delays an honest
///   fail-closed, and this reproduces the pre-existing expiry boundary exactly.
fn lease_attempt_budget(
    now: Instant,
    valid_until: Instant,
    timing: LeaseRenewalTiming,
) -> Option<Duration> {
    let remaining = valid_until.checked_duration_since(now)?;
    if remaining <= timing.retry_interval {
        return None;
    }
    Some(remaining.min(timing.attempt_budget()))
}

/// Sleep for `duration`, returning `true` when the guard asked the renewer to
/// stop instead.
async fn lease_sleep_or_stop(
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
    duration: Duration,
) -> bool {
    tokio::select! {
        changed = stop_rx.changed() => changed.is_err() || *stop_rx.borrow(),
        _ = tokio::time::sleep(duration) => false,
    }
}

/// Re-acquire a lease the datastore just refused to renew, but only when the
/// row proves nobody else ever held it.
///
/// `try_acquire_namespace_config_admission_lease` takes the row when it is
/// unowned, expired, or already this owner's, and bumps `generation` on every
/// ownership change while leaving it untouched for a same-owner re-take. The
/// `config_admission_locks` row is never deleted by any code path — release
/// only sets `expires_at = 0` — so `generation` is strictly monotonic per
/// namespace for the life of the datastore.
///
/// That makes `owner == ours && generation == ours` a proof, not a heuristic:
/// for a foreign owner to have been admitted, `generation` would have had to
/// increase, and it can never come back down. A matching generation therefore
/// means the lease was never handed to anyone else, so extending it cannot
/// create a second believing writer.
async fn reclaim_namespace_config_admission_lease<B>(
    db: &B,
    namespace: &str,
    owner: &str,
    generation: u64,
    budget: Duration,
) -> LeaseReclaim
where
    B: crate::config::db_backend::NamespaceConfigAdmissionLeaseBackend + ?Sized,
{
    let started_at = Instant::now();
    let acquired = tokio::time::timeout(
        budget,
        db.try_acquire_namespace_config_admission_lease(namespace, owner),
    )
    .await;
    let acquired = match acquired {
        Ok(Ok(acquired)) => acquired,
        Ok(Err(_error)) => {
            super::debug_persistence_failure_redacted("namespace_admission_lease_reclaim");
            return LeaseReclaim::Unavailable;
        }
        Err(_elapsed) => return LeaseReclaim::Unavailable,
    };
    match acquired {
        Some(reacquired) if reacquired == generation => LeaseReclaim::SameGeneration(started_at),
        Some(_) => {
            // The row changed hands and came back: this claim is useless to the
            // guard, and holding it would block the rightful next writer for a
            // whole lease duration.
            release_namespace_config_admission_claim(
                db,
                namespace,
                owner,
                "a namespace config admission lease reclaimed at a foreign generation",
                CONFIG_ADMISSION_LEASE_RETRY_INTERVAL,
            )
            .await;
            LeaseReclaim::Taken
        }
        None => LeaseReclaim::Taken,
    }
}

/// Keep one namespace config admission lease alive until the guard stops, the
/// datastore hands the namespace to somebody else, or the window closes.
///
/// Generic over the lease backend rather than over `DatabaseBackend` so tests
/// can drive the exact production loop against a fault-injecting fake without
/// standing up a datastore.
async fn run_namespace_config_admission_renewal<B>(
    db: Arc<B>,
    namespace: String,
    owner: String,
    generation: u64,
    timing: LeaseRenewalTiming,
    state: LeaseRenewalState,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> LeaseRenewalReport
where
    B: crate::config::db_backend::NamespaceConfigAdmissionLeaseBackend + ?Sized + 'static,
{
    let mut counters = LeaseRenewalCounters::default();
    let mut valid_until = state.lease_started_at + timing.lease_duration;
    loop {
        if lease_sleep_or_stop(&mut stop_rx, timing.renew_interval).await {
            return LeaseRenewalReport {
                outcome: LeaseRenewalOutcome::Stopped,
                counters,
            };
        }

        loop {
            let attempt_started_at = Instant::now();
            let Some(budget) = lease_attempt_budget(attempt_started_at, valid_until, timing) else {
                state.invalidate();
                tracing::error!(
                    namespace = %namespace,
                    renewals = counters.renewals,
                    retries = counters.retries,
                    reclaims = counters.reclaims,
                    detail_withheld = true,
                    "Namespace config admission lease expired before any renewal attempt could complete; failing closed"
                );
                return LeaseRenewalReport {
                    outcome: LeaseRenewalOutcome::Expired,
                    counters,
                };
            };
            let renewed = tokio::time::timeout(
                budget,
                db.renew_namespace_config_admission_lease(&namespace, &owner),
            )
            .await;
            match renewed {
                Ok(Ok(true)) => {
                    counters.renewals = counters.renewals.saturating_add(1);
                    valid_until = state.publish_deadline(attempt_started_at);
                    break;
                }
                Ok(Ok(false)) => {
                    // The conditional renewal matched no row. That is not yet
                    // proof of loss: the same outcome is produced by a stalled
                    // statement that reached the datastore after this owner's
                    // own expiry, with the row still untouched and unclaimed.
                    // A generation-preserving reclaim tells the two apart.
                    let reclaim = reclaim_namespace_config_admission_lease(
                        db.as_ref(),
                        &namespace,
                        &owner,
                        generation,
                        budget,
                    )
                    .await;
                    match reclaim {
                        LeaseReclaim::SameGeneration(reclaimed_at) => {
                            counters.reclaims = counters.reclaims.saturating_add(1);
                            valid_until = state.publish_deadline(reclaimed_at);
                            tracing::warn!(
                                namespace = %namespace,
                                generation = generation,
                                renewals = counters.renewals,
                                retries = counters.retries,
                                reclaims = counters.reclaims,
                                "Namespace config admission lease renewal was refused and the lease was re-acquired at the same generation; no other writer held it"
                            );
                            break;
                        }
                        LeaseReclaim::Taken => {
                            state.invalidate();
                            tracing::error!(
                                namespace = %namespace,
                                generation = generation,
                                renewals = counters.renewals,
                                retries = counters.retries,
                                reclaims = counters.reclaims,
                                "Namespace config admission lease renewal lost ownership to another writer"
                            );
                            return LeaseRenewalReport {
                                outcome: LeaseRenewalOutcome::Lost,
                                counters,
                            };
                        }
                        LeaseReclaim::Unavailable => {
                            counters.retries = counters.retries.saturating_add(1);
                            tracing::warn!(
                                namespace = %namespace,
                                retries = counters.retries,
                                detail_withheld = true,
                                "Namespace config admission lease reclaim did not complete; retrying inside the remaining lease window"
                            );
                            if lease_sleep_or_stop(&mut stop_rx, timing.retry_interval).await {
                                return LeaseRenewalReport {
                                    outcome: LeaseRenewalOutcome::Stopped,
                                    counters,
                                };
                            }
                        }
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    counters.retries = counters.retries.saturating_add(1);
                    tracing::warn!(
                        namespace = %namespace,
                        retries = counters.retries,
                        detail_withheld = true,
                        "Namespace config admission lease renewal attempt did not complete; retrying inside the remaining lease window"
                    );
                    if lease_sleep_or_stop(&mut stop_rx, timing.retry_interval).await {
                        return LeaseRenewalReport {
                            outcome: LeaseRenewalOutcome::Stopped,
                            counters,
                        };
                    }
                }
            }
        }
    }
}

/// Serialize graph- and credential-sensitive admin mutations for a namespace
/// from candidate validation through persistence. A bounded process-global
/// lock set is the cheap first tier; the datastore lease below coordinates
/// writable gateway instances that share SQL or MongoDB persistence.
///
/// SQL transactions and MongoDB leases provide the authoritative cross-process
/// backstop. The additional ASCII-folded `san_dns` constraint is conditional on
/// effective plugin associations, so it cannot use an unconditional case-folded
/// unique index without rejecting valid case variants used by exact-match
/// policies. This lock avoids redundant same-process candidate work while the
/// backend serialization covers separate admin processes.
/// Every credential mutation takes this lock, even for non-mTLS types, because
/// those endpoints persist the complete `Consumer` and could otherwise replay
/// stale `mtls_auth` entries loaded before a concurrent mTLS mutation. Every
/// plugin-graph mutation (including API-spec bundles) uses the same lock so a
/// prospective transaction-log schema snapshot remains authoritative until
/// the corresponding write commits.
pub(crate) async fn lock_local_namespace_config_admission(
    namespace: &str,
) -> MutexGuard<'static, ()> {
    let shard = namespace_config_admission_shard(namespace);
    namespace_config_admission_locks()[shard].lock().await
}

fn namespace_config_admission_locks() -> &'static Vec<Mutex<()>> {
    NAMESPACE_CONFIG_ADMISSION_LOCKS.get_or_init(|| {
        (0..NAMESPACE_CONFIG_ADMISSION_LOCK_SHARDS)
            .map(|_| Mutex::new(()))
            .collect()
    })
}

fn namespace_config_admission_shard(namespace: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    namespace.hash(&mut hasher);
    hasher.finish() as usize % NAMESPACE_CONFIG_ADMISSION_LOCK_SHARDS
}

/// Take the process-local shard mutexes covering every admission key in one
/// operation.
///
/// Two properties matter and neither is optional:
///
/// * **Deduplicated by shard.** The shard set is a bounded hash of the key, so
///   two distinct keys — a rename's source and target, or the global registry
///   key and a namespace name — can land on the same shard. `tokio::sync::Mutex`
///   is not reentrant, so locking that shard twice would deadlock the request
///   against itself.
/// * **Ascending shard order.** Every multi-key caller acquires shards in the
///   same total order, so two concurrent multi-key callers cannot each hold a
///   shard the other needs.
async fn lock_local_namespace_config_admission_multi<K: AsRef<str>>(
    keys: &[K],
) -> Vec<MutexGuard<'static, ()>> {
    let mut shards: Vec<usize> = keys
        .iter()
        .map(|key| namespace_config_admission_shard(key.as_ref()))
        .collect();
    shards.sort_unstable();
    shards.dedup();
    let locks = namespace_config_admission_locks();
    let mut guards = Vec::with_capacity(shards.len());
    for shard in shards {
        guards.push(locks[shard].lock().await);
    }
    guards
}

fn validate_candidate_plugin_graph(
    candidate: &GatewayConfig,
    http_client: &crate::plugins::PluginHttpClient,
) -> Result<(), AfterValidateError> {
    crate::plugin_cache::validate_plugin_composition_candidate(candidate, http_client)
        .map_err(|error| AfterValidateError::BadRequest(vec![error]))?;
    crate::plugin_cache::validate_tcp_connection_throttle_attachments(candidate)
        .map_err(AfterValidateError::BadRequest)
}

pub(crate) struct NamespaceConfigAdmissionGuard {
    /// Process-local shard mutexes held for this guard's lifetime. A
    /// single-namespace guard holds exactly one; the last guard of a multi-key
    /// registry acquisition holds the whole deduplicated set.
    local: Vec<MutexGuard<'static, ()>>,
    db: Option<Arc<dyn DatabaseBackend>>,
    namespace: String,
    owner: String,
    generation: u64,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    renew_task: Option<tokio::task::JoinHandle<LeaseRenewalReport>>,
    valid: Arc<AtomicBool>,
    lease_started_at: Instant,
    valid_until_millis: Arc<AtomicU64>,
    lease_state_rx: tokio::sync::watch::Receiver<u64>,
}

pub(crate) enum NamespaceConfigAdmissionCompletion<T> {
    Held(T),
    Lost { result: T, error: anyhow::Error },
}

impl NamespaceConfigAdmissionGuard {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Identity a backend re-verifies inside the transaction it is about to
    /// commit, so an operation that must not straddle a lease change (atomic
    /// batch persistence) aborts instead of compensating afterwards.
    pub(crate) fn lease_ref(
        &self,
    ) -> crate::config::db_backend::NamespaceConfigAdmissionLeaseRef<'_> {
        crate::config::db_backend::NamespaceConfigAdmissionLeaseRef {
            owner: &self.owner,
            generation: self.generation,
        }
    }

    pub(crate) fn immediately_succeeds_generation(&self, previous: u64) -> bool {
        previous.checked_add(1) == Some(self.generation)
    }

    pub(crate) fn ensure_held(&self) -> Result<(), anyhow::Error> {
        let elapsed_millis =
            u64::try_from(self.lease_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        if self.valid.load(Ordering::Acquire)
            && elapsed_millis < self.valid_until_millis.load(Ordering::Acquire)
        {
            Ok(())
        } else {
            anyhow::bail!("namespace config admission lease was lost before persistence")
        }
    }

    /// Test-only: mark the lease invalid so [`Self::ensure_held`] and
    /// [`Self::run_to_completion_while_held`] observe loss without waiting for
    /// the production renewer / TTL.
    #[allow(dead_code)]
    pub(crate) fn force_lose_for_test(&self) {
        self.valid.store(false, Ordering::Release);
        self.valid_until_millis.store(0, Ordering::Release);
    }

    /// Run a persistence operation that is not cancellation-safe to a concrete
    /// result while still observing the admission lease. If ownership is lost,
    /// the caller receives both the completed result and the lease error so it
    /// can verify or compensate under a newly acquired lease.
    pub(crate) async fn run_to_completion_while_held<F, T>(
        &self,
        future: F,
    ) -> Result<NamespaceConfigAdmissionCompletion<T>, anyhow::Error>
    where
        F: Future<Output = T>,
    {
        self.ensure_held()?;
        let mut lease_state_rx = self.lease_state_rx.clone();
        tokio::pin!(future);
        let persistence_started = AtomicBool::new(false);
        loop {
            let valid_until_millis = *lease_state_rx.borrow_and_update();
            let elapsed_millis =
                u64::try_from(self.lease_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            if valid_until_millis == 0 || elapsed_millis >= valid_until_millis {
                if !persistence_started.load(Ordering::Acquire) {
                    anyhow::bail!(
                        "namespace config admission lease was lost before persistence started"
                    );
                }
                let result = future.await;
                return Ok(NamespaceConfigAdmissionCompletion::Lost {
                    result,
                    error: anyhow::anyhow!(
                        "namespace config admission lease was lost during persistence"
                    ),
                });
            }
            let remaining = Duration::from_millis(valid_until_millis - elapsed_millis);
            tokio::select! {
                biased;
                changed = lease_state_rx.changed() => {
                    if changed.is_err() {
                        if !persistence_started.load(Ordering::Acquire) {
                            anyhow::bail!(
                                "namespace config admission lease monitor stopped before persistence started"
                            );
                        }
                        let result = future.await;
                        return Ok(NamespaceConfigAdmissionCompletion::Lost {
                            result,
                            error: anyhow::anyhow!(
                                "namespace config admission lease monitor stopped during persistence"
                            ),
                        });
                    }
                }
                _ = tokio::time::sleep(remaining) => {
                    if !persistence_started.load(Ordering::Acquire) {
                        anyhow::bail!(
                            "namespace config admission lease expired before persistence started"
                        );
                    }
                    let result = future.await;
                    return Ok(NamespaceConfigAdmissionCompletion::Lost {
                        result,
                        error: anyhow::anyhow!(
                            "namespace config admission lease expired during persistence"
                        ),
                    });
                }
                result = std::future::poll_fn(|context| {
                    persistence_started.store(true, Ordering::Release);
                    future.as_mut().poll(context)
                }) => {
                    return Ok(match self.ensure_held() {
                        Ok(()) => NamespaceConfigAdmissionCompletion::Held(result),
                        Err(error) => NamespaceConfigAdmissionCompletion::Lost { result, error },
                    });
                }
            }
        }
    }
}

impl Drop for NamespaceConfigAdmissionGuard {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(true);
        }
        let Some(db) = self.db.take() else {
            return;
        };
        let namespace = std::mem::take(&mut self.namespace);
        let owner = std::mem::take(&mut self.owner);
        let renew_task = self.renew_task.take();
        let local = std::mem::take(&mut self.local);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Some(task) = renew_task {
                    task.abort();
                    let _ = task.await;
                }
                match tokio::time::timeout(
                    CONFIG_ADMISSION_LEASE_RELEASE_TIMEOUT,
                    db.release_namespace_config_admission_lease(&namespace, &owner),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(_error)) => {
                        super::warn_persistence_failure_redacted(
                            "namespace_admission_lease_release",
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            namespace = %namespace,
                            "Timed out releasing namespace config admission lease; expiry will recover it"
                        );
                    }
                }
                drop(local);
            });
        }
    }
}

async fn release_namespace_config_admission_claim<B>(
    db: &B,
    namespace: &str,
    owner: &str,
    context: &'static str,
    budget: Duration,
) where
    B: crate::config::db_backend::NamespaceConfigAdmissionLeaseBackend + ?Sized,
{
    match tokio::time::timeout(
        budget,
        db.release_namespace_config_admission_lease(namespace, owner),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_error)) => {
            super::warn_persistence_failure_redacted("namespace_admission_claim_release");
        }
        Err(_) => tracing::warn!(
            %namespace,
            "Timed out releasing {context}; expiry will recover it"
        ),
    }
}

struct PendingNamespaceConfigAdmissionClaim {
    db: Arc<dyn DatabaseBackend>,
    namespace: String,
    owner: String,
    lease_started_at: Instant,
    generation: u64,
    armed: bool,
}

impl PendingNamespaceConfigAdmissionClaim {
    fn into_acquired(mut self) -> (Instant, u64) {
        self.armed = false;
        (self.lease_started_at, self.generation)
    }
}

impl Drop for PendingNamespaceConfigAdmissionClaim {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let db = self.db.clone();
        let namespace = self.namespace.clone();
        let owner = self.owner.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let _cleanup_task = runtime.spawn(async move {
                release_namespace_config_admission_claim(
                    db.as_ref(),
                    &namespace,
                    &owner,
                    "a cancelled namespace config admission acquisition",
                    CONFIG_ADMISSION_LEASE_RELEASE_TIMEOUT,
                )
                .await;
            });
        }
    }
}

pub(crate) async fn lock_namespace_config_admission(
    db: Arc<dyn DatabaseBackend>,
    namespace: &str,
) -> Result<NamespaceConfigAdmissionGuard, anyhow::Error> {
    let local = vec![lock_local_namespace_config_admission(namespace).await];
    lock_namespace_config_admission_with_local(db, namespace, local).await
}

async fn lock_namespace_config_admission_with_local(
    db: Arc<dyn DatabaseBackend>,
    namespace: &str,
    local: Vec<MutexGuard<'static, ()>>,
) -> Result<NamespaceConfigAdmissionGuard, anyhow::Error> {
    let owner = Uuid::new_v4().to_string();
    // Bound the wait rather than spin forever: see
    // `CONFIG_ADMISSION_LEASE_ACQUIRE_MAX_WAIT`.
    let acquisition_deadline = Instant::now() + CONFIG_ADMISSION_LEASE_ACQUIRE_MAX_WAIT;
    let (lease_started_at, generation) = loop {
        let acquire_db = db.clone();
        let acquire_namespace = namespace.to_string();
        let acquire_owner = owner.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let _acquire_task = tokio::spawn(async move {
            let attempt_started_at = Instant::now();
            let result = acquire_db
                .try_acquire_namespace_config_admission_lease(&acquire_namespace, &acquire_owner)
                .await;

            // An error can be an ambiguous datastore outcome. Make one
            // owner-qualified release attempt before reporting it. If the
            // request disappeared while acquisition was in flight, an
            // acquired claim is likewise released instead of waiting for its
            // full lease expiry.
            if result.is_err() {
                release_namespace_config_admission_claim(
                    acquire_db.as_ref(),
                    &acquire_namespace,
                    &acquire_owner,
                    "an ambiguous namespace config admission acquisition",
                    CONFIG_ADMISSION_LEASE_RETRY_INTERVAL,
                )
                .await;
            }

            let result = result.map(|generation| {
                generation.map(|generation| PendingNamespaceConfigAdmissionClaim {
                    db: acquire_db,
                    namespace: acquire_namespace,
                    owner: acquire_owner,
                    lease_started_at: attempt_started_at,
                    generation,
                    armed: true,
                })
            });
            // If the receiver disappeared before or after this send, the
            // undelivered/queued claim is dropped and starts cleanup.
            let _ = result_tx.send(result);
        });
        if let Some(claim) = result_rx.await.map_err(|_| {
            anyhow::anyhow!("namespace config admission acquisition task stopped unexpectedly")
        })?? {
            break claim.into_acquired();
        }
        if Instant::now() >= acquisition_deadline {
            tracing::warn!(
                %namespace,
                waited_seconds = CONFIG_ADMISSION_LEASE_ACQUIRE_MAX_WAIT.as_secs(),
                "Namespace config admission lease stayed held for a full lease duration; \
                 refusing the mutation as retryable congestion instead of waiting longer"
            );
            return Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                "namespace config admission lease for '{namespace}' was still held after \
                 waiting a full lease duration"
            )));
        }
        tokio::time::sleep(CONFIG_ADMISSION_LEASE_RETRY_INTERVAL).await;
    };

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let timing = LeaseRenewalTiming::PRODUCTION;
    let valid = Arc::new(AtomicBool::new(true));
    let lease_duration_millis =
        u64::try_from(timing.lease_duration.as_millis()).unwrap_or(u64::MAX);
    let valid_until_millis = Arc::new(AtomicU64::new(lease_duration_millis));
    let (lease_state_tx, lease_state_rx) = tokio::sync::watch::channel(lease_duration_millis);
    let state = LeaseRenewalState {
        valid: valid.clone(),
        valid_until_millis: valid_until_millis.clone(),
        lease_state_tx,
        lease_started_at,
        lease_duration_millis,
    };
    let renew_task = tokio::spawn(run_namespace_config_admission_renewal(
        db.clone(),
        namespace.to_string(),
        owner.clone(),
        generation,
        timing,
        state,
        stop_rx,
    ));

    Ok(NamespaceConfigAdmissionGuard {
        local,
        db: Some(db),
        namespace: namespace.to_string(),
        owner,
        generation,
        stop_tx: Some(stop_tx),
        renew_task: Some(renew_task),
        valid,
        lease_started_at,
        valid_until_millis,
        lease_state_rx,
    })
}

/// Test entry point: drive the production renewer against `db` with a scaled
/// timing envelope and stop it after `run_for`.
///
/// Every bound the renewer applies is derived from `timing`, so a scaled
/// envelope exercises the identical arithmetic in milliseconds instead of
/// minutes. Returns the renewer's report plus the guard-visible verdict
/// [`NamespaceConfigAdmissionGuard::ensure_held`] would reach at that instant.
#[allow(dead_code)] // Library integration tests exercise this seam; the binary target does not.
pub(crate) async fn run_namespace_config_admission_renewal_for_test(
    db: Arc<dyn crate::config::db_backend::NamespaceConfigAdmissionLeaseBackend>,
    namespace: &str,
    owner: &str,
    generation: u64,
    timing: LeaseRenewalTiming,
    run_for: Duration,
) -> (LeaseRenewalReport, bool) {
    let lease_started_at = Instant::now();
    let lease_duration_millis =
        u64::try_from(timing.lease_duration.as_millis()).unwrap_or(u64::MAX);
    let valid = Arc::new(AtomicBool::new(true));
    let valid_until_millis = Arc::new(AtomicU64::new(lease_duration_millis));
    let (lease_state_tx, _lease_state_rx) = tokio::sync::watch::channel(lease_duration_millis);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let state = LeaseRenewalState {
        valid: valid.clone(),
        valid_until_millis: valid_until_millis.clone(),
        lease_state_tx,
        lease_started_at,
        lease_duration_millis,
    };
    let mut task = tokio::spawn(run_namespace_config_admission_renewal(
        db,
        namespace.to_string(),
        owner.to_string(),
        generation,
        timing,
        state,
        stop_rx,
    ));
    let finished = tokio::select! {
        joined = &mut task => Some(joined),
        _ = tokio::time::sleep(run_for) => None,
    };
    let joined = match finished {
        Some(joined) => joined,
        None => {
            let _ = stop_tx.send(true);
            task.await
        }
    };
    let stopped = LeaseRenewalReport {
        outcome: LeaseRenewalOutcome::Stopped,
        counters: LeaseRenewalCounters::default(),
    };
    let report = joined.unwrap_or(stopped);
    let elapsed = lease_started_at.elapsed();
    let elapsed_millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let held = valid.load(Ordering::Acquire)
        && elapsed_millis < valid_until_millis.load(Ordering::Acquire);
    (report, held)
}

/// Every admission lease one namespace **registry** mutation holds.
///
/// The guards are acquired — and therefore released — in a total order: the
/// global `NAMESPACE_REGISTRY_ADMISSION_KEY` first, then the affected
/// namespace names in ascending order. Because every create, rename, and delete
/// takes the global key first, two gateway instances can never interleave two
/// registry mutations, and a rename's two-name acquisition cannot deadlock
/// against a concurrent single-name delete.
pub(crate) struct NamespaceRegistryAdmission {
    keys: Vec<String>,
    guards: Vec<NamespaceConfigAdmissionGuard>,
}

impl NamespaceRegistryAdmission {
    /// The exact lease identities the backend must re-verify inside the
    /// transaction it is about to commit.
    pub(crate) fn holds(&self) -> Vec<crate::config::db_backend::NamespaceAdmissionLeaseHold<'_>> {
        self.keys
            .iter()
            .zip(self.guards.iter())
            .map(
                |(key, guard)| crate::config::db_backend::NamespaceAdmissionLeaseHold {
                    key: key.as_str(),
                    lease: guard.lease_ref(),
                },
            )
            .collect()
    }

    /// Observe the global registry lease across a persistence future that is
    /// not cancellation-safe. The per-name leases are verified at the commit
    /// boundary by the backend; this is the local liveness view.
    pub(crate) async fn run_to_completion_while_held<F, T>(
        &self,
        future: F,
    ) -> Result<NamespaceConfigAdmissionCompletion<T>, anyhow::Error>
    where
        F: Future<Output = T>,
    {
        // `lock_namespace_registry_admission` always pushes the global registry
        // guard first, so index 0 exists for every constructed value.
        self.guards[0].run_to_completion_while_held(future).await
    }
}

/// Acquire the global registry lease plus one lease per affected namespace.
///
/// `names` may contain duplicates (a description-only update passes the same
/// name twice); they are deduplicated and sorted so the acquisition order is
/// identical for every caller.
pub(crate) async fn lock_namespace_registry_admission(
    db: Arc<dyn DatabaseBackend>,
    names: &[&str],
) -> Result<NamespaceRegistryAdmission, anyhow::Error> {
    let keys = crate::config::namespace_registry::namespace_registry_admission_keys(names);

    // One deduplicated, ascending-shard acquisition for the whole key set: the
    // per-key helper would self-deadlock the moment two keys hash to the same
    // shard.
    let mut local = lock_local_namespace_config_admission_multi(&keys).await;

    let mut guards = Vec::with_capacity(keys.len());
    for (index, key) in keys.iter().enumerate() {
        // The process-local shard guards ride on the LAST datastore lease so
        // they outlive every lease release. Earlier keys carry none.
        let carried = if index + 1 == keys.len() {
            std::mem::take(&mut local)
        } else {
            Vec::new()
        };
        // A failure here drops the guards acquired so far, which releases their
        // datastore leases in the reverse of the acquisition order.
        guards.push(lock_namespace_config_admission_with_local(db.clone(), key, carried).await?);
    }
    Ok(NamespaceRegistryAdmission { keys, guards })
}

async fn run_db_write_while_held<T, F>(
    guard: Option<&NamespaceConfigAdmissionGuard>,
    future: F,
) -> Result<NamespaceConfigAdmissionCompletion<DbResult<T>>, anyhow::Error>
where
    F: Future<Output = DbResult<T>>,
{
    match guard {
        Some(guard) => guard
            .run_to_completion_while_held(future)
            .await
            .map_err(mark_mtls_dns_admission_unavailable),
        None => Ok(NamespaceConfigAdmissionCompletion::Held(future.await)),
    }
}

/// Does any proxy *other than* `own_proxy_id` reference this plugin config?
///
/// A proxy-scoped create writes its own association as part of the same
/// transaction (issue #4611), so that association is not third-party state and
/// must not veto late-create compensation — deleting the config removes it
/// again. Any other proxy referencing the config is a genuine intervening
/// write.
async fn plugin_has_foreign_proxy_association(
    db: &dyn DatabaseBackend,
    namespace: &str,
    plugin_id: &str,
    own_proxy_id: Option<&str>,
) -> DbResult<bool> {
    let mut offset = 0_i64;
    const PAGE_SIZE: i64 = 1_000;
    loop {
        let page = db
            .list_proxies_paginated(namespace, PAGE_SIZE, offset)
            .await?;
        let items_len = page.items.len() as i64;
        if page.items.iter().any(|proxy| {
            own_proxy_id != Some(proxy.id.as_str())
                && proxy
                    .plugins
                    .iter()
                    .any(|association| association.plugin_config_id == plugin_id)
        }) {
            return Ok(true);
        }
        if items_len == 0 || offset + items_len >= page.total {
            return Ok(false);
        }
        offset += items_len;
    }
}

async fn proxy_has_scoped_plugin(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy_id: &str,
) -> DbResult<bool> {
    let mut offset = 0_i64;
    const PAGE_SIZE: i64 = 1_000;
    loop {
        let page = db
            .list_plugin_configs_paginated(namespace, PAGE_SIZE, offset)
            .await?;
        let items_len = page.items.len() as i64;
        if page
            .items
            .iter()
            .any(|plugin| plugin.proxy_id.as_deref() == Some(proxy_id))
        {
            return Ok(true);
        }
        if items_len == 0 || offset + items_len >= page.total {
            return Ok(false);
        }
        offset += items_len;
    }
}

/// Reacquire namespace admission after a successful late write. With no
/// intervening claimant, the original validation remains authoritative. If a
/// writer did intervene, undo only the still-current late delta; a later
/// same-resource mutation supersedes the delta and is left intact.
async fn recover_late_resource_write<R: AdminResource>(
    db: Arc<dyn DatabaseBackend>,
    namespace: &str,
    lost_generation: u64,
    http_client: crate::plugins::PluginHttpClient,
    action: LateResourceWrite<'_>,
    recovery: LateResourceRecovery<'_, R>,
) -> Result<Option<NamespaceConfigAdmissionGuard>, anyhow::Error> {
    let recovery_guard = lock_namespace_config_admission(db.clone(), namespace).await?;
    if recovery_guard.immediately_succeeds_generation(lost_generation) {
        return Ok(Some(recovery_guard));
    }
    if matches!(
        &action,
        LateResourceWrite::Update { .. } | LateResourceWrite::Delete { .. }
    ) && matches!(
        R::intervening_write_recovery(
            db.as_ref(),
            namespace,
            recovery.previous,
            http_client.clone(),
        )
        .await?,
        InterveningWriteRecovery::KeepCurrent
    ) {
        return Ok(None);
    }

    let compensation = async {
        match action {
            LateResourceWrite::Create => {
                let written = recovery.written.ok_or_else(|| {
                    anyhow::anyhow!("late create recovery is missing the written resource")
                })?;
                if let Some(current) =
                    R::db_get_for_write(db.as_ref(), namespace, written.id()).await?
                    && R::late_create_compensation_safe(
                        db.as_ref(),
                        namespace,
                        &current,
                        written,
                        recovery.delete_snapshots.map(|snapshots| snapshots.config),
                        http_client,
                    )
                    .await?
                    && !R::db_delete(db.as_ref(), namespace, written.id()).await?
                {
                    anyhow::bail!("late create compensation found no matching resource");
                }
            }
            LateResourceWrite::Update { id } => {
                let written = recovery.written.ok_or_else(|| {
                    anyhow::anyhow!("late update recovery is missing the written resource")
                })?;
                let previous = recovery.previous.ok_or_else(|| {
                    anyhow::anyhow!("late update recovery is missing the prior resource")
                })?;
                if R::db_get_for_write(db.as_ref(), namespace, id)
                    .await?
                    .is_some_and(|current| current.updated_at() == written.updated_at())
                    && !R::compensate_late_update(db.as_ref(), previous).await?
                {
                    anyhow::bail!("late update compensation found no matching resource");
                }
            }
            LateResourceWrite::Delete { id } => {
                let previous = recovery.previous.ok_or_else(|| {
                    anyhow::anyhow!("late delete recovery is missing the prior resource")
                })?;
                if R::db_get_for_write(db.as_ref(), namespace, id)
                    .await?
                    .is_none()
                {
                    R::compensate_late_delete(
                        db.as_ref(),
                        namespace,
                        previous,
                        recovery.delete_snapshots.map(|snapshots| snapshots.config),
                        recovery
                            .delete_snapshots
                            .and_then(|snapshots| snapshots.api_spec),
                        http_client,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    };
    match recovery_guard
        .run_to_completion_while_held(compensation)
        .await?
    {
        NamespaceConfigAdmissionCompletion::Held(result) => result?,
        NamespaceConfigAdmissionCompletion::Lost { result, error } => {
            result?;
            return Err(error);
        }
    }
    Ok(None)
}

/// Resolve the authoritative post-write view of a committed resource.
///
/// For every resource that has not opted into [`AdminResource::REREAD_AFTER_WRITE`]
/// this is the identity function on the request-side value, so the generic
/// settlement/late-write behaviour is untouched.
///
/// For a resource that HAS opted in, the committed record is re-read by
/// `(namespace, id)` through the same namespace-predicated store method a `GET`
/// uses. There is no cached fallback and no "close enough" default: if the
/// read fails, or the record is gone, the caller must report the write as
/// failed rather than answer with a revision the store never assigned. Returning
/// the request-side value in that case is precisely the defect this exists to
/// remove.
async fn settle_written_resource<R: AdminResource>(
    db: &dyn DatabaseBackend,
    namespace: &str,
    written: R,
) -> DbResult<R> {
    if !R::REREAD_AFTER_WRITE {
        return Ok(written);
    }
    match R::db_get(db, namespace, written.id()).await? {
        Some(stored) => Ok(stored),
        None => Err(anyhow::anyhow!(
            "committed {} could not be re-read for its authoritative stored state",
            R::RESOURCE_NAME
        )),
    }
}

/// Settle a committed write while continuing to observe namespace admission.
///
/// Merely retaining the guard is insufficient: its lease can expire while the
/// authoritative read is in flight. In that case the read may describe a later
/// writer, so fail closed instead of using it for this request's response and
/// audit after-image.
///
/// A resource that has NOT opted into [`AdminResource::REREAD_AFTER_WRITE`]
/// short-circuits before the lease is observed at all. There is no store read
/// to fence — settlement is the identity function on a value the caller already
/// holds — and the write has already COMMITTED by this point. Routing that pure
/// identity through the admission observation would let a lease that expired
/// after the commit turn a successful `200`/`201` into a reported failure, for
/// every generic resource, which is a behaviour change the re-read seam must
/// not impose on resources that do not use it.
async fn settle_written_resource_while_held<R: AdminResource>(
    guard: Option<&NamespaceConfigAdmissionGuard>,
    db: &dyn DatabaseBackend,
    namespace: &str,
    written: R,
) -> DbResult<R> {
    if !R::REREAD_AFTER_WRITE {
        return Ok(written);
    }
    match run_db_write_while_held(guard, settle_written_resource(db, namespace, written)).await? {
        NamespaceConfigAdmissionCompletion::Held(result) => result,
        NamespaceConfigAdmissionCompletion::Lost { result: _, error } => {
            Err(mark_mtls_dns_admission_unavailable(error))
        }
    }
}

struct OwnedWriteSettlementContext {
    db: Arc<dyn DatabaseBackend>,
    namespace: String,
    guard: Option<NamespaceConfigAdmissionGuard>,
    http_client: crate::plugins::PluginHttpClient,
    state: AdminState,
    actor: AuditActor,
}

/// Returns the AUTHORITATIVE committed resource — for a resource that opted
/// into [`AdminResource::REREAD_AFTER_WRITE`] this is the re-read record, so the
/// 201 body and the audit after-image both carry the state the store actually
/// holds; for every other resource it is the request-side value, unchanged.
async fn persist_create_to_settlement<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    written: R,
) -> DbResult<R> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        mut guard,
        http_client,
        state,
        actor,
    } = context;
    let success_db = db.clone();
    let result = match run_db_write_while_held(guard.as_ref(), R::db_create(db.as_ref(), &written))
        .await
    {
        Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
        Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
            Ok(()) => {
                let lost_generation = guard
                    .as_ref()
                    .map(NamespaceConfigAdmissionGuard::generation)
                    .unwrap_or_default();
                drop(guard.take());
                match recover_late_resource_write(
                    db,
                    &namespace,
                    lost_generation,
                    http_client,
                    LateResourceWrite::Create,
                    LateResourceRecovery {
                        written: Some(&written),
                        previous: None,
                        delete_snapshots: None,
                    },
                )
                .await
                {
                    Ok(Some(recovery_guard)) => {
                        guard = Some(recovery_guard);
                        Ok(())
                    }
                    Ok(None) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                        "namespace config admission was lost during create; the late write was compensated"
                    ))),
                    Err(_recovery_error) => {
                        Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                            "namespace config admission was lost during create and recovery failed"
                        )))
                    }
                }
            }
            Err(persistence_error) => Err(persistence_error),
        },
        Err(error) => Err(error),
    };
    result?;
    // Settle BEFORE auditing so the audit after-image and the response body are
    // the same authoritative record. A failure here is reported as a failed
    // write: the alternative — auditing and answering with the request-side
    // revision — is the stale-value defect itself.
    let settled = settle_written_resource_while_held::<R>(
        guard.as_ref(),
        success_db.as_ref(),
        &namespace,
        written,
    )
    .await?;
    finish_write_success(
        success_db,
        &state,
        &actor,
        &namespace,
        &settled,
        None,
        WriteAction::Create,
    )
    .await;
    Ok(settled)
}

/// `Ok(None)` is the not-found outcome (the row vanished between the precheck
/// and the write); `Ok(Some(settled))` carries the AUTHORITATIVE committed
/// resource — see [`persist_create_to_settlement`].
async fn persist_update_to_settlement<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    id: String,
    written: R,
    previous: R,
) -> DbResult<Option<R>> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        mut guard,
        http_client,
        state,
        actor,
    } = context;
    let success_db = db.clone();
    let result = match run_db_write_while_held(guard.as_ref(), R::db_update(db.as_ref(), &written))
        .await
    {
        Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
        Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
            Ok(false) => Ok(false),
            Ok(true) => {
                let lost_generation = guard
                    .as_ref()
                    .map(NamespaceConfigAdmissionGuard::generation)
                    .unwrap_or_default();
                drop(guard.take());
                match recover_late_resource_write(
                    db,
                    &namespace,
                    lost_generation,
                    http_client,
                    LateResourceWrite::Update { id: &id },
                    LateResourceRecovery {
                        written: Some(&written),
                        previous: Some(&previous),
                        delete_snapshots: None,
                    },
                )
                .await
                {
                    Ok(Some(recovery_guard)) => {
                        guard = Some(recovery_guard);
                        Ok(true)
                    }
                    Ok(None) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                        "namespace config admission was lost during update; the late write was compensated"
                    ))),
                    Err(_recovery_error) => {
                        Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                            "namespace config admission was lost during update and recovery failed"
                        )))
                    }
                }
            }
            Err(persistence_error) => Err(persistence_error),
        },
        Err(error) => Err(error),
    };
    if !result? {
        return Ok(None);
    }
    let settled = settle_written_resource_while_held::<R>(
        guard.as_ref(),
        success_db.as_ref(),
        &namespace,
        written,
    )
    .await?;
    finish_write_success(
        success_db,
        &state,
        &actor,
        &namespace,
        &settled,
        Some(&previous),
        WriteAction::Update { id: &id },
    )
    .await;
    Ok(Some(settled))
}

/// Issue #2997: DELETE of a reachable-but-undecodable row is the in-band repair
/// path. The row cannot be hydrated for pre-delete snapshot / late-write
/// compensation, and `load_namespace_snapshot` fails for the same reason, so
/// delete by primary key under the admission lock and audit identity only.
async fn persist_undecodable_delete_repair<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    id: String,
    delete_query: R::DeleteQuery,
) -> DbResult<bool> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        guard,
        http_client: _,
        state,
        actor,
    } = context;
    let success_db = db.clone();
    let result = match run_db_write_while_held(
        guard.as_ref(),
        R::db_delete_from_request(db.as_ref(), &namespace, &id, delete_query),
    )
    .await
    {
        Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
        Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
            Ok(false) => Ok(false),
            // Without a hydratable previous row or namespace snapshot we cannot
            // compensate a late write. Fail closed rather than claiming success
            // after an unverified admission loss.
            Ok(true) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                "namespace config admission was lost during undecodable-row delete repair"
            ))),
            Err(persistence_error) => Err(persistence_error),
        },
        Err(error) => Err(error),
    };
    if matches!(&result, Ok(true)) {
        let event = AuditEvent::new(
            &actor,
            "delete",
            R::RESOURCE_NAME.replace(' ', "_"),
            &id,
            &namespace,
            audit::delete_diff(json!({
                "id": id,
                "namespace": namespace,
                "undecodable_row_repair": true,
            })),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, success_db, event).await {
            super::log_audit_enqueue_failure(&error);
        }
    }
    result
}

/// Issue #2997: PUT overwrite of a reachable-but-undecodable row is an in-band
/// repair path. The prior row cannot be hydrated for `prepare_for_update` /
/// late-write compensation, so persist the request body by primary key under
/// the admission lock and audit against a null before-image.
async fn persist_undecodable_update_repair<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    id: String,
    written: R,
) -> DbResult<Option<R>> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        guard,
        http_client: _,
        state,
        actor,
    } = context;
    let result =
        match run_db_write_while_held(guard.as_ref(), R::db_update(db.as_ref(), &written)).await {
            Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
            Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
                Ok(false) => Ok(false),
                // Without a hydratable previous row or namespace snapshot we cannot
                // compensate a late write. Fail closed rather than claiming success
                // after an unverified admission loss.
                Ok(true) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                    "namespace config admission was lost during undecodable-row update repair"
                ))),
                Err(persistence_error) => Err(persistence_error),
            },
            Err(error) => Err(error),
        };
    if !result? {
        return Ok(None);
    }
    let settled =
        settle_written_resource_while_held::<R>(guard.as_ref(), db.as_ref(), &namespace, written)
            .await?;
    finish_write_success(
        db,
        &state,
        &actor,
        &namespace,
        &settled,
        None,
        WriteAction::Update { id: &id },
    )
    .await;
    Ok(Some(settled))
}

async fn persist_delete_to_settlement<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    id: String,
    recovery: OwnedLateDeleteRecovery<R>,
    delete_query: R::DeleteQuery,
) -> DbResult<bool> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        mut guard,
        http_client,
        state,
        actor,
    } = context;
    let success_db = db.clone();
    let result = match run_db_write_while_held(
        guard.as_ref(),
        R::db_delete_from_request(db.as_ref(), &namespace, &id, delete_query),
    )
    .await
    {
        Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
        Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
            Ok(false) => Ok(false),
            Ok(true) => {
                let lost_generation = guard
                    .as_ref()
                    .map(NamespaceConfigAdmissionGuard::generation)
                    .unwrap_or_default();
                drop(guard.take());
                match recover_late_resource_write(
                    db,
                    &namespace,
                    lost_generation,
                    http_client,
                    LateResourceWrite::Delete { id: &id },
                    LateResourceRecovery {
                        written: None,
                        previous: Some(&recovery.previous),
                        delete_snapshots: recovery.config.as_ref().map(|config| {
                            LateDeleteSnapshots {
                                config,
                                api_spec: recovery.api_spec.as_ref(),
                            }
                        }),
                    },
                )
                .await
                {
                    Ok(Some(_recovery_guard)) => Ok(true),
                    Ok(None) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                        "namespace config admission was lost during delete; the late write was compensated"
                    ))),
                    Err(_recovery_error) => {
                        Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                            "namespace config admission was lost during delete and recovery failed"
                        )))
                    }
                }
            }
            Err(persistence_error) => Err(persistence_error),
        },
        Err(error) => Err(error),
    };
    if matches!(&result, Ok(true)) {
        let event = AuditEvent::new(
            &actor,
            "delete",
            R::RESOURCE_NAME.replace(' ', "_"),
            &id,
            &namespace,
            audit::delete_diff(R::audit_body(&recovery.previous)),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, success_db, event).await {
            super::log_audit_enqueue_failure(&error);
        }
    }
    result
}

async fn finish_write_success<R: AdminResource>(
    db: Arc<dyn DatabaseBackend>,
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    resource: &R,
    existing: Option<&R>,
    action: WriteAction<'_>,
) {
    if let Err(_error) =
        R::after_write(db.as_ref(), state, namespace, resource, existing, action).await
    {
        super::warn_persistence_failure_redacted("admin_resource_post_write_hook");
    }

    let (audit_action, diff) = match action {
        WriteAction::Create => ("create", audit::create_diff(R::audit_body(resource))),
        WriteAction::Update { .. } => {
            let before = existing.map(R::audit_body).unwrap_or_else(|| json!(null));
            (
                "update",
                audit::update_diff(before, R::audit_body(resource)),
            )
        }
    };
    let event = AuditEvent::new(
        actor,
        audit_action,
        R::RESOURCE_NAME.replace(' ', "_"),
        resource.id(),
        namespace,
        diff,
    );
    if let Err(error) = audit::record(state.admin_audit_enabled, db, event).await {
        super::log_audit_enqueue_failure(&error);
    }
}

pub(super) async fn validate_transaction_log_schema_graph_on_blocking_pool(
    candidate: GatewayConfig,
    http_client: crate::plugins::PluginHttpClient,
) -> Result<(), AfterValidateError> {
    tokio::task::spawn_blocking(move || {
        crate::plugins::transaction_log_schema::validate_config_graph(
            &candidate,
            &http_client,
            true,
        )
    })
    .await
    .map_err(|error| {
        AfterValidateError::Db(anyhow::anyhow!(
            "transaction-log schema validation task failed: {error}"
        ))
    })?
    .map_err(AfterValidateError::BadRequest)
}

pub(crate) async fn current_transaction_log_schema_graph_is_valid(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
) -> DbResult<bool> {
    let candidate = db.load_namespace_snapshot(namespace).await?;
    let http_client = super::plugin_validation_http_client(state);
    match validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await {
        Ok(()) => Ok(true),
        Err(AfterValidateError::BadRequest(_) | AfterValidateError::Conflict(_)) => Ok(false),
        Err(AfterValidateError::Db(error)) => Err(error),
        Err(AfterValidateError::Response(_)) => {
            anyhow::bail!("transaction-log schema graph validation returned an HTTP response")
        }
    }
}

async fn validate_mtls_auth_candidate(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: Option<&Proxy>,
    plugin: Option<&PluginConfig>,
    removed_plugin_id: Option<&str>,
) -> Result<(), AfterValidateError> {
    let mut config = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    if let Some(proxy) = proxy {
        if let Some(existing) = config.proxies.iter_mut().find(|item| item.id == proxy.id) {
            *existing = proxy.clone();
        } else {
            config.proxies.push(proxy.clone());
        }
    }
    if let Some(plugin) = plugin {
        if let Some(existing) = config
            .plugin_configs
            .iter_mut()
            .find(|item| item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            config.plugin_configs.push(plugin.clone());
        }
    }
    if let Some(removed_plugin_id) = removed_plugin_id {
        config
            .plugin_configs
            .retain(|plugin| plugin.id != removed_plugin_id);
    }
    if proxy
        .is_some_and(|candidate| !config.has_effective_mtls_auth_for_proxy(candidate.id.as_str()))
    {
        return Ok(());
    }
    let compatibility_errors = config
        .validate_mtls_auth_compatibility()
        .err()
        .unwrap_or_default();
    if !compatibility_errors.is_empty() {
        return Err(AfterValidateError::BadRequest(compatibility_errors));
    }
    config
        .validate_unique_mtls_credentials()
        .map_err(AfterValidateError::Conflict)
}

/// The proxy candidates a proxy-scoped plugin write will change (issue #4611).
///
/// The Admin API now appends `{plugin_config_id}` to the target proxy in the
/// same transaction as the config row, so admission must validate the graph the
/// write will actually produce — otherwise an unsupported attachment (a
/// `tcp_connection_throttle` on a UDP proxy, say) would pass the pre-persist
/// checks and only fail inside the store.
///
/// Only the *gaining* proxy is materialised: detaching can never introduce a
/// composition conflict that the pre-attach graph did not already have.
async fn plugin_attach_proxy_candidates(
    db: &dyn DatabaseBackend,
    namespace: &str,
    resource: &PluginConfig,
) -> DbResult<Vec<Proxy>> {
    if resource.scope != PluginScope::Proxy {
        return Ok(Vec::new());
    }
    let Some(proxy_id) = resource.proxy_id.as_deref() else {
        return Ok(Vec::new());
    };
    // A missing proxy is already rejected by the `check_proxy_exists` gate
    // above; treat a race here as "nothing extra to validate" and let the
    // store's own referential checks decide. The write-path getter is used
    // deliberately: a proxy carrying a pre-existing invalid association must
    // stay repairable rather than turning every plugin write into a 503.
    let Some(mut proxy) = db.get_proxy_for_write(namespace, proxy_id).await? else {
        return Ok(Vec::new());
    };
    if !proxy
        .plugins
        .iter()
        .any(|association| association.plugin_config_id == resource.id)
    {
        proxy.plugins.push(crate::config::types::PluginAssociation {
            plugin_config_id: resource.id.clone(),
        });
    }
    Ok(vec![proxy])
}

/// Validate the exact post-mutation graph for cross-resource plugin contracts
/// before a Proxy or PluginConfig write is persisted.
pub(crate) async fn validate_plugin_graph_candidates(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    proxies: &[Proxy],
    plugins: &[PluginConfig],
    removed_plugin_id: Option<&str>,
) -> Result<(), AfterValidateError> {
    // Global plugin scope is global within one runtime namespace. CP snapshots
    // are filtered before broadcast and file/database modes load one namespace,
    // so cross-namespace plugins must never create false admission conflicts.
    let mut candidate = db
        .load_namespace_policy_graph(namespace)
        .await
        .map_err(AfterValidateError::Db)?;

    if let Some(removed_plugin_id) = removed_plugin_id {
        candidate
            .plugin_configs
            .retain(|plugin| plugin.namespace != namespace || plugin.id != removed_plugin_id);
    }

    for proxy in proxies {
        if let Some(existing) = candidate
            .proxies
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == proxy.id)
        {
            *existing = proxy.clone();
        } else {
            candidate.proxies.push(proxy.clone());
        }
    }
    for plugin in plugins {
        if let Some(existing) = candidate
            .plugin_configs
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            candidate.plugin_configs.push(plugin.clone());
        }
    }

    let http_client = super::plugin_validation_http_client(state);
    validate_candidate_plugin_graph(&candidate, &http_client)
}

/// Validate the exact graph produced by deleting a Proxy, including the
/// proxy-scoped plugin FK cascade and orphaned proxy-group cleanup performed by
/// both direct Proxy deletion and API-spec cascade deletion.
pub(crate) async fn validate_plugin_graph_proxy_deletion_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    removed_proxy_id: &str,
) -> Result<(), AfterValidateError> {
    let mut candidate = db
        .load_namespace_policy_graph(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    candidate
        .proxies
        .retain(|proxy| proxy.id != removed_proxy_id);
    candidate
        .plugin_configs
        .retain(|plugin| plugin.proxy_id.as_deref() != Some(removed_proxy_id));

    let remaining_associations: HashSet<String> = candidate
        .proxies
        .iter()
        .flat_map(|proxy| proxy.plugins.iter())
        .map(|association| association.plugin_config_id.clone())
        .collect();
    candidate.plugin_configs.retain(|plugin| {
        plugin.scope != PluginScope::ProxyGroup || remaining_associations.contains(&plugin.id)
    });

    let http_client = super::plugin_validation_http_client(state);
    validate_candidate_plugin_graph(&candidate, &http_client)
}

/// A direct proxy delete can cascade resources that the runtime snapshot
/// deliberately exposes without API-spec ownership metadata. Re-read every
/// resource that compensation would classify as hand-owned before persistence,
/// while namespace admission is still held, so a foreign spec's resource can
/// never be restored with its ownership stripped.
async fn validate_direct_api_spec_proxy_delete_restore_ownership(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
) -> Result<(), AfterValidateError> {
    let spec = db
        .get_api_spec_by_proxy(namespace, &proxy.id)
        .await
        .map_err(AfterValidateError::Db)?;
    let Some(spec) = spec else {
        if let Some(owner) = proxy.api_spec_id.as_deref() {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' is stamped to API spec '{}' but its owning API-spec metadata is missing",
                proxy.id, owner
            )]));
        }
        return Ok(());
    };
    if let Some(owner) = proxy.api_spec_id.as_deref()
        && owner != spec.id
    {
        return Err(AfterValidateError::BadRequest(vec![format!(
            "proxy '{}' is stamped to API spec '{}' but its owning metadata identifies API spec '{}'",
            proxy.id, owner, spec.id
        )]));
    }
    let snapshot = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    let associated_ids = proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect::<HashSet<_>>();
    let other_associated_ids = snapshot
        .proxies
        .iter()
        .filter(|candidate| candidate.id != proxy.id)
        .flat_map(|candidate| candidate.plugins.iter())
        .map(|association| association.plugin_config_id.as_str())
        .collect::<HashSet<_>>();

    for snapshot_plugin in snapshot.plugin_configs.iter().filter(|plugin| {
        plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
            || (plugin.scope == PluginScope::ProxyGroup
                && associated_ids.contains(plugin.id.as_str())
                && !other_associated_ids.contains(plugin.id.as_str()))
    }) {
        let Some(plugin) = db
            .get_plugin_config(namespace, &snapshot_plugin.id)
            .await
            .map_err(AfterValidateError::Db)?
        else {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' cascade plugin '{}' disappeared before API-spec restore ownership validation",
                proxy.id, snapshot_plugin.id
            )]));
        };
        if let Some(owner) = plugin.api_spec_id.as_deref()
            && owner != spec.id
        {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' cascade plugin '{}' is owned by API spec '{}', not owning API spec '{}'",
                proxy.id, plugin.id, owner, spec.id
            )]));
        }
    }

    if let Some(upstream_id) = proxy.upstream_id.as_deref() {
        let Some(upstream) = db
            .get_upstream(namespace, upstream_id)
            .await
            .map_err(AfterValidateError::Db)?
        else {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' upstream '{}' disappeared before API-spec restore ownership validation",
                proxy.id, upstream_id
            )]));
        };
        if let Some(owner) = upstream.api_spec_id.as_deref()
            && owner != spec.id
        {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' upstream '{}' is owned by API spec '{}', not owning API spec '{}'",
                proxy.id, upstream.id, owner, spec.id
            )]));
        }
    }

    Ok(())
}

/// Validate the post-mutation named log-schema graph for one namespace.
///
/// The authoritative snapshot is overlaid exactly as plugin CRUD/batch
/// persistence will change it, then definitions and referrers are validated in
/// an isolated registry bracket. No live registry state participates.
pub(crate) async fn validate_transaction_log_schema_candidates(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    plugins: &[PluginConfig],
    removed_plugin_id: Option<&str>,
) -> Result<(), AfterValidateError> {
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;

    if let Some(removed_plugin_id) = removed_plugin_id {
        candidate
            .plugin_configs
            .retain(|plugin| plugin.namespace != namespace || plugin.id != removed_plugin_id);
    }
    for plugin in plugins {
        if let Some(existing) = candidate
            .plugin_configs
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            candidate.plugin_configs.push(plugin.clone());
        }
    }

    let http_client = super::plugin_validation_http_client(state);
    validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await
}

/// Validate the exact post-PUT API-spec replacement candidate.
///
/// The persistence contract deletes plugin configs owned by the replaced spec,
/// removes associations declared only by the previous spec, preserves manual
/// associations, and then overlays the incoming proxy and plugins. Build that
/// same graph here so admission neither rejects a valid replacement because of
/// removed globals nor admits an invalid chain by dropping retained manual
/// associations.
pub(crate) async fn validate_plugin_graph_api_spec_replacement_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    existing_spec: &crate::config::types::ApiSpec,
    proxy: &Proxy,
    plugins: &[PluginConfig],
) -> Result<(), AfterValidateError> {
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    let replaced_plugins = db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
        .map_err(AfterValidateError::Db)?;
    let replaced_plugin_ids: HashSet<String> = replaced_plugins
        .into_iter()
        .map(|plugin| plugin.id)
        .collect();

    // Only plugin configs owned by this spec are replaceable. Treating an
    // incoming same-ID plugin as an overlay on a manual or differently owned
    // config would make the in-memory candidate diverge from persistence,
    // where the insert is rejected by the plugin-config primary key.
    if let Some(plugin) = plugins.iter().find(|plugin| {
        !replaced_plugin_ids.contains(&plugin.id)
            && candidate
                .plugin_configs
                .iter()
                .any(|existing| existing.namespace == namespace && existing.id == plugin.id)
    }) {
        return Err(AfterValidateError::BadRequest(vec![format!(
            "plugin_config id '{}' already exists in namespace '{}' outside api_spec '{}'; replacement cannot take ownership of it",
            plugin.id, namespace, existing_spec.id
        )]));
    }

    candidate
        .plugin_configs
        .retain(|plugin| !replaced_plugin_ids.contains(&plugin.id));
    for candidate_proxy in &mut candidate.proxies {
        candidate_proxy
            .plugins
            .retain(|association| !replaced_plugin_ids.contains(&association.plugin_config_id));
    }

    let previous_declared_assoc_ids =
        crate::admin::api_specs::declared_proxy_plugin_association_ids_from_stored_spec(
            existing_spec,
        );
    let incoming_assoc_ids: HashSet<&str> = proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    let mut replacement_proxy = proxy.clone();
    let mut preserved_associations = candidate
        .proxies
        .iter()
        .find(|item| item.namespace == namespace && item.id == proxy.id)
        .map(|item| item.plugins.clone())
        .unwrap_or_default();
    preserved_associations.retain(|association| {
        !previous_declared_assoc_ids.contains(&association.plugin_config_id)
            && !incoming_assoc_ids.contains(association.plugin_config_id.as_str())
    });
    preserved_associations.extend(proxy.plugins.iter().cloned());
    replacement_proxy.plugins = preserved_associations;

    if let Some(existing) = candidate
        .proxies
        .iter_mut()
        .find(|item| item.namespace == namespace && item.id == proxy.id)
    {
        *existing = replacement_proxy;
    } else {
        candidate.proxies.push(replacement_proxy);
    }
    for plugin in plugins {
        if let Some(existing) = candidate
            .plugin_configs
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            candidate.plugin_configs.push(plugin.clone());
        }
    }

    let http_client = super::plugin_validation_http_client(state);
    validate_candidate_plugin_graph(&candidate, &http_client)
}

/// Validate the named log-schema graph produced by an exact API-spec PUT.
///
/// `replace_api_spec_bundle` deletes every plugin config owned by the old spec
/// before inserting the replacement bundle. Mirror that ownership boundary so
/// removed definitions/referrers cannot leak into validation and retained
/// manual plugins remain part of the authoritative prospective namespace.
pub(crate) async fn validate_transaction_log_schema_api_spec_replacement_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    existing_spec: &crate::config::types::ApiSpec,
    plugins: &[PluginConfig],
) -> Result<(), AfterValidateError> {
    let replaced_plugins = db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
        .map_err(AfterValidateError::Db)?;
    if !plugins
        .iter()
        .chain(replaced_plugins.iter())
        .any(crate::plugins::transaction_log_schema::is_enabled_config_graph_participant)
    {
        return Ok(());
    }

    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    let replaced_plugin_ids: HashSet<String> = replaced_plugins
        .into_iter()
        .map(|plugin| plugin.id)
        .collect();

    if let Some(plugin) = plugins.iter().find(|plugin| {
        !replaced_plugin_ids.contains(&plugin.id)
            && candidate
                .plugin_configs
                .iter()
                .any(|existing| existing.namespace == namespace && existing.id == plugin.id)
    }) {
        return Err(AfterValidateError::BadRequest(vec![format!(
            "plugin_config id '{}' already exists in namespace '{}' outside api_spec '{}'; replacement cannot take ownership of it",
            plugin.id, namespace, existing_spec.id
        )]));
    }

    candidate
        .plugin_configs
        .retain(|plugin| !replaced_plugin_ids.contains(&plugin.id));
    for plugin in plugins {
        if let Some(existing) = candidate
            .plugin_configs
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            candidate.plugin_configs.push(plugin.clone());
        }
    }

    let http_client = super::plugin_validation_http_client(state);
    validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await
}

/// Validate the named log-schema graph produced by deleting an API spec.
///
/// API-spec deletion removes every plugin config owned by the spec, every
/// proxy-scoped config tied to the deleted proxy, and proxy-group configs that
/// become orphaned after that proxy's associations disappear. Mirror all three
/// cascades so retained manual referrers cannot be stranded while referrers
/// deleted by the same operation do not cause a false rejection.
pub(crate) async fn validate_transaction_log_schema_api_spec_deletion_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    existing_spec: &crate::config::types::ApiSpec,
) -> Result<(), AfterValidateError> {
    let spec_owned_plugins = db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
        .map_err(AfterValidateError::Db)?;
    let mut removed_plugin_ids: HashSet<String> = spec_owned_plugins
        .into_iter()
        .map(|plugin| plugin.id)
        .collect();
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;

    candidate
        .proxies
        .retain(|proxy| proxy.namespace != namespace || proxy.id != existing_spec.proxy_id);
    removed_plugin_ids.extend(
        candidate
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.namespace == namespace
                    && plugin.proxy_id.as_deref() == Some(existing_spec.proxy_id.as_str())
            })
            .map(|plugin| plugin.id.clone()),
    );

    let retained_association_ids: HashSet<&str> = candidate
        .proxies
        .iter()
        .flat_map(|proxy| proxy.plugins.iter())
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    removed_plugin_ids.extend(
        candidate
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.namespace == namespace
                    && plugin.scope == crate::config::types::PluginScope::ProxyGroup
                    && !retained_association_ids.contains(plugin.id.as_str())
            })
            .map(|plugin| plugin.id.clone()),
    );

    if !candidate.plugin_configs.iter().any(|plugin| {
        removed_plugin_ids.contains(&plugin.id)
            && crate::plugins::transaction_log_schema::is_enabled_config_graph_participant(plugin)
    }) {
        return Ok(());
    }

    candidate
        .plugin_configs
        .retain(|plugin| !removed_plugin_ids.contains(&plugin.id));
    let http_client = super::plugin_validation_http_client(state);
    validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await
}

/// Validate a wholesale namespace replacement without retaining resources that
/// the restore will delete. Runtime plugin chains are namespace-scoped, so the
/// normalized replacement is the complete authoritative candidate.
pub(crate) fn validate_plugin_graph_restore_candidate(
    state: &AdminState,
    replacement: &GatewayConfig,
) -> Result<(), AfterValidateError> {
    let http_client = super::plugin_validation_http_client(state);
    validate_candidate_plugin_graph(replacement, &http_client)
}

async fn consumer_candidate_config(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> DbResult<GatewayConfig> {
    let mut config = db.load_namespace_snapshot(namespace).await?;
    if let Some(existing) = config
        .consumers
        .iter_mut()
        .find(|item| item.id == consumer.id)
    {
        *existing = consumer.clone();
    } else {
        config.consumers.push(consumer.clone());
    }
    Ok(config)
}

pub(crate) async fn mtls_consumer_candidate_errors(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> DbResult<Vec<String>> {
    Ok(consumer_candidate_config(db, namespace, consumer)
        .await?
        .validate_unique_mtls_credentials()
        .err()
        .unwrap_or_default())
}

/// Reject an admin Consumer/credential write whose hmac_auth secret is
/// already claimed by another consumer in the namespace. Snapshot-based like
/// the mTLS candidate check (rather than a credential-index probe) so
/// pre-existing rows written before hmac secrets were policed are still
/// authoritative. `lock_namespace_config_admission` serializes same-process
/// prechecks; namespace-scoped SQL/Mongo uniqueness constraints are the
/// cross-process persistence backstop.
pub(crate) async fn hmac_consumer_candidate_errors(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> DbResult<Vec<String>> {
    Ok(consumer_candidate_config(db, namespace, consumer)
        .await?
        .validate_unique_hmac_credentials()
        .err()
        .unwrap_or_default())
}

impl ValidationError {
    fn into_messages(self) -> Vec<String> {
        match self {
            Self::Fields(errors) => errors,
            Self::Message(message) => vec![message],
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait AdminResource:
    Send + Sync + Serialize + DeserializeOwned + Clone + Sized + 'static
{
    const RESOURCE_NAME: &'static str;
    const RESOURCE_LABEL: &'static str;
    const VALIDATION_ERROR_LABEL: &'static str;
    const NOT_FOUND_MESSAGE: &'static str;
    const ID_CONFLICT_LABEL: &'static str = Self::RESOURCE_LABEL;
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = false;

    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
    fn namespace(&self) -> &str;
    fn set_namespace(&mut self, ns: String);
    fn set_created_at(&mut self, now: DateTime<Utc>);
    fn set_updated_at(&mut self, now: DateTime<Utc>);
    fn updated_at(&self) -> DateTime<Utc>;
    fn normalize(&mut self);
    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError>;
    fn cached_items(config: &GatewayConfig) -> &[Self];

    /// Stamp the authenticated admin subject onto the resource, for resources
    /// that persist server-side attribution alongside the durable audit log.
    ///
    /// Called after `normalize()` so a client-supplied value can never survive:
    /// attribution must come from the verified JWT, not the request body.
    /// Default is a no-op.
    fn set_actor(&mut self, _actor: &str) {}

    /// Re-read the committed record after a successful create/update and use
    /// THAT as both the success response body and the audit after-image.
    ///
    /// Default `false` keeps every existing resource on the historical
    /// behaviour of serializing the request-side value, so this changes nothing
    /// for them. A resource opts in when the store settles server-owned state
    /// the request body cannot predict — the gateway trust bundle's
    /// backend-assigned `revision` is exactly that: a `POST` body carries `0`
    /// and a `PUT` body carries the client's *expectation*, so serializing the
    /// request-side value would report a revision the store never wrote and
    /// audit the same wrong number.
    ///
    /// The re-read is fail-closed: it runs while the namespace admission guard
    /// is still relevant, and if it errors or finds nothing the write is
    /// reported as failed rather than answered with a fabricated revision.
    const REREAD_AFTER_WRITE: bool = false;

    /// The id a create with an omitted `id` should get, derived from the
    /// SERVER-selected namespace (`X-Ferrum-Namespace`).
    ///
    /// `None` — the default — keeps the historical behaviour of minting a
    /// UUID. A singleton resource overrides this so its default identity is
    /// derived from the authenticated namespace rather than from anything the
    /// request body could influence: `normalize()` runs before
    /// `set_namespace()`, so a body-derived default would key off the client's
    /// namespace field.
    fn default_id_for_namespace(namespace: &str) -> Option<String> {
        let _ = namespace;
        None
    }

    fn response_body(resource: &Self) -> Value {
        json!(resource)
    }

    fn response_body_for_role(resource: &Self, _role: AdminRole) -> Value {
        Self::response_body(resource)
    }

    fn audit_body(resource: &Self) -> Value {
        Self::response_body(resource)
    }

    /// Inspect the raw request body *before* it is deserialized into `Self`.
    /// Return `Err` to reject the request with a 400 Bad Request. Default is
    /// a no-op. Override on resources that need schema-specific raw checks.
    ///
    /// `action` distinguishes `POST` (`Create`) from `PUT` (`Update`) so a
    /// resource can demand explicit presence only where an absent key would
    /// silently overwrite prior state on a full replace.
    fn validate_raw_body(_body: &[u8], _action: WriteAction<'_>) -> Result<(), String> {
        Ok(())
    }

    fn labels_mut(&mut self) -> Option<&mut std::collections::BTreeMap<String, String>> {
        None
    }

    fn prepare_for_update(&mut self, _existing: &Self) {}

    /// Presence-aware repair for fields whose serde default is unsafe on a full
    /// replace. `raw` is the request body's top-level object, so an *absent* key
    /// can be distinguished from an explicitly supplied one. Update path only.
    fn restore_absent_update_fields(
        &mut self,
        _existing: &Self,
        _raw: &serde_json::Map<String, serde_json::Value>,
    ) {
    }

    fn prepare_for_write(&mut self) -> Result<(), PrepareWriteError> {
        Ok(())
    }

    fn map_validation_error(error: &ValidationError) -> Response<Full<Bytes>> {
        match error {
            ValidationError::Fields(errors) => validation_error_response::<Self>(errors),
            ValidationError::Message(message) => {
                validation_error_response::<Self>(std::slice::from_ref(message))
            }
        }
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        validation_error_response::<Self>(errors)
    }

    fn map_precheck_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &super::db_error_response(error),
        )
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        if let Some(conflict) = tcp_connection_throttle_attachment_conflict(error) {
            return Self::map_after_validate_errors(conflict.errors());
        }
        // Unique-constraint violations at persist time are conflicts, not
        // server faults: the admission prechecks are namespace-scoped and
        // raceable, so the DB constraint is the authoritative backstop (e.g.
        // reusing a proxy/upstream id that exists in another namespace, or a
        // concurrent create winning the race after the precheck passed).
        // Preserve the 409 disposition without surfacing driver-owned
        // constraint, key, schema, or duplicate-value text.
        if let Some(conflict) = mtls_dns_identity_conflict(error) {
            // Typed conflicts are classified anywhere in the chain, so render
            // the conflict itself: `error.to_string()` is the chain's outermost
            // message and would echo any driver/DSN/schema context a store
            // wrapped above it.
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": conflict.to_string() }),
            );
        }
        if super::chain_has_unique_constraint_violation(error) {
            super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": super::RESOURCE_IDENTITY_CONFLICT_MESSAGE }),
            )
        } else {
            super::json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &super::db_error_response(error),
            )
        }
    }

    fn map_delete_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        if let Some(unsupported) =
            crate::config::db_backend::proxy_delete_atomicity_unsupported(error)
        {
            super::json_response(
                StatusCode::NOT_IMPLEMENTED,
                &json!({
                    "error": crate::config::db_backend::PROXY_DELETE_ATOMICITY_UNSUPPORTED_MESSAGE,
                    "detail": unsupported.detail(),
                }),
            )
        } else if is_mtls_dns_admission_unavailable(error) {
            super::mtls_dns_admission_unavailable_response()
        } else if let Some(conflict) = tcp_connection_throttle_attachment_conflict(error) {
            Self::map_after_validate_errors(conflict.errors())
        } else if let Some(conflict) = mtls_dns_identity_conflict(error) {
            // Render the typed conflict rather than the chain's outermost
            // message; see `map_persist_db_error` above.
            super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": conflict.to_string()}),
            )
        } else {
            super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &super::db_error_response(error),
            )
        }
    }

    fn allow_cached_read_fallback(_error: &anyhow::Error) -> bool {
        true
    }

    // Reads/deletes are namespace-predicated at the query level (issue #2122
    // DB-M1): the backend WHERE clause / filter document carries the tenant
    // boundary, so no post-read namespace comparison is needed here.
    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>>;
    async fn db_get_for_write(
        db: &dyn DatabaseBackend,
        namespace: &str,
        id: &str,
    ) -> DbResult<Option<Self>> {
        Self::db_get(db, namespace, id).await
    }
    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>>;
    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()>;
    /// Returns `Ok(false)` when no row/document matched `(namespace, id)` —
    /// a PUT racing a concurrent delete surfaces as not-found instead of a
    /// phantom success (issue #2122 DB-M4).
    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool>;
    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool>;

    /// Extra query-string state for DELETE. Default is unused.
    type DeleteQuery: Send + Sync + Clone + Default + 'static;

    /// Parse resource-specific DELETE query parameters. Default ignores the
    /// query string. Return `Err` for a 400 before any persistence.
    fn parse_delete_query(_query: Option<&str>) -> Result<Self::DeleteQuery, String> {
        Ok(Self::DeleteQuery::default())
    }

    /// Persist a DELETE using options parsed from the request query.
    /// Default ignores `opts` and calls [`Self::db_delete`].
    async fn db_delete_from_request(
        db: &dyn DatabaseBackend,
        namespace: &str,
        id: &str,
        _opts: Self::DeleteQuery,
    ) -> DbResult<bool> {
        Self::db_delete(db, namespace, id).await
    }

    async fn compensate_late_delete(
        db: &dyn DatabaseBackend,
        _namespace: &str,
        previous: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        _previous_api_spec: Option<&ApiSpecDeleteSnapshot>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<()> {
        Self::db_create(db, previous).await
    }

    /// Put a prior version of the resource back after a late update.
    ///
    /// Default delegates to [`Self::db_update`]. A resource whose `db_update`
    /// derives an optimistic-concurrency expectation from the resource itself
    /// must override this: the late write already advanced the stored revision,
    /// so replaying `previous` with its pre-write expectation would always lose
    /// the compare-and-set and turn a compensable recovery into a hard failure.
    async fn compensate_late_update(db: &dyn DatabaseBackend, previous: &Self) -> DbResult<bool> {
        Self::db_update(db, previous).await
    }

    async fn intervening_write_recovery(
        _db: &dyn DatabaseBackend,
        _namespace: &str,
        _previous: Option<&Self>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<InterveningWriteRecovery> {
        Ok(InterveningWriteRecovery::Compensate)
    }

    async fn late_delete_api_spec_snapshot(
        _db: &dyn DatabaseBackend,
        _namespace: &str,
        _previous: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
    ) -> DbResult<Option<ApiSpecDeleteSnapshot>> {
        Ok(None)
    }

    async fn late_create_compensation_safe(
        _db: &dyn DatabaseBackend,
        _namespace: &str,
        current: &Self,
        written: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<bool> {
        Ok(current.updated_at() == written.updated_at())
    }

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>>;

    async fn after_validate(
        _db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        _resource: &Self,
        _existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        Ok(())
    }

    async fn before_delete(
        _db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        _existing: &Self,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        Ok(())
    }

    async fn after_write(
        _db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        _resource: &Self,
        _existing: Option<&Self>,
        _action: WriteAction<'_>,
    ) -> DbResult<()> {
        Ok(())
    }
}

pub(crate) async fn handle_list<R: AdminResource>(
    state: &AdminState,
    pagination: &super::PaginationParams,
    role: AdminRole,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(ref db) = state.db {
        match R::db_list(db.as_ref(), namespace, pagination).await {
            Ok(result) => {
                let items: Vec<Value> = result
                    .items
                    .iter()
                    .map(|resource| R::response_body_for_role(resource, role))
                    .collect();
                let body = super::paginate_db_response(&items, result.total, pagination);
                return Ok(super::json_response(StatusCode::OK, &body));
            }
            Err(error) => {
                if !R::allow_cached_read_fallback(&error) {
                    return Ok(R::map_precheck_db_error(&error));
                }
                super::warn_persistence_failure_redacted("admin_resource_list_cached_fallback");
            }
        }
    }

    if let Some(config) = state.cached_gateway_config() {
        let items = R::cached_items(&config)
            .iter()
            .filter(|resource| resource.namespace() == namespace);
        let body = super::paginate_mapped_response(items, pagination, |resource| {
            R::response_body_for_role(resource, role)
        });
        Ok(super::json_response_with_stale(StatusCode::OK, &body))
    } else {
        Ok(super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

pub(crate) async fn handle_get<R: AdminResource>(
    state: &AdminState,
    id: &str,
    role: AdminRole,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Err(message) = validate_resource_id(id) {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    if let Some(ref db) = state.db {
        match R::db_get(db.as_ref(), namespace, id).await {
            Ok(Some(resource)) => {
                let body = R::response_body_for_role(&resource, role);
                return Ok(super::json_response(StatusCode::OK, &body));
            }
            Ok(None) => {
                return Ok(not_found_response::<R>());
            }
            Err(error) => {
                if !R::allow_cached_read_fallback(&error) {
                    return Ok(R::map_precheck_db_error(&error));
                }
                super::warn_persistence_failure_redacted("admin_resource_get_cached_fallback");
            }
        }
    }

    if let Some(config) = state.cached_gateway_config() {
        match R::cached_items(&config)
            .iter()
            .find(|resource| resource.id() == id && resource.namespace() == namespace)
        {
            Some(resource) => {
                let body = R::response_body_for_role(resource, role);
                Ok(super::json_response_with_stale(StatusCode::OK, &body))
            }
            None => Ok(not_found_response::<R>()),
        }
    } else {
        Ok(super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

pub(crate) async fn handle_create<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    body: &[u8],
    namespace: &str,
    apply_mode: LiveApplyMode,
    provisioner: Option<&str>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    handle_write::<R>(
        state,
        actor,
        body,
        namespace,
        WriteAction::Create,
        apply_mode,
        provisioner,
    )
    .await
}

pub(crate) async fn handle_update<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    id: &str,
    body: &[u8],
    namespace: &str,
    apply_mode: LiveApplyMode,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    handle_write::<R>(
        state,
        actor,
        body,
        namespace,
        WriteAction::Update { id },
        apply_mode,
        None,
    )
    .await
}

/// Parse `cleanup_orphaned_upstream` from `DELETE /proxies/{id}`.
///
/// The parameter is absent → `true` (today's last-referenced hand-owned
/// orphan cleanup). Exactly one occurrence with the exact string `true` or
/// `false` is accepted; any other value or duplicate occurrence is an error
/// because this flag decides whether operator data is deleted.
pub(crate) fn parse_cleanup_orphaned_upstream_query(query: Option<&str>) -> Result<bool, String> {
    let Some(query) = query else {
        return Ok(true);
    };
    let mut parsed = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key.as_ref() != "cleanup_orphaned_upstream" {
            continue;
        }
        let this = match value.as_ref() {
            "true" => true,
            "false" => false,
            other => {
                return Err(format!(
                    "cleanup_orphaned_upstream must be 'true' or 'false', not '{other}'"
                ));
            }
        };
        if parsed.is_some() {
            return Err(
                "cleanup_orphaned_upstream must not be supplied more than once".to_string(),
            );
        }
        parsed = Some(this);
    }
    Ok(parsed.unwrap_or(true))
}

pub(crate) async fn handle_delete<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    id: &str,
    namespace: &str,
    query: Option<&str>,
    apply_mode: LiveApplyMode,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let _write_permit = match state.admit_write().await {
        Ok(permit) => permit,
        Err(response) => return Ok(response),
    };

    if let Err(message) = validate_resource_id(id) {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    let delete_query = match R::parse_delete_query(query) {
        Ok(opts) => opts,
        Err(message) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": message}),
            ));
        }
    };

    let db_arc = match state.db.as_ref() {
        Some(db) => db.clone(),
        None => {
            return Ok(super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };
    let db = db_arc.as_ref();
    let mut namespace_config_admission_guard = if R::SERIALIZE_NAMESPACE_CONFIG_ADMISSION {
        match lock_namespace_config_admission(db_arc.clone(), namespace).await {
            Ok(guard) => Some(guard),
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
    } else {
        None
    };
    let existing = match R::db_get_for_write(db, namespace, id).await {
        Ok(None) => {
            return Ok(not_found_response::<R>());
        }
        Err(error) if is_row_decode_rejection(&error) => {
            // Issue #2997: the target row exists but cannot be decoded. Skip
            // namespace-snapshot recovery (that load fails for the same row) and
            // delete by id so admin remains the in-band repair path.
            let persistence =
                match audit::spawn_with_request_slot(persist_undecodable_delete_repair::<R>(
                    OwnedWriteSettlementContext {
                        db: db_arc.clone(),
                        namespace: namespace.to_string(),
                        guard: namespace_config_admission_guard.take(),
                        http_client: super::plugin_validation_http_client(state),
                        state: state.clone(),
                        actor: actor.clone(),
                    },
                    id.to_string(),
                    delete_query.clone(),
                ))
                .await
                {
                    Ok(result) => result,
                    Err(error) => Err(anyhow::anyhow!(
                        "namespace undecodable-row delete persistence task failed: {error}"
                    )),
                };
            return match persistence {
                Ok(true) => Ok(state
                    .complete_live_config_mutation_after_commit_boxed(
                        namespace,
                        _write_permit,
                        super::empty_response(StatusCode::NO_CONTENT),
                        apply_mode,
                    )
                    .await),
                Ok(false) => Ok(not_found_response::<R>()),
                Err(error) => Ok(R::map_delete_db_error(&error)),
            };
        }
        Err(error) => {
            return Ok(R::map_precheck_db_error(&error));
        }
        Ok(Some(resource)) => resource,
    };
    let previous_snapshot = if R::SERIALIZE_NAMESPACE_CONFIG_ADMISSION {
        match db.load_namespace_snapshot(namespace).await {
            Ok(snapshot) => Some(snapshot),
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
    } else {
        None
    };
    let previous_api_spec = match R::late_delete_api_spec_snapshot(
        db,
        namespace,
        &existing,
        previous_snapshot.as_ref(),
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => return Ok(R::map_precheck_db_error(&error)),
    };

    let validation_ctx = ValidationCtx::from_state(state);
    if let Err(error) = R::before_delete(db, state, namespace, &existing, &validation_ctx).await {
        return Ok(map_after_validate_error::<R>(error));
    }

    let persistence = match audit::spawn_with_request_slot(persist_delete_to_settlement(
        OwnedWriteSettlementContext {
            db: db_arc.clone(),
            namespace: namespace.to_string(),
            guard: namespace_config_admission_guard.take(),
            http_client: super::plugin_validation_http_client(state),
            state: state.clone(),
            actor: actor.clone(),
        },
        id.to_string(),
        OwnedLateDeleteRecovery {
            previous: existing.clone(),
            config: previous_snapshot,
            api_spec: previous_api_spec,
        },
        delete_query,
    ))
    .await
    {
        Ok(result) => result,
        Err(error) => Err(anyhow::anyhow!(
            "namespace delete persistence task failed: {error}"
        )),
    };
    match persistence {
        Ok(true) => Ok(state
            .complete_live_config_mutation_after_commit_boxed(
                namespace,
                _write_permit,
                super::empty_response(StatusCode::NO_CONTENT),
                apply_mode,
            )
            .await),
        Ok(false) => Ok(not_found_response::<R>()),
        Err(error) => Ok(R::map_delete_db_error(&error)),
    }
}

pub(crate) fn prepare_batch_resource<R: AdminResource>(
    resource: &mut R,
    namespace: &str,
    now: DateTime<Utc>,
    validation_ctx: &ValidationCtx<'_>,
) -> Result<(), BatchPreparationError> {
    if resource.id().is_empty() {
        resource.set_id(Uuid::new_v4().to_string());
    } else if let Err(message) = validate_resource_id(resource.id()) {
        return Err(BatchPreparationError::Validation(vec![message]));
    }

    resource.normalize();
    resource.set_namespace(namespace.to_string());
    resource
        .validate(validation_ctx)
        .map_err(ValidationError::into_messages)
        .map_err(BatchPreparationError::Validation)?;
    if let Err(error) = resource.prepare_for_write() {
        return Err(match error {
            PrepareWriteError::InvalidRequest(message) => {
                BatchPreparationError::Validation(vec![message])
            }
            PrepareWriteError::Internal(message) => BatchPreparationError::Internal(message),
        });
    }
    resource.set_created_at(now);
    resource.set_updated_at(now);
    Ok(())
}

pub(crate) fn redact_consumer_for_response(consumer: &Consumer) -> Consumer {
    super::redact_consumer_credentials(consumer)
}

pub(crate) fn consumer_response_body(consumer: &Consumer) -> Value {
    json!(redact_consumer_for_response(consumer))
}

pub(crate) fn consumer_audit_body(consumer: &Consumer) -> Value {
    json!(super::redact_consumer_credentials_for_audit(consumer))
}

pub(crate) fn consumer_persist_error_response(error: &anyhow::Error) -> Response<Full<Bytes>> {
    if config_update_target_was_not_found(error) {
        return not_found_response::<Consumer>();
    }
    if is_mtls_dns_admission_unavailable(error) {
        return super::mtls_dns_admission_unavailable_response();
    }
    let unique_conflict =
        is_mtls_dns_identity_conflict(error) || super::chain_has_unique_constraint_violation(error);
    let message = consumer_persist_error_message(error);
    let status = if unique_conflict {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    super::json_response(status, &json!({"error": message}))
}

/// Redact persistence-level diagnostics before they reach an admin response.
/// MongoDB duplicate-key errors can echo indexed credential-derived values;
/// callers need the conflict disposition, never credential or index metadata.
/// Every branch renders a constant or an internally constructed typed message,
/// and the fallback logs no error text at all, so neither the wire nor the
/// admin log carries driver-provided material.
pub(crate) fn consumer_persist_error_message(error: &anyhow::Error) -> String {
    if is_mtls_dns_admission_unavailable(error) {
        MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE.to_string()
    } else if let Some(conflict) = mtls_dns_identity_conflict(error) {
        // Render the typed conflict, not the chain's outermost message: the
        // identities it names are internally constructed and not secrets, but
        // any driver context wrapped above it would be.
        conflict.to_string()
    } else if super::chain_has_unique_constraint_violation(error) {
        // Chain-aware: a MongoDB replica-set write wraps the inner E11000 in
        // transaction context, so matching only the outermost message would
        // drop a credential-index conflict into the branch below.
        "Consumer identity or credential conflicts with another Consumer in the namespace"
            .to_string()
    } else {
        super::redacted_persistence_error_message("consumer_persist", error).to_string()
    }
}

pub(crate) fn hash_consumer_credentials(
    consumer: &mut Consumer,
) -> Result<(), crate::config::types::BasicAuthCredentialPreparationError> {
    super::hash_consumer_secrets(consumer)
}

pub(crate) fn hash_basic_auth_credentials(
    cred: &mut Value,
) -> Result<(), crate::config::types::BasicAuthCredentialPreparationError> {
    super::hash_credential_passwords(cred)
}

pub(crate) fn validate_plugin_config_definition(
    state: &AdminState,
    pc: &PluginConfig,
) -> Result<(), String> {
    super::validate_plugin_config_definition(pc, super::plugin_validation_http_client(state))
}

async fn validate_openapi_validator_precondition(
    db: &dyn DatabaseBackend,
    namespace: &str,
    resource: &PluginConfig,
) -> Result<(), AfterValidateError> {
    if resource.plugin_name != "openapi_validator" {
        return Ok(());
    }
    if resource.scope != PluginScope::Proxy {
        return Err(AfterValidateError::BadRequest(vec![
            "openapi_validator requires scope 'proxy'".to_string(),
        ]));
    }
    let Some(proxy_id) = resource.proxy_id.as_deref() else {
        return Err(AfterValidateError::BadRequest(vec![
            "openapi_validator requires proxy_id".to_string(),
        ]));
    };
    // The lookup is namespace-predicated, so a proxy living in another
    // namespace is indistinguishable from a missing one — cross-namespace
    // references are rejected without disclosing other tenants' resources.
    match db.get_proxy(namespace, proxy_id).await {
        Ok(Some(proxy)) if proxy.api_spec_id.is_none() => {
            Err(AfterValidateError::BadRequest(vec![
                "openapi_validator requires a proxy with an attached api_spec".to_string(),
            ]))
        }
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(AfterValidateError::BadRequest(vec![format!(
            "proxy_id '{}' does not exist in namespace '{}'",
            proxy_id, namespace
        )])),
        Err(error) => Err(AfterValidateError::Db(error)),
    }
}

pub(crate) async fn validate_mesh_route_dispatch_plugin_upstream_references(
    db: &dyn DatabaseBackend,
    namespace: &str,
    plugin_config: &PluginConfig,
    batch_upstream_ids: Option<&HashSet<&str>>,
) -> DbResult<Vec<String>> {
    if !plugin_config.enabled || plugin_config.plugin_name != "mesh_route_dispatch" {
        return Ok(Vec::new());
    }

    let dispatch_config = match MeshRouteDispatchConfig::from_value(&plugin_config.config) {
        Ok(config) => config,
        Err(_) => return Ok(Vec::new()),
    };

    let mut errors = Vec::new();
    for (rule_idx, rule) in dispatch_config.rules.iter().enumerate() {
        let Some(upstream_id) = rule.destination.upstream_id.as_deref() else {
            continue;
        };
        if batch_upstream_ids.is_some_and(|ids| ids.contains(upstream_id)) {
            continue;
        }

        match db.check_upstream_exists(upstream_id, namespace).await {
            Ok(true) => {}
            Ok(false) => {
                // Reads are namespace-predicated, so an upstream in another
                // namespace reports as non-existent (cross-namespace
                // references are equally forbidden either way).
                errors.push(format!(
                    "PluginConfig '{}' (mesh_route_dispatch) rule {} references upstream_id '{}' that does not exist in namespace '{}'",
                    plugin_config.id, rule_idx, upstream_id, namespace
                ));
            }
            Err(error) => return Err(error),
        }
    }

    Ok(errors)
}

// The paginated namespace plugin-config loader that fed the backend-TLS-SNI /
// direct-H2 reverse-write admission screener was retired with that gate: an
// H1 SNI dial is now a supported representation, so an Upstream / Proxy write
// no longer has to reject a buffering, retrying, or `pool_enable_http2: false`
// association. Genuinely unrepresentable dials still fail closed at runtime.

/// The one redacted plugin-configuration projection.
///
/// Every non-admin read, every management audit record, and every diagnostic
/// rendering of a plugin `config` goes through here. The sensitivity contract
/// itself lives in [`crate::admin::plugin_config_projection`]: a per-plugin
/// schema of credential-bearing paths, backed by the historical name heuristic
/// and a structural URL-userinfo sweep.
pub(crate) fn plugin_config_audit_body(resource: &PluginConfig) -> Value {
    let mut body = json!(resource);
    if let Some(config) = body.get_mut("config") {
        crate::admin::plugin_config_projection::project_plugin_config(
            &resource.plugin_name,
            config,
        );
    }
    body
}

fn upstream_audit_body(resource: &Upstream) -> Value {
    let mut body = json!(resource);
    if let Some(token) = body
        .get_mut("service_discovery")
        .and_then(|sd| sd.get_mut("consul"))
        .and_then(|consul| consul.get_mut("token"))
        && !token.is_null()
    {
        *token = json!(crate::plugins::utils::metadata_redaction::REDACTED_PLACEHOLDER);
    }
    body
}

pub(crate) async fn check_port_available(
    port: u16,
    bind_address: &str,
    udp: bool,
) -> Result<(), String> {
    super::check_port_available(port, bind_address, udp).await
}

/// Validate the exact stream-listener group produced by creating or updating
/// `resource` in `namespace`.
///
/// Stream ports are no longer unconditionally unique: an opaque-TLS SNI group
/// or an L4 `stream_match` group deliberately stores multiple proxy rows on one
/// port. Persistence therefore cannot use a unique `(namespace, listen_port)`
/// index as its admission rule. Instead, admin writes load the authoritative
/// namespace snapshot under the namespace admission lease, replace this
/// resource in the affected port bucket, and run the same group validator used
/// by file, database-poll, and DP admission.
///
/// The returned boolean reports whether another stream proxy already owns the
/// port. In database mode that means the OS bind probe must be skipped: the
/// running Ferrum listener is expected to own the socket, and reconcile will
/// rebuild it as the validated shared listener after the write commits.
pub(crate) async fn validate_stream_port_candidate(
    db: &dyn DatabaseBackend,
    namespace: &str,
    resource: &Proxy,
) -> Result<bool, AfterValidateError> {
    if !resource.dispatch_kind.is_stream() {
        return Ok(false);
    }
    let Some(port) = resource.listen_port else {
        // The resource-level validator emits the field-specific missing-port
        // error before this helper is called.
        return Ok(false);
    };

    // Classify resource-local mistakes (for example `hosts` on a terminating
    // or backend-TLS-originating listener) as a field-level bad request. Only
    // conflicts introduced by combining otherwise-valid rows on one port are
    // 409 listener-group conflicts.
    GatewayConfig {
        proxies: vec![resource.clone()],
        ..Default::default()
    }
    .validate_stream_proxies()
    .map_err(AfterValidateError::BadRequest)?;

    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    let shares_existing_port = candidate.proxies.iter().any(|proxy| {
        proxy.namespace == namespace
            && proxy.id != resource.id
            && proxy.dispatch_kind.is_stream()
            && proxy.listen_port == Some(port)
    });
    candidate.proxies.retain(|proxy| {
        proxy.namespace == namespace
            && proxy.id != resource.id
            && proxy.dispatch_kind.is_stream()
            && proxy.listen_port == Some(port)
    });
    candidate.proxies.push(resource.clone());
    // `Proxy.resolved_tls` is a `#[serde(skip)]` derived projection, not a wire
    // field. The namespace snapshot arrives with it resolved, but the incoming
    // admin resource has only run `Proxy::normalize_fields()`, which cannot
    // resolve it (that needs the namespace's upstream set). Leaving the bucket
    // half-projected makes `validate_stream_proxies`'s shared-`tcps`
    // backend-TLS agreement check compare a resolved peer against a defaulted
    // candidate — `verify_server_cert` alone flips `true` → `false` — and reject
    // an identical, valid L4 `stream_match` group. Re-derive over the assembled
    // bucket (the snapshot's upstreams are untouched by the retain above) so the
    // comparison is like-for-like.
    candidate.resolve_upstream_tls();
    candidate
        .validate_stream_proxies()
        .map_err(AfterValidateError::Conflict)?;
    Ok(shares_existing_port)
}

pub(crate) async fn check_consumer_credential_uniqueness(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
    exclude_consumer_id: Option<&str>,
) -> DbResult<Option<String>> {
    for cred_type in ["keyauth", "mtls_auth"] {
        if let Some(cred_value) = consumer.credentials.get(cred_type)
            && let Some(message) = check_credential_value_uniqueness(
                db,
                namespace,
                cred_type,
                cred_value,
                exclude_consumer_id,
            )
            .await?
        {
            return Ok(Some(message));
        }
    }

    Ok(None)
}

pub(crate) async fn check_credential_value_uniqueness(
    db: &dyn DatabaseBackend,
    namespace: &str,
    cred_type: &str,
    cred_value: &Value,
    exclude_consumer_id: Option<&str>,
) -> DbResult<Option<String>> {
    let entries = Consumer::credential_entries_from_value(cred_value);

    match cred_type {
        "keyauth" => {
            for entry in entries {
                if let Some(key) = entry.get("key").and_then(|value| value.as_str()) {
                    match db
                        .check_keyauth_key_unique(namespace, key, exclude_consumer_id)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            return Ok(Some(
                                "A consumer with this API key already exists".to_string(),
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        "mtls_auth" => {
            for entry in entries {
                if let Some(identity) = entry.get("identity").and_then(|value| value.as_str()) {
                    match db
                        .check_mtls_identity_unique(namespace, identity, exclude_consumer_id)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            return Ok(Some(
                                "A consumer with this mTLS identity already exists".to_string(),
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

// Strip api_spec_id from client-submitted resources.  This field is
// admin-only ownership metadata set exclusively by the spec import
// handlers.  Allowing clients to set it via regular CRUD endpoints
// would let them claim spec ownership of hand-managed resources,
// causing unintended deletion during spec lifecycle operations.
// SQL INSERT/UPDATE statements already exclude the column, but Mongo's
// replace_one serializes the full struct.

#[async_trait::async_trait]
impl AdminResource for Upstream {
    fn labels_mut(&mut self) -> Option<&mut std::collections::BTreeMap<String, String>> {
        Some(&mut self.labels)
    }

    fn restore_absent_update_fields(
        &mut self,
        existing: &Self,
        raw: &serde_json::Map<String, serde_json::Value>,
    ) {
        if !raw.contains_key("labels") {
            self.labels = existing.labels.clone();
        }
    }

    const RESOURCE_NAME: &'static str = "upstream";
    const RESOURCE_LABEL: &'static str = "Upstream";
    const VALIDATION_ERROR_LABEL: &'static str = "upstream fields";
    const NOT_FOUND_MESSAGE: &'static str = "Upstream not found";
    // Serialize same-namespace upstream creates/updates/deletes through the
    // durable namespace config admission lease (local mutex + DB lease) so the
    // name precheck is authoritative across admin instances. The SQL/Mongo
    // unique `(namespace, name)` indexes remain the cross-process persistence
    // backstop when a writer bypasses this path.
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn normalize(&mut self) {
        self.api_spec_id = None;
        self.normalize_fields();
    }

    fn audit_body(resource: &Self) -> Value {
        upstream_audit_body(resource)
    }

    fn response_body_for_role(resource: &Self, role: AdminRole) -> Value {
        if role == AdminRole::Admin {
            Self::response_body(resource)
        } else {
            upstream_audit_body(resource)
        }
    }

    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        if self.targets.is_empty() && self.service_discovery.is_none() {
            return Err(ValidationError::Message(
                "At least one target is required (or configure service_discovery)".to_string(),
            ));
        }
        // Reject mesh-projected fields on the admin write path. This is an
        // operator-provided admission entry point, so the projected-field rejection
        // is correct here (it is intentionally NOT in `validate_fields`, which also
        // runs on the mesh slice-apply path and would false-error there).
        self.validate_operator_provided_fields()
            .map_err(ValidationError::Fields)?;
        self.validate_fields().map_err(ValidationError::Fields)?;
        // Screen literal-IP targets against the backend egress policy so an
        // admin write cannot point an upstream at a denied (e.g. cloud-metadata)
        // address that file/restore loads would reject.
        self.validate_backend_egress_ips(ctx.backend_allow_ips)
            .map_err(ValidationError::Fields)
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.upstreams
    }

    fn map_delete_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        let error_chain_contains = |needle| {
            error
                .chain()
                .any(|cause| cause.to_string().contains(needle))
        };
        if error_chain_contains("referenced by one or more proxies") {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": "Upstream is referenced by one or more proxies and cannot be deleted"}),
            );
        }
        if error_chain_contains("referenced by mesh_route_dispatch plugin_config") {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": "Upstream is referenced by a mesh_route_dispatch plugin_config and cannot be deleted"}),
            );
        }
        super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &super::db_error_response(error),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_upstream(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_upstreams_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.query_offset_i64(),
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_upstream(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_upstream(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_upstream(namespace, id).await
    }

    type DeleteQuery = ();

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        if let Some(name) = resource.name.as_deref() {
            match db
                .check_upstream_name_unique(namespace, name, exclude_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(Some(format!("Upstream name '{}' already exists", name)));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(None)
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        _state: &AdminState,
        namespace: &str,
        resource: &Self,
        _existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        let subset_names: HashSet<&str> = resource
            .subsets
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|subset| subset.name.as_str())
            .collect();
        let mut errors = Vec::new();
        let mut offset = 0_i64;
        const PAGE_SIZE: i64 = 1_000;

        loop {
            let page = db
                .list_proxies_paginated(namespace, PAGE_SIZE, offset)
                .await
                .map_err(AfterValidateError::Db)?;
            let items_len = page.items.len() as i64;

            for proxy in page.items {
                if proxy.upstream_id.as_deref() == Some(resource.id.as_str())
                    && let Some(subset_name) = proxy.upstream_subset.as_deref()
                    && !subset_names.contains(subset_name)
                {
                    errors.push(format!(
                        "upstream '{}' cannot remove subset '{}' while proxy '{}' references it",
                        resource.id, subset_name, proxy.id
                    ));
                }
            }

            if items_len == 0 {
                break;
            }
            offset += items_len;
            if offset >= page.total {
                break;
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AfterValidateError::BadRequest(errors))
        }
    }
}

/// Namespace-keyed gateway trust bundles (issue #3727).
///
/// The resource is a SINGLETON per namespace: a namespace's projected trust
/// state must be unambiguous, so a second create in the same namespace is a
/// 409. That rule is enforced in three places on purpose — here as a friendly
/// precheck, in the store's transaction, and finally by the SQL `namespace`
/// primary key / MongoDB `_id`, which is the only tier a concurrent writer on
/// another admin replica cannot race past.
///
/// There is deliberately no cached-config read fallback: trust state gates peer
/// verification, so answering from a possibly-stale in-memory snapshot when the
/// database is unreachable would be worse than reporting the outage.
#[async_trait::async_trait]
impl AdminResource for GatewayTrustBundleRecord {
    const RESOURCE_NAME: &'static str = "gateway trust bundle";
    const RESOURCE_LABEL: &'static str = "Gateway trust bundle";
    const VALIDATION_ERROR_LABEL: &'static str = "gateway trust bundle fields";
    const NOT_FOUND_MESSAGE: &'static str = "Gateway trust bundle not found";
    // Serialize same-namespace writes through the durable namespace config
    // admission lease so the singleton precheck is authoritative across admin
    // instances, exactly like upstream name uniqueness.
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;
    // `revision` is assigned by the store from the durable config-change
    // sequence, so neither a create body (which carries `0`) nor an update body
    // (which carries the client's *expectation*) knows the committed value. The
    // success response and the audit after-image are therefore taken from an
    // authoritative re-read rather than from the request-side resource.
    const REREAD_AFTER_WRITE: bool = true;

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn normalize(&mut self) {
        // Attribution is server-assigned in `set_actor`; drop anything the
        // client tried to author so the stored value is always the verified
        // admin subject.
        self.updated_by = None;
        // Trim only. The id default is derived from the SERVER-selected
        // namespace through `default_id_for_namespace`, because `normalize()`
        // runs before `set_namespace()` and `self.namespace` is still whatever
        // the request body claimed at this point.
        self.trim_fields();
    }

    fn set_actor(&mut self, actor: &str) {
        self.updated_by = Some(actor.to_string());
    }

    fn default_id_for_namespace(namespace: &str) -> Option<String> {
        Some(GatewayTrustBundleRecord::default_singleton_id(namespace))
    }

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.gateway_trust_bundles
    }

    fn allow_cached_read_fallback(_error: &anyhow::Error) -> bool {
        false
    }

    fn prepare_for_update(&mut self, existing: &Self) {
        // `created_at` belongs to the resource, not to this request.
        self.created_at = existing.created_at;
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        if let Some(conflict) =
            crate::config::db_backend::gateway_trust_bundle_revision_conflict(error)
        {
            // Render the typed conflict, never the chain's outer message: that
            // message can carry driver/DSN context.
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({
                    "error": crate::config::db_backend::GATEWAY_TRUST_BUNDLE_REVISION_CONFLICT_MESSAGE,
                    "expected_revision": conflict.expected,
                    "current_revision": conflict.current,
                }),
            );
        }
        if super::chain_has_unique_constraint_violation(error) {
            // The namespace primary key rejected a second record: another admin
            // replica won the create race.
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": GATEWAY_TRUST_BUNDLE_SINGLETON_CONFLICT_MESSAGE}),
            );
        }
        super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &super::db_error_response(error),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_gateway_trust_bundle(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_gateway_trust_bundles_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.query_offset_i64(),
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_gateway_trust_bundle(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        // `revision` on the request body is the client's expectation, not the
        // value to store: the store assigns the next revision itself. `0` (or
        // an omitted field) means "no expectation" and skips the compare-and-set
        // so a first-party tool can still force a write, while any non-zero
        // value makes a lost race a 409 instead of a silent overwrite.
        let expected = (resource.revision != 0).then_some(resource.revision);
        db.update_gateway_trust_bundle(resource, expected).await
    }

    async fn compensate_late_update(db: &dyn DatabaseBackend, previous: &Self) -> DbResult<bool> {
        // Undo a late write by restoring the prior MATERIAL, stating no
        // expectation. `previous.revision` is the revision from before the late
        // write, so routing this through `db_update` would assert a revision the
        // store has already moved past and every compensation would fail. The
        // restored record still receives a fresh backend-assigned revision, so
        // the rollback is a new incarnation of the material rather than a
        // resurrection of the old counter value.
        db.update_gateway_trust_bundle(previous, None).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_gateway_trust_bundle(namespace, id).await
    }

    type DeleteQuery = ();

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        _resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        match db.get_namespace_gateway_trust_bundle(namespace).await? {
            Some(existing) if Some(existing.id.as_str()) != exclude_id => Ok(Some(
                GATEWAY_TRUST_BUNDLE_SINGLETON_CONFLICT_MESSAGE.to_string(),
            )),
            _ => Ok(None),
        }
    }
}

/// Operator-facing message when a namespace already holds a trust-bundle
/// record. Names no ids and no material.
pub(crate) const GATEWAY_TRUST_BUNDLE_SINGLETON_CONFLICT_MESSAGE: &str =
    "namespace already has a gateway trust bundle; update or delete the existing resource instead";

#[async_trait::async_trait]
impl AdminResource for PluginConfig {
    fn labels_mut(&mut self) -> Option<&mut std::collections::BTreeMap<String, String>> {
        Some(&mut self.labels)
    }

    fn restore_absent_update_fields(
        &mut self,
        existing: &Self,
        raw: &serde_json::Map<String, serde_json::Value>,
    ) {
        if !raw.contains_key("labels") {
            self.labels = existing.labels.clone();
        }
    }

    const RESOURCE_NAME: &'static str = "plugin config";
    const RESOURCE_LABEL: &'static str = "Plugin config";
    const VALIDATION_ERROR_LABEL: &'static str = "plugin config fields";
    const NOT_FOUND_MESSAGE: &'static str = "Plugin config not found";
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;
    const ID_CONFLICT_LABEL: &'static str = "PluginConfig";

    /// `PUT` is a full replace and `enabled` carries `#[serde(default =
    /// "default_true")]`, so an omitted key would flip a deliberately disabled
    /// plugin row back on with a `200`. `openapi.yaml` already declares
    /// `enabled` required; enforce that on the replace path only — a `POST`
    /// has no prior state to overwrite, so it keeps defaulting.
    fn validate_raw_body(body: &[u8], action: WriteAction<'_>) -> Result<(), String> {
        let WriteAction::Update { .. } = action else {
            return Ok(());
        };
        // A non-object body falls through to the shared `from_slice` error so
        // the caller keeps seeing the existing `Invalid body: ...` message.
        if let Ok(Value::Object(raw)) = serde_json::from_slice::<Value>(body)
            && !raw.contains_key("enabled")
        {
            return Err(
                "PUT is a full replace: 'enabled' is required (openapi.yaml declares it required). Send the field explicitly."
                    .into(),
            );
        }
        Ok(())
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn normalize(&mut self) {
        self.api_spec_id = None;
        self.normalize_fields();
    }

    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)?;
        // A mesh_route_dispatch rule can override a matched request's backend to
        // an arbitrary literal IP; screen those against the egress policy here so
        // a direct/batch plugin write can't smuggle in a denied (e.g.
        // cloud-metadata) destination the whole-config loaders reject.
        if self.plugin_name == "mesh_route_dispatch" {
            crate::plugins::screen_mesh_route_dispatch_egress(&self.config, ctx.backend_allow_ips)
                .map_err(ValidationError::Fields)?;
        }
        // Redis-backed plugins (rate_limiting / request_deduplication /
        // ai_semantic_cache) build their client from `redis_url` without the
        // egress policy; screen a denied literal endpoint on direct/batch admin
        // writes too, matching the policy-aware whole-config / API-spec paths.
        crate::plugins::screen_redis_endpoint_egress(&self.config, ctx.backend_allow_ips)
            .map_err(|e| ValidationError::Fields(vec![e]))?;
        // ldap_auth (ldap_url) / kafka_logging (broker_list) dial their own
        // resolver outside the shared client + DnsCache; screen their literal
        // endpoints on direct/batch admin writes too.
        crate::plugins::screen_direct_client_endpoint_egress(
            &self.plugin_name,
            &self.config,
            ctx.backend_allow_ips,
        )
        .map_err(|e| ValidationError::Fields(vec![e]))?;
        Ok(())
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.plugin_configs
    }

    fn audit_body(resource: &Self) -> Value {
        plugin_config_audit_body(resource)
    }

    fn response_body_for_role(resource: &Self, role: AdminRole) -> Value {
        if role == AdminRole::Admin {
            Self::response_body(resource)
        } else {
            plugin_config_audit_body(resource)
        }
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": errors.join("; ")}),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_plugin_config(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_plugin_configs_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.query_offset_i64(),
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_plugin_config(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_plugin_config(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_plugin_config(namespace, id).await
    }

    type DeleteQuery = ();

    async fn compensate_late_delete(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: &Self,
        previous_snapshot: Option<&GatewayConfig>,
        _previous_api_spec: Option<&ApiSpecDeleteSnapshot>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<()> {
        let snapshot = previous_snapshot.ok_or_else(|| {
            anyhow::anyhow!("late plugin delete recovery is missing the namespace snapshot")
        })?;
        db.create_plugin_config(previous).await?;
        for prior_proxy in &snapshot.proxies {
            let prior_associations = prior_proxy
                .plugins
                .iter()
                .filter(|association| association.plugin_config_id == previous.id)
                .cloned()
                .collect::<Vec<_>>();
            if prior_associations.is_empty() {
                continue;
            }
            let Some(mut current_proxy) =
                db.get_proxy_for_write(namespace, &prior_proxy.id).await?
            else {
                continue;
            };
            let mut changed = false;
            for association in prior_associations {
                if !current_proxy
                    .plugins
                    .iter()
                    .any(|current| current.plugin_config_id == association.plugin_config_id)
                {
                    current_proxy.plugins.push(association);
                    changed = true;
                }
            }
            if changed {
                current_proxy.updated_at = Utc::now();
                if !db.update_proxy(&current_proxy).await? {
                    anyhow::bail!(
                        "late plugin delete compensation could not restore proxy '{}' associations",
                        current_proxy.id
                    );
                }
            }
        }
        Ok(())
    }

    async fn intervening_write_recovery(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: Option<&Self>,
        http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<InterveningWriteRecovery> {
        let mut candidate = db.load_namespace_snapshot(namespace).await?;
        if validate_transaction_log_schema_graph_on_blocking_pool(
            candidate.clone(),
            http_client.clone(),
        )
        .await
        .is_ok()
        {
            return Ok(InterveningWriteRecovery::KeepCurrent);
        }

        let previous = previous.ok_or_else(|| {
            anyhow::anyhow!("late plugin recovery is missing the prior plugin config")
        })?;
        if let Some(current) = candidate
            .plugin_configs
            .iter_mut()
            .find(|plugin| plugin.namespace == namespace && plugin.id == previous.id)
        {
            *current = previous.clone();
        } else {
            candidate.plugin_configs.push(previous.clone());
        }
        match validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await {
            Ok(()) => Ok(InterveningWriteRecovery::Compensate),
            Err(AfterValidateError::BadRequest(errors)) => anyhow::bail!(
                "late plugin recovery could not produce a valid transaction-log schema graph: {}",
                errors.join("; ")
            ),
            Err(AfterValidateError::Db(error)) => Err(error),
            Err(AfterValidateError::Conflict(errors)) => anyhow::bail!(
                "late plugin recovery conflicted while validating the transaction-log schema graph: {}",
                errors.join("; ")
            ),
            Err(AfterValidateError::Response(_)) => anyhow::bail!(
                "late plugin recovery received an unexpected response while validating the transaction-log schema graph"
            ),
        }
    }

    async fn late_create_compensation_safe(
        db: &dyn DatabaseBackend,
        namespace: &str,
        current: &Self,
        written: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<bool> {
        if current.updated_at != written.updated_at {
            return Ok(false);
        }
        let own_proxy_id = if written.scope == PluginScope::Proxy {
            written.proxy_id.as_deref()
        } else {
            None
        };
        if plugin_has_foreign_proxy_association(db, namespace, &written.id, own_proxy_id).await? {
            return Ok(false);
        }
        let mut candidate = db.load_namespace_snapshot(namespace).await?;
        candidate
            .plugin_configs
            .retain(|plugin| plugin.namespace != namespace || plugin.id != written.id);
        // Compensating the create also drops the association the create wrote
        // (issue #4611) — the delete cascades it — so the candidate graph must
        // not keep a proxy pointing at the removed config.
        for proxy in &mut candidate.proxies {
            proxy
                .plugins
                .retain(|association| association.plugin_config_id != written.id);
        }
        Ok(
            validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client)
                .await
                .is_ok(),
        )
    }

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        if resource.enabled
            && resource.plugin_name == "prometheus_metrics"
            && enabled_prometheus_metrics_owner_exists(db, namespace, exclude_id).await?
        {
            return Ok(Some(
                "prometheus_metrics permits at most one enabled global instance; another config already owns the process registry"
                    .to_string(),
            ));
        }
        Ok(None)
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        let known_plugins = crate::plugins::available_plugins();
        if !known_plugins.contains(&resource.plugin_name.as_str()) {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "Unknown plugin name '{}'. Available plugins: {:?}",
                resource.plugin_name, known_plugins
            )]));
        }

        if let Some(proxy_id) = resource.proxy_id.as_deref() {
            match db.check_proxy_exists(proxy_id, namespace).await {
                Ok(true) => {}
                Ok(false) => {
                    // Proxy reads are namespace-predicated (issue #2122
                    // DB-M1): a proxy in another namespace reports as
                    // missing, so cross-namespace references are rejected
                    // without disclosing other tenants' resources.
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "proxy_id '{}' does not exist in namespace '{}'",
                        proxy_id, namespace
                    )]));
                }
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        if crate::plugins::transaction_log_schema::participates_in_config_graph(resource) {
            if let Err(error) = crate::plugins::validate_plugin_config_policy_only(
                &resource.plugin_name,
                &resource.config,
                &state.backend_allow_ips,
            ) {
                return Err(AfterValidateError::BadRequest(vec![format!(
                    "Invalid plugin config: {}",
                    error
                )]));
            }
        } else if let Err(error) = validate_plugin_config_definition(state, resource) {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "Invalid plugin config: {}",
                error
            )]));
        }

        validate_openapi_validator_precondition(db, namespace, resource).await?;

        let upstream_errors =
            validate_mesh_route_dispatch_plugin_upstream_references(db, namespace, resource, None)
                .await
                .map_err(AfterValidateError::Db)?;
        if !upstream_errors.is_empty() {
            return Err(AfterValidateError::BadRequest(upstream_errors));
        }

        if resource.plugin_name == "mtls_auth"
            || existing.is_some_and(|plugin| plugin.plugin_name == "mtls_auth")
        {
            validate_mtls_auth_candidate(db, namespace, None, Some(resource), None).await?;
        }
        // Validate the graph the write will produce, including the proxy
        // association it attaches (issue #4611).
        let attach_candidates = plugin_attach_proxy_candidates(db, namespace, resource)
            .await
            .map_err(AfterValidateError::Db)?;
        validate_plugin_graph_candidates(
            db,
            state,
            namespace,
            &attach_candidates,
            std::slice::from_ref(resource),
            None,
        )
        .await?;
        if crate::plugins::transaction_log_schema::is_enabled_config_graph_participant(resource)
            || existing.is_some_and(
                crate::plugins::transaction_log_schema::is_enabled_config_graph_participant,
            )
        {
            validate_transaction_log_schema_candidates(
                db,
                state,
                namespace,
                std::slice::from_ref(resource),
                None,
            )
            .await?;
        }

        Ok(())
    }

    async fn before_delete(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        existing: &Self,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        if existing.plugin_name == "mtls_auth" {
            validate_mtls_auth_candidate(db, namespace, None, None, Some(&existing.id)).await?;
        }
        validate_plugin_graph_candidates(db, state, namespace, &[], &[], Some(&existing.id))
            .await?;
        if crate::plugins::transaction_log_schema::is_enabled_config_graph_participant(existing) {
            validate_transaction_log_schema_candidates(
                db,
                state,
                namespace,
                &[],
                Some(&existing.id),
            )
            .await?;
        }
        Ok(())
    }
}

/// Check for an enabled Prometheus registry owner already persisted anywhere.
///
/// Direct CRUD and batch admission both call this before writing so neither can
/// persist a snapshot that the runtime ownership validator will reject on the
/// next poll. `exclude_id` makes an in-place PUT of the current namespace owner
/// valid without exempting an identically named resource in another namespace.
pub(crate) async fn enabled_prometheus_metrics_owner_exists(
    db: &dyn DatabaseBackend,
    namespace: &str,
    exclude_id: Option<&str>,
) -> DbResult<bool> {
    enabled_prometheus_metrics_owner_exists_inner(db, namespace, exclude_id, false).await
}

/// Restore replaces one namespace wholesale, so owners in that namespace do
/// not conflict with the incoming payload; owners in every other namespace do.
pub(crate) async fn enabled_prometheus_metrics_owner_exists_outside_namespace(
    db: &dyn DatabaseBackend,
    namespace: &str,
) -> DbResult<bool> {
    enabled_prometheus_metrics_owner_exists_inner(db, namespace, None, true).await
}

async fn enabled_prometheus_metrics_owner_exists_inner(
    db: &dyn DatabaseBackend,
    namespace: &str,
    exclude_id: Option<&str>,
    exclude_current_namespace: bool,
) -> DbResult<bool> {
    const PAGE_SIZE: i64 = 1_000;
    let mut namespaces = db.list_namespaces_authoritative().await?;
    namespaces.push(namespace.to_string());
    namespaces.sort_unstable();
    namespaces.dedup();

    for candidate_namespace in namespaces {
        if exclude_current_namespace && candidate_namespace == namespace {
            continue;
        }
        let mut offset = 0_i64;
        loop {
            let page = db
                .list_plugin_configs_paginated(&candidate_namespace, PAGE_SIZE, offset)
                .await?;
            let items_len = page.items.len() as i64;
            if page.items.into_iter().any(|plugin| {
                plugin.enabled
                    && plugin.plugin_name == "prometheus_metrics"
                    && !(candidate_namespace == namespace && exclude_id == Some(plugin.id.as_str()))
            }) {
                return Ok(true);
            }
            if items_len == 0 {
                break;
            }
            offset += items_len;
            if offset >= page.total {
                break;
            }
        }
    }

    Ok(false)
}

#[async_trait::async_trait]
impl AdminResource for Proxy {
    fn labels_mut(&mut self) -> Option<&mut std::collections::BTreeMap<String, String>> {
        Some(&mut self.labels)
    }

    const RESOURCE_NAME: &'static str = "proxy";
    const RESOURCE_LABEL: &'static str = "Proxy";
    const VALIDATION_ERROR_LABEL: &'static str = "proxy fields";
    const NOT_FOUND_MESSAGE: &'static str = "Proxy not found";
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;

    /// `plugins` is `#[serde(default)]`, so a `PUT` body that omits the key
    /// would silently detach every association — including an authentication
    /// plugin — with a `200`. Rejecting would break far more callers than it
    /// protects, so an absent key preserves the stored associations (the
    /// presence-aware `PUT` semantics `/namespaces` already has). An explicit
    /// `"plugins": []` still clears them.
    fn restore_absent_update_fields(
        &mut self,
        existing: &Self,
        raw: &serde_json::Map<String, serde_json::Value>,
    ) {
        if !raw.contains_key("labels") {
            self.labels = existing.labels.clone();
        }

        if !raw.contains_key("plugins") {
            self.plugins = existing.plugins.clone();
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn normalize(&mut self) {
        self.api_spec_id = None;
        if let Some(methods) = self.allowed_methods.as_mut() {
            for method in methods {
                *method = crate::config::types::normalize_http_method_token(method);
            }
        }
        self.normalize_fields();
    }

    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)?;
        // Screen literal-IP backend_host / dns_override against the egress
        // policy so an admin write cannot target a denied (e.g. cloud-metadata)
        // address that file/restore loads would reject.
        self.validate_backend_egress_ips(ctx.backend_allow_ips)
            .map_err(ValidationError::Fields)?;

        for host in &self.hosts {
            if let Err(message) = crate::config::types::validate_host_entry(host) {
                return Err(ValidationError::Message(format!(
                    "Invalid proxy hosts: {}",
                    message
                )));
            }
        }

        if !self.dispatch_kind.is_stream()
            && let Some(path) = self.listen_path.as_deref()
            && let Some(pattern) = path.strip_prefix('~')
            && !pattern.is_empty()
        {
            let anchored = crate::config::types::anchor_regex_pattern(pattern);
            if let Err(error) = regex::Regex::new(&anchored) {
                return Err(ValidationError::Message(format!(
                    "Invalid proxy listen_path: invalid regex '{}': {}",
                    path, error
                )));
            }
        }

        if self.dispatch_kind.is_stream() {
            match self.listen_port {
                None => {
                    return Err(ValidationError::Message(format!(
                        "Stream proxy (scheme {}) must have a listen_port",
                        self.scheme_display()
                    )));
                }
                Some(0) => {
                    return Err(ValidationError::Message(
                        "listen_port 0 must be >= 1".to_string(),
                    ));
                }
                Some(_) => {}
            }
        } else if let Some(port) = self.listen_port
            && port == 0
        {
            return Err(ValidationError::Message(
                "listen_port 0 must be >= 1".to_string(),
            ));
        }

        Ok(())
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.proxies
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": errors.join("; ")}),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_proxy(namespace, id).await
    }

    fn allow_cached_read_fallback(error: &anyhow::Error) -> bool {
        !is_proxy_plugin_association_load_error(error)
    }

    async fn db_get_for_write(
        db: &dyn DatabaseBackend,
        namespace: &str,
        id: &str,
    ) -> DbResult<Option<Self>> {
        db.get_proxy_for_write(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_proxies_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.query_offset_i64(),
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_proxy(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_proxy(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_proxy(namespace, id).await
    }

    type DeleteQuery = bool;

    fn parse_delete_query(query: Option<&str>) -> Result<bool, String> {
        parse_cleanup_orphaned_upstream_query(query)
    }

    async fn db_delete_from_request(
        db: &dyn DatabaseBackend,
        namespace: &str,
        id: &str,
        cleanup_orphaned_upstream: bool,
    ) -> DbResult<bool> {
        db.delete_proxy_with_orphan_cleanup(namespace, id, cleanup_orphaned_upstream)
            .await
    }

    async fn late_create_compensation_safe(
        db: &dyn DatabaseBackend,
        namespace: &str,
        current: &Self,
        written: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<bool> {
        if current.updated_at != written.updated_at {
            return Ok(false);
        }
        let current_associations = current
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect::<HashSet<_>>();
        let written_associations = written
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect::<HashSet<_>>();
        if current_associations != written_associations {
            return Ok(false);
        }
        Ok(!proxy_has_scoped_plugin(db, namespace, &written.id).await?)
    }

    async fn compensate_late_delete(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: &Self,
        previous_snapshot: Option<&GatewayConfig>,
        previous_api_spec: Option<&ApiSpecDeleteSnapshot>,
        http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<()> {
        if let Some(api_spec_snapshot) = previous_api_spec {
            let bundle = crate::admin::api_specs::ExtractedBundle {
                proxy: previous.clone(),
                upstream: api_spec_snapshot.upstream.clone(),
                plugins: api_spec_snapshot.plugins.clone(),
            };
            db.restore_api_spec_bundle(
                &bundle,
                &api_spec_snapshot.spec,
                &api_spec_snapshot.additional_upstreams,
                &api_spec_snapshot.additional_plugins,
                &http_client,
            )
            .await?;
            return Ok(());
        }

        let snapshot = previous_snapshot.ok_or_else(|| {
            anyhow::anyhow!("late proxy delete recovery is missing the namespace snapshot")
        })?;
        let associated_ids: HashSet<&str> = previous
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let other_associated_ids: HashSet<&str> = snapshot
            .proxies
            .iter()
            .filter(|proxy| proxy.id != previous.id)
            .flat_map(|proxy| proxy.plugins.iter())
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let affected_plugins = snapshot
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.proxy_id.as_deref() == Some(previous.id.as_str())
                    || (plugin.scope == PluginScope::ProxyGroup
                        && associated_ids.contains(plugin.id.as_str())
                        && !other_associated_ids.contains(plugin.id.as_str()))
            })
            .cloned()
            .collect::<Vec<_>>();
        let affected_upstreams = snapshot
            .upstreams
            .iter()
            .filter(|upstream| previous.upstream_id.as_deref() == Some(upstream.id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for upstream in &affected_upstreams {
            if db.get_upstream(namespace, &upstream.id).await?.is_none() {
                db.create_upstream(upstream).await?;
            }
        }
        let mut proxy_without_associations = previous.clone();
        proxy_without_associations.plugins.clear();
        db.create_proxy(&proxy_without_associations).await?;
        for plugin in affected_plugins {
            if db.get_plugin_config(namespace, &plugin.id).await?.is_none() {
                db.create_plugin_config(&plugin).await?;
            }
        }
        if !db.update_proxy(previous).await? {
            anyhow::bail!("late proxy delete compensation could not restore associations");
        }
        Ok(())
    }

    async fn late_delete_api_spec_snapshot(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: &Self,
        previous_snapshot: Option<&GatewayConfig>,
    ) -> DbResult<Option<ApiSpecDeleteSnapshot>> {
        let Some(spec) = db.get_api_spec_by_proxy(namespace, &previous.id).await? else {
            return Ok(None);
        };
        let upstreams = db.list_spec_owned_upstreams(namespace, &spec.id).await?;
        let plugins = db
            .list_spec_owned_plugin_configs(namespace, &spec.id)
            .await?;
        let upstream = match upstreams.as_slice() {
            [] => None,
            [upstream] => Some(upstream.clone()),
            _ => {
                return Err(api_spec_restore_snapshot_validation(format!(
                    "API spec '{}' owns multiple upstreams, which direct proxy delete recovery cannot reproduce safely",
                    spec.id
                )));
            }
        };
        let mut additional_upstreams = Vec::new();
        if let Some(current_upstream_id) = previous.upstream_id.as_deref()
            && upstream.as_ref().map(|item| item.id.as_str()) != Some(current_upstream_id)
        {
            match db.get_upstream(namespace, current_upstream_id).await? {
                Some(current) if current.api_spec_id.is_none() => {
                    additional_upstreams.push(current);
                }
                Some(current) => {
                    return Err(api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' cannot snapshot proxy '{}' current upstream '{}': it is owned by API spec '{}'",
                        spec.id,
                        previous.id,
                        current.id,
                        current.api_spec_id.as_deref().unwrap_or("<unknown>")
                    )));
                }
                None => {
                    return Err(api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' proxy '{}' references missing upstream '{}'",
                        spec.id, previous.id, current_upstream_id
                    )));
                }
            }
        }

        let snapshot = previous_snapshot.ok_or_else(|| {
            anyhow::anyhow!("direct API-spec proxy delete is missing the namespace snapshot")
        })?;
        let owned_plugin_ids: HashSet<&str> =
            plugins.iter().map(|plugin| plugin.id.as_str()).collect();
        let associated_ids: HashSet<&str> = previous
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let other_associated_ids: HashSet<&str> = snapshot
            .proxies
            .iter()
            .filter(|proxy| proxy.id != previous.id)
            .flat_map(|proxy| proxy.plugins.iter())
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let additional_plugin_ids = snapshot
            .plugin_configs
            .iter()
            .filter(|plugin| !owned_plugin_ids.contains(plugin.id.as_str()))
            .filter(|plugin| {
                plugin.proxy_id.as_deref() == Some(previous.id.as_str())
                    || (plugin.scope == PluginScope::ProxyGroup
                        && associated_ids.contains(plugin.id.as_str())
                        && !other_associated_ids.contains(plugin.id.as_str()))
            })
            .map(|plugin| plugin.id.clone())
            .collect::<Vec<_>>();
        let mut additional_plugins = Vec::with_capacity(additional_plugin_ids.len());
        for plugin_id in &additional_plugin_ids {
            let plugin = db
                .get_plugin_config(namespace, plugin_id)
                .await?
                .ok_or_else(|| {
                    api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' direct proxy delete snapshot lost plugin '{}' before persistence",
                        spec.id, plugin_id
                    ))
                })?;
            if let Some(owner) = plugin.api_spec_id.as_deref() {
                return Err(api_spec_restore_snapshot_validation(format!(
                    "API spec '{}' cannot delete proxy '{}': cascade plugin '{}' is owned by API spec '{}'",
                    spec.id, previous.id, plugin.id, owner
                )));
            }
            validate_api_spec_proxy_plugin_association(&plugin, &previous.id)
                .map_err(|error| api_spec_restore_snapshot_validation(error.to_string()))?;
            additional_plugins.push(plugin);
        }

        let additional_plugin_id_set: HashSet<&str> =
            additional_plugin_ids.iter().map(String::as_str).collect();
        for association in &previous.plugins {
            let plugin_id = association.plugin_config_id.as_str();
            if owned_plugin_ids.contains(plugin_id) || additional_plugin_id_set.contains(plugin_id)
            {
                continue;
            }
            let plugin = db
                .get_plugin_config(namespace, plugin_id)
                .await?
                .ok_or_else(|| {
                    api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' proxy association references missing plugin '{}'",
                        spec.id, plugin_id
                    ))
                })?;
            if let Some(owner) = plugin.api_spec_id.as_deref() {
                return Err(api_spec_restore_snapshot_validation(format!(
                    "API spec '{}' cannot delete proxy '{}': associated plugin '{}' is owned by API spec '{}'",
                    spec.id, previous.id, plugin.id, owner
                )));
            }
            validate_api_spec_proxy_plugin_association(&plugin, &previous.id)
                .map_err(|error| api_spec_restore_snapshot_validation(error.to_string()))?;
        }

        let bundle = crate::admin::api_specs::ExtractedBundle {
            proxy: previous.clone(),
            upstream: upstream.clone(),
            plugins: plugins.clone(),
        };
        validate_api_spec_restore_inputs(
            &bundle,
            &spec,
            &additional_upstreams,
            &additional_plugins,
            true,
        )
        .map_err(|error| api_spec_restore_snapshot_validation(error.to_string()))?;
        Ok(Some(ApiSpecDeleteSnapshot {
            spec,
            upstream,
            plugins,
            additional_upstreams,
            additional_plugins,
        }))
    }

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        if !resource.dispatch_kind.is_stream() {
            match db
                .check_listen_path_unique(
                    namespace,
                    resource.listen_path.as_deref(),
                    &resource.hosts,
                    exclude_id,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(Some(PROXY_ROUTE_CONFLICT_ERROR.to_string()));
                }
                Err(error) => return Err(error),
            }
        }

        if let Some(name) = resource.name.as_deref() {
            match db
                .check_proxy_name_unique(namespace, name, exclude_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => return Ok(Some(format!("Proxy name '{}' already exists", name))),
                Err(error) => return Err(error),
            }
        }

        Ok(None)
    }

    fn map_precheck_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        if let Some(validation) = error.downcast_ref::<ApiSpecRestoreSnapshotValidation>() {
            return super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": validation.to_string()}),
            );
        }
        super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &super::db_error_response(error),
        )
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        if let Some(conflict) = tcp_connection_throttle_attachment_conflict(error) {
            return Self::map_after_validate_errors(conflict.errors());
        }
        if super::chain_has_proxy_route_conflict(error) {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": PROXY_ROUTE_CONFLICT_ERROR}),
            );
        }
        if let Some(conflict) = mtls_dns_identity_conflict(error) {
            // Typed, chain-deep classification must render the typed message,
            // not the outermost context; see the default `map_persist_db_error`.
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": conflict.to_string() }),
            );
        }
        if super::chain_has_unique_constraint_violation(error) {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": super::RESOURCE_IDENTITY_CONFLICT_MESSAGE }),
            );
        }

        super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &super::db_error_response(error),
        )
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        if let Some(upstream_id) = resource.upstream_id.as_deref() {
            // Namespace-predicated lookup: an upstream in another namespace
            // reports as missing (cross-namespace references are equally
            // forbidden either way).
            match db.get_upstream(namespace, upstream_id).await {
                Ok(Some(upstream)) => {
                    if let Some(owner_spec_id) = upstream.api_spec_id.as_deref() {
                        let same_spec_proxy = existing
                            .and_then(|proxy| proxy.api_spec_id.as_deref())
                            == Some(owner_spec_id);
                        if !same_spec_proxy {
                            return Err(AfterValidateError::BadRequest(vec![format!(
                                "upstream_id '{}' is owned by api_spec '{}' and cannot be attached to proxy '{}'; create a hand-managed upstream or update the owning API spec",
                                upstream_id, owner_spec_id, resource.id
                            )]));
                        }
                    }
                    if let Some(subset_name) = resource.upstream_subset.as_deref() {
                        let subset_exists = upstream
                            .subsets
                            .as_ref()
                            .is_some_and(|subsets| subsets.iter().any(|s| s.name == subset_name));
                        if !subset_exists {
                            return Err(AfterValidateError::BadRequest(vec![format!(
                                "upstream_subset '{}' is not defined on upstream_id '{}'",
                                subset_name, upstream_id
                            )]));
                        }
                    }
                }
                Ok(None) => {
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "upstream_id '{}' does not exist in namespace '{}'",
                        upstream_id, namespace
                    )]));
                }
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        match db
            .validate_proxy_plugin_associations(resource.id(), namespace, &resource.plugins)
            .await
        {
            Ok(errors) if !errors.is_empty() => {
                return Err(AfterValidateError::BadRequest(vec![format!(
                    "Invalid proxy plugin associations: {}",
                    errors.join("; ")
                )]));
            }
            Ok(_) => {}
            Err(error) => return Err(AfterValidateError::Db(error)),
        }

        // Validate the exact post-write stream listener bucket before any
        // persistence. A valid shared SNI/L4 port is admitted; every invalid
        // duplicate remains fail-closed with the canonical group diagnostic.
        let shares_existing_stream_port =
            validate_stream_port_candidate(db, namespace, resource).await?;

        // HTTP proxy associations can make a dormant/global `san_dns` policy
        // effective just as stream proxies can. The candidate helper checks
        // every transport but returns immediately when this proxy has no
        // effective `mtls_auth` association; compatibility validation itself
        // remains stream-specific.
        validate_mtls_auth_candidate(db, namespace, Some(resource), None, None).await?;
        validate_plugin_graph_candidates(
            db,
            state,
            namespace,
            std::slice::from_ref(resource),
            &[],
            None,
        )
        .await?;

        if resource.dispatch_kind.is_stream()
            && let Some(port) = resource.listen_port
            && ctx.mode != "cp"
        {
            if ctx.reserved_ports.contains(&port) {
                return Err(AfterValidateError::Response(Box::new(
                    super::json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} conflicts with a gateway reserved port (proxy/admin/gRPC listener)",
                            port
                        )}),
                    ),
                )));
            }

            let port_changed = existing.and_then(|proxy| proxy.listen_port) != Some(port);
            let transport_changed = existing
                .map(|proxy| proxy.dispatch_kind.is_udp() != resource.dispatch_kind.is_udp())
                .unwrap_or(false);
            let should_probe = (existing.is_none() || port_changed || transport_changed)
                && !shares_existing_stream_port;
            if should_probe
                && let Err(error) = check_port_available(
                    port,
                    ctx.stream_bind_address,
                    resource.dispatch_kind.is_udp(),
                )
                .await
            {
                return Err(AfterValidateError::Response(Box::new(
                    super::json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} is not available on the host: {}",
                            port, error
                        )}),
                    ),
                )));
            }
        }

        Ok(())
    }

    async fn before_delete(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        existing: &Self,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        validate_direct_api_spec_proxy_delete_restore_ownership(db, namespace, existing).await?;
        validate_plugin_graph_proxy_deletion_candidate(db, state, namespace, &existing.id).await
    }

    async fn after_write(
        db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        action: WriteAction<'_>,
    ) -> DbResult<()> {
        if db.db_type() == "mongodb"
            && matches!(action, WriteAction::Update { .. })
            && let Some(old_proxy) = existing
            && let Some(old_upstream_id) = old_proxy.upstream_id.as_deref()
            && resource.upstream_id.as_deref() != Some(old_upstream_id)
        {
            // The previous upstream lives in the proxy's own namespace (the
            // write precheck loaded `existing` namespace-scoped).
            db.cleanup_orphaned_upstream(&old_proxy.namespace, old_upstream_id)
                .await?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl AdminResource for Consumer {
    fn labels_mut(&mut self) -> Option<&mut std::collections::BTreeMap<String, String>> {
        Some(&mut self.labels)
    }

    fn restore_absent_update_fields(
        &mut self,
        existing: &Self,
        raw: &serde_json::Map<String, serde_json::Value>,
    ) {
        if !raw.contains_key("labels") {
            self.labels = existing.labels.clone();
        }
    }

    const RESOURCE_NAME: &'static str = "consumer";
    const RESOURCE_LABEL: &'static str = "Consumer";
    const VALIDATION_ERROR_LABEL: &'static str = "consumer fields";
    const NOT_FOUND_MESSAGE: &'static str = "Consumer not found";
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn normalize(&mut self) {
        self.normalize_fields();
    }

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.consumers
    }

    fn response_body(resource: &Self) -> Value {
        consumer_response_body(resource)
    }

    fn audit_body(resource: &Self) -> Value {
        consumer_audit_body(resource)
    }

    fn prepare_for_update(&mut self, existing: &Self) {
        // Ordinary Consumer responses are a closed credential projection, so a
        // read-modify-write PUT of such a response cannot express the state it
        // was never shown. Restore what the projection hides — Basic and
        // unknown/custom credential types omitted entirely, and known secrets
        // returned as the `[REDACTED]` placeholder. Explicit replacement and
        // deletion use the credential endpoints.
        crate::config::types::preserve_response_hidden_consumer_credentials(self, existing);
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        super::json_response(StatusCode::CONFLICT, &json!({"error": errors.join("; ")}))
    }

    fn map_delete_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        if let Some(conflict) = mtls_dns_identity_conflict(error) {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": conflict.to_string()}),
            );
        }
        let error_chain_contains = |needle| {
            error
                .chain()
                .any(|cause| cause.to_string().contains(needle))
        };
        if error_chain_contains("referenced by access_control plugin_config") {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": "Consumer is referenced by one or more access_control plugin_configs and cannot be deleted"}),
            );
        }
        super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &super::db_error_response(error),
        )
    }

    fn prepare_for_write(&mut self) -> Result<(), PrepareWriteError> {
        let consumer_id = self.id.clone();
        hash_consumer_credentials(self).map_err(|error| match error {
            crate::config::types::BasicAuthCredentialPreparationError::InvalidCredential(
                message,
            ) => PrepareWriteError::InvalidRequest(format!(
                "Failed to prepare Basic-auth credentials for consumer {}: {}",
                consumer_id, message
            )),
            crate::config::types::BasicAuthCredentialPreparationError::ServerConfiguration(
                message,
            ) => PrepareWriteError::Internal(format!(
                "Failed to prepare Basic-auth credentials for consumer {}: {}",
                consumer_id, message
            )),
        })
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        consumer_persist_error_response(error)
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_consumer(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_consumers_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.query_offset_i64(),
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_consumer(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_consumer(resource, &BatchConfigWriteMode::Admission)
            .await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_consumer(namespace, id).await
    }

    type DeleteQuery = ();

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        match db
            .check_consumer_identity_unique(
                namespace,
                &resource.id,
                &resource.username,
                resource.custom_id.as_deref(),
                exclude_id,
            )
            .await
        {
            Ok(Some(message)) => return Ok(Some(message)),
            Ok(None) => {}
            Err(error) => return Err(error),
        }

        check_consumer_credential_uniqueness(db, namespace, resource, exclude_id).await
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        _state: &AdminState,
        namespace: &str,
        resource: &Self,
        _existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        let mut errors = Vec::new();
        if resource.has_credential("mtls_auth") {
            errors.extend(
                mtls_consumer_candidate_errors(db, namespace, resource)
                    .await
                    .map_err(AfterValidateError::Db)?,
            );
        }
        if resource.has_credential("hmac_auth") {
            errors.extend(
                hmac_consumer_candidate_errors(db, namespace, resource)
                    .await
                    .map_err(AfterValidateError::Db)?,
            );
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(AfterValidateError::BadRequest(errors))
        }
    }
}

fn not_found_response<R: AdminResource>() -> Response<Full<Bytes>> {
    super::json_response(
        StatusCode::NOT_FOUND,
        &json!({"error": R::NOT_FOUND_MESSAGE}),
    )
}

fn map_after_validate_error<R: AdminResource>(error: AfterValidateError) -> Response<Full<Bytes>> {
    match error {
        AfterValidateError::BadRequest(field_errors) => R::map_after_validate_errors(&field_errors),
        AfterValidateError::Conflict(errors) => {
            super::json_response(StatusCode::CONFLICT, &json!({"error": errors.join("; ")}))
        }
        AfterValidateError::Db(error) => R::map_precheck_db_error(&error),
        AfterValidateError::Response(response) => *response,
    }
}

fn config_update_target_was_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains(" was not found in namespace '")
            || message.contains("proxy '") && message.ends_with("' was not found")
            || message.contains("consumer '") && message.ends_with("' was not found")
            || message.contains("plugin config '") && message.ends_with("' was not found")
            || message.contains("upstream '") && message.ends_with("' was not found")
    })
}

async fn handle_write<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    body: &[u8],
    namespace: &str,
    action: WriteAction<'_>,
    apply_mode: LiveApplyMode,
    provisioner: Option<&str>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let _write_permit = match state.admit_write().await {
        Ok(permit) => permit,
        Err(response) => return Ok(response),
    };

    if let WriteAction::Update { id } = action
        && let Err(message) = validate_resource_id(id)
    {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    let db_arc = match state.db.as_ref() {
        Some(db) => db.clone(),
        None => {
            return Ok(super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };
    let db = db_arc.as_ref();
    let mut namespace_config_admission_guard = if R::SERIALIZE_NAMESPACE_CONFIG_ADMISSION {
        match lock_namespace_config_admission(db_arc.clone(), namespace).await {
            Ok(guard) => Some(guard),
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
    } else {
        None
    };

    if let Err(message) = R::validate_raw_body(body, action) {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    let mut resource: R = match serde_json::from_slice(body) {
        Ok(resource) => resource,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", error)}),
            ));
        }
    };
    if matches!(action, WriteAction::Create)
        && let Some(labels) = resource.labels_mut()
    {
        super::provisioning::stamp(labels, provisioner);
    }

    let mut undecodable_update_repair = false;
    let existing = match action {
        WriteAction::Create => None,
        WriteAction::Update { id } => match R::db_get_for_write(db, namespace, id).await {
            // Updating a resource that does not exist in this namespace is a
            // 404 — proceeding would let the persist step "succeed" against
            // zero rows (issue #2122 DB-M4 phantom update).
            Ok(None) => {
                return Ok(not_found_response::<R>());
            }
            Ok(existing) => existing,
            Err(error) if is_row_decode_rejection(&error) => {
                // Issue #2997: row exists but cannot be hydrated. Proceed
                // without prepare_for_update / late-write previous so PUT
                // remains an in-band overwrite repair (must not be 503).
                undecodable_update_repair = true;
                None
            }
            Err(error) => {
                return Ok(R::map_precheck_db_error(&error));
            }
        },
    };
    if let Some(guard) = namespace_config_admission_guard.as_ref()
        && let Err(error) = guard.ensure_held()
    {
        return Ok(R::map_precheck_db_error(&error));
    }
    match action {
        WriteAction::Create => {
            if resource.id().is_empty() {
                // `namespace` here is the authenticated `X-Ferrum-Namespace`
                // value, never the body's — see `default_id_for_namespace`.
                resource.set_id(
                    R::default_id_for_namespace(namespace)
                        .unwrap_or_else(|| Uuid::new_v4().to_string()),
                );
            } else if let Err(message) = validate_resource_id(resource.id()) {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": message}),
                ));
            }
        }
        WriteAction::Update { id } => {
            resource.set_id(id.to_string());
            if let Some(existing) = existing.as_ref() {
                // `from_slice::<R>` already succeeded, so this only skips
                // bodies that are not a JSON object.
                if let Ok(Value::Object(raw)) = serde_json::from_slice::<Value>(body) {
                    resource.restore_absent_update_fields(existing, &raw);
                }
                resource.prepare_for_update(existing);
            }
        }
    }

    resource.normalize();
    resource.set_namespace(namespace.to_string());
    resource.set_actor(&actor.sub);

    let validation_ctx = ValidationCtx::from_state(state);
    if let Err(validation_error) = resource.validate(&validation_ctx) {
        return Ok(R::map_validation_error(&validation_error));
    }

    if matches!(action, WriteAction::Create) {
        match R::db_get(db, namespace, resource.id()).await {
            Ok(Some(_)) => {
                return Ok(super::json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!(
                        "{} with ID '{}' already exists",
                        R::ID_CONFLICT_LABEL,
                        resource.id()
                    )}),
                ));
            }
            Ok(None) => {}
            // Issue #2997: an undecodable row still occupies the id — treat as
            // conflict (409), not connectivity 503, so operators see a clear
            // repair signal rather than a false outage.
            Err(error) if is_row_decode_rejection(&error) => {
                return Ok(super::json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!(
                        "{} with ID '{}' already exists",
                        R::ID_CONFLICT_LABEL,
                        resource.id()
                    )}),
                ));
            }
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
    }

    let exclude_id = match action {
        WriteAction::Create => None,
        WriteAction::Update { id } => Some(id),
    };
    match R::check_uniqueness(db, namespace, &resource, exclude_id).await {
        Ok(Some(message)) => {
            return Ok(super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": message}),
            ));
        }
        Ok(None) => {}
        Err(error) => return Ok(R::map_precheck_db_error(&error)),
    }

    if let Err(error) = R::after_validate(
        db,
        state,
        namespace,
        &resource,
        existing.as_ref(),
        &validation_ctx,
    )
    .await
    {
        return Ok(map_after_validate_error::<R>(error));
    }

    if let Err(error) = resource.prepare_for_write() {
        return Ok(super::json_response(
            error.status(),
            &json!({"error": error.message()}),
        ));
    }

    let now = Utc::now();
    match action {
        WriteAction::Create => {
            resource.set_created_at(now);
            resource.set_updated_at(now);
        }
        WriteAction::Update { .. } => {
            resource.set_updated_at(now);
        }
    }

    // The resource as the STORE holds it after the write. Identical to
    // `resource` for every resource that has not opted into
    // `REREAD_AFTER_WRITE`; for one that has, it carries server-settled state
    // (the gateway trust bundle's backend-assigned `revision`) that the request
    // body could not have known.
    let settled;
    match action {
        WriteAction::Create => {
            let persistence = match audit::spawn_with_request_slot(persist_create_to_settlement(
                OwnedWriteSettlementContext {
                    db: db_arc.clone(),
                    namespace: namespace.to_string(),
                    guard: namespace_config_admission_guard.take(),
                    http_client: super::plugin_validation_http_client(state),
                    state: state.clone(),
                    actor: actor.clone(),
                },
                resource.clone(),
            ))
            .await
            {
                Ok(result) => result,
                Err(error) => Err(anyhow::anyhow!(
                    "namespace create persistence task failed: {error}"
                )),
            };
            match persistence {
                Ok(created) => settled = created,
                Err(error) => return Ok(R::map_persist_db_error(&error, action)),
            }
        }
        WriteAction::Update { id } => {
            if undecodable_update_repair {
                let persistence =
                    match audit::spawn_with_request_slot(persist_undecodable_update_repair(
                        OwnedWriteSettlementContext {
                            db: db_arc.clone(),
                            namespace: namespace.to_string(),
                            guard: namespace_config_admission_guard.take(),
                            http_client: super::plugin_validation_http_client(state),
                            state: state.clone(),
                            actor: actor.clone(),
                        },
                        id.to_string(),
                        resource.clone(),
                    ))
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => Err(anyhow::anyhow!(
                            "namespace undecodable-row update persistence task failed: {error}"
                        )),
                    };
                match persistence {
                    Ok(None) => return Ok(not_found_response::<R>()),
                    Ok(Some(updated)) => settled = updated,
                    Err(error) => return Ok(R::map_persist_db_error(&error, action)),
                }
            } else {
                let Some(previous) = existing.clone() else {
                    return Ok(super::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &json!({"error": "Update persistence is missing the prior resource"}),
                    ));
                };
                let persistence =
                    match audit::spawn_with_request_slot(persist_update_to_settlement(
                        OwnedWriteSettlementContext {
                            db: db_arc.clone(),
                            namespace: namespace.to_string(),
                            guard: namespace_config_admission_guard.take(),
                            http_client: super::plugin_validation_http_client(state),
                            state: state.clone(),
                            actor: actor.clone(),
                        },
                        id.to_string(),
                        resource.clone(),
                        previous,
                    ))
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => Err(anyhow::anyhow!(
                            "namespace update persistence task failed: {error}"
                        )),
                    };
                // The row vanished between the precheck and the write (concurrent
                // delete). The backend recorded no change — report not-found
                // rather than a phantom success (issue #2122 DB-M4).
                match persistence {
                    Ok(None) => return Ok(not_found_response::<R>()),
                    Ok(Some(updated)) => settled = updated,
                    Err(error) => return Ok(R::map_persist_db_error(&error, action)),
                }
            }
        }
    }

    let body = R::response_body_for_role(&settled, actor.role);
    let status = match action {
        WriteAction::Create => StatusCode::CREATED,
        WriteAction::Update { .. } => StatusCode::OK,
    };
    Ok(state
        .complete_live_config_mutation_after_commit_boxed(
            namespace,
            _write_permit,
            super::json_response(status, &body),
            apply_mode,
        )
        .await)
}

fn validation_error_response<R: AdminResource>(field_errors: &[String]) -> Response<Full<Bytes>> {
    super::json_response(
        StatusCode::BAD_REQUEST,
        &json!({"error": format!(
            "Invalid {}: {}",
            R::VALIDATION_ERROR_LABEL,
            field_errors.join("; ")
        )}),
    )
}

#[cfg(test)]
mod redis_plugin_projection_tests {
    use crate::admin::plugin_config_projection::{
        is_credential_bearing_url_config_key, is_sensitive_plugin_config_key,
        project_plugin_config, redact_sensitive_plugin_config_fields,
    };
    use serde_json::json;

    #[test]
    fn integrity_key_matcher_covers_normalized_and_collapsed_forms() {
        for key in [
            "redis_integrity_key",
            "Redis-Integrity-Key",
            "redis.integrity.key",
            "REDIS_INTEGRITY_KEY",
            "redisIntegrityKey",
            "integrity_key",
            "integrityKey",
        ] {
            assert!(
                is_sensitive_plugin_config_key(key),
                "{key} should be treated as signing-material"
            );
        }
        assert!(!is_sensitive_plugin_config_key("integrity_status"));
        assert!(!is_sensitive_plugin_config_key("ttl_seconds"));
    }

    #[test]
    fn redis_url_key_matcher_is_delimiter_insensitive() {
        for key in [
            "redis_url",
            "Redis-Url",
            "REDIS.URL",
            "redis-url",
            "redisUrl",
            "RedisURL",
        ] {
            assert!(
                is_credential_bearing_url_config_key(key),
                "{key} should be treated as a credential-bearing URL"
            );
        }
        assert!(!is_credential_bearing_url_config_key("redis_username"));
        assert!(!is_credential_bearing_url_config_key("endpoint_url"));
        assert!(!is_credential_bearing_url_config_key("redis_urls"));
    }

    #[test]
    fn nested_integrity_keys_and_redis_urls_are_projected() {
        let mut config = json!({
            "ttl_seconds": 60,
            "redis_integrity_key": "signing-secret-0123456789abcdef",
            "providers": [{
                "redisIntegrityKey": "nested-signing-secret-0123456789",
                "Redis-Url": "redis://user:pass@cache.internal:6379/3?token=q#f",
                "redisUrl": "redis://nested:nested-pass@other.internal:6379/1?tok=n#g"
            }]
        });
        redact_sensitive_plugin_config_fields(&mut config);

        assert_eq!(config["ttl_seconds"], 60);
        assert_eq!(config["redis_integrity_key"], "[REDACTED]");
        assert_eq!(config["providers"][0]["redisIntegrityKey"], "[REDACTED]");
        assert_eq!(
            config["providers"][0]["Redis-Url"],
            "redis://redacted@cache.internal:6379/3"
        );
        assert_eq!(
            config["providers"][0]["redisUrl"],
            "redis://redacted@other.internal:6379/1"
        );
        let serialized = config.to_string();
        assert!(
            !serialized.contains("signing-secret")
                && !serialized.contains("nested-signing")
                && !serialized.contains("pass")
                && !serialized.contains("nested-pass")
                && !serialized.contains("token=q")
                && !serialized.contains("tok=n"),
            "nested projection leaked secret material: {config}"
        );
    }

    #[test]
    fn redis_url_projection_fails_closed_for_non_strings() {
        let mut config = json!({"redis_url": 42, "sync_mode": "redis"});
        project_plugin_config("rate_limiting", &mut config);
        assert_eq!(config["redis_url"], "[REDACTED]");
        assert_eq!(config["sync_mode"], "redis");

        let mut null_url = json!({"redis_url": null});
        project_plugin_config("rate_limiting", &mut null_url);
        assert!(null_url["redis_url"].is_null());
    }
}
