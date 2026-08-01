//! Shared, expiring renewal leases for file-backed TLS material stores.
//!
//! Every serving replica starts its own ACME renewal scheduler, so without a
//! shared claim two replicas can decide the same certificate is due, create two
//! orders against the same account, collide on challenge state, and burn CA
//! rate limits (issue #2409). A lease is a named, holder-stamped, expiring
//! claim persisted next to the ACME stores in the same shared directory and
//! mutated through the same exclusive-lock read-modify-write, so "who owns this
//! renewal" is decided by authoritative shared state rather than by a
//! process-local map.
//!
//! Ownership is fail-closed in both directions: a lease that cannot be read or
//! written is *not* acquired (the certificate is skipped this cycle rather than
//! renewed twice), and a holder that crashes loses its claim automatically once
//! `expires_at` passes, so another replica takes over without operator action.
//! A fencing counter (`fence`) makes renew/release idempotent against a claim
//! that was already taken over.
//!
//! # Exclusion is unconditional
//!
//! A **live** claim excludes every acquirer, including one presenting the same
//! holder identity. Two processes can legitimately share an identity —
//! `FERRUM_TLS_STORE_INSTANCE_ID` set to the same value by mistake, or the old
//! and new pod of an overlapping replacement — and letting the second one
//! reacquire would bump the fence and start a second renewal while the first is
//! still mid-ACME. There is therefore no "restart reclaims its own claim" fast
//! path: **crash recovery happens through expiry**, and a configured instance
//! id is validated strictly (never silently sanitized into a collision) so two
//! distinct configured values cannot converge onto one identity.
//!
//! # The TTL alone does not bound overlap
//!
//! ACME is not a fenced remote system: the CA honours an order regardless of
//! which replica believes it owns the renewal. So the claim has to stay alive
//! for the *whole* external operation, not just past the parts we predicted
//! would be slow. [`RenewalLeaseKeeper`] runs a heartbeat for the lifetime of a
//! renewal, extends the claim at a fraction of the TTL through
//! `spawn_blocking` (store I/O and locking are synchronous), fails closed on
//! any store error, and publishes a loss signal that the long-running async
//! ACME/hook/sleep/poll work selects against — so a lost claim cancels the
//! renewal before the next side effect instead of at the next explicit check.
//!
//! # A commit needs a fence, not two checks
//!
//! The lease table and the account/order/certificate stores are separate
//! documents behind separate advisory locks, so checking ownership before and
//! after a synchronous target-store write bounds nothing: a claim that expires
//! (or a heartbeat that fails) while a slow write is in flight lets another
//! replica acquire and publish, and the after-check observes the loss it can no
//! longer undo. [`TlsLeaseStore::commit_fenced`] therefore verifies
//! holder/fence/liveness and then runs the target mutation **while still
//! holding the lease store's exclusive lock**, so acquisition, renewal, and
//! takeover cannot cross the commit.
//!
//! The lock order is always **lease store first, then target store**, and it is
//! only ever taken across a narrow synchronous commit — never across an ACME
//! network call, a provider hook, a propagation sleep, or an authorization
//! poll, all of which use [`RenewalLeaseKeeper::guarded`] instead. No path
//! holds a target-store lock and then waits for the lease lock, so the nesting
//! cannot cycle.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::watch;
use uuid::Uuid;

use crate::tls::shared_store::{SharedStoreError, SharedStoreFile, VersionedStoreFile};

const LEASE_STORE_FILE_NAME: &str = "tls-leases.json";
const DEFAULT_STORE_DIR: &str = "./ferrum-managed-tls";

/// Expired leases are kept this long so operators can see recent ownership
/// history, then pruned so the document cannot grow without bound.
const EXPIRED_LEASE_RETENTION_SECONDS: i64 = 24 * 60 * 60;

/// Fallback TTL when a caller-supplied duration is not representable.
const FALLBACK_LEASE_TTL_MILLIS: i64 = 900 * 1_000;

/// Longest accepted `FERRUM_TLS_STORE_INSTANCE_ID`.
const MAX_INSTANCE_ID_LEN: usize = 128;

/// Shortest heartbeat cadence, so a deliberately tiny test TTL still produces
/// useful beats without becoming a busy loop.
const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(200);

/// Lease name for the per-certificate ACME renewal claim.
pub fn acme_renewal_lease_name(certificate_id: &str) -> String {
    format!("acme-renewal:{certificate_id}")
}

#[derive(Debug, Error)]
pub enum TlsLeaseError {
    #[error(transparent)]
    Store(#[from] SharedStoreError),
    #[error("TLS lease store path is invalid: {0}")]
    InvalidPath(String),
    /// Fail-closed rejection of a configured instance identity. Carries only the
    /// rule that was broken — never the configured value, which is echoed back
    /// into logs and shared state.
    #[error("FERRUM_TLS_STORE_INSTANCE_ID is invalid: {0}")]
    InvalidInstanceId(String),
    /// A lease operation could not be driven to a conclusion (blocking task
    /// join failure). Treated as loss of ownership by every caller.
    #[error("TLS lease maintenance failed: {0}")]
    Maintenance(String),
}

/// One persisted claim. Contains no material and no credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsLeaseRecord {
    /// Opaque instance identity of the current holder.
    pub holder: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Monotonic per-name counter bumped on every acquisition. A guard whose
    /// fence no longer matches has been superseded and must not renew, release,
    /// or act on the claim.
    pub fence: u64,
}

impl TlsLeaseRecord {
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsLeaseStoreFile {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    leases: BTreeMap<String, TlsLeaseRecord>,
}

impl VersionedStoreFile for TlsLeaseStoreFile {
    fn store_version(&self) -> u64 {
        self.version
    }

    fn set_store_version(&mut self, version: u64) {
        self.version = version;
    }
}

/// Shared lease table for one managed-TLS store directory.
#[derive(Debug)]
pub struct TlsLeaseStore {
    holder: String,
    file: SharedStoreFile<TlsLeaseStoreFile>,
}

impl TlsLeaseStore {
    /// Open the lease table in `dir` under this process's instance identity.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, TlsLeaseError> {
        let holder = process_instance_id()?.to_string();
        Self::open_with_holder(dir, holder)
    }

    /// Open the lease table under an explicit holder identity.
    ///
    /// Exposed so a deployment (or a two-instance test) can give two stores
    /// over the same directory the distinct identities two replicas would have.
    /// The identity is validated, never sanitized: silently folding an invalid
    /// value onto some other identity is exactly how two replicas end up
    /// colliding on one claim.
    pub fn open_with_holder(
        dir: impl Into<PathBuf>,
        holder: String,
    ) -> Result<Self, TlsLeaseError> {
        let holder = validate_instance_id(&holder).map_err(TlsLeaseError::InvalidInstanceId)?;
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(TlsLeaseError::InvalidPath(
                "store directory must not be empty".to_string(),
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|error| {
            TlsLeaseError::InvalidPath(format!(
                "failed to create TLS lease store directory '{}': {error}",
                dir.display()
            ))
        })?;
        let file = SharedStoreFile::open(dir.join(LEASE_STORE_FILE_NAME))?;
        Ok(Self { holder, file })
    }

    pub fn holder(&self) -> &str {
        &self.holder
    }

    /// Current record for `name`, live or expired. Diagnostics and tests only.
    pub fn peek(&self, name: &str) -> Result<Option<TlsLeaseRecord>, TlsLeaseError> {
        let document = self.file.snapshot()?;
        Ok(document.leases.get(name).cloned())
    }

    /// Claim `name` for `ttl`, or return `None` when a live claim already exists.
    ///
    /// The decision is made under the exclusive store lock against authoritative
    /// shared state, so exactly one instance can hold a given name at a time.
    ///
    /// **Any** live claim denies acquisition, including one stamped with this
    /// instance's own holder identity. Two processes sharing an identity (an
    /// operator pinning `FERRUM_TLS_STORE_INSTANCE_ID` to the same value twice,
    /// or an overlapping rolling replacement) would otherwise both believe they
    /// own the renewal while the first is still driving external ACME work; the
    /// fence would advance under it and it would only notice at its next
    /// explicit check. A crashed holder is recovered through expiry instead.
    pub fn try_acquire(
        self: &Arc<Self>,
        name: &str,
        ttl: Duration,
    ) -> Result<Option<TlsLeaseGuard>, TlsLeaseError> {
        let holder = self.holder.clone();
        let name_owned = name.to_string();
        let fence = self.file.mutate_if::<_, TlsLeaseError>(move |document| {
            let now = Utc::now();
            if let Some(existing) = document.leases.get(&name_owned)
                && existing.is_live_at(now)
            {
                // Denied: a live claim exists. Publish nothing, so a non-owner
                // scanning every cycle does not rewrite the shared document
                // (and cannot lose a race it already lost).
                return Ok((false, None));
            }
            prune_expired(document, now);
            let fence = document
                .leases
                .get(&name_owned)
                .map(|existing| existing.fence)
                .unwrap_or(0)
                .saturating_add(1);
            document.leases.insert(
                name_owned.clone(),
                TlsLeaseRecord {
                    holder: holder.clone(),
                    acquired_at: now,
                    expires_at: now + lease_delta(ttl),
                    fence,
                },
            );
            Ok((true, Some(fence)))
        })?;
        let Some(fence) = fence else {
            return Ok(None);
        };
        Ok(Some(TlsLeaseGuard {
            store: Arc::clone(self),
            name: name.to_string(),
            fence,
            released: false,
        }))
    }

    /// Whether this instance still holds a live claim on `name` at `fence`.
    ///
    /// A read-only ownership check for the points either side of a synchronous
    /// commit, where "did we still own this when we wrote it" is the question
    /// and extending the claim would be wrong.
    pub fn is_owner(&self, name: &str, fence: u64) -> Result<bool, TlsLeaseError> {
        let document = self.file.snapshot()?;
        let now = Utc::now();
        Ok(document.leases.get(name).is_some_and(|existing| {
            existing.holder == self.holder && existing.fence == fence && existing.is_live_at(now)
        }))
    }

    /// Extend a claim this instance still owns. `false` means it was lost.
    pub fn renew(&self, guard: &TlsLeaseGuard, ttl: Duration) -> Result<bool, TlsLeaseError> {
        self.renew_claim(&guard.name, guard.fence, ttl)
    }

    /// [`Self::renew`] addressed by name and fence, for the heartbeat, which
    /// cannot borrow the guard the caller is still using.
    pub fn renew_claim(
        &self,
        name: &str,
        fence: u64,
        ttl: Duration,
    ) -> Result<bool, TlsLeaseError> {
        let holder = self.holder.clone();
        let name = name.to_string();
        self.file.mutate_if::<_, TlsLeaseError>(move |document| {
            let now = Utc::now();
            let Some(existing) = document.leases.get_mut(&name) else {
                return Ok((false, false));
            };
            if existing.holder != holder || existing.fence != fence || !existing.is_live_at(now) {
                return Ok((false, false));
            }
            existing.expires_at = now + lease_delta(ttl);
            Ok((true, true))
        })
    }

    /// Run `commit` under the lease store's exclusive lock, and only while this
    /// instance still holds a live claim on `name` at `fence`.
    ///
    /// This is the fence for a synchronous target-store mutation. An ownership
    /// check on each side of the write is not sufficient, because the lease
    /// table and the account/order/certificate stores use different locks: if
    /// the claim expires or a heartbeat fails while a slow mutation is in
    /// flight, another replica can acquire and publish while the stale write
    /// still lands, and the after-check detects the loss without being able to
    /// undo it. Holding the lease lock for the whole mutation makes
    /// acquisition, renewal, and takeover unable to cross the commit: another
    /// replica's `try_acquire` blocks on the same lock until it has finished.
    ///
    /// The lease document is deliberately **never** rewritten here — the
    /// mutation runs as a no-document-change lock scope — so a failing target
    /// store cannot bump the lease store version or disturb any holder's
    /// record. `commit`'s own result, error included, is carried out as the
    /// outcome.
    ///
    /// # Lock order
    ///
    /// Lease store first, then the target store the closure touches. Nothing
    /// takes them the other way round, so the nesting cannot cycle. Nothing
    /// about the claim is exposed to `commit`, and no store contents are
    /// logged.
    ///
    /// A commit that starts under a live claim may finish even if the nominal
    /// TTL elapses mid-write, precisely because takeover is blocked on this
    /// lock. The caller's next ownership check — immediately after the lock is
    /// released — is what stops any further work.
    pub fn commit_fenced<T>(
        &self,
        name: &str,
        fence: u64,
        commit: impl FnOnce() -> T,
    ) -> Result<FencedCommit<T>, TlsLeaseError> {
        let holder = self.holder.clone();
        let name = name.to_string();
        self.file.mutate_if::<_, TlsLeaseError>(move |document| {
            let now = Utc::now();
            let owned = document.leases.get(&name).is_some_and(|existing| {
                existing.holder == holder && existing.fence == fence && existing.is_live_at(now)
            });
            if !owned {
                return Ok((false, FencedCommit::NotOwner));
            }
            Ok((false, FencedCommit::Committed(commit())))
        })
    }

    fn release_claim(&self, name: &str, fence: u64) -> Result<bool, TlsLeaseError> {
        let holder = self.holder.clone();
        let name = name.to_string();
        self.file.mutate_if::<_, TlsLeaseError>(move |document| {
            let Some(existing) = document.leases.get_mut(&name) else {
                return Ok((false, false));
            };
            if existing.holder != holder || existing.fence != fence {
                // Superseded by another holder (or by a later acquisition):
                // releasing here would hand away a claim we no longer own.
                return Ok((false, false));
            }
            // Retain the record with an elapsed expiry rather than deleting it,
            // so the fence keeps advancing monotonically for this name.
            existing.expires_at = Utc::now();
            Ok((true, true))
        })
    }
}

/// Outcome of [`TlsLeaseStore::commit_fenced`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencedCommit<T> {
    /// The claim was live and still ours; the mutation ran under the lease
    /// lock and produced this value.
    Committed(T),
    /// Ownership was absent, expired, or superseded. The mutation did **not**
    /// run, so nothing was published on a claim this instance no longer holds.
    NotOwner,
}

/// A held lease. Releases on drop so a completed or aborted renewal does not
/// block another instance for the remainder of the TTL.
#[derive(Debug)]
pub struct TlsLeaseGuard {
    store: Arc<TlsLeaseStore>,
    name: String,
    fence: u64,
    released: bool,
}

impl TlsLeaseGuard {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fence(&self) -> u64 {
        self.fence
    }

    pub fn holder(&self) -> &str {
        self.store.holder()
    }

    /// Extend this claim. `false` means another instance has taken it over and
    /// the caller must stop acting on it.
    pub fn renew(&self, ttl: Duration) -> Result<bool, TlsLeaseError> {
        self.store.renew(self, ttl)
    }

    /// Release explicitly, surfacing a persistence failure the `Drop` path can
    /// only log.
    pub fn release(mut self) -> Result<(), TlsLeaseError> {
        self.released = true;
        self.store.release_claim(&self.name, self.fence).map(|_| ())
    }

    fn store(&self) -> &Arc<TlsLeaseStore> {
        &self.store
    }
}

/// The shared claim was lost mid-operation: it expired and was taken over, or
/// the lease table could not be reached. Either way this instance must stop
/// producing side effects for the operation immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the shared TLS renewal claim was lost")]
pub struct RenewalLeaseLost;

/// Keeps a renewal claim alive for the whole external operation and cancels the
/// operation the moment it cannot.
///
/// The claim's TTL is not a bound on overlap by itself: the ACME directory does
/// not honour Ferrum's fence, so a certificate order, a DNS-01 hook, a
/// propagation wait, or an authorization poll that outlives the TTL lets a
/// second replica acquire and start ordering while the first is still running.
/// The keeper closes that window:
///
/// * a heartbeat extends the claim every `ttl / 3` (never faster than
///   [`MIN_HEARTBEAT_INTERVAL`]), so the TTL only has to cover one beat plus
///   scheduling slack rather than an entire ACME cycle;
/// * every extension runs inside `spawn_blocking`, because the store's I/O and
///   its advisory lock are synchronous and must not occupy a runtime worker;
/// * **any** heartbeat outcome other than "still ours" — takeover, store error,
///   or a task that could not be joined — is fail-closed loss;
/// * loss is published on a `watch` channel that [`Self::guarded`] selects
///   against, so long-running async work is abandoned at its next await point
///   instead of at the next explicit check;
/// * [`Self::commit_fenced`] is the synchronous-commit companion: it verifies
///   ownership and runs the target-store mutation under the *same* lease lock,
///   so a superseded owner cannot publish certificate/order/account state;
/// * [`Self::ensure_owned`] re-reads authoritative state without extending
///   anything, for the check immediately after a fenced commit and before the
///   next stretch of external work;
/// * [`Self::guarded_cleanup`] is [`Self::guarded`] preceded by an
///   authoritative *refresh*, because a retraction hook that is ready to run
///   immediately would otherwise slip through the gap between a takeover
///   landing and the next beat observing it — and a claim confirmed with
///   almost no lifetime left could expire and be taken over between the
///   confirmation and the hook's first poll.
///
/// Every one of those store operations is synchronous and lock-taking, so none
/// of them ever runs on a runtime worker — including the release performed when
/// a keeper is dropped rather than finished, which is handed to the blocking
/// pool and falls back to expiry if it cannot be scheduled.
///
/// A crashed process runs no heartbeat, so its claim expires and the
/// certificate becomes reclaimable exactly as before.
#[derive(Debug)]
pub struct RenewalLeaseKeeper {
    guard: Option<TlsLeaseGuard>,
    store: Arc<TlsLeaseStore>,
    name: String,
    fence: u64,
    /// The claim's TTL, retained so a preflight can re-establish a full
    /// protected interval rather than merely confirming whatever is left.
    ttl: Duration,
    lost_tx: Arc<watch::Sender<bool>>,
    lost_rx: watch::Receiver<bool>,
    stop_tx: watch::Sender<bool>,
    progress: HeartbeatProgress,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

/// How far the heartbeat loop has got, as a state rather than an interval.
///
/// `started` counts extensions handed to the blocking pool; `settled` counts
/// the ones the loop has since awaited back. `started > settled` therefore
/// means an extension is in flight *right now*, which is precisely the
/// condition [`RenewalLeaseKeeper::finish`] must clear before it releases the
/// claim — see [`RenewalLeaseKeeper::stop_heartbeat`].
///
/// `stop_requested` is the other half of that state: it is set as
/// [`RenewalLeaseKeeper::stop_heartbeat`] enters, *before* it awaits the loop,
/// so "shutdown has asked the loop to stop and an extension is still in flight"
/// is a directly observable conjunction rather than something inferred from how
/// long a shutdown has failed to complete.
///
/// Two counters and a flag, updated once per heartbeat interval (never faster
/// than [`MIN_HEARTBEAT_INTERVAL`], and in production a third of a >= 60s TTL)
/// and once per shutdown. Nothing on the request path reads or writes them.
#[derive(Debug, Clone, Default)]
pub struct HeartbeatProgress(Arc<HeartbeatCounters>);

#[derive(Debug, Default)]
struct HeartbeatCounters {
    started: AtomicU64,
    settled: AtomicU64,
    stop_requested: AtomicBool,
}

impl HeartbeatProgress {
    /// Extensions handed to the blocking pool since the keeper started.
    #[allow(dead_code)]
    pub fn started(&self) -> u64 {
        self.0.started.load(Ordering::SeqCst)
    }

    /// Extensions the loop has awaited to completion.
    #[allow(dead_code)]
    pub fn settled(&self) -> u64 {
        self.0.settled.load(Ordering::SeqCst)
    }

    /// Whether an extension has been started and not yet awaited back.
    #[allow(dead_code)]
    pub fn extension_in_flight(&self) -> bool {
        self.started() > self.settled()
    }

    /// Whether shutdown has already asked the heartbeat loop to stop. Set
    /// before the join is awaited, so it is true for the whole settling window.
    #[allow(dead_code)]
    pub fn stop_requested(&self) -> bool {
        self.0.stop_requested.load(Ordering::SeqCst)
    }

    fn start(&self) {
        self.0.started.fetch_add(1, Ordering::SeqCst);
    }

    fn settle(&self) {
        self.0.settled.fetch_add(1, Ordering::SeqCst);
    }

    fn request_stop(&self) {
        self.0.stop_requested.store(true, Ordering::SeqCst);
    }
}

impl RenewalLeaseKeeper {
    /// Take over `guard` and start heartbeating it.
    pub fn start(guard: TlsLeaseGuard, ttl: Duration) -> Self {
        let store = Arc::clone(guard.store());
        let name = guard.name().to_string();
        let fence = guard.fence();
        let (lost_tx, lost_rx) = watch::channel(false);
        let lost_tx = Arc::new(lost_tx);
        let (stop_tx, stop_rx) = watch::channel(false);
        let progress = HeartbeatProgress::default();
        let heartbeat = tokio::spawn(heartbeat_loop(
            Arc::clone(&store),
            name.clone(),
            fence,
            ttl,
            Arc::clone(&lost_tx),
            stop_rx,
            progress.clone(),
        ));
        Self {
            guard: Some(guard),
            store,
            name,
            fence,
            ttl,
            lost_tx,
            lost_rx,
            stop_tx,
            progress,
            heartbeat: Some(heartbeat),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Heartbeat progress, which outlives the keeper so shutdown settlement can
    /// be checked after [`Self::finish`] has consumed it.
    #[allow(dead_code)]
    pub fn heartbeat_progress(&self) -> HeartbeatProgress {
        self.progress.clone()
    }

    pub fn fence(&self) -> u64 {
        self.fence
    }

    /// Whether the claim has already been observed as lost.
    pub fn is_lost(&self) -> bool {
        *self.lost_rx.borrow()
    }

    /// Run `future`, abandoning it if the claim is lost while it is in flight.
    ///
    /// This is how ACME network calls, provider hooks, propagation sleeps, and
    /// readiness polls stop producing side effects promptly rather than at some
    /// later checkpoint.
    pub async fn guarded<F>(&self, future: F) -> Result<F::Output, RenewalLeaseLost>
    where
        F: Future,
    {
        if self.is_lost() {
            return Err(RenewalLeaseLost);
        }
        let mut lost = self.lost_rx.clone();
        tokio::select! {
            biased;
            _ = lost.wait_for(|lost| *lost) => Err(RenewalLeaseLost),
            output = future => Ok(output),
        }
    }

    /// Run a best-effort cleanup step inside the claim's cancellation scope,
    /// after atomically re-establishing the claim's protected interval.
    ///
    /// Cleanup is a side effect like any other: a DNS-01 provider hook that
    /// retracts `_acme-challenge` records must not run once the claim has moved
    /// on, because the instance that took it over republishes those same names
    /// and needs them to survive. An *ordinary* cleanup failure is not loss —
    /// the caller logs it and may keep working under the claim it still holds.
    ///
    /// # Why the loss signal alone is not enough here
    ///
    /// [`Self::guarded`] cancels on the *published* loss signal, which only
    /// becomes true once a heartbeat has observed the takeover. A cleanup hook
    /// that is ready to run immediately would be polled to completion in the
    /// gap between the takeover landing in the lease table and the next beat
    /// noticing it — retracting the new owner's records before this instance
    /// had any reason to believe it had lost anything. So the preflight is
    /// authoritative and up front, and the cleanup future is **not polled at
    /// all** unless it succeeds. The cancellation scope then still covers a
    /// claim lost *during* a slow hook.
    ///
    /// # Why it refreshes rather than merely confirms
    ///
    /// A read-only ownership check answers "is this claim live *right now*",
    /// which can be true with microseconds of TTL left. The claim may then
    /// legally expire and be taken over between that read and the hook's very
    /// first poll, putting the retraction back in exactly the window the check
    /// exists to close. [`Self::refresh_claim`] instead extends the claim under
    /// the lease store's exclusive lock — the same fenced read-modify-write a
    /// heartbeat uses, so a superseded fence cannot extend anything — and a
    /// successful preflight therefore hands the hook a full TTL rather than a
    /// remainder. Failure of any kind (taken over, expired, store error,
    /// unjoinable task) is fail-closed loss and marks the keeper lost.
    pub async fn guarded_cleanup<F, T, E>(&self, cleanup: F) -> GuardedCleanup<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        if self.refresh_claim().await.is_err() {
            return GuardedCleanup::Lost;
        }
        match self.guarded(cleanup).await {
            Ok(Ok(value)) => GuardedCleanup::Completed(value),
            Ok(Err(error)) => GuardedCleanup::Failed(error),
            Err(RenewalLeaseLost) => GuardedCleanup::Lost,
        }
    }

    /// Run a synchronous target-store mutation fenced by this claim.
    ///
    /// One `spawn_blocking` covers the ownership check *and* the mutation,
    /// because [`TlsLeaseStore::commit_fenced`] holds the lease store's
    /// exclusive advisory lock across both and that lock — like the target
    /// store's own — is synchronous. Absent, expired, superseded, or unreadable
    /// ownership, and a task that could not be joined, are all fail-closed
    /// loss: the mutation never runs (or could not be driven to a conclusion),
    /// the keeper is marked lost so concurrently [`guarded`](Self::guarded)
    /// work is cancelled as well, and the caller abandons without publishing.
    ///
    /// A target-store *error* is not loss. It is carried inside `T` and
    /// propagates to the caller normally.
    pub async fn commit_fenced<T, F>(&self, commit: F) -> Result<T, RenewalLeaseLost>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        if self.is_lost() {
            return Err(RenewalLeaseLost);
        }
        let store = Arc::clone(&self.store);
        let name = self.name.clone();
        let fence = self.fence;
        let outcome =
            tokio::task::spawn_blocking(move || store.commit_fenced(&name, fence, commit)).await;
        match outcome {
            Ok(Ok(FencedCommit::Committed(value))) => Ok(value),
            Ok(Ok(FencedCommit::NotOwner)) => {
                tracing::warn!(
                    lease = %self.name,
                    "the shared TLS renewal claim is no longer held by this instance; the store write was not performed"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "could not fence a TLS store write against the shared renewal claim"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Err(error) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "fenced TLS store write could not be joined"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
        }
    }

    /// Confirm this instance still owns the claim, without extending it.
    ///
    /// Fail-closed: a store error is loss, and marks the keeper lost so any
    /// concurrently [`guarded`](Self::guarded) work is cancelled too.
    pub async fn ensure_owned(&self) -> Result<(), RenewalLeaseLost> {
        if self.is_lost() {
            return Err(RenewalLeaseLost);
        }
        let store = Arc::clone(&self.store);
        let name = self.name.clone();
        let fence = self.fence;
        let owned = tokio::task::spawn_blocking(move || store.is_owner(&name, fence)).await;
        match owned {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => {
                tracing::warn!(
                    lease = %self.name,
                    "the shared TLS renewal claim is no longer held by this instance"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "could not confirm ownership of the shared TLS renewal claim"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Err(error) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "TLS renewal claim ownership check could not be joined"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
        }
    }

    /// Re-establish a full protected interval for this claim, or lose it.
    ///
    /// This is [`Self::ensure_owned`]'s answer plus a guarantee about the
    /// *future*: the extension and the ownership test are one fenced
    /// read-modify-write under the lease store's exclusive lock
    /// ([`TlsLeaseStore::renew_claim`]), so there is no ownership logic
    /// duplicated here and a claim whose holder or fence has moved on cannot
    /// extend anything. On success the caller is entitled to a whole TTL, not
    /// to whatever was left when it asked.
    ///
    /// Fail-closed exactly like the heartbeat: takeover, expiry, store error,
    /// and an unjoinable task are all loss, and all mark the keeper lost so
    /// concurrently [`guarded`](Self::guarded) work is cancelled too.
    async fn refresh_claim(&self) -> Result<(), RenewalLeaseLost> {
        if self.is_lost() {
            return Err(RenewalLeaseLost);
        }
        let store = Arc::clone(&self.store);
        let name = self.name.clone();
        let fence = self.fence;
        let ttl = self.ttl;
        let refreshed =
            tokio::task::spawn_blocking(move || store.renew_claim(&name, fence, ttl)).await;
        match refreshed {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => {
                tracing::warn!(
                    lease = %self.name,
                    "the shared TLS renewal claim is no longer held by this instance"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "could not refresh the shared TLS renewal claim"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
            Err(error) => {
                tracing::warn!(
                    lease = %self.name,
                    error = %error,
                    "TLS renewal claim refresh could not be joined"
                );
                self.mark_lost();
                Err(RenewalLeaseLost)
            }
        }
    }

    fn mark_lost(&self) {
        let _ = self.lost_tx.send(true);
    }

    /// Stop the heartbeat, wait for it to settle, then release the claim.
    ///
    /// The release also runs on a blocking thread, because it is another
    /// synchronous read-modify-write under the store's advisory lock.
    pub async fn finish(mut self) -> Result<(), TlsLeaseError> {
        self.stop_heartbeat().await;
        let Some(guard) = self.guard.take() else {
            return Ok(());
        };
        match tokio::task::spawn_blocking(move || guard.release()).await {
            Ok(result) => result,
            Err(error) => Err(TlsLeaseError::Maintenance(format!(
                "renewal claim release task failed: {error}"
            ))),
        }
    }

    /// Settle the heartbeat: ask the loop to stop and wait for it, **without**
    /// aborting.
    ///
    /// Aborting would only cancel the loop at its next await point. If that
    /// await is the extension's `spawn_blocking` join handle, dropping the
    /// handle neither cancels nor joins the blocking work, so the beat could
    /// still land — after the release below — and leave a claim alive that
    /// nobody is driving. Waiting for the loop to return is what makes
    /// "settled" true, because the loop itself awaits its in-flight extension
    /// before observing the stop signal.
    ///
    /// The stop request is published on [`HeartbeatProgress`] first, so the
    /// settling window — stop asked for, extension still in flight, loop not
    /// yet returned — is observable state rather than an elapsed interval.
    async fn stop_heartbeat(&mut self) {
        self.progress.request_stop();
        let _ = self.stop_tx.send(true);
        let Some(handle) = self.heartbeat.take() else {
            return;
        };
        if let Err(error) = handle.await {
            tracing::warn!(
                lease = %self.name,
                error = %error,
                "TLS renewal claim heartbeat did not shut down cleanly"
            );
        }
    }
}

impl Drop for RenewalLeaseKeeper {
    fn drop(&mut self) {
        // Emergency path only: `finish()` has already settled the heartbeat, so
        // this runs for a keeper abandoned by an early return, a panic, or a
        // cancelled scheduler. It is deliberately best effort — `drop` cannot
        // await — but it must still be bounded, so the loop is both told to
        // stop (it exits at the top of its next iteration, including after an
        // in-flight extension returns) and aborted (so a loop parked in its
        // sleep does not wait out the interval).
        //
        // A single detached in-flight beat cannot resurrect the claim. The
        // guard's release checks only holder and fence, while an extension
        // additionally requires the record to be *live*. So a beat that lands
        // before the release is overwritten by it, and one that lands after
        // sees an already-elapsed `expires_at` and declines. That holds whether
        // the release runs now or a moment later on a blocking thread, which is
        // why the deferral below is safe.
        self.progress.request_stop();
        let _ = self.stop_tx.send(true);
        if let Some(handle) = self.heartbeat.take() {
            handle.abort();
        }
        self.release_without_blocking_the_runtime();
    }
}

impl RenewalLeaseKeeper {
    /// Release the claim from `Drop` without ever parking a runtime thread.
    ///
    /// `TlsLeaseGuard::drop` performs a *synchronous* read-modify-write under
    /// the lease store's cross-process advisory lock, which can wait up to
    /// `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`. Letting the keeper's fields
    /// drop in place would therefore block whichever thread abandoned the
    /// renewal — on the emergency path that is a Tokio worker, and blocking one
    /// for up to two minutes because a shared volume is contended is exactly
    /// the runtime stall this offload exists to prevent. `finish()` is
    /// unaffected: it still settles the heartbeat and then awaits the release
    /// on a blocking thread, so its ordering guarantee is unchanged.
    ///
    /// Fail-safe by expiry. If the guard cannot be handed to a blocking thread
    /// the claim is simply not released here; it stops being heartbeaten (the
    /// loop has just been stopped and aborted) and lapses at `expires_at`,
    /// after which another replica takes it over. Never releasing is always
    /// safe; blocking the runtime is not.
    fn release_without_blocking_the_runtime(&mut self) {
        let Some(guard) = self.guard.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            // On a runtime: the release must not run here. Dropping the guard
            // inside the blocking task performs exactly the same release.
            // The join handle is discarded deliberately: dropping a
            // `spawn_blocking` handle does not cancel the task, so the release
            // still runs to completion on the blocking pool.
            Ok(handle) => drop(handle.spawn_blocking(move || drop(guard))),
            // Off-runtime (a synchronous caller, a test, shutdown after the
            // runtime is gone): there is no worker to protect and no blocking
            // pool to schedule onto, so release inline as before.
            Err(_) => drop(guard),
        }
    }
}

/// Outcome of [`RenewalLeaseKeeper::guarded_cleanup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedCleanup<T, E> {
    /// The cleanup ran to completion under the claim.
    Completed(T),
    /// The cleanup ran and failed on its own terms. The claim is still held, so
    /// the caller may log this and continue.
    Failed(E),
    /// The claim could not be re-established when the cleanup was asked for —
    /// so it never ran — or it was lost while the cleanup was in flight and the
    /// cleanup was cancelled. Either way the caller must abandon without
    /// publishing anything further.
    Lost,
}

/// Extend the claim until it is lost or the keeper asks the loop to stop.
///
/// The stop signal is only ever observed at the top of an iteration, so an
/// extension already in flight is awaited rather than left running detached.
/// That is what lets [`RenewalLeaseKeeper::finish`] guarantee no beat lands
/// after the release. `progress` makes that in-flight window observable.
async fn heartbeat_loop(
    store: Arc<TlsLeaseStore>,
    name: String,
    fence: u64,
    ttl: Duration,
    lost_tx: Arc<watch::Sender<bool>>,
    mut stop_rx: watch::Receiver<bool>,
    progress: HeartbeatProgress,
) {
    let interval = heartbeat_interval(ttl);
    loop {
        tokio::select! {
            biased;
            // Resolves immediately when the stop signal is already set, so the
            // iteration after an extension exits without another beat.
            _ = stop_rx.wait_for(|stop| *stop) => return,
            _ = tokio::time::sleep(interval) => {}
        }
        let store = Arc::clone(&store);
        let beat_name = name.clone();
        progress.start();
        let outcome =
            tokio::task::spawn_blocking(move || store.renew_claim(&beat_name, fence, ttl)).await;
        // Reached only when the loop itself awaited the extension back. A loop
        // cancelled at that await never gets here, which is what makes
        // "settled" mean settled.
        progress.settle();
        match outcome {
            Ok(Ok(true)) => continue,
            Ok(Ok(false)) => {
                tracing::warn!(
                    lease = %name,
                    "the shared TLS renewal claim was taken over by another instance"
                );
            }
            Ok(Err(error)) => {
                // Fail closed. An unwritable lease table means ownership can no
                // longer be asserted, so the renewal must stop rather than keep
                // producing ACME side effects on an assumption.
                tracing::warn!(
                    lease = %name,
                    error = %error,
                    "could not extend the shared TLS renewal claim; abandoning the renewal"
                );
            }
            Err(error) => {
                tracing::warn!(
                    lease = %name,
                    error = %error,
                    "TLS renewal claim heartbeat could not be joined; abandoning the renewal"
                );
            }
        }
        let _ = lost_tx.send(true);
        return;
    }
}

/// Beat at a third of the TTL so a single missed or slow extension does not
/// expire the claim.
fn heartbeat_interval(ttl: Duration) -> Duration {
    let floor = MIN_HEARTBEAT_INTERVAL;
    let ceiling = ttl.max(floor);
    (ttl / 3).max(floor).min(ceiling)
}

impl Drop for TlsLeaseGuard {
    /// Release the claim synchronously.
    ///
    /// This waits on the lease store's advisory lock, so it must not run on a
    /// Tokio worker. Every async owner arranges that: `RenewalLeaseKeeper`
    /// releases through `spawn_blocking` on both the normal
    /// ([`RenewalLeaseKeeper::finish`]) and emergency
    /// (`RenewalLeaseKeeper::release_without_blocking_the_runtime`) paths. A
    /// guard held directly by async code must do the same rather than letting
    /// it drop in place.
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // A failed release is not fatal: the lease expires on its own.
        if let Err(error) = self.store.release_claim(&self.name, self.fence) {
            tracing::warn!(
                lease = %self.name,
                error = %error,
                "failed to release TLS renewal lease; it will expire on its own"
            );
        }
    }
}

fn prune_expired(document: &mut TlsLeaseStoreFile, now: DateTime<Utc>) {
    let retention = chrono::TimeDelta::try_seconds(EXPIRED_LEASE_RETENTION_SECONDS)
        .unwrap_or_else(chrono::TimeDelta::zero);
    let cutoff = now - retention;
    document.leases.retain(|_, lease| lease.expires_at > cutoff);
}

/// Clamp a lease TTL into `chrono` space. Callers pass operator-clamped values;
/// this only guards against an unrepresentable duration.
fn lease_delta(ttl: Duration) -> chrono::TimeDelta {
    let millis = i64::try_from(ttl.as_millis());
    let millis = millis.unwrap_or(FALLBACK_LEASE_TTL_MILLIS);
    let delta = chrono::TimeDelta::try_milliseconds(millis);
    delta.unwrap_or_else(chrono::TimeDelta::zero)
}

/// Accept a configured instance id verbatim, or reject it.
///
/// Deliberately **not** a sanitizer. Dropping disallowed characters or
/// truncating an overlong value maps two distinct configured identities onto
/// one — `pod-a/1` and `pod-a1`, or two pod names sharing a 128-character
/// prefix — and a collision here is what lets a second process reacquire a live
/// claim. An unusable value fails closed instead, so the misconfiguration is
/// visible at startup rather than as a duplicate ACME order weeks later.
///
/// The error names the rule, never the value: the id is operator-supplied text
/// that flows into logs and shared state.
fn validate_instance_id(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("must not be empty".to_string());
    }
    if raw.chars().count() > MAX_INSTANCE_ID_LEN {
        return Err(format!(
            "must be at most {MAX_INSTANCE_ID_LEN} characters (got {})",
            raw.chars().count()
        ));
    }
    let permitted = |character: char| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
    };
    if !raw.chars().all(permitted) {
        return Err("must contain only ASCII letters, digits, '-', '_', '.', or ':'".to_string());
    }
    Ok(raw.to_string())
}

static PROCESS_INSTANCE_ID: OnceLock<Result<String, String>> = OnceLock::new();

/// Stable identity for this process's lease claims.
///
/// `FERRUM_TLS_STORE_INSTANCE_ID` lets an operator pin a stable per-replica
/// identity (for example a StatefulSet pod name) so ownership is attributable
/// in the shared lease table and in logs. It does **not** let a restarted
/// replica reclaim its own still-live claim: a live claim excludes every
/// acquirer, and a crashed holder is recovered through expiry.
///
/// A configured value that is empty, overlong, or contains disallowed
/// characters is an error. The generated fallback is always valid and always
/// distinct across processes.
pub fn process_instance_id() -> Result<&'static str, TlsLeaseError> {
    let resolved = PROCESS_INSTANCE_ID.get_or_init(|| {
        match crate::config::env_config::tls_store_instance_id_from_env() {
            Some(configured) => validate_instance_id(&configured),
            None => Ok(format!(
                "pid{}-{}",
                std::process::id(),
                Uuid::new_v4().simple()
            )),
        }
    });
    match resolved {
        Ok(identity) => Ok(identity.as_str()),
        Err(reason) => Err(TlsLeaseError::InvalidInstanceId(reason.clone())),
    }
}

fn lease_store_dir_from_env() -> PathBuf {
    let path = crate::config::env_config::tls_managed_store_path_from_env();
    if path.is_empty() {
        PathBuf::from(DEFAULT_STORE_DIR)
    } else {
        PathBuf::from(path)
    }
}

static GLOBAL_TLS_LEASE_STORE: OnceLock<Result<Arc<TlsLeaseStore>, String>> = OnceLock::new();

pub fn global_lease_store() -> Result<Arc<TlsLeaseStore>, String> {
    GLOBAL_TLS_LEASE_STORE
        .get_or_init(|| {
            TlsLeaseStore::open(lease_store_dir_from_env())
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .clone()
}
