//! Issue #2409: exactly one instance renews a given ACME certificate.
//!
//! Every serving replica runs its own renewal scheduler. The shared lease table
//! is what makes the renewal decision single-writer: a claim is granted to one
//! holder, excludes *every* other acquirer while it is live — including one
//! presenting the same instance identity — expires on its own so a crashed
//! holder fails over, and carries a fence so a superseded holder cannot
//! resurrect its claim.
//!
//! The claim also has to survive the operation it guards. ACME does not fence
//! side effects for Ferrum, so a static TTL bounds nothing once an
//! order/finalize cycle runs long; `RenewalLeaseKeeper` heartbeats the claim for
//! the whole renewal and cancels the in-flight work the moment it is lost.

//! Store commits are additionally *fenced*: the mutation runs while the lease
//! table's own exclusive lock is held, so acquisition and takeover cannot cross
//! it and a superseded owner can never land a stale write beside the new
//! owner's.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ferrum_edge::tls::lease::{
    FencedCommit, GuardedCleanup, RenewalLeaseKeeper, TlsLeaseError, TlsLeaseStore,
    acme_renewal_lease_name,
};

/// Generous ceiling on "this must eventually happen". It is a diagnostic bound,
/// never a schedule: a slow or paused runner spends longer here rather than
/// turning correct behaviour red.
const SETTLE_BUDGET: Duration = Duration::from_secs(30);

/// One replica's view of the shared lease table.
fn instance(dir: &Path, holder: &str) -> Arc<TlsLeaseStore> {
    let opened = TlsLeaseStore::open_with_holder(dir, holder.to_string());
    Arc::new(opened.expect("open lease store"))
}

/// Bounded poll of a condition on the current thread, for the synchronous
/// tests. `false` means the condition never held within `budget`.
fn wait_until(budget: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if ready() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// [`wait_until`] on the runtime, so a single-threaded test runtime keeps
/// driving the keeper's own tasks while the condition is polled.
async fn wait_until_async(budget: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if ready() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Hold the lease store's own cross-process advisory lock from a *separate*
/// open file, exactly as a second instance would.
///
/// Nothing is stubbed: `SharedStoreFile` locks the sidecar `.tls-leases.json.lock`
/// with `flock`, whose locks are per open file description, so a second open in
/// this same process contends for real. Dropping the returned handle releases
/// it.
///
/// The acquisition retries rather than asserting on the first attempt: a
/// heartbeat may legitimately be holding the lock at that instant, and the test
/// wants the lock, not a verdict on who had it first.
fn hold_store_lock(dir: &Path) -> File {
    let file = open_store_lock_file(dir);
    assert!(
        wait_until(SETTLE_BUDGET, || file.try_lock().is_ok()),
        "the test must be able to take the lease store's lock"
    );
    file
}

/// A fresh open file description on the lease store's sidecar lock, unlocked.
///
/// Separate from [`hold_store_lock`] so a test can also *probe* the lock —
/// `try_lock` answers immediately either way, which makes "somebody else holds
/// this right now" a state to read rather than a window to wait out.
fn open_store_lock_file(dir: &Path) -> File {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(".tls-leases.json.lock"))
        .expect("open the lease store's lock file")
}

/// Poll the persisted record until a heartbeat has advanced `expires_at` past
/// `beyond`, or give up after `timeout`.
///
/// Event driven rather than a blind sleep: a paused scheduler costs latency
/// here instead of turning correct production behaviour into a red test, and
/// the absence of any beat still fails (through the caller's diagnostic) rather
/// than passing because a sleep happened to be long enough.
async fn wait_for_extension(
    store: &Arc<TlsLeaseStore>,
    name: &str,
    beyond: DateTime<Utc>,
    timeout: Duration,
) -> Option<DateTime<Utc>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(Some(record)) = store.peek(name)
            && record.expires_at > beyond
        {
            return Some(record.expires_at);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Sleep until wall-clock time is past `moment`, in bounded steps, so the
/// "operation" outlives a specific expiry rather than a guessed duration.
async fn sleep_until_past(moment: DateTime<Utc>) {
    loop {
        let Ok(remaining) = (moment - Utc::now()).to_std() else {
            return;
        };
        tokio::time::sleep(remaining.max(Duration::from_millis(25))).await;
    }
}

#[test]
fn only_one_instance_can_hold_a_renewal_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A must win the first claim");
    assert_eq!(lease.holder(), "replica-a");
    assert_eq!(lease.name(), name);

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(denied.is_none(), "a live claim must exclude the other");

    let record = instance_b.peek(&name).expect("B reads");
    assert_eq!(record.expect("claim present").holder, "replica-a");
}

#[test]
fn an_expired_claim_fails_over_to_another_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let short = Duration::from_millis(150);

    let held = instance_a.try_acquire(&name, short).expect("A claims");
    let lease = held.expect("A must win the first claim");
    // A crashed holder never releases. Leaking the guard reproduces that
    // exactly: only expiry can hand the claim over.
    std::mem::forget(lease);

    let denied = instance_b.try_acquire(&name, short).expect("B attempts");
    assert!(denied.is_none(), "the claim is still live");

    std::thread::sleep(Duration::from_millis(400));

    let taken = instance_b.try_acquire(&name, short).expect("B retries");
    let lease = taken.expect("an expired claim must fail over");
    assert_eq!(lease.holder(), "replica-b");
}

#[test]
fn releasing_a_claim_lets_another_instance_take_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A must win the first claim");
    lease.release().expect("A releases");

    let taken = instance_b.try_acquire(&name, ttl).expect("B claims");
    let lease = taken.expect("B must take the released claim");
    assert_eq!(lease.holder(), "replica-b");
}

#[test]
fn dropping_a_claim_releases_it_for_another_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    {
        let held = instance_a.try_acquire(&name, ttl).expect("A claims");
        assert!(held.is_some(), "A must win the first claim");
    }

    let taken = instance_b.try_acquire(&name, ttl).expect("B claims");
    assert!(taken.is_some(), "a dropped claim must not wedge renewal");
}

#[test]
fn a_superseded_holder_cannot_renew_its_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let short = Duration::from_millis(150);

    let held = instance_a.try_acquire(&name, short).expect("A claims");
    let stale = held.expect("A must win the first claim");
    std::thread::sleep(Duration::from_millis(400));

    let taken = instance_b.try_acquire(&name, short).expect("B claims");
    let fresh = taken.expect("B takes over the expired claim");
    assert_ne!(stale.fence(), fresh.fence(), "takeover bumps the fence");

    let renewed = stale.renew(short).expect("stale renew is answered");
    assert!(!renewed, "a superseded holder must not extend the claim");

    let record = instance_a.peek(&name).expect("read");
    assert_eq!(record.expect("claim present").holder, "replica-b");
}

#[test]
fn a_live_holder_can_extend_its_own_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(400);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A must win the first claim");
    let before = instance_a.peek(&name).expect("read").expect("present");

    assert!(lease.renew(Duration::from_secs(60)).expect("renew"));

    let after = instance_a.peek(&name).expect("read").expect("present");
    assert!(after.expires_at > before.expires_at, "renewal extends");
    assert_eq!(after.fence, before.fence, "renewal keeps the fence");

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(denied.is_none(), "the extended claim still excludes B");
}

#[test]
fn distinct_certificates_get_independent_claims() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let first = acme_renewal_lease_name("cert-one");
    let second = acme_renewal_lease_name("cert-two");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&first, ttl).expect("A claims");
    assert!(held.is_some(), "A takes the first certificate");
    let held = instance_b.try_acquire(&second, ttl).expect("B claims");
    assert!(held.is_some(), "B renews a different certificate");

    let denied = instance_b.try_acquire(&first, ttl).expect("B attempts");
    assert!(denied.is_none(), "the first claim is still A's");
}

/// A second process presenting the *same* holder identity must be denied while
/// the claim is live. Two processes can share an identity through a duplicated
/// `FERRUM_TLS_STORE_INSTANCE_ID` or an overlapping rolling replacement, and
/// letting the newcomer reacquire would bump the fence and start a second
/// renewal while the original is still driving external ACME work — which the
/// original would only notice at its next explicit check.
#[test]
fn a_second_instance_with_the_same_identity_cannot_take_a_live_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let original = held.expect("A must win the first claim");

    let twin = instance(dir.path(), "replica-a");
    let denied = twin.try_acquire(&name, ttl).expect("the twin attempts");
    assert!(
        denied.is_none(),
        "a live claim must exclude a same-identity acquirer too"
    );

    let record = twin.peek(&name).expect("read").expect("claim present");
    assert_eq!(
        record.fence,
        original.fence(),
        "a denied acquisition must not advance the fence under the live holder"
    );
    assert!(
        original.renew(ttl).expect("the original renews"),
        "the original holder keeps its claim"
    );
}

/// Crash recovery for a same-identity restart happens through expiry, not
/// through immediate reclamation — and the takeover advances the fence, so the
/// dead generation can no longer renew or release.
#[test]
fn a_same_identity_restart_reclaims_only_after_expiry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let short = Duration::from_millis(150);

    let held = instance_a.try_acquire(&name, short).expect("A claims");
    let crashed = held.expect("A must win the first claim");
    let crashed_fence = crashed.fence();
    // A crashed holder never releases; leaking the guard reproduces that.
    std::mem::forget(crashed);

    let restarted = instance(dir.path(), "replica-a");
    let denied = restarted
        .try_acquire(&name, short)
        .expect("restart attempts");
    assert!(denied.is_none(), "the claim is still live");

    std::thread::sleep(Duration::from_millis(400));

    let taken = restarted
        .try_acquire(&name, short)
        .expect("restart retries");
    let lease = taken.expect("an expired claim must be reclaimable");
    assert_eq!(lease.holder(), "replica-a");
    assert!(
        lease.fence() > crashed_fence,
        "takeover must advance the fence past the crashed generation"
    );
}

/// A configured instance id is validated, never sanitized. Silently dropping
/// disallowed characters or truncating an overlong value maps two distinct
/// configured identities onto one, which is exactly the collision that lets a
/// second process reacquire a live claim.
#[test]
fn an_invalid_configured_instance_id_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");

    let empty = TlsLeaseStore::open_with_holder(dir.path(), String::new());
    assert!(matches!(empty, Err(TlsLeaseError::InvalidInstanceId(_))));

    let blank = TlsLeaseStore::open_with_holder(dir.path(), "   ".to_string());
    assert!(matches!(blank, Err(TlsLeaseError::InvalidInstanceId(_))));

    // Would previously have been sanitized to `pod-a1`, colliding with a real
    // `pod-a1` replica.
    let punctuated = TlsLeaseStore::open_with_holder(dir.path(), "pod-a/1".to_string());
    assert!(matches!(
        punctuated,
        Err(TlsLeaseError::InvalidInstanceId(_))
    ));

    // Would previously have been truncated to the shared 128-character prefix.
    let overlong = format!("{}-one", "n".repeat(128));
    let overlong = TlsLeaseStore::open_with_holder(dir.path(), overlong);
    assert!(matches!(overlong, Err(TlsLeaseError::InvalidInstanceId(_))));

    let accepted = TlsLeaseStore::open_with_holder(dir.path(), "pod-a.ns:1".to_string());
    assert_eq!(accepted.expect("valid identity").holder(), "pod-a.ns:1");
}

/// The failure message names the rule, never the configured value: an instance
/// id is operator-supplied text that flows into logs and shared state.
#[test]
fn an_invalid_instance_id_error_does_not_echo_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rejected = "pod-a/secret-looking-value";
    let error = TlsLeaseStore::open_with_holder(dir.path(), rejected.to_string())
        .expect_err("must be rejected");
    assert!(
        !error.to_string().contains(rejected),
        "the diagnostic must not echo the configured identity"
    );
}

/// Two configured identities that a sanitizer would collapse must stay
/// distinct: whichever holds the claim, the other is excluded.
#[test]
fn identities_that_a_sanitizer_would_collide_stay_distinct() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = instance(dir.path(), "pod-a-1");
    let second = instance(dir.path(), "pod-a-2");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = first.try_acquire(&name, ttl).expect("first claims");
    assert!(held.is_some(), "the first identity wins");
    let denied = second.try_acquire(&name, ttl).expect("second attempts");
    assert!(denied.is_none(), "a distinct identity is excluded");
}

// ---------------------------------------------------------------------------
// Continuous lease maintenance for the whole external renewal operation.
//
// The TTL alone bounds nothing: ACME does not fence side effects for Ferrum, so
// an order/finalize cycle that outruns the TTL would let a second replica
// acquire and start ordering while the first is still polling. The keeper is
// what closes that window.
// ---------------------------------------------------------------------------

/// A renewal that outlives the claim's *original* expiry still has exactly one
/// owner, because the heartbeat keeps extending it while the work is in flight.
///
/// The proof is state driven, not timing driven. A persisted extension is
/// observed first (so a missing heartbeat fails on the diagnostic timeout, not
/// on a sleep that was merely long enough), then the operation is run until
/// wall-clock time is genuinely past the original expiry, then exclusion is
/// re-asserted. The TTL is deliberately generous — production clamps it to at
/// least 60 seconds — so a scheduler pause on a shared runner cannot expire a
/// claim the heartbeat is servicing correctly.
#[tokio::test]
async fn a_long_operation_retains_exactly_one_owner_via_the_heartbeat() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    // Beats every 2s; tolerates a ~4s pause between beats.
    let ttl = Duration::from_secs(6);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);
    let original_expiry = instance_a
        .peek(&name)
        .expect("read")
        .expect("present")
        .expires_at;

    // Proof one: a beat actually reached the shared table. Without a heartbeat
    // this never happens and the test fails here.
    let extended = wait_for_extension(&instance_a, &name, original_expiry, Duration::from_secs(60))
        .await
        .expect("the heartbeat must persist an extension of the claim");
    assert!(
        extended > original_expiry,
        "the persisted claim must have been extended past its original expiry"
    );

    // Proof two: stand in for account registration, order creation, challenge
    // publication, propagation, polling, and finalization — work that runs
    // until the original expiry is genuinely in the past.
    keeper
        .guarded(sleep_until_past(original_expiry))
        .await
        .expect("the claim survives work that outlives its original TTL");
    assert!(
        Utc::now() > original_expiry,
        "the operation must have crossed the original expiry"
    );
    keeper.ensure_owned().await.expect("still the owner");

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(
        denied.is_none(),
        "the heartbeat must keep the claim live for the whole operation"
    );

    keeper.finish().await.expect("release");

    let taken = instance_b.try_acquire(&name, ttl).expect("B retries");
    assert!(
        taken.is_some(),
        "a released claim must hand over immediately"
    );
}

/// A lease table showing another live holder, as a replica that was paused past
/// its expiry and then resumed would find.
fn takeover_document(name: &str) -> String {
    format!(
        concat!(
            r#"{{"version":99,"leases":{{"{name}":{{"#,
            r#""holder":"replica-b","#,
            r#""acquired_at":"2026-01-01T00:00:00Z","#,
            r#""expires_at":"2999-01-01T00:00:00Z","#,
            r#""fence":9999}}}}}}"#
        ),
        name = name
    )
}

/// Losing the claim cancels the in-flight operation instead of letting it run to
/// completion and publish final state.
#[tokio::test]
async fn losing_the_claim_cancels_in_flight_work() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // Another instance took the claim over while this one was stalled. The next
    // heartbeat must see the foreign holder and higher fence.
    std::fs::write(dir.path().join("tls-leases.json"), takeover_document(&name))
        .expect("simulate a takeover by another instance");

    // Stands in for the rest of the ACME cycle: polling, finalization, download.
    let remaining_work = tokio::time::sleep(Duration::from_secs(30));
    let outcome = keeper.guarded(remaining_work).await;
    assert!(
        outcome.is_err(),
        "guarded work must be cancelled once the claim is lost"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");
    assert!(
        keeper.ensure_owned().await.is_err(),
        "a superseded holder must not be allowed to publish final state"
    );

    // The takeover survives: the superseded holder must not have released or
    // rewritten the new owner's claim.
    let record = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(record.holder, "replica-b");
    assert_eq!(record.fence, 9999);
}

/// A store that cannot be read or written fails closed: the renewal is
/// cancelled rather than continued on the assumption that the claim still
/// holds.
#[tokio::test]
async fn a_heartbeat_store_error_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // Corrupt the shared lease table the way a truncated write or a foreign
    // writer would. Every subsequent read fails closed rather than degrading to
    // an empty document.
    std::fs::write(dir.path().join("tls-leases.json"), b"{ not json").expect("corrupt the table");

    let long = tokio::time::sleep(Duration::from_secs(30));
    let outcome = keeper.guarded(long).await;
    assert!(
        outcome.is_err(),
        "an unreadable lease table must cancel the renewal"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");
    assert!(
        keeper.ensure_owned().await.is_err(),
        "final state must not be published after a heartbeat store error"
    );
}

/// An abandoned keeper stops heartbeating. Without this a keeper dropped
/// without `finish()` — an early return, a panic, a cancelled scheduler — would
/// keep a claim alive for a renewal nobody is driving, wedging the certificate
/// until the process exits.
#[tokio::test]
async fn an_abandoned_keeper_stops_heartbeating() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);
    assert!(!keeper.is_lost());
    let progress = keeper.heartbeat_progress();
    let started_before_drop = progress.started();
    // Dropped without `finish()`.
    std::mem::drop(keeper);

    // Drop cannot await an extension already running on the blocking pool. It
    // may therefore land one final beat before the best-effort release, but the
    // stopped loop must never start another and the claim must become
    // reclaimable. Polling the actual takeover is scheduler-independent; a
    // fixed sleep raced a saturated blocking pool and mistook that one allowed
    // in-flight beat for a continuing heartbeat loop.
    let mut taken = None;
    assert!(
        wait_until_async(SETTLE_BUDGET, || {
            if taken.is_none() {
                taken = instance_b.try_acquire(&name, ttl).expect("B retries");
            }
            taken.is_some()
        })
        .await,
        "the certificate must become reclaimable again"
    );
    assert!(
        progress.started() <= started_before_drop.saturating_add(1),
        "dropping the keeper may settle one in-flight beat but must not start another"
    );
}

// ---------------------------------------------------------------------------
// Fenced commits.
//
// The lease table and the account/order/certificate stores are separate
// documents behind separate locks, so an ownership check on each side of a
// write bounds nothing: a claim that expires mid-write lets another replica
// acquire and publish while the stale write still lands, and the after-check
// detects a loss it cannot undo. The commit therefore runs while the lease
// store's own exclusive lock is held.
// ---------------------------------------------------------------------------

/// A superseded owner's target-store mutation must never run at all — detecting
/// the loss afterwards would be too late to unpublish a certificate.
#[tokio::test]
async fn a_target_store_mutation_cannot_run_after_ownership_is_lost() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // Another instance took the claim over while this one was stalled.
    std::fs::write(dir.path().join("tls-leases.json"), takeover_document(&name))
        .expect("simulate a takeover by another instance");

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    let outcome = keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await;
    assert!(
        outcome.is_err(),
        "a superseded owner must not be allowed to commit"
    );
    assert!(
        !published.load(Ordering::SeqCst),
        "the target-store mutation must not run once ownership is gone"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");

    // The new owner's claim is untouched: a refused commit writes nothing.
    let record = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(record.holder, "replica-b");
    assert_eq!(record.fence, 9999);
}

/// An absent claim — the lease table was reset, or the record pruned — is the
/// same fail-closed answer as a superseded one.
#[tokio::test]
async fn a_missing_claim_refuses_the_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    std::fs::write(
        dir.path().join("tls-leases.json"),
        br#"{"version":7,"leases":{}}"#,
    )
    .expect("reset the lease table");

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    let outcome = keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await;
    assert!(outcome.is_err(), "an absent claim must refuse the commit");
    assert!(
        !published.load(Ordering::SeqCst),
        "the target-store mutation must not run without a claim"
    );
    assert!(keeper.is_lost(), "the keeper records the loss");
}

/// A takeover cannot be granted while a fenced commit is in flight, even once
/// the claim's nominal TTL has elapsed — the acquirer blocks on the same lease
/// lock. Once the commit has finished, the newly expired claim is acquirable
/// and the stale owner cannot commit a second time.
///
/// Every step is an explicit event or an observed state, never an interval.
/// The commit closure announces that it is running *inside* the lease lock and
/// then blocks until this test releases it, so the window is opened and closed
/// deliberately. Expiry is read back from the persisted record against
/// wall-clock time. The exclusion is then read directly off the primitive that
/// enforces it — a second open file description on the store's own sidecar lock
/// is refused *immediately* — rather than inferred from a takeover failing to
/// happen inside some chosen window. A takeover has nothing else to block on:
/// `try_acquire` reaches this same lock before it can look at any record.
#[test]
fn a_takeover_cannot_cross_a_fenced_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    // Short enough that the nominal TTL elapses while the commit below is held.
    let ttl = Duration::from_millis(300);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A wins");
    let fence = lease.fence();
    // No heartbeat and no release: the owner is mid-write when its claim ages
    // out. Leaking the guard reproduces that without racing the commit.
    std::mem::forget(lease);

    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let finished = Arc::new(AtomicBool::new(false));
    let commit_flag = Arc::clone(&finished);
    let committing = Arc::clone(&instance_a);
    let commit_name = name.clone();
    let commit = std::thread::spawn(move || {
        committing.commit_fenced(&commit_name, fence, move || {
            // Stands in for a slow account/order/certificate mutation. It
            // starts and ends where the test says, so "in flight" is a fact
            // rather than an assumption about scheduling.
            entered_tx.send(()).expect("the test observes commit entry");
            release_rx
                .recv_timeout(SETTLE_BUDGET)
                .expect("the test releases the commit");
            commit_flag.store(true, Ordering::SeqCst);
            "published"
        })
    });

    // The mutation is running, which means `commit_fenced` verified ownership
    // and is holding the lease store's exclusive lock right now.
    entered_rx
        .recv_timeout(SETTLE_BUDGET)
        .expect("the fenced commit must start under the live claim");

    // The claim's nominal TTL elapses while that lock is held. Read back from
    // the persisted record and compared against wall-clock time, so this is an
    // observed state rather than a slept-through duration. `peek` never takes
    // the writer lock, so it answers while the commit holds it.
    let claim = instance_a.peek(&name).expect("read").expect("present");
    let expiry = claim.expires_at;
    assert!(
        wait_until(SETTLE_BUDGET, || Utc::now() > expiry),
        "the claim's nominal TTL must elapse while the commit is in flight"
    );

    // The exclusion, read off the lock itself. `try_acquire` takes exactly this
    // sidecar lock before it can read, decide, or write anything, so a lock that
    // is refused here is a takeover that cannot proceed. `try_lock` returns at
    // once, so this is an immediate state read and cannot pass by being slow.
    let probe = open_store_lock_file(dir.path());
    match probe.try_lock() {
        Err(TryLockError::WouldBlock) => {}
        Ok(()) => panic!(
            "the lease store's lock was free while a fenced commit was in flight; \
             a takeover could have crossed the commit"
        ),
        Err(TryLockError::Error(error)) => panic!("lease lock probe failed: {error}"),
    }
    std::mem::drop(probe);
    assert!(
        !finished.load(Ordering::SeqCst),
        "the commit must still be in flight"
    );

    release_tx.send(()).expect("release the fenced commit");

    let outcome = commit
        .join()
        .expect("commit thread")
        .expect("the commit is answered");
    assert_eq!(
        outcome,
        FencedCommit::Committed("published"),
        "a commit that started under a live claim finishes under it"
    );
    assert!(
        finished.load(Ordering::SeqCst),
        "the commit ran its mutation to completion"
    );

    // Only now — with the lock released and the claim already expired — is the
    // takeover answerable, and it is granted.
    let taken = instance_b
        .try_acquire(&name, ttl)
        .expect("B attempts")
        .expect("once the commit released the lock, the expired claim is acquirable");
    assert_eq!(taken.holder(), "replica-b");

    let second = Arc::new(AtomicBool::new(false));
    let second_flag = Arc::clone(&second);
    let refused = instance_a
        .commit_fenced(&name, fence, move || {
            second_flag.store(true, Ordering::SeqCst);
        })
        .expect("the second attempt is answered");
    assert_eq!(
        refused,
        FencedCommit::NotOwner,
        "the stale owner is superseded once the takeover landed"
    );
    assert!(
        !second.load(Ordering::SeqCst),
        "a superseded owner must not perform a second commit"
    );
}

/// Final renewal publication runs two target-store mutations under one lease
/// fence — order `Valid` first, then certificate material. A takeover must not
/// be able to slip between them the way it could when those writes were
/// separate `commit_fenced` calls.
#[test]
fn two_target_mutations_share_one_lease_fence_without_a_takeover_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_millis(300);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A wins");
    let fence = lease.fence();
    std::mem::forget(lease);

    let first_done = Arc::new(AtomicBool::new(false));
    let second_done = Arc::new(AtomicBool::new(false));
    let (after_first_tx, after_first_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let committing = Arc::clone(&instance_a);
    let commit_name = name.clone();
    let first_flag = Arc::clone(&first_done);
    let second_flag = Arc::clone(&second_done);
    let commit = std::thread::spawn(move || {
        committing.commit_fenced(&commit_name, fence, move || {
            // Stands in for the order Valid transition.
            first_flag.store(true, Ordering::SeqCst);
            after_first_tx
                .send(())
                .expect("the test observes the first mutation");
            release_rx
                .recv_timeout(SETTLE_BUDGET)
                .expect("the test releases the mid-publication hold");
            // Stands in for certificate-store publication.
            second_flag.store(true, Ordering::SeqCst);
            "published-both"
        })
    });

    after_first_rx
        .recv_timeout(SETTLE_BUDGET)
        .expect("first mutation must run under the live claim");
    assert!(
        first_done.load(Ordering::SeqCst),
        "order Valid stand-in must have committed"
    );
    assert!(
        !second_done.load(Ordering::SeqCst),
        "certificate publication stand-in must still be pending inside the same fence"
    );

    // While the fence is still held between the two mutations, the lease store
    // lock itself is busy — a takeover cannot cross that gap.
    let probe = open_store_lock_file(dir.path());
    match probe.try_lock() {
        Err(TryLockError::WouldBlock) => {}
        Ok(()) => panic!(
            "the lease store's lock was free between the two final-publication \
             mutations; a takeover could have crossed the publication boundary"
        ),
        Err(TryLockError::Error(error)) => panic!("lease lock probe failed: {error}"),
    }
    std::mem::drop(probe);

    let claim = instance_a.peek(&name).expect("read").expect("present");
    assert!(
        wait_until(SETTLE_BUDGET, || Utc::now() > claim.expires_at),
        "the nominal TTL must elapse while the fence still covers both writes"
    );
    assert!(
        !second_done.load(Ordering::SeqCst),
        "the second mutation must still be inside the held fence after expiry"
    );

    release_tx
        .send(())
        .expect("release the mid-publication hold");
    let outcome = commit
        .join()
        .expect("commit thread")
        .expect("the commit is answered");
    assert_eq!(outcome, FencedCommit::Committed("published-both"));
    assert!(
        first_done.load(Ordering::SeqCst) && second_done.load(Ordering::SeqCst),
        "both final-publication mutations must complete under the one fence"
    );

    // Only after the combined fence releases can a takeover land.
    let taken = instance_b
        .try_acquire(&name, ttl)
        .expect("B attempts")
        .expect("expired claim is acquirable once the fence releases");
    assert_eq!(taken.holder(), "replica-b");
}

/// A target-store failure is not a lease failure: it propagates to the caller
/// and leaves the claim exactly as it was, rather than rewriting or releasing
/// the record another holder may be relying on.
#[test]
fn a_target_store_error_propagates_without_disturbing_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let lease = held.expect("A wins");
    let before = instance_a.peek(&name).expect("read").expect("present");

    let outcome = instance_a
        .commit_fenced(&name, lease.fence(), || {
            Err::<(), String>("shared TLS store write failed".to_string())
        })
        .expect("the commit itself succeeds");
    assert_eq!(
        outcome,
        FencedCommit::Committed(Err("shared TLS store write failed".to_string())),
        "the target store's own error must be carried out to the caller"
    );

    let after = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(
        before, after,
        "a failed target-store write must not rewrite or release the claim"
    );

    let denied = instance_b.try_acquire(&name, ttl).expect("B attempts");
    assert!(denied.is_none(), "the claim is still exclusively A's");
    assert!(
        lease.renew(ttl).expect("A renews"),
        "A must still be able to maintain the claim it never lost"
    );
}

// ---------------------------------------------------------------------------
// Cleanup is a side effect too.
// ---------------------------------------------------------------------------

/// Losing the claim cancels DNS-01 cleanup. The instance that took over
/// republishes the same `_acme-challenge` names, so a superseded instance
/// retracting them would break the new owner's validation — and nothing later
/// in the renewal may publish either.
///
/// The preflight has to be *authoritative and up front*, not merely a
/// cancellation scope over the published loss signal: the takeover lands in the
/// lease table before any heartbeat has had a reason to observe it, and a
/// retraction hook is perfectly capable of completing inside that gap. The TTL
/// here is deliberately long enough that **no beat can run during the test**,
/// and the cleanup future retracts on its very first poll — so `Lost` can only
/// come from a preflight made before the future was polled at all.
///
/// The preflight is a *refresh*, so this also pins that it cannot extend
/// anything on a superseded fence: the new owner's record must come back out
/// exactly as it went in.
#[tokio::test]
async fn losing_the_claim_cancels_dns_cleanup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    // Beats every 20s: the heartbeat cannot be what notices the takeover.
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    // The takeover lands as finalization completes, i.e. exactly when cleanup
    // would otherwise run unguarded.
    std::fs::write(dir.path().join("tls-leases.json"), takeover_document(&name))
        .expect("simulate a takeover by another instance");
    assert!(
        !keeper.is_lost(),
        "the takeover has not been published as a loss yet; the guard must not \
         be relying on the heartbeat having noticed it"
    );

    let retracted = Arc::new(AtomicBool::new(false));
    let retract = Arc::clone(&retracted);
    // Stands in for a DNS-01 cleanup hook that is ready to go: it retracts the
    // records the instant it is polled, with no await in front of it.
    let cleanup = async move {
        retract.store(true, Ordering::SeqCst);
        Ok::<(), String>(())
    };
    assert_eq!(
        keeper.guarded_cleanup(cleanup).await,
        GuardedCleanup::Lost,
        "cleanup must fail closed against authoritative ownership, before the \
         heartbeat has published anything"
    );
    assert!(
        !retracted.load(Ordering::SeqCst),
        "a superseded instance must not retract the new owner's challenge \
         records, so the cleanup future must never have been polled"
    );
    assert!(
        keeper.is_lost(),
        "the authoritative preflight must also mark the keeper lost, so \
         concurrent guarded work is cancelled too"
    );
    let owner = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(
        owner.holder, "replica-b",
        "the takeover stands; the preflight must not have rewritten it"
    );
    assert_eq!(
        owner.fence, 9999,
        "a superseded fence must not be able to extend the new owner's claim"
    );

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    let commit = keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await;
    assert!(
        commit.is_err(),
        "an abandoned renewal must not progress into final publication"
    );
    assert!(
        !published.load(Ordering::SeqCst),
        "no unguarded side effect may follow a cancelled cleanup"
    );
}

/// An ordinary cleanup-hook failure is *not* loss: it is reported so the caller
/// can log it, and the renewal keeps going under the claim it still holds.
#[tokio::test]
async fn an_ordinary_cleanup_failure_keeps_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);

    let cleanup = async { Err::<(), String>("hook exited 1".to_string()) };
    assert_eq!(
        keeper.guarded_cleanup(cleanup).await,
        GuardedCleanup::Failed("hook exited 1".to_string()),
        "a hook failure must be reported rather than treated as loss"
    );
    assert!(!keeper.is_lost(), "the claim is still held");

    let published = Arc::new(AtomicBool::new(false));
    let publish = Arc::clone(&published);
    keeper
        .commit_fenced(move || publish.store(true, Ordering::SeqCst))
        .await
        .expect("certificate processing continues under the same claim");
    assert!(published.load(Ordering::SeqCst));
}

/// The cleanup preflight *refreshes* the claim rather than merely confirming
/// it, and does so before the hook is polled.
///
/// Confirming is not enough on its own: a claim can be authoritatively live
/// with a sliver of TTL left, expire, and be taken over between the check
/// returning and the hook's first poll — which is the same retraction-after-
/// takeover the check exists to prevent, just moved a few microseconds later.
/// A refresh under the lease store's own lock hands the hook a whole TTL
/// instead.
///
/// The evidence is taken from inside the future: the hook reads the persisted
/// record on its very first poll, so an `expires_at` already past the one the
/// acquisition wrote can only have been advanced *before* the hook ran. The TTL
/// is long enough that no heartbeat can beat during the test, so the preflight
/// is the only thing that could have advanced it.
#[tokio::test]
async fn the_cleanup_preflight_refreshes_the_claim_before_the_hook_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let name = acme_renewal_lease_name("edge-cert");
    // Beats every 20s: the heartbeat cannot be what advances the claim.
    let ttl = Duration::from_secs(60);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);
    let before = instance_a.peek(&name).expect("read").expect("present");

    // `expires_at` is `now + ttl`, so a refresh advances it exactly when the
    // refresh happens strictly later than the acquisition. Observed, not
    // assumed: the assertion below would otherwise rest on the clock having
    // ticked between two adjacent writes.
    assert!(
        wait_until(SETTLE_BUDGET, || Utc::now() > before.acquired_at),
        "the clock must advance past the acquisition"
    );

    let sampling = Arc::clone(&instance_a);
    let sample_name = name.clone();
    // Stands in for a DNS-01 cleanup hook that is ready to go: it samples the
    // authoritative record the instant it is polled, with no await in front.
    let cleanup = async move {
        let sampled = sampling.peek(&sample_name).expect("read").expect("present");
        Ok::<DateTime<Utc>, String>(sampled.expires_at)
    };
    let at_first_poll = match keeper.guarded_cleanup(cleanup).await {
        GuardedCleanup::Completed(expires_at) => expires_at,
        other => panic!("the cleanup must run under the refreshed claim: {other:?}"),
    };
    assert!(
        at_first_poll > before.expires_at,
        "the preflight must have extended the claim before the hook was polled"
    );

    let after = instance_a.peek(&name).expect("read").expect("present");
    assert_eq!(
        after.expires_at, at_first_poll,
        "nothing after the preflight may rewrite the claim"
    );
    assert_eq!(
        after.holder, before.holder,
        "a refresh must not change the holder"
    );
    assert_eq!(
        after.fence, before.fence,
        "a refresh extends the claim; it must not bump the fence"
    );
    assert!(!keeper.is_lost(), "the claim is still held");
}

// ---------------------------------------------------------------------------
// Heartbeat shutdown.
// ---------------------------------------------------------------------------

/// `finish()` settles an extension that is genuinely in flight before it
/// releases the claim.
///
/// Aborting the heartbeat task is not settlement: if it is parked on a
/// `spawn_blocking` extension, dropping that join handle neither cancels nor
/// joins the blocking work, so a beat can still land *after* the release and
/// leave a claim alive that nobody is driving.
///
/// So the extension is put — and held — in flight for real, by taking the
/// store's own advisory lock from a second open file the way another instance
/// would. `HeartbeatProgress` makes every step a state the test waits *for*,
/// never an interval it waits *out*: `started > settled` means the loop has
/// handed an extension to the blocking pool and not yet awaited it back, and
/// `stop_requested` means shutdown has already asked the loop to stop. Their
/// conjunction is the settling window, and `JoinHandle::is_finished()` is then
/// read directly rather than timed. The discriminating evidence is the final
/// `settled == started`, which is reached only on the loop's own path *after*
/// the extension's join handle resolves; a loop cancelled at that await never
/// increments it.
#[tokio::test]
async fn finish_settles_an_in_flight_heartbeat_before_release() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "replica-a");
    let instance_b = instance(dir.path(), "replica-b");
    let name = acme_renewal_lease_name("edge-cert");
    // Beats every 200ms, so an extension is offered promptly once the store
    // lock is held against it.
    let ttl = Duration::from_millis(600);

    let held = instance_a.try_acquire(&name, ttl).expect("A claims");
    let keeper = RenewalLeaseKeeper::start(held.expect("A wins"), ttl);
    let progress = keeper.heartbeat_progress();

    // Another instance is mid-write on the shared table. Nothing is stubbed:
    // this is the same `flock` Ferrum's own writers take.
    let blocker = hold_store_lock(dir.path());

    // Observed, not assumed: an extension is in the blocking pool and the loop
    // is awaiting it.
    let extending = || progress.extension_in_flight();
    assert!(
        wait_until_async(SETTLE_BUDGET, extending).await,
        "an extension must be in flight while the store lock is held against it"
    );

    let finishing = tokio::spawn(keeper.finish());

    // Wait *positively* for the state that makes the next assertion meaningful:
    // shutdown has asked the loop to stop, and the extension it must settle is
    // still in flight. `stop_requested` is set as `finish()` enters, before it
    // awaits the loop, so this cannot be reached by `finish()` having already
    // returned. The blocked extension keeps `extension_in_flight()` true for as
    // long as this test holds the store lock, so the conjunction is stable
    // rather than a race the poll might miss.
    let settling = || progress.stop_requested() && progress.extension_in_flight();
    assert!(
        wait_until_async(SETTLE_BUDGET, settling).await,
        "finish() must reach the point of settling a heartbeat extension"
    );

    // Read directly: the loop cannot have returned while its extension is still
    // in the blocking pool, so `finish()` — which awaits that loop rather than
    // aborting it — cannot have completed. No interval is waited out and no
    // forbidden event is timed.
    assert!(
        !finishing.is_finished(),
        "finish() must not complete while a heartbeat extension is in flight"
    );

    // Hand the store back; the blocked extension can now run to completion.
    std::mem::drop(blocker);

    tokio::time::timeout(SETTLE_BUDGET, finishing)
        .await
        .expect("finish() must complete once the extension settles")
        .expect("the finish task")
        .expect("release");

    assert_eq!(
        progress.settled(),
        progress.started(),
        "finish() must have awaited every extension it started; an aborted loop \
         never settles the beat it was parked on"
    );

    let released = instance_a.peek(&name).expect("read").expect("present");
    assert!(
        released.expires_at <= Utc::now(),
        "finish() must leave the claim released"
    );

    let taken = instance_b.try_acquire(&name, ttl).expect("B claims");
    assert!(
        taken.is_some(),
        "a settled, released claim hands over immediately"
    );
}

/// Dropping a keeper must not release its claim on the runtime thread.
///
/// `TlsLeaseGuard`'s release is a synchronous read-modify-write under the lease
/// store's *cross-process* advisory lock, bounded only by
/// `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`. `finish()` has always offloaded it,
/// but the emergency path — a keeper abandoned by an early return, a panic, or
/// a cancelled scheduler — used to let the guard drop in place, which on a
/// Tokio worker parks that worker for as long as a peer holds the lock.
///
/// The test holds the lock exactly as a mid-flight peer writer would, so an
/// inline release would block. A single-worker runtime makes that observable:
/// if the drop blocked, the `yield_now` below could never complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn dropping_a_keeper_never_releases_the_claim_on_a_runtime_worker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "instance-a");
    let name = acme_renewal_lease_name("cert-abandoned-mid-renewal");
    let ttl = Duration::from_secs(30);
    let guard = instance_a
        .try_acquire(&name, ttl)
        .expect("A claims")
        .expect("an unclaimed lease is acquirable");
    let keeper = RenewalLeaseKeeper::start(guard, ttl);

    // A peer writer holds the store lock, so any synchronous release would wait
    // on it rather than returning promptly.
    let blocker = hold_store_lock(dir.path());

    drop(keeper);

    // The sole worker is still able to make progress. An inline release would
    // be parked on the lock the blocker holds, and this could not complete.
    tokio::time::timeout(Duration::from_secs(5), tokio::task::yield_now())
        .await
        .expect("a keeper drop must not park the runtime worker");

    // Hand the lock back; the deferred release can now land.
    std::mem::drop(blocker);

    // Fail-safe either way: the claim is released promptly if the deferred work
    // ran, and lapses at `expires_at` if it could not be scheduled. What must
    // not happen is the runtime stalling, which the assertion above covers.
    let instance_b = instance(dir.path(), "instance-b");
    let taken_over = wait_until_async(SETTLE_BUDGET, || {
        instance_a
            .peek(&name)
            .ok()
            .flatten()
            .is_some_and(|record| record.expires_at <= Utc::now())
    })
    .await;
    assert!(
        taken_over,
        "a dropped keeper's claim must be released rather than held for the full TTL"
    );

    let reclaimed = instance_b.try_acquire(&name, ttl).expect("B claims");
    let reclaimed = reclaimed.expect("a released claim hands over to another instance");

    // Release off the runtime for the same reason the keeper does.
    tokio::task::spawn_blocking(move || drop(reclaimed))
        .await
        .expect("release the takeover claim");
}

/// `finish()` keeps its stronger guarantee: the release is awaited, so by the
/// time it returns the claim is observably released rather than merely
/// scheduled.
///
/// This is the contrast with the drop path above, and it is what stops the
/// offload from being mistaken for a weakening of the normal shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_still_settles_the_release_before_it_returns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let instance_a = instance(dir.path(), "instance-a");
    let name = acme_renewal_lease_name("cert-finished-cleanly");
    let ttl = Duration::from_secs(30);
    let guard = instance_a
        .try_acquire(&name, ttl)
        .expect("A claims")
        .expect("an unclaimed lease is acquirable");
    let keeper = RenewalLeaseKeeper::start(guard, ttl);

    keeper.finish().await.expect("finish releases the claim");

    // Read immediately, with no polling: `finish()` awaited the release, so the
    // claim is already released on return.
    let record = instance_a.peek(&name).expect("read").expect("present");
    assert!(
        record.expires_at <= Utc::now(),
        "finish() must not return before the release has landed"
    );
}
