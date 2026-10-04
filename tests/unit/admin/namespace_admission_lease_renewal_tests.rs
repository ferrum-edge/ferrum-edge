//! Namespace config admission lease renewal under datastore stalls (#4146).
//!
//! The production renewer is driven directly against a fault-injecting lease
//! backend, on a timing envelope scaled from production's 120s/30s/1s to
//! 2400ms/600ms/40ms. The 4:1 lease-to-renew-interval ratio is preserved, and
//! every bound the renewer applies is derived from that envelope, so the scaled
//! runs exercise the identical arithmetic.

use async_trait::async_trait;
use ferrum_edge::_test_support::{
    TestLeaseBackend, TestLeaseRenewalOutcome, TestLeaseRenewalTiming,
    run_namespace_config_admission_renewal_for_test,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LEASE_DURATION_MS: u64 = 2_400;
const RENEW_INTERVAL_MS: u64 = 600;
const RETRY_INTERVAL_MS: u64 = 40;

fn scaled_timing() -> TestLeaseRenewalTiming {
    TestLeaseRenewalTiming {
        lease_duration_ms: LEASE_DURATION_MS,
        renew_interval_ms: RENEW_INTERVAL_MS,
        retry_interval_ms: RETRY_INTERVAL_MS,
    }
}

/// A single `config_admission_locks` row with injectable faults.
struct FakeLeaseRow {
    owner: String,
    generation: u64,
    expires_at: Instant,
    /// No renewal or acquisition answers before this instant. Models the
    /// datastore stall that precedes the observed lost-ownership errors.
    stalled_until: Option<Instant>,
    /// Number of renewals that report no live match without touching the row.
    renew_refusals: u32,
    stalled_forever: bool,
    renew_calls: u32,
    acquire_calls: u32,
    release_calls: u32,
}

struct FakeLeaseBackend {
    lease_duration: Duration,
    row: Mutex<FakeLeaseRow>,
    active_renewals: AtomicU32,
}

struct ActiveRenewal<'a>(&'a AtomicU32);

impl Drop for ActiveRenewal<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl FakeLeaseBackend {
    fn new(owner: &str, generation: u64) -> Self {
        let lease_duration = Duration::from_millis(LEASE_DURATION_MS);
        Self {
            lease_duration,
            row: Mutex::new(FakeLeaseRow {
                owner: owner.to_string(),
                generation,
                expires_at: Instant::now() + lease_duration,
                stalled_until: None,
                renew_refusals: 0,
                stalled_forever: false,
                renew_calls: 0,
                acquire_calls: 0,
                release_calls: 0,
            }),
            active_renewals: AtomicU32::new(0),
        }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, FakeLeaseRow> {
        match self.row.lock() {
            Ok(row) => row,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn stall_for(&self, stall: Duration) {
        self.locked().stalled_until = Some(Instant::now() + stall);
    }

    fn refuse_renewals(&self, count: u32) {
        self.locked().renew_refusals = count;
    }

    fn hand_row_to(&self, owner: &str) {
        let mut row = self.locked();
        row.owner = owner.to_string();
        row.generation += 1;
        row.expires_at = Instant::now() + self.lease_duration;
    }

    fn counts(&self) -> (u32, u32, u32) {
        let row = self.locked();
        (row.renew_calls, row.acquire_calls, row.release_calls)
    }

    /// Block while a stall window is open. The guard is dropped first so a
    /// concurrent caller is not serialized behind the sleep.
    async fn wait_out_stall(&self) {
        let stalled_until = self.locked().stalled_until;
        if let Some(deadline) = stalled_until {
            let now = Instant::now();
            if deadline > now {
                tokio::time::sleep(deadline - now).await;
            }
        }
    }
}

#[async_trait]
impl ferrum_edge::config::db_backend::NamespaceConfigAdmissionLeaseBackend for FakeLeaseBackend {
    async fn try_acquire_namespace_config_admission_lease(
        &self,
        _namespace: &str,
        owner: &str,
    ) -> Result<Option<u64>, anyhow::Error> {
        self.wait_out_stall().await;
        let mut row = self.locked();
        row.acquire_calls += 1;
        let now = Instant::now();
        let claimable = row.owner == owner || row.expires_at <= now;
        if !claimable {
            return Ok(None);
        }
        if row.owner != owner {
            row.owner = owner.to_string();
            row.generation += 1;
        }
        row.expires_at = now + self.lease_duration;
        Ok(Some(row.generation))
    }

    async fn renew_namespace_config_admission_lease(
        &self,
        _namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> {
        self.active_renewals.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveRenewal(&self.active_renewals);
        let stalled_forever = {
            let mut row = self.locked();
            row.renew_calls += 1;
            row.stalled_forever
        };
        if stalled_forever {
            std::future::pending::<()>().await;
        }
        self.wait_out_stall().await;
        let mut row = self.locked();
        if row.renew_refusals > 0 {
            row.renew_refusals -= 1;
            return Ok(false);
        }
        let now = Instant::now();
        if row.owner != owner || row.expires_at <= now {
            return Ok(false);
        }
        row.expires_at = now + self.lease_duration;
        Ok(true)
    }

    async fn release_namespace_config_admission_lease(
        &self,
        _namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> {
        let mut row = self.locked();
        row.release_calls += 1;
        if row.owner != owner {
            return Ok(false);
        }
        row.expires_at = Instant::now();
        Ok(true)
    }
}

/// A stall two and a half renew intervals long — well past one renewal
/// interval, well inside the lease TTL — must be ridden out, not treated as a
/// loss.
///
/// Before #4146 the single unbounded `await` absorbed the whole stall and the
/// lease had already expired by the time the statement applied.
#[tokio::test]
async fn stall_longer_than_a_renew_interval_but_shorter_than_the_ttl_keeps_ownership() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-a", 7));
    backend.stall_for(Duration::from_millis(1_500));
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-a",
        7,
        scaled_timing(),
        Duration::from_millis(2_000),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Stopped,
        "a stall inside the lease window must not end the renewer: {observed:?}"
    );
    assert!(
        observed.still_held,
        "ownership must survive a stall shorter than the TTL: {observed:?}"
    );
    assert!(
        observed.retries >= 1,
        "the stall must be visible as at least one retried attempt: {observed:?}"
    );
    assert!(
        observed.renewals >= 1,
        "the renewer must have completed a renewal after the stall: {observed:?}"
    );
}

/// A stall that outlives the lease window still invalidates. The retry budget
/// is derived from the remaining validity, so it can never outlive real expiry.
#[tokio::test]
async fn stall_longer_than_the_ttl_fails_closed() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-b", 3));
    backend.stall_for(Duration::from_millis(20_000));
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-b",
        3,
        scaled_timing(),
        Duration::from_millis(6_000),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Expired,
        "a stall past the lease window must fail closed: {observed:?}"
    );
    assert!(
        !observed.still_held,
        "an expired lease must never report itself as held: {observed:?}"
    );
    assert_eq!(
        observed.renewals, 0,
        "nothing was renewable during the stall: {observed:?}"
    );
    assert!(
        observed.retries >= 2,
        "the window must be spent on bounded retries, not one blocking wait: {observed:?}"
    );

    let (_, acquires, releases) = backend.counts();
    assert_eq!(
        acquires, 0,
        "an expiring renewer must not claim a row it cannot prove: {observed:?}"
    );
    assert_eq!(
        releases, 0,
        "an expiring renewer has nothing to release: {observed:?}"
    );
}

/// A refused renewal must fail closed even if the stored owner and generation
/// still match. Release leaves those fields intact; reclaiming them would allow
/// a delayed command to revive a cancelled guard after cleanup.
#[tokio::test]
async fn refused_renewal_never_reclaims_the_same_generation() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-c", 11));
    backend.refuse_renewals(1);
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-c",
        11,
        scaled_timing(),
        Duration::from_millis(1_500),
    )
    .await;

    assert_eq!(observed.outcome, TestLeaseRenewalOutcome::Lost);
    assert!(!observed.still_held);
    assert_eq!(observed.reclaims, 0);
    assert_eq!(backend.counts(), (1, 0, 0));
}

/// When another writer genuinely holds the namespace, the renewer fails closed
/// instead of reclaiming. This is the split-brain fence.
#[tokio::test]
async fn ownership_taken_by_another_writer_fails_closed() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-d", 5));
    backend.hand_row_to("someone-else");
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-d",
        5,
        scaled_timing(),
        Duration::from_millis(1_500),
    )
    .await;

    assert_eq!(
        observed.outcome,
        TestLeaseRenewalOutcome::Lost,
        "a foreign owner must end the renewer: {observed:?}"
    );
    assert!(
        !observed.still_held,
        "a lost lease must never report itself as held: {observed:?}"
    );
    assert_eq!(
        observed.reclaims, 0,
        "a foreign owner is not reclaimable: {observed:?}"
    );
}

/// Expiry without takeover is still a lost lease. The next request must obtain
/// a fresh guard and revalidate, rather than continue using the old admission.
#[tokio::test]
async fn expired_same_owner_lease_is_never_reacquired() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-e", 2));
    backend.locked().expires_at = Instant::now();
    let lease: TestLeaseBackend = backend.clone();

    let observed = run_namespace_config_admission_renewal_for_test(
        lease,
        "ferrum",
        "owner-e",
        2,
        scaled_timing(),
        Duration::from_millis(1_500),
    )
    .await;

    assert_eq!(observed.outcome, TestLeaseRenewalOutcome::Lost);
    assert!(!observed.still_held);
    assert_eq!(observed.reclaims, 0);
    assert_eq!(backend.counts(), (1, 0, 0));
}

/// Stop cancels a permanently pending renewal without retaining a task or
/// waiting for its driver future to settle. The backend's live-row predicate,
/// rather than a join result, must fence any server-side command left behind.
#[tokio::test]
async fn permanently_stalled_renewal_is_dropped_on_stop() {
    let backend = Arc::new(FakeLeaseBackend::new("owner-f", 4));
    backend.locked().stalled_forever = true;
    let lease: TestLeaseBackend = backend.clone();

    let observed = tokio::time::timeout(
        Duration::from_secs(2),
        run_namespace_config_admission_renewal_for_test(
            lease,
            "ferrum",
            "owner-f",
            4,
            scaled_timing(),
            Duration::from_millis(1_500),
        ),
    )
    .await
    .expect("stop cannot wait for a permanently stalled operation");

    assert_eq!(observed.outcome, TestLeaseRenewalOutcome::Stopped);
    assert!(observed.still_held);
    assert!(observed.retries >= 1);
    assert_eq!(backend.active_renewals.load(Ordering::SeqCst), 0);
    assert_eq!(backend.counts().1, 0, "a keeper must never acquire");
}
