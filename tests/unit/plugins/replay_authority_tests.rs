//! Tests for the shared single-use replay authority
//! (`ferrum_edge::plugins::utils::replay_authority`).
//!
//! This is the one abstraction behind `jwks_auth`'s DPoP proofs (issue #3834)
//! and `hmac_auth`'s `ferrum-hmac-v2` nonces (issue #3837), so the contracts
//! below are the security properties both plugins inherit:
//!
//! * atomic check-and-insert with exactly one winner under concurrency;
//! * capacity that prunes only **expired** markers and refuses otherwise —
//!   never evicting a live marker to admit a new request — with each live
//!   authority enforcing its own admitted cap against the shared lane so an
//!   equivalent reload that raises or lowers capacity takes effect without
//!   forgetting history;
//! * exact TTL boundary semantics;
//! * lane ownership that survives an equivalent reload and converges for
//!   equivalent replicas, while isolating distinct namespaces / policies /
//!   sub-domains;
//! * bounded, tombstoned lane retirement.

use std::sync::{Arc, Barrier};
use std::time::Duration;

use ferrum_edge::_test_support::{ReplaySetNxReplyError, classify_replay_set_nx_reply};
use ferrum_edge::plugins::Plugin;
use ferrum_edge::plugins::utils::redis_rate_limiter::{
    RedisConfig, RedisRateLimitClient, arm_shared_replay_apply_pause_for_test,
    disarm_shared_replay_apply_pause_for_test, shared_replay_apply_pause_entered_for_test,
    shared_replay_transition_lock_held_for_test,
};
use ferrum_edge::plugins::utils::replay_authority::{
    MAX_PROCESS_REPLAY_LANES, ReplayAdmission, ReplayAuthority, ReplayDomain, ReplayMarker,
    ReplayScope, SharedReplayAuthorityHealth, admit_process_at, counters, monotonic_millis,
    process_lane, process_lane_registered_for_tests, process_max_entries, shared_authority_degraded,
    shared_health_snapshot, validate_scope_backend,
};

use super::redis_resp::{TIME_CMD, host_clock_time_reply};

const PROFILE: &str = "ferrum-replay-authority-tests-v1";
const RETENTION: Duration = Duration::from_secs(600);

fn replay_redis_client(config: RedisConfig) -> RedisRateLimitClient {
    RedisRateLimitClient::for_replay_authority(config, None, false, None)
        .expect("construction without a CA path must succeed")
}

/// A distinct protection domain per test, so parallel suite siblings cannot
/// consume one another's lanes or markers.
fn domain(sub: &str) -> ReplayDomain {
    ReplayDomain::new(PROFILE, "ferrum", "replay_authority_tests", sub, "0")
}

fn process_authority(sub: &str, max_entries: usize) -> ReplayAuthority {
    ReplayAuthority::process("test", &domain(sub), max_entries, RETENTION, 8)
        .expect("process lane should be created")
}

/// A marker charged to a principal of its own. Lane-wide capacity tests use
/// it so the per-principal quota (a quarter of the cap, minimum one) cannot
/// refuse first and mask the lane-cap behavior under test.
fn lane_marker(sub: &str, proof: &str) -> ReplayMarker {
    domain(sub).marker_with_principal(&[b"c", proof.as_bytes()], &[proof.as_bytes()])
}

#[tokio::test]
async fn process_lane_reserves_replay_capacity_for_other_principals() {
    let policy = "principal-quota-regression";
    let authority = process_authority(policy, 8);
    let replay_domain = domain(policy);

    for nonce in [b"first".as_slice(), b"second".as_slice()] {
        let marker = replay_domain.marker(&[b"principal-a", nonce]);
        assert_eq!(authority.admit(&marker).await, ReplayAdmission::Admitted);
    }
    let over_quota = replay_domain.marker(&[b"principal-a", b"third"]);
    assert_eq!(
        authority.admit(&over_quota).await,
        ReplayAdmission::CapacityRefused
    );

    let other_principal = replay_domain.marker(&[b"principal-b", b"first"]);
    assert_eq!(
        authority.admit(&other_principal).await,
        ReplayAdmission::Admitted
    );
}

#[tokio::test]
async fn dpop_capacity_is_charged_to_token_principal_across_proof_keys() {
    let policy = "dpop-token-principal-quota-regression";
    let authority = process_authority(policy, 8);
    let replay_domain = domain(policy);

    for (jkt, jti) in [
        (b"key-a".as_slice(), b"proof-1".as_slice()),
        (b"key-b".as_slice(), b"proof-2".as_slice()),
    ] {
        let marker =
            replay_domain.marker_with_principal(&[jkt, jti], &[b"issuer", b"service-account"]);
        assert_eq!(authority.admit(&marker).await, ReplayAdmission::Admitted);
    }
    let over_quota = replay_domain
        .marker_with_principal(&[b"key-c", b"proof-3"], &[b"issuer", b"service-account"]);
    assert_eq!(
        authority.admit(&over_quota).await,
        ReplayAdmission::CapacityRefused
    );

    let other_principal = replay_domain.marker_with_principal(
        &[b"key-d", b"proof-4"],
        &[b"issuer", b"another-service-account"],
    );
    assert_eq!(
        authority.admit(&other_principal).await,
        ReplayAdmission::Admitted
    );
}

/// Reclaiming a principal's expired markers returns its quota share, so the
/// per-principal bound throttles retained claims instead of locking the
/// principal out for the life of the lane.
#[test]
fn expired_markers_return_their_principal_quota_share() {
    let sub = "principal-quota-reclaim";
    // A cap of 8 gives each principal a share of 2.
    let authority = process_authority(sub, 8);
    let now = monotonic_millis();
    let first = domain(sub).marker(&[b"principal-a", b"first"]);
    let second = domain(sub).marker(&[b"principal-a", b"second"]);
    let third = domain(sub).marker(&[b"principal-a", b"third"]);

    for marker in [&first, &second] {
        assert_eq!(
            admit_process_at(&authority, marker, now),
            Some(ReplayAdmission::Admitted)
        );
    }
    assert_eq!(
        admit_process_at(&authority, &third, now),
        Some(ReplayAdmission::CapacityRefused),
        "a principal at its share is refused while its markers are live"
    );

    let after_expiry = now + RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        admit_process_at(&authority, &third, after_expiry),
        Some(ReplayAdmission::Admitted),
        "pruning the principal's expired markers must return its share"
    );
    let lane = process_lane(&authority).expect("process lane");
    assert_eq!(lane.retained_entries(), 1);
}

/// Refreshing a principal's own expired marker in place reuses the slot it
/// already holds: it is admitted at the share without being charged twice,
/// and the share still refuses a genuinely new marker afterwards.
#[test]
fn a_principal_at_its_share_may_reuse_its_own_expired_marker() {
    let sub = "principal-quota-refresh";
    let authority = process_authority(sub, 8);
    let now = monotonic_millis();
    let later = now + 1_000;
    let first = domain(sub).marker(&[b"principal-a", b"first"]);
    let second = domain(sub).marker(&[b"principal-a", b"second"]);
    let third = domain(sub).marker(&[b"principal-a", b"third"]);

    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, later),
        Some(ReplayAdmission::Admitted)
    );

    // `first` has expired; `second` is still live.
    let after_first_expires = now + RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        admit_process_at(&authority, &first, after_first_expires),
        Some(ReplayAdmission::Admitted),
        "a principal at its share may reuse its own expired slot"
    );
    assert_eq!(
        admit_process_at(&authority, &third, after_first_expires),
        Some(ReplayAdmission::CapacityRefused),
        "the in-place refresh must still count against the principal's share"
    );
    assert_eq!(
        admit_process_at(&authority, &second, after_first_expires),
        Some(ReplayAdmission::Replay)
    );
}

/// Concurrent claims by one principal reserve its share atomically: exactly
/// the share is admitted however the claims interleave, while the lane itself
/// still has room.
#[test]
fn concurrent_claims_by_one_principal_never_exceed_its_share() {
    const WORKERS: usize = 32;
    let sub = "principal-quota-concurrent";
    // A cap of 32 gives each principal a share of 8.
    let authority = Arc::new(process_authority(sub, WORKERS));
    let barrier = Arc::new(Barrier::new(WORKERS));

    let workers: Vec<_> = (0..WORKERS)
        .map(|idx| {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let nonce = idx.to_string();
                let marker = domain(sub).marker(&[b"principal-a", nonce.as_bytes()]);
                barrier.wait();
                admit_process_at(&authority, &marker, monotonic_millis())
                    .expect("process authority")
            })
        })
        .collect();

    let admitted = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker should not panic"))
        .filter(|outcome| *outcome == ReplayAdmission::Admitted)
        .count();
    assert_eq!(
        admitted,
        WORKERS / 4,
        "one principal may hold only its share"
    );

    let other = domain(sub).marker(&[b"principal-b", b"first"]);
    assert_eq!(
        admit_process_at(&authority, &other, monotonic_millis()),
        Some(ReplayAdmission::Admitted),
        "another principal keeps the lane capacity the first could not take"
    );
}

/// The shared authority may admit only on Redis's exact successful `SET NX`
/// reply. A RESP string with any other contents is semantically malformed and
/// cannot prove that the marker was persisted.
#[test]
fn shared_claim_accepts_only_the_exact_redis_set_success_reply() {
    assert_eq!(classify_replay_set_nx_reply(Some("OK")), Ok(true));
    assert_eq!(classify_replay_set_nx_reply(None), Ok(false));
    for malformed in ["", "ok", "QUEUED", "PONG", "1"] {
        assert_eq!(
            classify_replay_set_nx_reply(Some(malformed)),
            Err(ReplaySetNxReplyError::InvalidClaimReply),
            "unexpected reply {malformed:?} must fail closed"
        );
    }
}

// ── atomic check-and-insert ─────────────────────────────────────────

#[tokio::test]
async fn sequential_replay_of_the_same_marker_is_rejected() {
    let authority = process_authority("sequential", 16);
    let marker = domain("sequential").marker(&[b"consumer", b"nonce-1"]);

    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Admitted);
    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Replay);
    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Replay);
}

#[tokio::test]
async fn a_distinct_marker_is_admitted_independently() {
    let authority = process_authority("distinct", 16);
    let first = domain("distinct").marker(&[b"consumer", b"nonce-1"]);
    let second = domain("distinct").marker(&[b"consumer", b"nonce-2"]);

    assert_eq!(authority.admit(&first).await, ReplayAdmission::Admitted);
    assert_eq!(authority.admit(&second).await, ReplayAdmission::Admitted);
}

/// Two simultaneous claims of one previously unseen marker have exactly one
/// winner. The decision and the insertion happen under a single entry guard, so
/// there is no read-then-write window for a second request to slip through.
#[test]
fn concurrent_claims_of_one_unseen_marker_have_exactly_one_winner() {
    const WORKERS: usize = 32;
    let authority = Arc::new(process_authority("concurrent", 64));
    let marker = domain("concurrent").marker(&[b"consumer", b"contended"]);
    let barrier = Arc::new(Barrier::new(WORKERS));

    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                admit_process_at(&authority, &marker, monotonic_millis())
                    .expect("process authority")
            })
        })
        .collect();

    let admitted = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker should not panic"))
        .filter(|outcome| *outcome == ReplayAdmission::Admitted)
        .count();
    assert_eq!(admitted, 1, "exactly one concurrent claim may win");
}

/// Concurrent claims of *distinct* markers must all succeed: the entry guard
/// must not serialize independent admissions into false replays.
#[test]
fn concurrent_distinct_markers_are_all_admitted() {
    const WORKERS: usize = 32;
    let authority = Arc::new(process_authority("concurrent-distinct", WORKERS));
    let barrier = Arc::new(Barrier::new(WORKERS));

    let workers: Vec<_> = (0..WORKERS)
        .map(|idx| {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let label = idx.to_string();
                let marker = lane_marker("concurrent-distinct", &label);
                barrier.wait();
                admit_process_at(&authority, &marker, monotonic_millis())
                    .expect("process authority")
            })
        })
        .collect();

    assert!(
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker should not panic"))
            .all(|outcome| outcome == ReplayAdmission::Admitted)
    );
}

// ── capacity never forgets a live marker ────────────────────────────

/// This is the core of issue #3834: at capacity the authority prunes expired
/// markers and refuses otherwise. Filling a lane must never make an unexpired
/// marker reusable.
#[test]
fn capacity_refuses_rather_than_evicting_a_live_marker() {
    let authority = process_authority("capacity", 2);
    let now = monotonic_millis();
    let first = lane_marker("capacity", "first");
    let second = lane_marker("capacity", "second");
    let third = lane_marker("capacity", "third");

    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Admitted)
    );
    // The lane is full and nothing is expired: the NEW request is refused.
    assert_eq!(
        admit_process_at(&authority, &third, now),
        Some(ReplayAdmission::CapacityRefused)
    );
    // …and the marker the pressure was supposed to displace is still live.
    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Replay),
        "capacity pressure must not make an unexpired marker reusable"
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Replay)
    );
}

/// Repeated saturated refusals while every retained marker is still live must
/// not walk the map again. The conservative earliest-expiry bound makes those
/// refusals O(1).
#[test]
fn repeated_full_live_refusals_do_not_rescan() {
    let authority = process_authority("capacity-no-rescan", 2);
    let now = monotonic_millis();
    let first = lane_marker("capacity-no-rescan", "first");
    let second = lane_marker("capacity-no-rescan", "second");
    let third = lane_marker("capacity-no-rescan", "third");

    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Admitted)
    );
    let lane = process_lane(&authority).expect("process lane");
    let scans_after_fill = lane.prune_scans();
    for _ in 0..64 {
        assert_eq!(
            admit_process_at(&authority, &third, now),
            Some(ReplayAdmission::CapacityRefused)
        );
    }
    assert_eq!(
        lane.prune_scans(),
        scans_after_fill,
        "full-live refusals must not rescan while no marker can yet have expired"
    );
    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Replay),
        "O(1) refusal must not evict a live marker"
    );
}

/// Once the earliest live expiry is due, the capacity path may scan and reclaim
/// expired slots so a new proof can be admitted.
#[test]
fn expiration_triggers_reclamation_after_o1_refusals() {
    let authority = process_authority("capacity-expire-scan", 2);
    let now = monotonic_millis();
    let first = lane_marker("capacity-expire-scan", "first");
    let second = lane_marker("capacity-expire-scan", "second");
    let third = lane_marker("capacity-expire-scan", "third");

    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &third, now),
        Some(ReplayAdmission::CapacityRefused)
    );
    let lane = process_lane(&authority).expect("process lane");
    let scans_before = lane.prune_scans();

    let after_expiry = now + RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        admit_process_at(&authority, &third, after_expiry),
        Some(ReplayAdmission::Admitted),
        "an expired slot must be reclaimed once expiration is due"
    );
    assert!(
        lane.prune_scans() > scans_before,
        "expiration must be allowed to scan and reclaim"
    );
}

/// Concurrent insertion while a due prune recomputes the earliest bound must
/// not drop a still-live marker or treat it as expired.
#[test]
fn concurrent_insert_during_prune_cannot_forget_a_live_marker() {
    const WORKERS: usize = 16;
    let authority = Arc::new(process_authority("capacity-concurrent-bound", 4));
    let now = monotonic_millis();
    let shorts: Vec<_> = (0..3)
        .map(|idx| lane_marker("capacity-concurrent-bound", &format!("short-{idx}")))
        .collect();
    let live = lane_marker("capacity-concurrent-bound", "live-kept");
    for marker in &shorts {
        assert_eq!(
            admit_process_at(&authority, marker, now),
            Some(ReplayAdmission::Admitted)
        );
    }
    let later = now + 1_000;
    assert_eq!(
        admit_process_at(&authority, &live, later),
        Some(ReplayAdmission::Admitted)
    );

    let after_shorts = now + RETENTION.as_millis() as u64 + 1;
    let barrier = Arc::new(Barrier::new(WORKERS));
    let workers: Vec<_> = (0..WORKERS)
        .map(|idx| {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                if idx % 2 == 0 {
                    let live = lane_marker("capacity-concurrent-bound", "live-kept");
                    admit_process_at(&authority, &live, after_shorts)
                } else {
                    let fresh = lane_marker("capacity-concurrent-bound", &format!("fresh-{idx}"));
                    admit_process_at(&authority, &fresh, after_shorts)
                }
            })
        })
        .collect();
    for worker in workers {
        let _ = worker.join().expect("worker");
    }
    assert_eq!(
        admit_process_at(&authority, &live, after_shorts),
        Some(ReplayAdmission::Replay),
        "a still-live marker must survive concurrent prune recomputation"
    );
}

/// Two writers paused after `fetch_min` and before writer release must not
/// look like a stable even seqlock epoch. The old protocol incremented one
/// sequence on begin and again on finish; two in-flight writers made that
/// counter even, so a prune that had already passed their shards could publish
/// a later bound and never see the earlier markers.
#[test]
fn two_held_writers_cannot_hide_an_earlier_expiry_from_prune_publication() {
    const CAP: usize = 4;
    let authority = process_authority("capacity-multiwriter-bound", CAP);
    let lane = process_lane(&authority).expect("process lane");
    let retention_ms = u64::try_from(RETENTION.as_millis()).expect("retention fits u64");
    let t_early = 0;
    let t_writer = 50_000;
    let t_later = 100_000;
    let t_prune = retention_ms + 1;
    let writer_expires_at = t_writer + retention_ms;
    let later_expires_at = t_later + retention_ms;
    let t_after_writers_expire = writer_expires_at + 1;

    let first = lane_marker("capacity-multiwriter-bound", "first");
    let second = lane_marker("capacity-multiwriter-bound", "second");
    let later_a = lane_marker("capacity-multiwriter-bound", "later-a");
    let later_b = lane_marker("capacity-multiwriter-bound", "later-b");
    let early_a = lane_marker("capacity-multiwriter-bound", "early-a");
    let early_b = lane_marker("capacity-multiwriter-bound", "early-b");
    let extra = lane_marker("capacity-multiwriter-bound", "extra");

    assert_eq!(
        admit_process_at(&authority, &first, t_early),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, t_early),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &later_a, t_later),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &later_b, t_later),
        Some(ReplayAdmission::Admitted)
    );

    let mut held = Vec::new();
    let reclaimed = lane.prune_expired_with_after_scan_for_tests(t_prune, || {
        for marker in [&early_a, &early_b] {
            held.push(
                lane.admit_at_holding_expiry_write_for_tests(marker, RETENTION, CAP, t_writer)
                    .expect("reclaimed slots must admit the held writers"),
            );
        }
    });
    assert_eq!(reclaimed, 2, "the due prune must reclaim the expired pair");
    assert_eq!(
        held.len(),
        2,
        "the old even-parity hole requires two concurrent writers"
    );

    for writer in held {
        writer.finish();
    }

    let published = lane.earliest_expiry_millis_for_tests();
    assert!(
        published <= writer_expires_at,
        "prune must not publish a later bound ({published}) than the held writers ({writer_expires_at}); later-only markers expire at {later_expires_at}"
    );

    let scans_before = lane.prune_scans();
    assert_eq!(
        admit_process_at(&authority, &extra, t_after_writers_expire),
        Some(ReplayAdmission::Admitted),
        "once the held writers expire, capacity pressure must reclaim them rather than skip until the later bound"
    );
    assert!(
        lane.prune_scans() > scans_before,
        "reclamation after the held writers expire must walk the map"
    );
    assert_eq!(
        admit_process_at(&authority, &later_a, t_after_writers_expire),
        Some(ReplayAdmission::Replay),
        "a still-live later marker must not be evicted to make room"
    );
}

/// Once the retained markers expire, their slots are reclaimed and new requests
/// are admitted again — capacity degrades into refusal, not into a permanent
/// outage.
#[test]
fn expired_markers_are_reclaimed_to_admit_new_requests() {
    let authority = process_authority("capacity-reclaim", 2);
    let now = monotonic_millis();
    let first = lane_marker("capacity-reclaim", "first");
    let second = lane_marker("capacity-reclaim", "second");
    let third = lane_marker("capacity-reclaim", "third");

    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Admitted)
    );

    let after_expiry = now + RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        admit_process_at(&authority, &third, after_expiry),
        Some(ReplayAdmission::Admitted),
        "an expired slot is reclaimable"
    );

    let lane = process_lane(&authority).expect("process lane");
    let cap = process_max_entries(&authority).expect("process capacity");
    assert!(
        lane.retained_entries() <= cap,
        "reclamation must respect the hard capacity bound"
    );
}

/// A zero-usable-capacity lane refuses rather than admitting unprotected.
#[test]
fn a_single_slot_lane_still_rejects_a_live_duplicate_before_refusing() {
    let authority = process_authority("capacity-one", 1);
    let now = monotonic_millis();
    let marker = lane_marker("capacity-one", "only");
    let other = lane_marker("capacity-one", "other");

    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    // A live duplicate is a REPLAY, decided before any capacity handling.
    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Replay)
    );
    assert_eq!(
        admit_process_at(&authority, &other, now),
        Some(ReplayAdmission::CapacityRefused)
    );
}

// ── TTL boundaries ──────────────────────────────────────────────────

/// A marker protects through its exact last millisecond and becomes reusable
/// only strictly after the horizon elapses.
#[test]
fn marker_protection_covers_the_exact_retention_boundary() {
    let authority = process_authority("ttl", 8);
    let now = monotonic_millis();
    let marker = domain("ttl").marker(&[b"c", b"boundary"]);
    let retention_millis = RETENTION.as_millis() as u64;

    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &marker, now + retention_millis - 1),
        Some(ReplayAdmission::Replay),
        "one millisecond before expiry the marker is still live"
    );
    assert_eq!(
        admit_process_at(&authority, &marker, now + retention_millis),
        Some(ReplayAdmission::Admitted),
        "at the horizon the marker has expired"
    );
}

/// A late wakeup far past the horizon must not resurrect protection, and the
/// re-admission must carry a full fresh interval.
#[test]
fn re_admission_after_expiry_starts_a_full_fresh_interval() {
    let authority = process_authority("ttl-late", 8);
    let now = monotonic_millis();
    let marker = domain("ttl-late").marker(&[b"c", b"late"]);
    let retention_millis = RETENTION.as_millis() as u64;

    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    let late = now + retention_millis * 10;
    assert_eq!(
        admit_process_at(&authority, &marker, late),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &marker, late + retention_millis - 1),
        Some(ReplayAdmission::Replay),
        "the re-admitted marker must carry a complete protection interval"
    );
}

// ── lane ownership across reloads and replicas ──────────────────────

/// An equivalent reload must inherit live markers. This is the reload replay
/// opening from issue #3834: a rebuilt plugin generation that resolves the same
/// protection domain must join the same lane, not start empty.
#[test]
fn an_equivalent_reload_inherits_live_markers() {
    let marker = domain("reload").marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    let original = process_authority("reload", 8);
    assert_eq!(
        admit_process_at(&original, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    // Retire the generation that made the claim, exactly as a plugin-cache
    // rebuild does, and construct an equivalent replacement.
    drop(original);
    let reloaded = process_authority("reload", 8);
    assert_eq!(
        admit_process_at(&reloaded, &marker, now),
        Some(ReplayAdmission::Replay),
        "a rebuilt generation must not accept an already-admitted proof"
    );
}

/// Two independently constructed authorities for one policy identity share a
/// lane — the single-process analogue of two replicas converging on one shared
/// keyspace.
#[test]
fn equivalent_authorities_share_one_lane() {
    let marker = domain("shared-lane").marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    let first = process_authority("shared-lane", 8);
    let second = process_authority("shared-lane", 8);
    assert_eq!(
        admit_process_at(&first, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&second, &marker, now),
        Some(ReplayAdmission::Replay)
    );
}

/// A widened retention on a later generation must not shorten an existing
/// marker's protection, and a *narrowed* one must not either: the stored expiry
/// only ever moves forward.
#[test]
fn an_existing_marker_keeps_at_least_its_admitted_interval() {
    let marker = domain("retention-change").marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    let long = ReplayAuthority::process(
        "test",
        &domain("retention-change"),
        8,
        Duration::from_secs(600),
        8,
    )
    .expect("lane");
    assert_eq!(
        admit_process_at(&long, &marker, now),
        Some(ReplayAdmission::Admitted)
    );

    // A replacement generation declaring a much shorter retention joins the
    // same lane; the already-admitted marker keeps its original expiry.
    let short = ReplayAuthority::process(
        "test",
        &domain("retention-change"),
        8,
        Duration::from_secs(1),
        8,
    )
    .expect("lane");
    assert_eq!(
        admit_process_at(&short, &marker, now + 5_000),
        Some(ReplayAdmission::Replay),
        "a shorter replacement retention must not expire an existing marker early"
    );
}

/// An equivalent reload that lowers capacity must start refusing new markers
/// at the new cap without forgetting any live marker or isolating onto a
/// fresh lane.
#[test]
fn equivalent_reload_decrease_enforces_new_capacity_without_forgetting_live_markers() {
    let first = lane_marker("capacity-decrease", "first");
    let second = lane_marker("capacity-decrease", "second");
    let third = lane_marker("capacity-decrease", "third");
    let now = monotonic_millis();

    let original = process_authority("capacity-decrease", 2);
    assert_eq!(
        admit_process_at(&original, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&original, &second, now),
        Some(ReplayAdmission::Admitted)
    );
    drop(original);

    let lowered = process_authority("capacity-decrease", 1);
    assert_eq!(
        process_max_entries(&lowered),
        Some(1),
        "the replacement generation must enforce its own admitted cap"
    );
    assert_eq!(
        admit_process_at(&lowered, &first, now),
        Some(ReplayAdmission::Replay),
        "lowering capacity must not forget a live marker"
    );
    assert_eq!(
        admit_process_at(&lowered, &second, now),
        Some(ReplayAdmission::Replay),
        "every live marker from the prior generation must stay claimed"
    );
    assert_eq!(
        admit_process_at(&lowered, &third, now),
        Some(ReplayAdmission::CapacityRefused),
        "a lowered cap must refuse new admissions while live markers remain"
    );
    let lane = process_lane(&lowered).expect("shared lane");
    assert_eq!(
        lane.retained_entries(),
        2,
        "live markers must remain even when they exceed the new cap"
    );
}

/// A lowered cap must refuse a new use of an expired occupied marker while live
/// markers still fill the new limit. Refreshing that expired slot in place would
/// admit above the replacement generation's cap.
#[test]
fn decreased_capacity_refuses_an_expired_occupied_marker_while_live_markers_fill_the_cap() {
    let first = lane_marker("capacity-decrease-expired", "first");
    let second = lane_marker("capacity-decrease-expired", "second");
    let third = lane_marker("capacity-decrease-expired", "third");
    let now = monotonic_millis();

    let original = process_authority("capacity-decrease-expired", 3);
    assert_eq!(
        admit_process_at(&original, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    let later = now + 1_000;
    assert_eq!(
        admit_process_at(&original, &second, later),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&original, &third, later),
        Some(ReplayAdmission::Admitted)
    );
    drop(original);

    let lowered = process_authority("capacity-decrease-expired", 2);
    // `first` has expired; `second` and `third` remain live and already fill
    // the replacement cap of 2.
    let after_first_expires = now + RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        admit_process_at(&lowered, &first, after_first_expires),
        Some(ReplayAdmission::CapacityRefused),
        "an expired occupied marker must not bypass a lowered cap while live markers remain"
    );
    assert_eq!(
        admit_process_at(&lowered, &second, after_first_expires),
        Some(ReplayAdmission::Replay),
        "live markers must not be evicted to recycle an expired occupied key"
    );
    assert_eq!(
        admit_process_at(&lowered, &third, after_first_expires),
        Some(ReplayAdmission::Replay),
        "every remaining live marker must stay claimed"
    );
    let lane = process_lane(&lowered).expect("shared lane");
    assert_eq!(
        lane.retained_entries(),
        2,
        "the expired occupied marker is pruned, live markers stay"
    );
}

/// When expired-only pruning restores headroom under a lowered cap, a new claim
/// — including a new use of a previously expired occupied marker — is admitted
/// again. Live markers stay claimed.
#[test]
fn decreased_capacity_admits_after_expired_pruning_restores_headroom() {
    let first = lane_marker("capacity-decrease-headroom", "first");
    let second = lane_marker("capacity-decrease-headroom", "second");
    let third = lane_marker("capacity-decrease-headroom", "third");
    let fourth = lane_marker("capacity-decrease-headroom", "fourth");
    let now = monotonic_millis();

    let original = process_authority("capacity-decrease-headroom", 3);
    assert_eq!(
        admit_process_at(&original, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&original, &second, now),
        Some(ReplayAdmission::Admitted)
    );
    let later = now + 1_000;
    assert_eq!(
        admit_process_at(&original, &third, later),
        Some(ReplayAdmission::Admitted)
    );
    drop(original);

    let lowered = process_authority("capacity-decrease-headroom", 2);
    // Expire the two earlier markers, leaving `third` live. Pruning those two
    // restores a slot under the new cap of 2.
    let after_two_expire = now + RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        admit_process_at(&lowered, &first, after_two_expire),
        Some(ReplayAdmission::Admitted),
        "pruning expired markers must restore headroom for the occupied key"
    );
    assert_eq!(
        admit_process_at(&lowered, &third, after_two_expire),
        Some(ReplayAdmission::Replay),
        "the remaining live marker must stay claimed"
    );
    assert_eq!(
        admit_process_at(&lowered, &second, after_two_expire),
        Some(ReplayAdmission::CapacityRefused),
        "the restored slot is consumed by the re-admitted marker; the new cap then refuses"
    );
    assert_eq!(
        admit_process_at(&lowered, &fourth, after_two_expire),
        Some(ReplayAdmission::CapacityRefused),
        "once live markers fill the new cap, further claims refuse"
    );
    let lane = process_lane(&lowered).expect("shared lane");
    let cap = process_max_entries(&lowered).expect("process capacity");
    assert!(
        lane.retained_entries() <= cap,
        "reclamation must leave the lane within the replacement cap"
    );
}

/// An equivalent reload that raises capacity must restore headroom against
/// the same marker history without reopening an already-claimed proof.
#[test]
fn equivalent_reload_increase_restores_headroom_without_reopening_live_markers() {
    let first = lane_marker("capacity-increase", "first");
    let second = lane_marker("capacity-increase", "second");
    let now = monotonic_millis();

    let original = process_authority("capacity-increase", 1);
    assert_eq!(
        admit_process_at(&original, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&original, &second, now),
        Some(ReplayAdmission::CapacityRefused)
    );
    drop(original);

    let raised = process_authority("capacity-increase", 2);
    assert_eq!(
        process_max_entries(&raised),
        Some(2),
        "the replacement generation must enforce the raised cap"
    );
    assert_eq!(
        admit_process_at(&raised, &first, now),
        Some(ReplayAdmission::Replay),
        "raising capacity must not reopen an already-claimed proof"
    );
    assert_eq!(
        admit_process_at(&raised, &second, now),
        Some(ReplayAdmission::Admitted),
        "raising capacity must restore headroom on the same lane"
    );
}

/// Two independently constructed authorities for one domain each enforce the
/// cap they were admitted with. Construction order must not freeze the first
/// constructor's cap onto the shared lane.
#[test]
fn equivalent_authorities_enforce_their_own_capacity_regardless_of_construction_order() {
    let now = monotonic_millis();

    for (sub, first_cap, second_cap) in [
        ("capacity-order-high-first", 4, 2),
        ("capacity-order-low-first", 2, 4),
    ] {
        let first_marker = lane_marker(sub, "first");
        let second_marker = lane_marker(sub, "second");
        let third_marker = lane_marker(sub, "third");

        let first = process_authority(sub, first_cap);
        let second = process_authority(sub, second_cap);
        assert_eq!(process_max_entries(&first), Some(first_cap));
        assert_eq!(process_max_entries(&second), Some(second_cap));

        assert_eq!(
            admit_process_at(&first, &first_marker, now),
            Some(ReplayAdmission::Admitted)
        );
        assert_eq!(
            admit_process_at(&second, &second_marker, now),
            Some(ReplayAdmission::Admitted)
        );

        let (low, high) = if first_cap < second_cap {
            (&first, &second)
        } else {
            (&second, &first)
        };

        assert_eq!(
            admit_process_at(low, &third_marker, now),
            Some(ReplayAdmission::CapacityRefused),
            "the lower-cap authority must refuse at its own cap (sub={sub})"
        );
        assert_eq!(
            admit_process_at(high, &third_marker, now),
            Some(ReplayAdmission::Admitted),
            "the higher-cap authority must still have headroom (sub={sub})"
        );
        assert_eq!(
            admit_process_at(&first, &first_marker, now),
            Some(ReplayAdmission::Replay)
        );
        assert_eq!(
            admit_process_at(&second, &second_marker, now),
            Some(ReplayAdmission::Replay)
        );
    }
}

// ── domain isolation ────────────────────────────────────────────────

#[test]
fn distinct_domains_do_not_share_markers() {
    let now = monotonic_millis();
    let left = process_authority("isolation-a", 8);
    let right = process_authority("isolation-b", 8);
    let left_marker = domain("isolation-a").marker(&[b"c", b"proof"]);
    let right_marker = domain("isolation-b").marker(&[b"c", b"proof"]);

    assert_ne!(left_marker.digest(), right_marker.digest());
    assert_eq!(
        admit_process_at(&left, &left_marker, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&right, &right_marker, now),
        Some(ReplayAdmission::Admitted),
        "one policy's history must not suppress another's"
    );
}

#[test]
fn every_domain_component_participates_in_the_identity() {
    let base = ReplayDomain::new(PROFILE, "ns", "plugin", "config", "sub");
    let parts: [&[u8]; 2] = [b"c", b"n"];
    let base_marker = base.marker(&parts).digest();

    for variant in [
        ReplayDomain::new("other-profile", "ns", "plugin", "config", "sub"),
        ReplayDomain::new(PROFILE, "other-ns", "plugin", "config", "sub"),
        ReplayDomain::new(PROFILE, "ns", "other-plugin", "config", "sub"),
        ReplayDomain::new(PROFILE, "ns", "plugin", "other-config", "sub"),
        ReplayDomain::new(PROFILE, "ns", "plugin", "config", "other-sub"),
    ] {
        assert_ne!(base_marker, variant.marker(&parts).digest());
    }
}

/// Field framing: a component boundary cannot be forged by embedding a
/// delimiter, because every field is length-prefixed.
#[test]
fn domain_and_marker_fields_are_length_framed() {
    assert_ne!(
        ReplayDomain::new(PROFILE, "a", "bc", "d", "e")
            .marker(&[b"x"])
            .digest(),
        ReplayDomain::new(PROFILE, "ab", "c", "d", "e")
            .marker(&[b"x"])
            .digest(),
    );
    let one = domain("framing");
    assert_ne!(
        one.marker(&[b"ab", b"c"]).digest(),
        one.marker(&[b"a", b"bc"]).digest(),
    );
    assert_ne!(
        one.marker(&[b"a|b"]).digest(),
        one.marker(&[b"a", b"b"]).digest(),
    );
}

// ── retirement / bounded garbage collection ─────────────────────────

/// A retired lane is a tombstone: it stays registered while any marker is live,
/// and is reclaimed only once every marker has expired.
#[test]
fn a_retired_lane_is_reclaimed_only_after_every_marker_expires() {
    let lane_domain = domain("retirement");
    let marker = lane_domain.marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    {
        let authority =
            ReplayAuthority::process("test", &lane_domain, 8, RETENTION, 8).expect("lane");
        assert_eq!(
            admit_process_at(&authority, &marker, now),
            Some(ReplayAdmission::Admitted)
        );
    }
    // The plugin generation is gone but the lane is still registered, so its
    // live marker keeps protecting.
    assert!(process_lane_registered_for_tests(&lane_domain));

    // Creating any new lane runs the bounded cold-path reclamation. While the
    // marker is live the retired lane must survive it.
    let _keepalive = process_authority("retirement-probe", 4);
    assert!(
        process_lane_registered_for_tests(&lane_domain),
        "a lane retaining a live marker must never be reclaimed"
    );

    let rejoined = ReplayAuthority::process("test", &lane_domain, 8, RETENTION, 8).expect("lane");
    assert_eq!(
        admit_process_at(&rejoined, &marker, now),
        Some(ReplayAdmission::Replay)
    );
}

#[test]
fn the_process_lane_registry_is_bounded() {
    // The bound is a real cap rather than advisory; matching the exported
    // constant keeps a future change from silently unbounding it. `1_024` is
    // already greater than zero, so a separate constant inequality would trip
    // `clippy::assertions_on_constants`.
    assert_eq!(MAX_PROCESS_REPLAY_LANES, 1_024);
}

// ── configuration admission ─────────────────────────────────────────

#[test]
fn scope_parsing_admits_exactly_two_declarations() {
    assert_eq!(
        ReplayScope::parse("p", "replay_scope", "process").expect("process"),
        ReplayScope::Process
    );
    assert_eq!(
        ReplayScope::parse("p", "replay_scope", " SHARED ").expect("shared"),
        ReplayScope::Shared
    );
    for invalid in ["", "local", "redis", "prosess", "Process-local"] {
        assert!(ReplayScope::parse("p", "replay_scope", invalid).is_err());
    }
}

/// `shared` without a backend would silently be process-local — the exact
/// "multi-replica production configuration falls back to local acceptance"
/// failure — and a provisioned backend nothing consults is equally a
/// misconfiguration.
#[test]
fn scope_and_backend_must_agree() {
    assert!(validate_scope_backend("p", "replay_scope", ReplayScope::Shared, true).is_ok());
    assert!(validate_scope_backend("p", "replay_scope", ReplayScope::Process, false).is_ok());

    let missing_backend =
        validate_scope_backend("p", "replay_scope", ReplayScope::Shared, false).unwrap_err();
    assert!(missing_backend.contains("sync_mode"));

    let unused_backend =
        validate_scope_backend("p", "replay_scope", ReplayScope::Process, true).unwrap_err();
    assert!(unused_backend.contains("shared"));
}

#[test]
fn replay_scope_diagnostics_preserve_schema_and_suggestions_when_rendered() {
    for value in [
        "'REPLAY_VALUE_MARKER",
        "\"REPLAY_VALUE_MARKER\\\n",
        "927451",
        "true",
    ] {
        let error =
            ReplayScope::parse("jwks_auth", "provider[3].dpop_replay_scope", value).unwrap_err();
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        for expected in [
            "`provider[3].dpop_replay_scope`",
            "must be exactly `process` or `shared`",
            "`sync_mode: redis`",
        ] {
            assert!(rendered.contains(expected), "{rendered}");
        }
        for withheld in ["REPLAY_VALUE_MARKER", "927451", "true"] {
            assert!(!rendered.contains(withheld), "{rendered}");
        }
    }
    for (scope, redis_configured, reason) in [
        (ReplayScope::Shared, false, "requires"),
        (ReplayScope::Process, true, "is only meaningful"),
    ] {
        let error = validate_scope_backend("hmac_auth", "replay_scope", scope, redis_configured)
            .unwrap_err();
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        for expected in ["`replay_scope`", "`shared`", "`sync_mode: redis`", reason] {
            assert!(rendered.contains(expected), "{rendered}");
        }
    }
}

// ── observability ───────────────────────────────────────────────────

/// Counters move on the paths they claim to describe. They are process-global
/// and monotonic, so the assertions are on deltas rather than absolute values.
#[tokio::test]
async fn counters_record_replay_and_capacity_outcomes() {
    let before = counters();
    let authority = process_authority("counters", 1);
    let marker = domain("counters").marker(&[b"c", b"proof"]);
    let other = domain("counters").marker(&[b"c", b"other"]);

    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Admitted);
    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Replay);
    assert_eq!(
        authority.admit(&other).await,
        ReplayAdmission::CapacityRefused
    );

    let after = counters();
    assert!(after.admitted_process > before.admitted_process);
    assert!(after.replay_rejected > before.replay_rejected);
    assert!(after.capacity_refused > before.capacity_refused);
    assert!(after.process_lanes >= 1);
}

/// The public snapshot must stay label-free. Serializing it and checking that
/// only the fixed field names appear is the structural guard against someone
/// adding a namespace, policy id, or marker to it later.
#[test]
fn the_counter_snapshot_carries_no_labels() {
    let value = serde_json::to_value(counters()).expect("counters serialize");
    let object = value.as_object().expect("counters are an object");
    let mut names: Vec<&str> = object.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "admitted_process",
            "admitted_shared",
            "authority_unavailable",
            "capacity_refused",
            "legacy_unsafe_profile_accepted",
            "process_lanes",
            "replay_rejected",
            "shared_authorities",
            "shared_authorities_unavailable",
        ]
    );
    assert!(
        object.values().all(serde_json::Value::is_number),
        "every counter must be a bare number: no label, identity, or error text"
    );
}

/// Neither a domain nor a marker may print recoverable proof material.
#[test]
fn debug_renderings_never_disclose_marker_material() {
    let one = domain("debug");
    let marker = one.marker(&[b"super-secret-nonce", b"consumer-42"]);
    assert_eq!(format!("{one:?}"), "ReplayDomain(<digest>)");
    assert_eq!(format!("{marker:?}"), "ReplayMarker(<digest>)");

    let authority = process_authority("debug", 4);
    let rendered = format!("{authority:?}");
    assert!(rendered.contains("process"));
    assert!(!rendered.contains("secret"));
}

// ── shared authority fails closed ───────────────────────────────────

/// A `shared` authority whose backend cannot be reached rejects the protected
/// request. There is deliberately no fallback to process-local acceptance: a
/// per-replica fallback would reinstate exactly the cross-replica bypass the
/// shared authority exists to close.
///
/// The endpoint is a closed loopback port, so this exercises the real
/// connect-failure path (the same one a timeout, a partition, or an
/// authentication rejection lands on) without needing a live server.
#[tokio::test]
async fn a_shared_authority_with_an_unreachable_backend_fails_closed() {
    let _serialized = shared_health_guard_async().await;
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            // Port 1 is reserved and never listening.
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
        }),
        "ferrum:replay_authority_tests:unreachable",
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");

    let client = Arc::new(replay_redis_client(config));
    let authority = shared_live(client, RETENTION);
    assert_eq!(authority.mode(), "shared");

    let marker = domain("shared-unreachable").marker(&[b"c", b"proof"]);
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable,
        "an unreachable shared backend must reject, never admit locally"
    );
    // Still unavailable on a second attempt: nothing silently degrades into a
    // local lane that would start accepting.
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable
    );

    // A shared authority contributes nothing to any process lane.
    assert!(process_lane(&authority).is_none());
}

/// The shared authority is registered for readiness/metrics, and its outage is
/// observable without retaining the client, its endpoint, or its credentials.
#[tokio::test]
async fn an_unavailable_shared_authority_is_visible_in_the_counters() {
    let _serialized = shared_health_guard_async().await;
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
        }),
        "ferrum:replay_authority_tests:observable",
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");

    let client = Arc::new(replay_redis_client(config));
    let authority = shared_live(Arc::clone(&client), RETENTION);

    let marker = domain("shared-observable").marker(&[b"c", b"proof"]);
    let before = counters();
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable
    );
    let after = counters();
    assert!(after.authority_unavailable > before.authority_unavailable);
    assert!(after.shared_authorities >= 1);
    assert!(
        after.shared_authorities_unavailable >= 1,
        "a degraded shared authority must be visible to readiness"
    );
    assert!(shared_authority_degraded());
}

// ── shared-authority health for readiness ───────────────────────────
//
// Shared-replay health counters are process-global, so these cases serialize
// against each other. Other `shared` configurations in the unit suite either
// fail admission or stay detached until `commit_background_tasks`, so a
// serialized case observes only its own registrations.
/// A tokio mutex rather than a `std` one so the async cases can hold it across
/// their awaits without a `!Send` guard.
static SHARED_HEALTH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn shared_health_guard() -> tokio::sync::MutexGuard<'static, ()> {
    SHARED_HEALTH_LOCK.blocking_lock()
}

async fn shared_health_guard_async() -> tokio::sync::MutexGuard<'static, ()> {
    SHARED_HEALTH_LOCK.lock().await
}

async fn wait_until(mut pred: impl FnMut() -> bool, what: &str) {
    for _ in 0..500 {
        if pred() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting until {what}");
}

async fn wait_until_available(client: &RedisRateLimitClient) {
    wait_until(
        || client.is_available(),
        "the replay backend completed a topology-screened probe",
    )
    .await;
}

/// Bounded, yield-friendly spin for the synchronous shared-replay concurrency
/// tests. Unlike [`wait_until`] this does not need a Tokio runtime, so it can
/// gate `std::thread` workers deterministically.
fn wait_for_sync(mut pred: impl FnMut() -> bool, what: &str) {
    for _ in 0..10_000_000 {
        if pred() {
            return;
        }
        std::thread::yield_now();
    }
    panic!("timed out waiting until {what}");
}

fn unreachable_shared_client(prefix: &str) -> Arc<RedisRateLimitClient> {
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            // Port 1 is reserved and never listening.
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
            // Long enough that no background recovery dial races an assertion.
            "redis_health_check_interval_seconds": 3600,
        }),
        prefix,
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");
    Arc::new(replay_redis_client(config))
}

/// Construct and activate a live shared authority, matching a committed plugin
/// generation. Production construction stays detached until commit.
fn shared_live(client: Arc<RedisRateLimitClient>, retention: Duration) -> ReplayAuthority {
    let authority = ReplayAuthority::shared(client, retention);
    authority.activate();
    authority
}

/// Shape-only validation and uncommitted runtime construction both build the
/// real plugin so config admission stays aligned with runtime parsing, but that
/// candidate is not a live policy until commit. It must neither enter the
/// process readiness aggregate nor arm a backend probe. Commit after atomic
/// installation registers exactly one dependency per plugin-owned Redis client.
#[test]
fn validation_construction_does_not_publish_shared_replay_readiness() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();
    let hmac_config = serde_json::json!({
        "replay_scope": "shared",
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1",
        "redis_health_check_interval_seconds": 3600
    });
    let jwks_config = serde_json::json!({
        "providers": [{
            "jwks": {"keys": []},
            "issuer": "https://idp.example.com",
            "require_dpop": true,
            "dpop_replay_scope": "shared"
        }],
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1",
        "redis_health_check_interval_seconds": 3600
    });

    let detached_hmac = ferrum_edge::plugins::hmac_auth::HmacAuth::new(&hmac_config)
        .expect("shape-only HMAC validation");
    let detached_jwks = ferrum_edge::plugins::jwks_auth::JwksAuth::new(
        &jwks_config,
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
    )
    .expect("shape-only JWKS validation");
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "unpublished validation candidates must not affect readiness"
    );
    assert!(
        !detached_hmac.shared_replay_recovery_started_for_test(),
        "shape-only HMAC validation must not arm Redis recovery"
    );
    assert!(
        !detached_jwks.shared_replay_recovery_started_for_test(),
        "shape-only JWKS validation must not arm Redis recovery"
    );

    let uncommitted_hmac =
        ferrum_edge::plugins::hmac_auth::HmacAuth::new_with_http_client_and_config_id(
            &hmac_config,
            ferrum_edge::plugins::utils::PluginHttpClient::default(),
            Some("live-hmac-replay-policy"),
        )
        .expect("runtime HMAC construction");
    let uncommitted_jwks = ferrum_edge::plugins::jwks_auth::JwksAuth::new_with_config_id(
        &jwks_config,
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some("live-jwks-replay-policy"),
    )
    .expect("runtime JWKS construction");
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "an uncommitted runtime candidate must not affect readiness"
    );
    assert!(
        !uncommitted_hmac.shared_replay_recovery_started_for_test()
            && !uncommitted_jwks.shared_replay_recovery_started_for_test(),
        "uncommitted construction must not arm Redis recovery"
    );

    uncommitted_hmac.commit_background_tasks();
    uncommitted_jwks.commit_background_tasks();
    let registered = shared_health_snapshot();
    assert_eq!(
        registered.shared_authorities,
        baseline.shared_authorities + 2
    );
    assert_eq!(
        registered.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 2,
        "both unproven committed dependencies fail readiness closed"
    );

    uncommitted_hmac.commit_background_tasks();
    uncommitted_jwks.commit_background_tasks();
    assert_eq!(
        shared_health_snapshot(),
        registered,
        "commit must register each plugin-owned Redis client exactly once"
    );

    drop((uncommitted_hmac, uncommitted_jwks));
    assert_eq!(shared_health_snapshot(), baseline);
    drop((detached_hmac, detached_jwks));
    assert_eq!(shared_health_snapshot(), baseline);
}

/// A later provider that fails validation must drop every earlier shared
/// authority without ever publishing readiness or arming recovery.
#[test]
fn an_invalid_jwks_candidate_does_not_publish_shared_replay_readiness() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();
    let error = ferrum_edge::plugins::jwks_auth::JwksAuth::new_with_config_id(
        &serde_json::json!({
            "providers": [
                {
                    "jwks": {"keys": []},
                    "issuer": "https://idp-a.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "shared"
                },
                {
                    "issuer": "https://idp-b.example.com"
                }
            ],
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1",
            "redis_health_check_interval_seconds": 3600
        }),
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some("invalid-jwks-replay-policy"),
    )
    .err()
    .expect("provider[1] has no usable JWKS source");
    assert!(
        error.contains("jwks"),
        "the candidate must fail closed on the later provider: {error}"
    );
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "a rejected JWKS candidate must not change packed replay health"
    );
}

/// An invalid HMAC candidate is refused before any shared client is published.
#[test]
fn an_invalid_hmac_candidate_does_not_publish_shared_replay_readiness() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();
    let error = ferrum_edge::plugins::hmac_auth::HmacAuth::new_with_http_client_and_config_id(
        &serde_json::json!({ "replay_scope": "shared" }),
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some("invalid-hmac-replay-policy"),
    )
    .err()
    .expect("shared HMAC requires Redis");
    assert!(
        error.contains("shared"),
        "the candidate must fail closed without a Redis backend: {error}"
    );
    assert_eq!(shared_health_snapshot(), baseline);
}

/// Several `shared` JWKS providers reuse one Redis client; commit counts it
/// once, and dropping the uncommitted candidate never decrements health.
#[test]
fn committing_jwks_shared_providers_registers_one_client() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();
    let plugin = ferrum_edge::plugins::jwks_auth::JwksAuth::new_with_config_id(
        &serde_json::json!({
            "providers": [
                {
                    "jwks": {"keys": []},
                    "issuer": "https://idp-a.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "shared"
                },
                {
                    "jwks": {"keys": []},
                    "issuer": "https://idp-b.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "shared"
                }
            ],
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1",
            "redis_health_check_interval_seconds": 3600
        }),
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some("jwks-shared-providers"),
    )
    .expect("two shared providers construct");
    assert_eq!(shared_health_snapshot(), baseline);
    plugin.commit_background_tasks();
    let registered = shared_health_snapshot();
    assert_eq!(
        registered.shared_authorities,
        baseline.shared_authorities + 1,
        "one Redis client is one shared authority"
    );
    plugin.commit_background_tasks();
    assert_eq!(shared_health_snapshot(), registered);
    drop(plugin);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// A detached shared authority fails closed without a local lane, without
/// moving packed health, and without arming a Redis dial.
#[tokio::test]
async fn a_detached_shared_authority_fails_closed_without_local_fallback() {
    let _serialized = shared_health_guard_async().await;
    let baseline = shared_health_snapshot();
    let client = unreachable_shared_client("ferrum:replay_authority_tests:detached-admit");
    let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
    assert_eq!(shared_health_snapshot(), baseline);
    assert!(
        !authority.recovery_checker_started_for_test(),
        "detached construction must not start the recovery checker"
    );
    assert!(
        client.publish_reachable_for_test(),
        "availability without activation must not become a local admit path"
    );
    assert!(client.is_available());

    let marker = domain("detached-admit").marker(&[b"c", b"proof"]);
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable,
        "an uncommitted shared authority must reject, never admit locally"
    );
    assert!(
        !authority.recovery_checker_started_for_test(),
        "a precommit miss must not dial Redis"
    );
    assert!(process_lane(&authority).is_none());
    assert_eq!(shared_health_snapshot(), baseline);

    drop(authority);
    drop(client);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// Commit under a Tokio runtime arms recovery exactly once per plugin-owned
/// client. Construction still must not.
#[tokio::test]
async fn committing_hmac_and_jwks_under_tokio_starts_recovery_exactly_once() {
    let _serialized = shared_health_guard_async().await;
    let baseline = shared_health_snapshot();
    let hmac_config = serde_json::json!({
        "replay_scope": "shared",
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1",
        "redis_health_check_interval_seconds": 3600
    });
    let jwks_config = serde_json::json!({
        "providers": [{
            "jwks": {"keys": []},
            "issuer": "https://idp.example.com",
            "require_dpop": true,
            "dpop_replay_scope": "shared"
        }],
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:1",
        "redis_health_check_interval_seconds": 3600
    });

    let hmac = ferrum_edge::plugins::hmac_auth::HmacAuth::new_with_http_client_and_config_id(
        &hmac_config,
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some("tokio-hmac-replay-policy"),
    )
    .expect("runtime HMAC construction");
    let jwks = ferrum_edge::plugins::jwks_auth::JwksAuth::new_with_config_id(
        &jwks_config,
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some("tokio-jwks-replay-policy"),
    )
    .expect("runtime JWKS construction");
    assert_eq!(shared_health_snapshot(), baseline);
    assert!(
        !hmac.shared_replay_recovery_started_for_test()
            && !jwks.shared_replay_recovery_started_for_test(),
        "construction under Tokio still must not dial Redis"
    );

    hmac.commit_background_tasks();
    jwks.commit_background_tasks();
    assert!(hmac.shared_replay_recovery_started_for_test());
    assert!(jwks.shared_replay_recovery_started_for_test());
    let registered = shared_health_snapshot();
    assert_eq!(
        registered.shared_authorities,
        baseline.shared_authorities + 2
    );

    hmac.commit_background_tasks();
    jwks.commit_background_tasks();
    assert_eq!(shared_health_snapshot(), registered);

    drop((hmac, jwks));
    assert_eq!(shared_health_snapshot(), baseline);
}

/// The bounded aggregate readiness consumes: an unavailable shared authority is
/// visible, recovery clears it, and a retired plugin generation stops counting.
#[test]
fn shared_authority_health_tracks_outage_recovery_and_retirement() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:health");
    let authority = shared_live(Arc::clone(&client), RETENTION);

    let registered = shared_health_snapshot();
    assert_eq!(
        registered.shared_authorities,
        baseline.shared_authorities + 1,
        "a live shared authority is counted exactly once"
    );
    assert!(registered.required());
    assert_eq!(
        registered.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1,
        "a freshly built replay client is unproven and must fail closed"
    );
    assert!(registered.unavailable());
    assert!(!client.is_available());
    assert!(
        !client.health_checker_started_for_test(),
        "registration without a Tokio runtime must not panic or latch the probe"
    );

    // Recovery restores it with no rebuild and no config reload.
    assert!(client.publish_reachable_for_test());
    let recovered = shared_health_snapshot();
    assert_eq!(
        recovered.shared_authorities_unavailable, baseline.shared_authorities_unavailable,
        "a recovered backend must stop failing readiness"
    );
    assert_eq!(
        recovered.shared_authorities,
        baseline.shared_authorities + 1
    );

    // Retiring the generation drops it from the aggregate immediately: the
    // health registration is independent of secret-bearing client data and
    // does not retain historical handles on the probe path.
    drop(authority);
    drop(client);
    let retired = shared_health_snapshot();
    assert_eq!(
        retired.shared_authorities, baseline.shared_authorities,
        "a retired plugin generation must not remain counted"
    );
    assert_eq!(
        retired.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable
    );
}

/// Registration under a Tokio runtime must arm the bounded readiness probe
/// immediately so recovery does not wait for protected traffic.
#[tokio::test]
async fn registering_a_shared_authority_under_tokio_arms_the_readiness_probe() {
    let _serialized = shared_health_guard_async().await;
    let client = unreachable_shared_client("ferrum:replay_authority_tests:arm-probe");
    let authority = shared_live(Arc::clone(&client), RETENTION);
    assert!(!client.is_available());
    assert!(
        client.health_checker_started_for_test(),
        "a required shared backend must probe without waiting for a protected request"
    );
    drop(authority);
    drop(client);
}

/// Activation without a reactor must stay panic-free, and a later request-path
/// miss under a runtime must still arm recovery.
#[tokio::test]
async fn a_runtime_appearing_later_still_arms_the_replay_readiness_probe() {
    let _serialized = shared_health_guard_async().await;
    let (client, authority) = std::thread::spawn(|| {
        let client = unreachable_shared_client("ferrum:replay_authority_tests:later-runtime");
        let authority = shared_live(Arc::clone(&client), RETENTION);
        assert!(
            !client.health_checker_started_for_test(),
            "no reactor: do not latch the started flag"
        );
        (client, authority)
    })
    .join()
    .expect("thread should not panic");
    assert!(!client.health_checker_started_for_test());
    let marker = domain("later-runtime").marker(&[b"c", b"proof"]);
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable,
        "unproven state fails closed without waiting on the backend"
    );
    assert!(
        client.health_checker_started_for_test(),
        "the first miss under a runtime must arm the bounded probe"
    );
    drop(authority);
    drop(client);
}

/// One backend shared by several providers is one authority, not several.
/// `jwks_auth` builds a single Redis client per plugin generation and hands it
/// to every `shared` provider, so a per-provider registration would report one
/// backend as many and inflate a readiness aggregate.
#[test]
fn one_backend_shared_by_several_authorities_is_counted_once() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:dedupe");
    let first = shared_live(Arc::clone(&client), RETENTION);
    let second = shared_live(Arc::clone(&client), RETENTION);
    let third = shared_live(Arc::clone(&client), RETENTION);

    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities + 1,
        "three providers over one backend are one shared authority"
    );

    drop((first, second, third));
    drop(client);
    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities
    );
}

/// The probe/metrics snapshot is two integers loaded from a packed atomic.
/// Admin readiness and `/metrics/runtime` must observe the same precomputed
/// pair — never a scanned registry.
#[test]
fn shared_health_snapshot_is_a_lock_free_fixed_cardinality_load() {
    let _serialized = shared_health_guard();
    let snapshot = shared_health_snapshot();
    assert_eq!(
        std::mem::size_of::<SharedReplayAuthorityHealth>(),
        2 * std::mem::size_of::<u64>(),
        "the snapshot is two integers, not a scanned collection"
    );
    let runtime = counters();
    assert_eq!(snapshot.shared_authorities, runtime.shared_authorities);
    assert_eq!(
        snapshot.shared_authorities_unavailable,
        runtime.shared_authorities_unavailable
    );
    let copy = snapshot;
    assert_eq!(copy, snapshot);
}

/// Distinct Redis clients are distinct authorities. HMAC and JWKS each build
/// their own client, so two live clients must count twice.
#[test]
fn distinct_shared_clients_are_counted_separately() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let hmac = unreachable_shared_client("ferrum:replay_authority_tests:hmac");
    let jwks = unreachable_shared_client("ferrum:replay_authority_tests:jwks");
    let hmac_authority = shared_live(Arc::clone(&hmac), RETENTION);
    let jwks_authority = shared_live(Arc::clone(&jwks), RETENTION);

    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities + 2,
        "HMAC and JWKS clients are distinct authorities"
    );

    drop(hmac_authority);
    drop(hmac);
    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities + 1,
        "retiring one client must not retire the other"
    );

    drop(jwks_authority);
    drop(jwks);
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "both distinct clients must clear on drop"
    );
}

/// Generic rate-limiter clients are not shared replay authorities.
#[test]
fn a_generic_redis_client_does_not_contribute_to_shared_replay_health() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 3600,
        }),
        "ferrum:replay_authority_tests:generic",
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");
    let client = RedisRateLimitClient::new(config, None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(
        client.is_available(),
        "operational Redis clients keep historical initial reachability"
    );
    client.mark_unavailable_for_test();
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "generic Redis policy clients must not move replay health"
    );
    drop(client);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// Terminal topology is sticky: recovery cannot resurrect health, and drop
/// still clears the generation.
#[test]
fn terminal_topology_publishes_unavailable_and_cannot_resurrect() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:terminal");
    let authority = shared_live(Arc::clone(&client), RETENTION);
    client.mark_topology_unsupported_for_test();

    let terminal = shared_health_snapshot();
    assert_eq!(terminal.shared_authorities, baseline.shared_authorities + 1);
    assert_eq!(
        terminal.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1
    );
    assert!(
        !client.publish_reachable_for_test(),
        "terminal topology must refuse resurrection"
    );
    assert_eq!(
        shared_health_snapshot().shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1,
        "a refused recovery must not decrement unavailable"
    );

    drop(authority);
    drop(client);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// A replacement generation takes over the count: overlapping live generations
/// add, and retiring the old one leaves only the new.
#[test]
fn replacement_generation_clears_the_retired_count() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let old_client = unreachable_shared_client("ferrum:replay_authority_tests:replace-old");
    old_client.mark_unavailable_for_test();
    let old = shared_live(Arc::clone(&old_client), RETENTION);
    let new_client = unreachable_shared_client("ferrum:replay_authority_tests:replace-new");
    let new = shared_live(Arc::clone(&new_client), RETENTION);

    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities + 2,
        "old and new generations overlap during reload"
    );

    drop(old);
    drop(old_client);
    let after_old = shared_health_snapshot();
    assert_eq!(
        after_old.shared_authorities,
        baseline.shared_authorities + 1
    );
    assert_eq!(
        after_old.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1,
        "the live replacement stays unproven; only the retired generation drops"
    );

    drop(new);
    drop(new_client);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// Retired generations clear counts without needing a later registration to
/// prune historical handles — the previous Vec<Weak> leaked dead entries on
/// this path.
#[test]
fn retired_generations_clear_counts_without_a_later_registration() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();
    for idx in 0..32 {
        let client =
            unreachable_shared_client(&format!("ferrum:replay_authority_tests:retire-{idx}"));
        client.mark_unavailable_for_test();
        let authority = shared_live(Arc::clone(&client), RETENTION);
        assert_eq!(
            shared_health_snapshot().shared_authorities,
            baseline.shared_authorities + 1
        );
        assert_eq!(
            shared_health_snapshot().shared_authorities_unavailable,
            baseline.shared_authorities_unavailable + 1
        );
        drop(authority);
        drop(client);
        assert_eq!(
            shared_health_snapshot(),
            baseline,
            "generation {idx} must clear without a later prune registration"
        );
    }
}

/// Concurrent availability transitions and drops must not underflow, double
/// count, or leave a healthy-empty snapshot while a live authority remains.
#[test]
fn concurrent_transitions_and_drop_keep_exact_counts() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:race");
    let authority = Arc::new(shared_live(Arc::clone(&client), RETENTION));
    const WORKERS: usize = 8;
    let barrier = Arc::new(Barrier::new(WORKERS));

    let workers: Vec<_> = (0..WORKERS)
        .map(|idx| {
            let client = Arc::clone(&client);
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                match idx % 4 {
                    0 => client.mark_unavailable_for_test(),
                    1 => {
                        let _ = client.publish_reachable_for_test();
                    }
                    2 => client.mark_topology_unsupported_for_test(),
                    _ => {}
                }
                let snap = shared_health_snapshot();
                assert!(
                    snap.shared_authorities_unavailable <= snap.shared_authorities,
                    "unavailable cannot exceed registered authorities"
                );
                drop(authority);
                drop(client);
            })
        })
        .collect();

    drop(authority);
    drop(client);
    for worker in workers {
        worker.join().expect("worker should not panic");
    }
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "every generation must retire exactly once after concurrent drop"
    );
}

/// First registration racing an outage must publish exactly one authority and
/// the matching unavailable bit — never a healthy-empty or double count.
#[test]
fn concurrent_registration_and_outage_publish_exact_counts() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:register-race");
    const WORKERS: usize = 6;
    let barrier = Arc::new(Barrier::new(WORKERS));
    let workers: Vec<_> = (0..WORKERS)
        .map(|idx| {
            let client = Arc::clone(&client);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let authority = match idx % 3 {
                    0 => Some(shared_live(Arc::clone(&client), RETENTION)),
                    1 => {
                        client.mark_unavailable_for_test();
                        None
                    }
                    _ => {
                        let _ = client.publish_reachable_for_test();
                        None
                    }
                };
                let snap = shared_health_snapshot();
                assert!(snap.shared_authorities_unavailable <= snap.shared_authorities);
                assert!(snap.shared_authorities <= baseline.shared_authorities + 1);
                authority
            })
        })
        .collect();

    let authorities: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker should not panic"))
        .collect();
    let registered = shared_health_snapshot();
    assert_eq!(
        registered.shared_authorities,
        baseline.shared_authorities + 1,
        "one client is one authority even under a registration/outage race"
    );
    assert!(registered.shared_authorities_unavailable <= registered.shared_authorities);

    drop(authorities);
    drop(client);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// Deterministic regression for the tear the lock-free shared replay health
/// accounting used to allow (#4077): the per-registration `(epoch, state)`
/// word update and its global packed-count delta must publish as one
/// linearized critical section. The gate below holds the first transition
/// exactly between its word store and its delta, proving the packed pair
/// cannot go through an impossible state and a concurrent outage cannot
/// publish out of epoch order.
#[test]
fn transition_and_global_publish_are_one_linearized_critical_section() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:linearized");
    assert!(
        client.publish_reachable_for_test(),
        "prove reachable before attaching so the first count is a reachable sample"
    );
    let reachable = client.capture_shared_replay_registration_sample_for_test();
    assert!(reachable.available());
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "attaching the handle must not publish before apply"
    );

    struct DisarmOnDrop;
    impl Drop for DisarmOnDrop {
        fn drop(&mut self) {
            disarm_shared_replay_apply_pause_for_test();
        }
    }

    let after = std::thread::scope(|scope| {
        arm_shared_replay_apply_pause_for_test();
        let _disarm = DisarmOnDrop;

        let publisher = scope.spawn({
            let client = Arc::clone(&client);
            move || client.publish_shared_replay_registration_sample_for_test(reachable)
        });

        wait_for_sync(
            || shared_replay_apply_pause_entered_for_test() >= 1,
            "the first transition to reach the tear point",
        );

        // Reaching the tear point means the per-registration word is published
        // (the gate sits between the word store and the delta), …
        // … but the global delta is not, and the transition lock spans both.
        assert_eq!(
            shared_health_snapshot(),
            baseline,
            "the global delta must not apply before the tear point releases"
        );
        assert!(
            shared_replay_transition_lock_held_for_test(),
            "the transition lock must be held across the word + delta publish"
        );

        // A concurrent outage must serialize behind the held lock rather than
        // publishing its unavailable delta out of epoch order.
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (started_w, done_w) = (Arc::clone(&started), Arc::clone(&done));
        let outage = scope.spawn({
            let client = Arc::clone(&client);
            move || {
                started_w.store(true, std::sync::atomic::Ordering::Release);
                client.mark_unavailable_for_test();
                done_w.store(true, std::sync::atomic::Ordering::Release);
            }
        });

        wait_for_sync(
            || started.load(std::sync::atomic::Ordering::Acquire),
            "the outage thread to start",
        );
        for _ in 0..10_000_000 {
            if done.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            std::hint::spin_loop();
        }
        assert!(
            !done.load(std::sync::atomic::Ordering::Acquire),
            "a concurrent outage must not complete while the transition lock is held"
        );
        assert!(
            shared_replay_transition_lock_held_for_test(),
            "the lock must still be held while the concurrent outage is pending"
        );
        assert_eq!(
            shared_health_snapshot(),
            baseline,
            "the packed pair must stay untouched until the pause releases"
        );

        disarm_shared_replay_apply_pause_for_test();
        publisher.join().expect("publisher must not panic");
        outage.join().expect("outage thread must not panic");

        let settled = shared_health_snapshot();
        assert_eq!(
            settled.shared_authorities,
            baseline.shared_authorities + 1,
            "the paused registration publishes exactly one authority"
        );
        assert_eq!(
            settled.shared_authorities_unavailable,
            baseline.shared_authorities_unavailable + 1,
            "the concurrent outage moves exactly that one authority to unavailable"
        );
        settled
    });

    assert_eq!(
        shared_health_snapshot(),
        after,
        "the published pair stays exactly correct once the race settles"
    );

    drop(client);
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "retirement clears the single authority exactly once"
    );
}

/// A stale reachable registration sample must not overwrite a later unavailable
/// notification. The previous bounded resample loop could apply the sampled
/// `on_available` after the eighth iteration even though a newer outage had
/// already notified — leaving `/health` permanently ready while the client is
/// unreachable.
#[test]
fn stale_reachable_registration_sample_cannot_overwrite_later_unavailable() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:stale-ready");
    assert!(
        client.publish_reachable_for_test(),
        "prove reachable before capturing so the stale sample is a reachable epoch"
    );
    let stale = client.capture_shared_replay_registration_sample_for_test();
    assert!(
        stale.available(),
        "the sample is a proven reachable epoch captured before the outage"
    );
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "attaching the health handle must not publish counts before apply"
    );

    client.mark_unavailable_for_test();
    let after_notify = shared_health_snapshot();
    assert_eq!(
        after_notify.shared_authorities,
        baseline.shared_authorities + 1
    );
    assert_eq!(
        after_notify.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1,
        "the outage notify is the first publish when apply has not run yet"
    );
    assert!(after_notify.unavailable());
    assert!(!client.is_available());

    client.publish_shared_replay_registration_sample_for_test(stale);
    let settled = shared_health_snapshot();
    assert_eq!(
        settled, after_notify,
        "stale reachable sample must not resurrect readiness after the outage settles"
    );
    assert!(settled.unavailable());
    assert!(!client.is_available());

    let authority = shared_live(Arc::clone(&client), RETENTION);
    assert_eq!(
        shared_health_snapshot(),
        settled,
        "production register remains exactly-once after the stale-sample race"
    );

    drop(authority);
    drop(client);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// A stale unavailable registration sample must not overwrite a later recovery
/// notification, which would leave `/health` permanently unready while the
/// client is reachable.
#[test]
fn stale_unavailable_registration_sample_cannot_overwrite_later_recovery() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:stale-down");
    client.mark_unavailable_for_test();
    let stale = client.capture_shared_replay_registration_sample_for_test();
    assert!(
        !stale.available(),
        "the sample is the proven outage, captured before recovery"
    );
    assert_eq!(
        shared_health_snapshot(),
        baseline,
        "attaching after an unregistered outage must not publish until apply or notify"
    );

    assert!(client.publish_reachable_for_test());
    let recovered = shared_health_snapshot();
    assert_eq!(
        recovered.shared_authorities,
        baseline.shared_authorities + 1
    );
    assert_eq!(
        recovered.shared_authorities_unavailable, baseline.shared_authorities_unavailable,
        "recovery notify is the first publish and must clear unreadiness"
    );
    assert!(!recovered.unavailable());
    assert!(client.is_available());

    client.publish_shared_replay_registration_sample_for_test(stale);
    assert_eq!(
        shared_health_snapshot(),
        recovered,
        "stale unavailable sample must not hide the settled recovery"
    );
    assert!(client.is_available());

    let authority = shared_live(Arc::clone(&client), RETENTION);
    assert_eq!(shared_health_snapshot(), recovered);

    drop(authority);
    drop(client);
    assert_eq!(shared_health_snapshot(), baseline);
}

/// Terminal topology is sticky against a stale reachable registration sample:
/// the packed word must stay unavailable and reachable publication must keep
/// failing after the stale apply.
#[test]
fn stale_reachable_registration_sample_cannot_overwrite_terminal_topology() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:stale-terminal");
    assert!(client.publish_reachable_for_test());
    let stale = client.capture_shared_replay_registration_sample_for_test();
    assert!(stale.available());

    client.mark_topology_unsupported_for_test();
    let terminal = shared_health_snapshot();
    assert_eq!(terminal.shared_authorities, baseline.shared_authorities + 1);
    assert_eq!(
        terminal.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1
    );
    assert!(!client.publish_reachable_for_test());

    client.publish_shared_replay_registration_sample_for_test(stale);
    assert_eq!(
        shared_health_snapshot(),
        terminal,
        "stale reachable sample must not resurrect a terminal generation"
    );
    assert!(!client.is_available());
    assert!(!client.publish_reachable_for_test());

    let authority = shared_live(Arc::clone(&client), RETENTION);
    assert_eq!(shared_health_snapshot(), terminal);

    drop(authority);
    drop(client);
    assert_eq!(shared_health_snapshot(), baseline);
}

// ── bounded, redacted shared claim ──────────────────────────────────

/// RESP wire form of the command-name bulk string. Substring `SET`/`INFO`
/// also match `CLIENT SETINFO`, so handshake bytes must not be treated as
/// the replay claim or the topology screen.
const SET_CMD: &[u8] = b"$3\r\nSET\r\n";
const INFO_CMD: &[u8] = b"$4\r\nINFO\r\n";
const PING_CMD: &[u8] = b"$4\r\nPING\r\n";
const INFO_MEMORY_ARG: &[u8] = b"$6\r\nMEMORY\r\n";
const CLUSTER_DISABLED_INFO: &str = "# Cluster\r\ncluster_enabled:0\r\n";
const SAFE_MEMORY_INFO: &str = "# Memory\r\nmaxmemory:0\r\nmaxmemory_policy:noeviction\r\n";

fn resp_bulk(text: &str) -> Vec<u8> {
    format!("${}\r\n{text}\r\n", text.len()).into_bytes()
}

fn replay_info_reply(chunk: &[u8]) -> Option<Vec<u8>> {
    if !resp_contains(chunk, INFO_CMD) {
        return None;
    }
    if resp_contains(chunk, INFO_MEMORY_ARG) {
        Some(resp_bulk(SAFE_MEMORY_INFO))
    } else {
        Some(resp_bulk(CLUSTER_DISABLED_INFO))
    }
}

/// The standalone `TIME` screening probe a REQUEST-QUOTA connection runs after
/// its `INFO` screens, answered from the one shared fixture definition.
///
/// A replay authority reads no server clock — it claims markers with
/// `SET NX EX` — so its connections skip the probe and these fixtures are never
/// asked. The arm is retained because a fake peer that stands in for a real
/// Redis should answer what a real Redis answers, and because a fixture shared
/// with quota coverage would otherwise refuse the endpoint with its catch-all
/// `+OK`. See [`super::redis_resp`].
fn replay_time_reply(chunk: &[u8]) -> Option<Vec<u8>> {
    resp_contains(chunk, TIME_CMD).then(host_clock_time_reply)
}

fn resp_contains(chunk: &[u8], command: &[u8]) -> bool {
    chunk.windows(command.len()).any(|window| window == command)
}

/// Number of RESP command arrays in one read chunk — the redis crate pipelines
/// its connection setup, so a single read can carry several commands.
fn resp_command_count(chunk: &[u8]) -> usize {
    chunk.iter().filter(|&&byte| byte == b'*').count().max(1)
}

/// How the fake backend answers the `SET` that carries a replay claim.
#[derive(Clone, Copy)]
enum ClaimBehavior {
    /// Accepted, authenticated, screened — and then simply never answered.
    Silent,
    /// A RESP error reply (`-NOAUTH …`, `-WRONGPASS …`, `-OOM …`).
    Error(&'static str),
    /// A reply that is not valid RESP for this command: protocol uncertainty.
    Garbage,
    /// The socket closes with no reply at all: a partition mid-command.
    Disconnect,
    /// The command IS executed and the reply is then lost. A later attempt sees
    /// the key that the lost command created.
    ExecutedThenLost,
}

/// A minimal RESP server that completes connection setup and the topology
/// screen, then answers the replay claim per [`ClaimBehavior`].
///
/// The interesting shapes here are the ones a *connect* timeout cannot catch:
/// the peer accepts the TCP connection, authenticates, and answers `INFO`
/// cleanly, so the client holds a screened, usable connection — and only then
/// misbehaves.
async fn spawn_claim_redis_server(
    behavior: ClaimBehavior,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    // Server-side record of whether the claim key exists, for `ExecutedThenLost`.
    let claimed = Arc::new(std::sync::atomic::AtomicBool::new(false));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let claimed = Arc::clone(&claimed);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            let chunk = &buf[..read];
                            let reply: Vec<u8> = if resp_contains(chunk, SET_CMD) {
                                match behavior {
                                    ClaimBehavior::Silent => continue,
                                    ClaimBehavior::Disconnect => break,
                                    ClaimBehavior::Error(text) => text.as_bytes().to_vec(),
                                    ClaimBehavior::Garbage => b"@not-resp\r\n".to_vec(),
                                    ClaimBehavior::ExecutedThenLost => {
                                        if claimed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                                            // The key the lost command created is
                                            // still there: `SET NX` declines.
                                            b"$-1\r\n".to_vec()
                                        } else {
                                            // Executed, then the reply is lost.
                                            break;
                                        }
                                    }
                                }
                            } else if let Some(reply) = replay_info_reply(chunk) {
                                reply
                            } else if let Some(reply) = replay_time_reply(chunk) {
                                reply
                            } else {
                                // The redis crate pipelines connection setup, so
                                // reply once per command array in the chunk.
                                b"+OK\r\n".repeat(resp_command_count(chunk))
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx)
}

/// Handshake succeeds; the first `silent_pings` PING commands are accepted
/// and then never answered. Later PINGs return `PONG` and INFO screens are
/// usable, so a timeout must not permanently prevent recovery.
async fn spawn_ping_silent_then_healthy_redis(
    silent_pings: usize,
) -> (
    u16,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let pings = Arc::new(AtomicUsize::new(0));
    let pings_task = Arc::clone(&pings);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let pings = Arc::clone(&pings_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            let chunk = &buf[..read];
                            if resp_contains(chunk, PING_CMD) {
                                let index = pings.fetch_add(1, Ordering::SeqCst);
                                if index < silent_pings {
                                    // Accepted, authenticated, silent PING.
                                    continue;
                                }
                                if stream.write_all(b"+PONG\r\n").await.is_err() {
                                    break;
                                }
                                continue;
                            }
                            let reply: Vec<u8> = if let Some(reply) = replay_info_reply(chunk) {
                                reply
                            } else if let Some(reply) = replay_time_reply(chunk) {
                                reply
                            } else {
                                b"+OK\r\n".repeat(resp_command_count(chunk))
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, pings, shutdown_tx)
}

/// Handshake and PING succeed; `INFO CLUSTER` is accepted and then never
/// answered. A PING alone must not publish replay readiness.
async fn spawn_info_silent_redis_server() -> (u16, tokio::sync::oneshot::Sender<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            let chunk = &buf[..read];
                            if resp_contains(chunk, INFO_CMD) {
                                // Topology screen never completes.
                                continue;
                            }
                            let reply = b"+OK\r\n".repeat(resp_command_count(chunk));
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx)
}

fn claim_client(port: u16, prefix: &str) -> Arc<RedisRateLimitClient> {
    claim_client_with_interval(port, prefix, 3600)
}

fn claim_client_with_interval(
    port: u16,
    prefix: &str,
    interval_seconds: u64,
) -> Arc<RedisRateLimitClient> {
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": format!("redis://127.0.0.1:{port}/0"),
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": interval_seconds,
        }),
        prefix,
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");
    Arc::new(replay_redis_client(config))
}

/// A topology-screened probe restores availability without a protected request
/// and without test-injected reachability.
#[tokio::test]
async fn a_screened_probe_restores_shared_readiness_without_protected_traffic() {
    let _serialized = shared_health_guard_async().await;
    let baseline = shared_health_snapshot();
    let (port, shutdown) = spawn_claim_redis_server(ClaimBehavior::Silent).await;
    let client = claim_client(port, "ferrum:replay_authority_tests:probe-ready");
    assert!(!client.is_available());
    let authority = shared_live(Arc::clone(&client), RETENTION);
    assert_eq!(
        shared_health_snapshot().shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1,
        "unproven registration must fail closed"
    );
    wait_until_available(&client).await;
    let recovered = shared_health_snapshot();
    assert_eq!(
        recovered.shared_authorities_unavailable, baseline.shared_authorities_unavailable,
        "a screened probe must restore readiness without admit or manual injection"
    );
    assert_eq!(
        recovered.shared_authorities,
        baseline.shared_authorities + 1
    );
    drop(authority);
    drop(client);
    let _ = shutdown.send(());
    assert_eq!(shared_health_snapshot(), baseline);
}

/// Completing PING without a topology screen must not publish the authority
/// reachable. Cluster nodes answer PING while still redirecting every key.
#[tokio::test]
async fn a_ping_alone_does_not_publish_replay_readiness() {
    let _serialized = shared_health_guard_async().await;
    let baseline = shared_health_snapshot();
    let (port, shutdown) = spawn_info_silent_redis_server().await;
    let client = claim_client(port, "ferrum:replay_authority_tests:ping-only");
    let authority = shared_live(Arc::clone(&client), RETENTION);
    for _ in 0..150 {
        assert!(
            !client.is_available(),
            "PING without INFO CLUSTER is not topology proof"
        );
        assert!(
            !client.is_topology_unsupported(),
            "an incomplete screen is an outage, not a terminal Cluster rejection"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        shared_health_snapshot().shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1
    );
    drop(authority);
    drop(client);
    let _ = shutdown.send(());
    assert_eq!(shared_health_snapshot(), baseline);
}

/// A backend that accepts/authenticates and then never answers PING must not
/// publish reachable, and the timeout must not wedge the single-flight
/// checker: a later healthy PING still recovers packed readiness.
#[tokio::test]
async fn a_silent_recovery_ping_times_out_and_does_not_wedge_retry() {
    use std::sync::atomic::Ordering;

    let _serialized = shared_health_guard_async().await;
    let baseline = shared_health_snapshot();
    let (port, pings, shutdown) = spawn_ping_silent_then_healthy_redis(1).await;
    let client = claim_client_with_interval(port, "ferrum:replay_authority_tests:ping-timeout", 1);
    let authority = shared_live(Arc::clone(&client), RETENTION);
    assert!(!client.is_available());
    assert_eq!(
        shared_health_snapshot().shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1,
        "unproven registration must fail closed"
    );
    assert!(client.health_checker_started_for_test());

    wait_until(
        || pings.load(Ordering::SeqCst) >= 1,
        "recovery PING dispatched",
    )
    .await;
    let after_ping = std::time::Instant::now();
    // Unanswered PING is not recovery. Stay fail-closed through most of the
    // admitted connect timeout (1s) so a hang would miss the later retry.
    while after_ping.elapsed() < Duration::from_millis(800) {
        assert!(
            !client.is_available(),
            "an unanswered recovery PING must not publish reachable"
        );
        assert!(
            !client.is_topology_unsupported(),
            "a PING timeout is a retryable outage, not a terminal rejection"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    wait_until_available(&client).await;
    assert!(
        after_ping.elapsed() < Duration::from_secs(10),
        "a PING timeout must not wedge the single-flight recovery checker, took {:?}",
        after_ping.elapsed()
    );
    assert!(
        pings.load(Ordering::SeqCst) >= 2,
        "the checker must retry PING after the timeout"
    );
    assert!(!client.is_topology_unsupported());
    assert_eq!(
        shared_health_snapshot().shared_authorities_unavailable,
        baseline.shared_authorities_unavailable,
        "a later healthy PING must restore packed readiness"
    );

    drop(authority);
    drop(client);
    let _ = shutdown.send(());
    assert_eq!(shared_health_snapshot(), baseline);
}

/// A silent recovery PING publishes only the closed-set timeout class, never
/// Redis error text, the key prefix, or other replay material.
///
/// The fake server counting the PING only proves the command was accepted.
/// Classification is a separate signal: redis-rs' default 500ms response
/// timeout must not be logged as `connection_failed`, and the admitted
/// one-second PING bound must emit `connection_timeout` beside the redacted
/// endpoint.
#[tokio::test(flavor = "current_thread")]
async fn a_silent_recovery_ping_logs_only_the_timeout_classification() {
    use std::sync::atomic::Ordering;

    let _serialized = shared_health_guard_async().await;
    let (logs, guard) = super::plugin_utils::capture_logs();
    let (port, pings, shutdown) = spawn_ping_silent_then_healthy_redis(usize::MAX).await;
    let prefix = "ferrum:replay_authority_tests:ping-timeout-log";
    let client = claim_client(port, prefix);
    let authority = shared_live(Arc::clone(&client), RETENTION);
    wait_until(
        || pings.load(Ordering::SeqCst) >= 1,
        "recovery PING dispatched",
    )
    .await;
    wait_until(
        || logs.contents().contains("connection_timeout"),
        "PING timeout classification logged",
    )
    .await;
    drop(guard);
    let captured = logs.contents();
    assert!(
        captured.contains("connection_timeout"),
        "PING timeout must use the closed-set classification: {captured}"
    );
    assert!(
        !captured.contains("connection_failed"),
        "a silent PING must not be classified as a generic connect failure: {captured}"
    );
    assert!(
        !captured.contains("PING did not complete")
            && !captured.contains("timed out")
            && !captured.contains(prefix)
            && !captured.contains("PONG"),
        "must not log Redis error text, key prefix, or reply material: {captured}"
    );
    assert!(!client.is_available());
    assert!(!client.is_topology_unsupported());
    drop(authority);
    drop(client);
    let _ = shutdown.send(());
}

/// A connected backend that never answers the claim must produce a fixed
/// fail-closed result inside the admitted bound, not hold the protected request.
#[tokio::test]
async fn a_connected_backend_that_never_answers_fails_closed_within_the_bound() {
    let _serialized = shared_health_guard_async().await;
    let (port, shutdown) = spawn_claim_redis_server(ClaimBehavior::Silent).await;
    let client = claim_client(port, "ferrum:replay_authority_tests:silent");
    let authority = shared_live(Arc::clone(&client), RETENTION);
    wait_until_available(&client).await;
    let marker = domain("shared-silent").marker(&[b"c", b"proof"]);

    let started = std::time::Instant::now();
    let outcome = authority.admit(&marker).await;
    let elapsed = started.elapsed();

    assert_eq!(
        outcome,
        ReplayAdmission::AuthorityUnavailable,
        "an unanswered claim is uncertainty, never local acceptance"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "the claim must be bounded by the configured Redis timeout, took {elapsed:?}"
    );
    assert!(
        !client.is_available(),
        "an unanswered claim marks the backend unavailable so readiness can see it"
    );

    let _ = shutdown.send(());
}

/// The claim primitive publishes no backend text and no key material.
///
/// A `RedisError` renders server-supplied detail, and the key IS the replay
/// marker, so the claim path may only log a fixed classification beside the
/// already-redacted endpoint.
#[tokio::test]
async fn the_shared_claim_primitive_publishes_no_backend_or_key_material() {
    let _serialized = shared_health_guard_async().await;
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": "redis://claim-user:claim-password@127.0.0.1:1/0",
            "redis_connect_timeout_seconds": 1,
        }),
        "ferrum:replay_authority_tests:redaction",
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");

    // The one endpoint rendering the claim path may log strips userinfo.
    let redacted = config.redacted_url();
    assert!(!redacted.contains("claim-user"));
    assert!(!redacted.contains("claim-password"));

    let client = Arc::new(replay_redis_client(config));
    let authority = shared_live(Arc::clone(&client), RETENTION);
    let marker = domain("shared-redaction").marker(&[b"consumer-1", b"nonce-1"]);

    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable
    );

    // Nothing about the authority, the marker, or the outcome renders proof
    // material: the classification set is fixed and content-free.
    assert_eq!(format!("{marker:?}"), "ReplayMarker(<digest>)");
    assert_eq!(
        format!("{authority:?}"),
        "ReplayAuthority { mode: \"shared\" }"
    );
    for outcome in [
        ReplayAdmission::Admitted,
        ReplayAdmission::Replay,
        ReplayAdmission::CapacityRefused,
        ReplayAdmission::AuthorityUnavailable,
    ] {
        let classification = outcome.classification();
        assert!(
            [
                "admitted",
                "replay",
                "capacity_refused",
                "authority_unavailable"
            ]
            .contains(&classification),
            "classification must come from the closed set: {classification}"
        );
    }
}

/// Every shared-backend uncertainty class fails closed with the same fixed
/// classification. None of them may admit, and none may fall back to a local
/// lane.
#[tokio::test]
async fn every_shared_backend_uncertainty_class_fails_closed() {
    let _serialized = shared_health_guard_async().await;

    for (label, behavior) in [
        // Authentication rejection: the client cannot enforce here at all.
        (
            "authentication",
            ClaimBehavior::Error("-NOAUTH Authentication required.\r\n"),
        ),
        (
            "wrong_credentials",
            ClaimBehavior::Error("-WRONGPASS invalid username-password pair\r\n"),
        ),
        // Capacity: a Redis that refuses the write under memory pressure or an
        // eviction policy is an unavailable authority, never an acceptance.
        (
            "capacity",
            ClaimBehavior::Error("-OOM command not allowed when used memory > 'maxmemory'.\r\n"),
        ),
        // Protocol uncertainty: the reply is not something this command can mean.
        ("protocol", ClaimBehavior::Garbage),
        // Partition: the socket dies mid-command.
        ("partition", ClaimBehavior::Disconnect),
    ] {
        let (port, shutdown) = spawn_claim_redis_server(behavior).await;
        let client = claim_client(port, "ferrum:replay_authority_tests:uncertainty");
        let authority = shared_live(Arc::clone(&client), RETENTION);
        wait_until_available(&client).await;
        let marker = domain("shared-uncertainty").marker(&[b"c", label.as_bytes()]);

        assert_eq!(
            authority.admit(&marker).await,
            ReplayAdmission::AuthorityUnavailable,
            "{label}: uncertainty must reject the protected request"
        );
        assert!(
            !client.is_available(),
            "{label}: the outage must be visible to readiness"
        );
        assert!(
            process_lane(&authority).is_none(),
            "{label}: a shared authority must never acquire a local lane"
        );

        // Still refused on retry: nothing degrades into local acceptance.
        assert_eq!(
            authority.admit(&marker).await,
            ReplayAdmission::AuthorityUnavailable
        );

        drop(authority);
        drop(client);
        let _ = shutdown.send(());
    }
}

/// A command Redis executed whose reply was then lost must stay fail closed on
/// retry, because the marker the lost command wrote is still there.
///
/// This is the one case where "the authority is uncertain" and "the claim
/// happened" are both true. The client sees `AuthorityUnavailable` and refuses,
/// and the retry observes the existing key as a replay — so losing a reply can
/// cost the client one request, never a second acceptance.
#[tokio::test]
async fn a_claim_whose_reply_was_lost_stays_fail_closed_on_retry() {
    let _serialized = shared_health_guard_async().await;

    let (port, shutdown) = spawn_claim_redis_server(ClaimBehavior::ExecutedThenLost).await;
    let client = claim_client(port, "ferrum:replay_authority_tests:lost-reply");
    let authority = shared_live(Arc::clone(&client), RETENTION);
    wait_until_available(&client).await;
    let marker = domain("shared-lost-reply").marker(&[b"c", b"nonce"]);

    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable,
        "an unacknowledged claim is uncertain and must refuse the request"
    );
    assert!(!client.is_available());

    // The background recovery checker reconnects and republishes availability.
    // Recovery must restore service — and must not reopen the lost claim.
    assert!(client.publish_reachable_for_test());
    assert!(client.is_available());

    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::Replay,
        "the marker the lost command wrote is still there, so the retry is a replay"
    );

    drop(authority);
    drop(client);
    let _ = shutdown.send(());
}

/// There is no bookkeeping mutex on the snapshot path. A live unavailable
/// authority must remain visible across repeated loads — the previous poisoned
/// `Mutex<Vec<Weak<_>>>` could hide it behind a healthy-empty default.
#[test]
fn shared_health_snapshot_cannot_hide_a_live_unavailable_authority() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:visible");
    client.mark_unavailable_for_test();
    let authority = shared_live(Arc::clone(&client), RETENTION);
    let before = shared_health_snapshot();
    assert_eq!(before.shared_authorities, baseline.shared_authorities + 1);
    assert_eq!(
        before.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1
    );

    for _ in 0..32 {
        let snap = shared_health_snapshot();
        assert_eq!(snap, before);
        assert!(snap.unavailable());
        let runtime = counters();
        assert_eq!(runtime.shared_authorities, snap.shared_authorities);
        assert_eq!(
            runtime.shared_authorities_unavailable,
            snap.shared_authorities_unavailable
        );
    }

    let extra = unreachable_shared_client("ferrum:replay_authority_tests:visible-extra");
    extra.mark_unavailable_for_test();
    let extra_authority = shared_live(Arc::clone(&extra), RETENTION);
    assert_eq!(
        shared_health_snapshot().shared_authorities,
        before.shared_authorities + 1
    );

    drop(extra_authority);
    drop(extra);
    drop(authority);
    drop(client);
    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities
    );
}

/// Parse the `EX` TTL out of a RESP `SET … NX EX <ttl>` command.
fn parse_set_ex_ttl(chunk: &[u8]) -> Option<u64> {
    const EX: &[u8] = b"$2\r\nEX\r\n";
    let idx = chunk.windows(EX.len()).position(|window| window == EX)?;
    let rest = &chunk[idx + EX.len()..];
    if rest.first() == Some(&b':') {
        let end = rest.iter().position(|&byte| byte == b'\r')?;
        return std::str::from_utf8(rest.get(1..end)?).ok()?.parse().ok();
    }
    if rest.first() == Some(&b'$') {
        let header_end = rest.windows(2).position(|window| window == b"\r\n")?;
        let start = header_end + 2;
        let value_end = rest[start..]
            .windows(2)
            .position(|window| window == b"\r\n")?;
        return std::str::from_utf8(rest.get(start..start + value_end)?)
            .ok()?
            .parse()
            .ok();
    }
    None
}

/// Handshake + topology screen, then record the `EX` argument of every `SET`.
async fn spawn_ttl_observing_redis_server() -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    Arc<std::sync::Mutex<Vec<u64>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_for_server = Arc::clone(&observed);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let observed = Arc::clone(&observed_for_server);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            let chunk = &buf[..read];
                            let reply: Vec<u8> = if resp_contains(chunk, SET_CMD) {
                                if let Some(ttl) = parse_set_ex_ttl(chunk) {
                                    observed
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .push(ttl);
                                }
                                b"+OK\r\n".to_vec()
                            } else if let Some(reply) = replay_info_reply(chunk) {
                                reply
                            } else if let Some(reply) = replay_time_reply(chunk) {
                                reply
                            } else {
                                b"+OK\r\n".repeat(resp_command_count(chunk))
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, observed)
}

/// The shared claim writes the exact Redis `EX` TTL: integral retentions stay
/// exact, a fractional remainder rounds up, and zero still becomes a positive
/// Redis-valid TTL. Observed on the command that `admit` actually sends.
#[tokio::test]
async fn shared_claim_writes_the_exact_ceil_ttl_on_the_set_command() {
    let _serialized = shared_health_guard_async().await;
    let (port, shutdown, observed) = spawn_ttl_observing_redis_server().await;
    let client = claim_client(port, "ferrum:replay_authority_tests:ttl");

    for (label, retention, expected) in [
        ("integral", Duration::from_secs(601), 601u64),
        ("fractional", Duration::from_millis(600_500), 601u64),
        ("zero", Duration::ZERO, 1u64),
    ] {
        let authority = shared_live(Arc::clone(&client), retention);
        wait_until_available(&client).await;
        let marker = domain("shared-ttl").marker(&[b"c", label.as_bytes()]);
        assert_eq!(
            authority.admit(&marker).await,
            ReplayAdmission::Admitted,
            "{label}: the observing backend must accept the claim"
        );
        drop(authority);

        let ttl = observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .unwrap_or_else(|| panic!("{label}: SET NX EX must have been observed"));
        assert_eq!(ttl, expected, "{label}: Redis EX ttl");
    }

    drop(client);
    let _ = shutdown.send(());
}

const SENTINEL_USER: &str = "SENTINEL-REDIS-USER-r149";
const SENTINEL_PASS: &str = "SENTINEL-REDIS-PASS-r149";
const SENTINEL_PREFIX: &str = "SENTINEL-KEY-PREFIX-r149";
const SENTINEL_AUTH_ERR: &str = "SENTINEL-AUTH-ERR-r149";
const SENTINEL_CMD_ERR: &str = "SENTINEL-CMD-ERR-r149";
const SENTINEL_MOVED_HOST: &str = "SENTINEL-MOVED-HOST-r149";
const SENTINEL_TIME_ERR: &str = "SENTINEL-TIME-ERR-r5584";

#[derive(Clone, Copy)]
enum LoggingShape {
    AuthReject,
    CommandError,
    ClusterInfo,
    ClusterMoved,
    /// The standalone `TIME` screen answers an ordinary `-ERR`. A replay
    /// authority must never send that command in the first place, so this peer
    /// serves it and every claim on it still succeeds.
    TimeError,
}

async fn spawn_logging_redis_server(
    shape: LoggingShape,
) -> (
    u16,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accept_probes = Arc::clone(&probes);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let probes = Arc::clone(&accept_probes);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let chunk = &buf[..read];
                            let reply: Vec<u8> = match shape {
                                LoggingShape::AuthReject => {
                                    format!("-WRONGPASS {SENTINEL_AUTH_ERR}\r\n")
                                        .repeat(resp_command_count(chunk))
                                        .into_bytes()
                                }
                                LoggingShape::ClusterInfo if resp_contains(chunk, INFO_CMD) => {
                                    let text = "# Cluster\r\ncluster_enabled:1\r\n";
                                    format!("${}\r\n{text}\r\n", text.len()).into_bytes()
                                }
                                LoggingShape::ClusterMoved if resp_contains(chunk, SET_CMD) => {
                                    format!("-MOVED 1 {SENTINEL_MOVED_HOST}:7000\r\n").into_bytes()
                                }
                                LoggingShape::CommandError if resp_contains(chunk, SET_CMD) => {
                                    format!("-ERR {SENTINEL_CMD_ERR}\r\n").into_bytes()
                                }
                                LoggingShape::TimeError if resp_contains(chunk, TIME_CMD) => {
                                    format!("-ERR {SENTINEL_TIME_ERR}\r\n").into_bytes()
                                }
                                _ if resp_contains(chunk, INFO_CMD) => {
                                    replay_info_reply(chunk).expect("INFO chunk")
                                }
                                // Only after the shape-specific arms above: an
                                // `AuthReject` peer rejects `TIME` like every
                                // other command, and `ClusterInfo` is terminal
                                // at `INFO` before the probe ever runs.
                                _ if resp_contains(chunk, TIME_CMD) => host_clock_time_reply(),
                                _ => b"+OK\r\n".repeat(resp_command_count(chunk)),
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, probes, shutdown_tx)
}

fn sentinel_replay_config(port: u16) -> RedisConfig {
    RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": format!(
                "redis://{SENTINEL_USER}:{SENTINEL_PASS}@127.0.0.1:{port}/0"
            ),
            "redis_username": SENTINEL_USER,
            "redis_password": SENTINEL_PASS,
            "redis_key_prefix": SENTINEL_PREFIX,
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 3600,
        }),
        SENTINEL_PREFIX,
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config")
}

fn assert_sentinels_absent(logs: &str, context: &str) {
    for sentinel in [
        SENTINEL_USER,
        SENTINEL_PASS,
        SENTINEL_PREFIX,
        SENTINEL_AUTH_ERR,
        SENTINEL_CMD_ERR,
        SENTINEL_MOVED_HOST,
        SENTINEL_TIME_ERR,
    ] {
        assert!(
            !logs.contains(sentinel),
            "{context} leaked {sentinel:?}: {logs}"
        );
    }
}

/// Replay-backend failures publish only a fixed classification beside the
/// redacted endpoint. Connection/authentication, command, and topology paths
/// are driven through a real RESP peer so the assertion is on emitted tracing,
/// not on source text.
#[tokio::test(flavor = "current_thread")]
async fn replay_client_logs_only_classification_and_redacted_endpoint() {
    let _serialized = shared_health_guard_async().await;

    for (label, shape, expected_class) in [
        (
            "authentication",
            LoggingShape::AuthReject,
            "connection_failed",
        ),
        ("command", LoggingShape::CommandError, "command_failed"),
        (
            "topology_probe",
            LoggingShape::ClusterInfo,
            "unsupported_topology",
        ),
        (
            "topology_command",
            LoggingShape::ClusterMoved,
            "unsupported_topology",
        ),
        // No `server_clock` row: a replay authority reads no clock, so its
        // connections never probe `TIME` and there is no such rejection to
        // classify. That the probe is genuinely absent is asserted by
        // `a_replay_authority_never_probes_the_server_clock` below.
    ] {
        let (port, probes, shutdown) = spawn_logging_redis_server(shape).await;
        let config = sentinel_replay_config(port);
        let redacted = config.redacted_url();
        assert!(
            !redacted.contains(SENTINEL_USER) && !redacted.contains(SENTINEL_PASS),
            "{label}: redacted endpoint must strip userinfo: {redacted}"
        );

        let (logs, guard) = super::plugin_utils::capture_logs();
        let client = Arc::new(replay_redis_client(config));
        let authority = shared_live(Arc::clone(&client), RETENTION);
        let marker = domain("shared-logging").marker(&[b"c", label.as_bytes()]);
        match shape {
            LoggingShape::AuthReject => {
                wait_until(
                    || probes.load(std::sync::atomic::Ordering::SeqCst) > 0,
                    &format!("{label}: fake Redis observed a health-check probe"),
                )
                .await;
                wait_until(
                    || logs.contents().contains(expected_class),
                    &format!("{label}: probe classification"),
                )
                .await;
                assert_eq!(
                    authority.admit(&marker).await,
                    ReplayAdmission::AuthorityUnavailable,
                    "{label}: sentinel backend must fail closed"
                );
            }
            LoggingShape::ClusterInfo => {
                wait_until(
                    || client.is_topology_unsupported(),
                    &format!("{label}: terminal topology probe"),
                )
                .await;
                assert_eq!(
                    authority.admit(&marker).await,
                    ReplayAdmission::AuthorityUnavailable,
                    "{label}: sentinel backend must fail closed"
                );
            }
            LoggingShape::CommandError | LoggingShape::ClusterMoved => {
                wait_until_available(&client).await;
                assert_eq!(
                    authority.admit(&marker).await,
                    ReplayAdmission::AuthorityUnavailable,
                    "{label}: sentinel backend must fail closed"
                );
            }
            LoggingShape::TimeError => unreachable!("no server_clock row above"),
        }
        drop(guard);
        let captured = logs.contents();

        assert!(
            captured.contains(expected_class),
            "{label}: expected classification {expected_class:?} in {captured}"
        );
        assert!(
            captured.contains(&redacted),
            "{label}: redacted endpoint must be present in {captured}"
        );
        assert_sentinels_absent(&captured, label);

        drop(authority);
        drop(client);
        let _ = shutdown.send(());
    }
}

/// A replay authority reads no server clock, so an endpoint whose ACL refuses
/// `TIME` must still admit its claims.
///
/// Connection screening is shared with request-quota clients, so making the
/// `TIME` probe a property of the socket took every replay-only deployment on a
/// restrictive ACL out of service for a command it never sends. The peer here
/// answers `-ERR` to `TIME` and `+OK` to the claim: a client that probed would
/// discard the connection unpublished and fail closed, and a client that does
/// not probe claims normally.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_authority_never_probes_the_server_clock() {
    let _serialized = shared_health_guard_async().await;

    let (port, _probes, shutdown) = spawn_logging_redis_server(LoggingShape::TimeError).await;
    let config = sentinel_replay_config(port);
    let (logs, guard) = super::plugin_utils::capture_logs();
    let client = Arc::new(replay_redis_client(config));
    let authority = shared_live(Arc::clone(&client), RETENTION);

    wait_until_available(&client).await;
    let marker = domain("shared-no-clock").marker(&[b"c", b"first"]);
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::Admitted,
        "an endpoint that denies TIME still backs single-use claims"
    );

    drop(guard);
    let captured = logs.contents();
    assert!(
        !captured.contains("server_clock"),
        "no server-clock classification may be published for a consumer that reads \
         no clock: {captured}"
    );
    assert_sentinels_absent(&captured, "no_clock_probe");

    drop(authority);
    drop(client);
    let _ = shutdown.send(());
}

/// Generic rate-limiter clients keep publishing backend error text. The replay
/// policy must not leak onto them.
///
/// Handshake authentication failures are normalized by redis-rs, so exercise a
/// post-handshake command error where the server detail survives in `%error`.
#[tokio::test(flavor = "current_thread")]
async fn generic_redis_client_still_logs_backend_error_text() {
    let (port, _probes, shutdown) = spawn_logging_redis_server(LoggingShape::CommandError).await;
    let config = sentinel_replay_config(port);
    let (logs, guard) = super::plugin_utils::capture_logs();
    let client = RedisRateLimitClient::new(config, None, false, None)
        .expect("construction without a CA path must succeed");
    let _ = client
        .set_bytes_nx_with_expire("ferrum:replay:test-key", b"value", 60)
        .await;
    drop(guard);
    let captured = logs.contents();
    assert!(
        captured.contains(SENTINEL_CMD_ERR),
        "operational Redis clients must still log backend error text: {captured}"
    );
    let _ = shutdown.send(());
}

#[derive(Clone, Copy)]
enum MemoryInfoBehavior {
    Payload(&'static str),
    Raw(&'static str),
    Never,
    Sequence(&'static [&'static str]),
}

async fn spawn_memory_policy_redis(
    memory: MemoryInfoBehavior,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let screens = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let screens = Arc::clone(&screens);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            let chunk = &buf[..read];
                            let reply: Vec<u8> = if resp_contains(chunk, INFO_MEMORY_ARG) {
                                let index = screens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                match memory {
                                    MemoryInfoBehavior::Payload(text) => resp_bulk(text),
                                    MemoryInfoBehavior::Raw(raw) => raw.as_bytes().to_vec(),
                                    MemoryInfoBehavior::Never => continue,
                                    MemoryInfoBehavior::Sequence(texts) => {
                                        let text = texts
                                            .get(index)
                                            .copied()
                                            .unwrap_or(texts[texts.len() - 1]);
                                        resp_bulk(text)
                                    }
                                }
                            } else if resp_contains(chunk, INFO_CMD) {
                                resp_bulk(CLUSTER_DISABLED_INFO)
                            } else if let Some(reply) = replay_time_reply(chunk) {
                                reply
                            } else {
                                b"+OK\r\n".repeat(resp_command_count(chunk))
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx)
}

const MEMORY_UNLIMITED: &str = "# Memory\r\nmaxmemory:0\r\nmaxmemory_policy:allkeys-lru\r\n";
const MEMORY_NOEVICTION: &str = "# Memory\r\nmaxmemory:1048576\r\nmaxmemory_policy:noeviction\r\n";
const MEMORY_VOLATILE: &str = "# Memory\r\nmaxmemory:1048576\r\nmaxmemory_policy:volatile-lru\r\n";
const MEMORY_ALLKEYS: &str = "# Memory\r\nmaxmemory:1048576\r\nmaxmemory_policy:allkeys-lfu\r\n";
const MEMORY_MALFORMED: &str = "# Memory\r\nmaxmemory_human:1M\r\nused_memory:123\r\n";

#[tokio::test]
async fn replay_redis_accepts_unlimited_memory_or_noeviction() {
    let _serialized = shared_health_guard_async().await;
    for (label, payload) in [
        ("maxmemory-zero", MEMORY_UNLIMITED),
        ("noeviction", MEMORY_NOEVICTION),
    ] {
        let (port, shutdown) =
            spawn_memory_policy_redis(MemoryInfoBehavior::Payload(payload)).await;
        let client = claim_client(port, &format!("ferrum:replay_authority_tests:mem-{label}"));
        let authority = shared_live(Arc::clone(&client), RETENTION);
        wait_until_available(&client).await;
        assert!(
            !client.is_topology_unsupported(),
            "{label}: a safe memory policy is not terminal"
        );
        drop(authority);
        drop(client);
        let _ = shutdown.send(());
    }
}

#[tokio::test]
async fn replay_redis_rejects_an_evicting_policy_terminally() {
    let _serialized = shared_health_guard_async().await;
    for (label, payload) in [
        ("volatile-lru", MEMORY_VOLATILE),
        ("allkeys-lfu", MEMORY_ALLKEYS),
    ] {
        let (port, shutdown) =
            spawn_memory_policy_redis(MemoryInfoBehavior::Payload(payload)).await;
        let client = claim_client(
            port,
            &format!("ferrum:replay_authority_tests:evict-{label}"),
        );
        let authority = shared_live(Arc::clone(&client), RETENTION);
        wait_until(
            || client.is_topology_unsupported(),
            &format!("{label}: evicting policy must be terminal"),
        )
        .await;
        assert!(
            !client.is_available(),
            "{label}: an evicting policy must fail closed"
        );
        drop(authority);
        drop(client);
        let _ = shutdown.send(());
    }
}

#[tokio::test]
async fn replay_redis_treats_unproven_memory_policy_as_a_recoverable_outage() {
    let _serialized = shared_health_guard_async().await;
    for (label, behavior) in [
        ("malformed", MemoryInfoBehavior::Payload(MEMORY_MALFORMED)),
        (
            "acl",
            MemoryInfoBehavior::Raw(
                "-NOPERM this user has no permissions to run the 'info' command or its subcommand\r\n",
            ),
        ),
        ("timeout", MemoryInfoBehavior::Never),
    ] {
        let (port, shutdown) = spawn_memory_policy_redis(behavior).await;
        let client = claim_client(
            port,
            &format!("ferrum:replay_authority_tests:unproven-{label}"),
        );
        let authority = shared_live(Arc::clone(&client), RETENTION);
        for _ in 0..80 {
            assert!(
                !client.is_available(),
                "{label}: unproven memory policy must fail closed"
            );
            assert!(
                !client.is_topology_unsupported(),
                "{label}: unproven memory policy is recoverable, not terminal"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(authority);
        drop(client);
        let _ = shutdown.send(());
    }
}

#[tokio::test]
async fn replay_redis_recovers_after_an_unproven_memory_policy_screen() {
    let _serialized = shared_health_guard_async().await;
    let (port, shutdown) = spawn_memory_policy_redis(MemoryInfoBehavior::Sequence(&[
        MEMORY_MALFORMED,
        MEMORY_NOEVICTION,
    ]))
    .await;
    let client = claim_client_with_interval(port, "ferrum:replay_authority_tests:mem-recover", 1);
    let authority = shared_live(Arc::clone(&client), RETENTION);
    wait_until_available(&client).await;
    assert!(!client.is_topology_unsupported());
    drop(authority);
    drop(client);
    let _ = shutdown.send(());
}

#[tokio::test]
async fn replay_redis_does_not_recover_from_a_proven_evicting_policy() {
    let _serialized = shared_health_guard_async().await;
    let (port, shutdown) = spawn_memory_policy_redis(MemoryInfoBehavior::Sequence(&[
        MEMORY_VOLATILE,
        MEMORY_NOEVICTION,
    ]))
    .await;
    let client = claim_client(port, "ferrum:replay_authority_tests:mem-terminal");
    let authority = shared_live(Arc::clone(&client), RETENTION);
    wait_until(
        || client.is_topology_unsupported(),
        "evicting policy is terminal",
    )
    .await;
    for _ in 0..80 {
        assert!(
            !client.is_available(),
            "a later noeviction reply must not resurrect a proven-unsafe generation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(authority);
    drop(client);
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "current_thread")]
async fn replay_redis_memory_policy_logs_only_closed_set_classifications() {
    let _serialized = shared_health_guard_async().await;
    let (logs, guard) = super::plugin_utils::capture_logs();
    let (port, shutdown) =
        spawn_memory_policy_redis(MemoryInfoBehavior::Payload(MEMORY_VOLATILE)).await;
    let client = claim_client(port, "ferrum:replay_authority_tests:mem-log");
    let authority = shared_live(Arc::clone(&client), RETENTION);
    wait_until(
        || client.is_topology_unsupported(),
        "unsafe eviction classification",
    )
    .await;
    drop(guard);
    let captured = logs.contents();
    assert!(
        captured.contains("unsafe_eviction_policy"),
        "must publish the closed-set classification: {captured}"
    );
    assert!(
        !captured.contains("volatile-lru")
            && !captured.contains("maxmemory")
            && !captured.contains(MEMORY_VOLATILE),
        "must not log raw INFO text: {captured}"
    );
    drop(authority);
    drop(client);
    let _ = shutdown.send(());
}
