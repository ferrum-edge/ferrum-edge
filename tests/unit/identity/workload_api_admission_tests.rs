//! Workload API transport-admission policy (issue #3758).
//!
//! These pin the *decision* half of the admission boundary — the part a
//! single-uid test process cannot reach through real sockets, because it cannot
//! connect as a second user. The live half (real sockets, real gRPC, permit
//! release across every close path, bounded shutdown) is in
//! `tests/integration/workload_api_admission_tests.rs`.
//!
//! What is pinned here:
//!
//! - every limit is finite and has a hard ceiling that configuration cannot
//!   raise, and `0` is refused rather than meaning "unbounded";
//! - the per-UID quota is **strictly below** the global ceiling on both gates,
//!   so one UID can never hold the whole pool;
//! - the total ceiling admits exactly `N` and refuses `N + 1`;
//! - the per-UID quota refuses a saturated UID **while a different UID is still
//!   served**, both sequentially and under a concurrent burst — the fair-share
//!   property the whole per-UID bound exists for;
//! - a released permit returns capacity to both accountings;
//! - a connection's watchdog is cancelled when the connection is dropped, and a
//!   detached gate never force-closes;
//! - the packed liveness word transitions coherently and refreshes on reads;
//! - every pending write-side poll is woken and resolved by the force close;
//! - the same fair-share rule holds one layer up for **RPCs**: the service-wide
//!   ceiling admits exactly `N`, the per-UID quota sheds a saturated UID while a
//!   different UID keeps being served, shed RPCs leave no per-UID state behind,
//!   and both defaults are sized for legitimate long-lived stream occupancy;
//! - no admission permit or gate discloses a peer UID through `Debug`;
//! - the watchdog tick is a bounded fraction of the deadline it enforces rather
//!   than a fixed interval multiplied by the connection count;
//! - accept failures are classified and retried within a bounded backoff, and
//!   only a listener-invalid error terminates admission;
//! - the metric families the boundary exports carry a closed label set.

use ferrum_edge::identity::workload_api::admission::{
    DEFAULT_MAX_CONCURRENT_RPCS, DEFAULT_MAX_CONCURRENT_RPCS_PER_UID, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_UID, IDLE_TIMEOUT_CEILING, INITIAL_CONNECTION_TIMEOUT_CEILING,
    LONG_LIVED_RPCS_PER_CONNECTION, MAX_CONCURRENT_RPCS_CEILING,
    MAX_CONCURRENT_RPCS_PER_UID_CEILING, MAX_CONCURRENT_STREAMS_CEILING, MAX_CONNECTIONS_CEILING,
    MAX_CONNECTIONS_PER_UID_CEILING, MIN_MAX_CONCURRENT_RPCS, MIN_MAX_CONNECTIONS,
    SHUTDOWN_GRACE_CEILING, WATCHDOG_MAX_TICK, WATCHDOG_MIN_TICK, WATCHDOG_TICK_DIVISOR,
};
use ferrum_edge::identity::workload_api::{
    AcceptDecision, AcceptFailure, AcceptRetryPolicy, ConnectionActivity, ConnectionAdmission,
    RpcAdmission, WorkloadApiAdmissionConfig, close_reason, reject_reason, watchdog_tick,
};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Deadlines far enough out that a paused-clock test which yields many times
/// cannot trip one by accident; those tests are about cancellation and the
/// force-close channel, not about the deadlines.
fn long_lived_limits(max_connections: usize, max_per_uid: usize) -> WorkloadApiAdmissionConfig {
    WorkloadApiAdmissionConfig {
        initial_connection_timeout: Duration::from_secs(300),
        idle_timeout: Duration::from_secs(3600),
        ..limits(max_connections, max_per_uid)
    }
}

/// A configuration small enough to saturate deterministically.
///
/// `max_per_uid` must stay strictly below `max_connections`; a configuration
/// that does not is a fairness defect the gates refuse, and the tests that
/// exercise that refusal build it explicitly.
fn limits(max_connections: usize, max_per_uid: usize) -> WorkloadApiAdmissionConfig {
    WorkloadApiAdmissionConfig {
        max_connections,
        max_connections_per_uid: max_per_uid,
        ..WorkloadApiAdmissionConfig::default()
    }
}

#[test]
fn default_admission_limits_are_finite_and_within_every_ceiling() {
    let defaults = WorkloadApiAdmissionConfig::default();
    defaults
        .validate()
        .expect("the shipped defaults must themselves be acceptable configuration");

    assert!(defaults.max_connections > 0 && defaults.max_connections <= MAX_CONNECTIONS_CEILING);
    assert!(
        defaults.max_connections_per_uid > 0
            && defaults.max_connections_per_uid <= MAX_CONNECTIONS_PER_UID_CEILING
    );
    assert!(
        defaults.max_concurrent_streams > 0
            && defaults.max_concurrent_streams <= MAX_CONCURRENT_STREAMS_CEILING
    );
    assert!(
        defaults.max_concurrent_rpcs > 0
            && defaults.max_concurrent_rpcs <= MAX_CONCURRENT_RPCS_CEILING
    );
    assert!(
        !defaults.initial_connection_timeout.is_zero()
            && defaults.initial_connection_timeout <= INITIAL_CONNECTION_TIMEOUT_CEILING
    );
    assert!(!defaults.idle_timeout.is_zero() && defaults.idle_timeout <= IDLE_TIMEOUT_CEILING);
    assert!(
        !defaults.shutdown_grace.is_zero() && defaults.shutdown_grace <= SHUTDOWN_GRACE_CEILING
    );

    assert!(
        defaults.max_concurrent_rpcs_per_uid > 0
            && defaults.max_concurrent_rpcs_per_uid <= MAX_CONCURRENT_RPCS_PER_UID_CEILING
    );

    // The per-UID quotas must actually bind, or one peer can take the pool.
    assert!(
        defaults.max_connections_per_uid < defaults.max_connections,
        "the default per-UID quota must be strictly below the global ceiling"
    );
    assert!(
        defaults.max_concurrent_rpcs_per_uid < defaults.max_concurrent_rpcs,
        "the default per-UID RPC quota must be strictly below the service-wide ceiling"
    );
    // The keepalive derived from the idle deadline has to refresh it, or a
    // healthy long-lived rotation stream would be closed as idle.
    assert!(
        defaults.keepalive_interval() < defaults.idle_timeout,
        "keepalive must fire well inside the idle deadline"
    );
}

#[test]
fn zero_is_refused_for_every_limit_rather_than_meaning_unbounded() {
    let cases: [(&str, WorkloadApiAdmissionConfig); 8] = [
        (
            "MAX_CONNECTIONS",
            WorkloadApiAdmissionConfig {
                max_connections: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "MAX_CONNECTIONS_PER_UID",
            WorkloadApiAdmissionConfig {
                max_connections_per_uid: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "MAX_CONCURRENT_STREAMS",
            WorkloadApiAdmissionConfig {
                max_concurrent_streams: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "MAX_CONCURRENT_RPCS",
            WorkloadApiAdmissionConfig {
                max_concurrent_rpcs: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "MAX_CONCURRENT_RPCS_PER_UID",
            WorkloadApiAdmissionConfig {
                max_concurrent_rpcs_per_uid: 0,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "INITIAL_CONNECTION_TIMEOUT_SECONDS",
            WorkloadApiAdmissionConfig {
                initial_connection_timeout: Duration::ZERO,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "IDLE_TIMEOUT_SECONDS",
            WorkloadApiAdmissionConfig {
                idle_timeout: Duration::ZERO,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
        (
            "SHUTDOWN_GRACE_SECONDS",
            WorkloadApiAdmissionConfig {
                shutdown_grace: Duration::ZERO,
                ..WorkloadApiAdmissionConfig::default()
            },
        ),
    ];

    for (setting, config) in cases {
        let error = config
            .validate()
            .expect_err("zero must be refused, not read as unbounded")
            .to_string();
        assert!(
            error.contains(setting),
            "the diagnostic must name the setting the operator has to fix; got: {error}"
        );
    }
}

#[test]
fn an_over_ceiling_limit_is_refused_and_names_its_ceiling() {
    let error = WorkloadApiAdmissionConfig {
        max_connections: MAX_CONNECTIONS_CEILING + 1,
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("a soft limit may not be raised past the hard safety ceiling")
    .to_string();
    assert!(error.contains(&MAX_CONNECTIONS_CEILING.to_string()));

    let error = WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: MAX_CONCURRENT_RPCS_CEILING + 1,
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("the RPC ceiling is hard too")
    .to_string();
    assert!(error.contains(&MAX_CONCURRENT_RPCS_CEILING.to_string()));
}

#[test]
fn a_per_uid_quota_at_or_above_the_global_ceiling_is_refused() {
    // Not merely useless: an operator who wrote this believes they have a
    // per-principal bound and does not, which is precisely the posture this
    // issue is about.
    let error = limits(8, 9)
        .validate()
        .expect_err("a quota that can never bind is a misconfiguration")
        .to_string();
    assert!(error.contains("MAX_CONNECTIONS_PER_UID"));

    // Equality is refused just as firmly. A quota equal to the global ceiling
    // lets one UID hold every connection, which is exactly the "another UID
    // retains service" promise this bound is documented to keep.
    let error = limits(8, 8)
        .validate()
        .expect_err("a quota equal to the global ceiling is not a fair share")
        .to_string();
    assert!(error.contains("MAX_CONNECTIONS_PER_UID"));
    assert!(
        error.contains("strictly below"),
        "the diagnostic must say what the operator has to change; got: {error}"
    );

    // ...and the largest fair quota is admitted, so the rule is `<`, not `<=`
    // spelled pessimistically.
    limits(8, 7)
        .validate()
        .expect("a quota one below the global ceiling is the largest fair share");
}

#[test]
fn a_global_ceiling_below_the_fairness_floor_is_refused() {
    // With one total connection there is no fair share to hand out: whichever
    // UID connects first holds the entire pool. The floor is therefore two.
    let error = limits(1, 1)
        .validate()
        .expect_err("a single-connection pool cannot be fairly shared")
        .to_string();
    assert!(error.contains("MAX_CONNECTIONS"));
    assert!(error.contains(&MIN_MAX_CONNECTIONS.to_string()));

    limits(MIN_MAX_CONNECTIONS, 1)
        .validate()
        .expect("the smallest fair configuration is exactly the floor with a quota of one");
}

#[test]
fn an_idle_deadline_at_or_below_the_initial_one_is_refused() {
    let error = WorkloadApiAdmissionConfig {
        initial_connection_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(30),
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("an established connection must get more room than a silent one")
    .to_string();
    assert!(error.contains("IDLE_TIMEOUT_SECONDS"));
}

#[test]
fn clamping_enforces_the_ceilings_even_when_validation_is_bypassed() {
    // `validate` is the loud gate; this is the belt. A runtime reached another
    // way must still not exceed a ceiling.
    let clamped = WorkloadApiAdmissionConfig {
        max_connections: usize::MAX,
        max_connections_per_uid: usize::MAX,
        max_concurrent_streams: u32::MAX,
        max_concurrent_rpcs: usize::MAX,
        max_concurrent_rpcs_per_uid: usize::MAX,
        initial_connection_timeout: Duration::from_secs(u64::from(u32::MAX)),
        idle_timeout: Duration::from_secs(u64::from(u32::MAX)),
        shutdown_grace: Duration::from_secs(u64::from(u32::MAX)),
    }
    .clamped();

    assert_eq!(clamped.max_connections, MAX_CONNECTIONS_CEILING);
    assert_eq!(
        clamped.max_connections_per_uid,
        MAX_CONNECTIONS_PER_UID_CEILING
    );
    assert_eq!(
        clamped.max_concurrent_streams,
        MAX_CONCURRENT_STREAMS_CEILING
    );
    assert_eq!(clamped.max_concurrent_rpcs, MAX_CONCURRENT_RPCS_CEILING);
    assert_eq!(
        clamped.max_concurrent_rpcs_per_uid,
        MAX_CONCURRENT_RPCS_PER_UID_CEILING
    );
    assert_eq!(
        clamped.initial_connection_timeout,
        INITIAL_CONNECTION_TIMEOUT_CEILING
    );
    assert_eq!(clamped.idle_timeout, IDLE_TIMEOUT_CEILING);
    assert_eq!(clamped.shutdown_grace, SHUTDOWN_GRACE_CEILING);

    // The clamp preserves the fairness invariant even against an over-ceiling
    // quota: 1024 is strictly below 4096, so one UID still cannot take the pool.
    assert!(clamped.max_connections_per_uid < clamped.max_connections);
    assert!(clamped.max_concurrent_rpcs_per_uid < clamped.max_concurrent_rpcs);

    // Zero clamps up to a finite floor rather than down to "unbounded", and the
    // floor is the smallest *fair* configuration rather than `1 / 1`.
    let floor = WorkloadApiAdmissionConfig {
        max_connections: 0,
        max_connections_per_uid: 0,
        max_concurrent_streams: 0,
        max_concurrent_rpcs: 0,
        max_concurrent_rpcs_per_uid: 0,
        initial_connection_timeout: Duration::ZERO,
        idle_timeout: Duration::ZERO,
        shutdown_grace: Duration::ZERO,
    }
    .clamped();
    assert_eq!(floor.max_connections, MIN_MAX_CONNECTIONS);
    assert_eq!(floor.max_connections_per_uid, 1);
    assert_eq!(floor.max_concurrent_streams, 1);
    assert_eq!(floor.max_concurrent_rpcs, MIN_MAX_CONCURRENT_RPCS);
    assert_eq!(floor.max_concurrent_rpcs_per_uid, 1);
    assert_eq!(floor.initial_connection_timeout, Duration::from_secs(1));
    assert_eq!(floor.idle_timeout, Duration::from_secs(1));
    assert_eq!(floor.shutdown_grace, Duration::from_secs(1));
}

#[test]
fn clamping_never_produces_a_quota_that_can_take_the_whole_pool() {
    // The belt has to hold for *every* input, not just the ones `validate`
    // would have caught: a runtime reached another way must still leave a
    // second UID somewhere to go.
    for max_connections in [0usize, 1, 2, 3, 7, 256, MAX_CONNECTIONS_CEILING, usize::MAX] {
        for max_connections_per_uid in [
            0usize,
            1,
            2,
            max_connections,
            max_connections.saturating_add(1),
            MAX_CONNECTIONS_PER_UID_CEILING,
            usize::MAX,
        ] {
            let clamped = limits(max_connections, max_connections_per_uid).clamped();
            assert!(
                clamped.max_connections >= MIN_MAX_CONNECTIONS,
                "a fair pool needs room for at least two connections, got {clamped:?}"
            );
            assert!(
                clamped.max_connections_per_uid >= 1,
                "a quota of zero would refuse every peer, got {clamped:?}"
            );
            assert!(
                clamped.max_connections_per_uid < clamped.max_connections,
                "clamping must never let one UID hold the whole pool, got {clamped:?}"
            );
            clamped.validate().expect(
                "a clamped configuration must itself be acceptable configuration; otherwise the \
                 defensive path and the loud gate disagree about what a bounded transport is",
            );
        }
    }
}

#[test]
fn a_constructed_admission_gate_never_exceeds_a_ceiling() {
    let admission = ConnectionAdmission::detached(WorkloadApiAdmissionConfig {
        max_connections: MAX_CONNECTIONS_CEILING * 4,
        max_connections_per_uid: MAX_CONNECTIONS_PER_UID_CEILING * 4,
        ..WorkloadApiAdmissionConfig::default()
    });
    assert_eq!(admission.limits().max_connections, MAX_CONNECTIONS_CEILING);
    assert_eq!(
        admission.limits().max_connections_per_uid,
        MAX_CONNECTIONS_PER_UID_CEILING
    );
}

#[test]
fn the_total_ceiling_admits_exactly_n_and_refuses_n_plus_one() {
    const TOTAL: usize = 4;
    // Per-UID raised to the largest *fair* value — one below the total — so this
    // test isolates the global bound. It cannot be raised to the total itself:
    // that is the configuration the fairness gate refuses, and it is also why
    // the live suite cannot saturate the global ceiling from one UID.
    let policy = limits(TOTAL, TOTAL - 1);
    policy
        .validate()
        .expect("the largest fair quota is acceptable configuration");
    let admission = ConnectionAdmission::detached(policy);

    let mut held = Vec::new();
    for index in 0..TOTAL {
        // Distinct uids so the per-UID quota cannot be what is being observed.
        held.push(
            admission
                .reserve(1000 + index as u32)
                .expect("every connection up to the ceiling is admitted"),
        );
    }
    assert_eq!(admission.active_connections(), TOTAL);
    assert!(
        admission.reserve(2000).is_none(),
        "connection N+1 must be refused rather than admitted or queued"
    );

    // Release one and prove capacity actually came back, which is the property
    // a leak on any close path would break.
    held.pop();
    assert_eq!(admission.active_connections(), TOTAL - 1);
    let recovered = admission
        .reserve(2000)
        .expect("a released permit returns capacity to the global pool");
    drop(recovered);
    drop(held);
    assert_eq!(admission.active_connections(), 0);
}

#[test]
fn a_saturated_uid_is_refused_while_a_different_uid_is_still_served() {
    // The whole point of the per-UID bound: one compromised socket-group member
    // must not be able to deny identity service to the rest of the node.
    const TOTAL: usize = 8;
    const PER_UID: usize = 2;
    let admission = ConnectionAdmission::detached(limits(TOTAL, PER_UID));

    let hostile: Vec<_> = (0..PER_UID)
        .map(|_| {
            admission
                .reserve(1000)
                .expect("a peer may use its own quota in full")
        })
        .collect();
    assert!(
        admission.reserve(1000).is_none(),
        "the peer's next connection must be refused at its quota"
    );

    let neighbour = admission
        .reserve(1001)
        .expect("a different UID must still be served while another UID is saturated");
    assert_eq!(admission.active_connections(), PER_UID + 1);

    // The refusal must not have consumed a global slot either: a per-UID
    // refusal that leaked the total permit would turn a per-principal bound
    // into a global denial-of-service primitive.
    let mut remaining = Vec::new();
    for _ in 0..(TOTAL - PER_UID - 1) {
        remaining.push(
            admission
                .reserve(1002)
                .or_else(|| admission.reserve(1003))
                .or_else(|| admission.reserve(1004))
                .or_else(|| admission.reserve(1005))
                .expect("global capacity is intact after per-UID refusals"),
        );
    }
    assert_eq!(admission.active_connections(), TOTAL);

    drop(hostile);
    drop(neighbour);
    drop(remaining);
    assert_eq!(admission.active_connections(), 0);

    // And the saturated UID is served again once it releases.
    assert!(admission.reserve(1000).is_some());
}

#[test]
fn repeated_refusals_do_not_grow_per_uid_state() {
    // A refused uid must not leave an accounting entry behind, or a probing
    // flood from many uids would itself be an unbounded allocation.
    let admission = ConnectionAdmission::detached(limits(2, 1));
    let held = vec![
        admission.reserve(1000).expect("first is admitted"),
        admission.reserve(1001).expect("second is admitted"),
    ];
    for uid in 0..5_000u32 {
        // The pool is full, so every one of these is refused. None may leave an
        // accounting entry behind.
        assert!(admission.reserve(uid).is_none());
    }
    drop(held);
    assert_eq!(
        admission.active_connections(),
        0,
        "no refused or released reservation may remain charged"
    );
}

#[test]
fn admission_reason_labels_are_a_closed_compile_time_set() {
    // Fixed-cardinality contract: these are the only values that can appear in
    // the `reason` dimension, and none of them is derived from anything a peer
    // controls (no UID, PID, SPIFFE ID, or token material).
    let reject = [
        reject_reason::PEER_CREDENTIALS,
        reject_reason::MAX_CONNECTIONS,
        reject_reason::MAX_CONNECTIONS_PER_UID,
        reject_reason::SHUTTING_DOWN,
    ];
    let close = [
        close_reason::INITIAL_TIMEOUT,
        close_reason::IDLE_TIMEOUT,
        close_reason::SHUTDOWN_DEADLINE,
    ];
    for reason in reject.iter().chain(close.iter()) {
        assert!(
            reason
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "a reason label must be a stable snake_case constant, got {reason}"
        );
    }
    let mut all: Vec<&str> = reject.iter().chain(close.iter()).copied().collect();
    all.sort_unstable();
    let before = all.len();
    all.dedup();
    assert_eq!(before, all.len(), "reason constants must be distinct");
}

#[test]
fn a_concurrent_burst_from_a_saturated_uid_never_denies_an_independent_uid() {
    // The ordering regression this pins is invisible to a sequential test.
    //
    // If `reserve` took the *global* permit before checking the per-UID quota,
    // every one of the hammering threads below would hold one of the remaining
    // global slots while it queued for the per-UID lock — and for as long as
    // that queue drained, the shared pool would read as empty and the innocent
    // UIDs would be refused with `max_connections`. The quota would then be a
    // denial-of-service primitive rather than a fair share.
    //
    // With the quota judged first, under the same lock, an over-quota caller
    // never touches the global semaphore at all, so the assertion below is an
    // invariant rather than a race the test hopes to win.
    const TOTAL: usize = 8;
    const HOSTILE_QUOTA: usize = 4;
    const HOSTILE_UID: u32 = 1000;
    const HAMMER_THREADS: usize = 4;
    const ROUNDS: usize = 300;

    let admission = ConnectionAdmission::detached(limits(TOTAL, HOSTILE_QUOTA));
    // The hostile UID holds its full quota for the whole test, so every further
    // attempt from it must be refused on the quota, never on the global pool.
    let _hostile_held: Vec<_> = (0..HOSTILE_QUOTA)
        .map(|_| {
            admission
                .reserve(HOSTILE_UID)
                .expect("a peer may use its own quota in full")
        })
        .collect();

    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..HAMMER_THREADS {
            let hammer = admission.clone();
            let stop = &stop;
            scope.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    assert!(
                        hammer.reserve(HOSTILE_UID).is_none(),
                        "a UID at its quota must be refused, never admitted"
                    );
                    std::thread::yield_now();
                }
            });
        }

        for round in 0..ROUNDS {
            // Take *every* remaining global slot with independent UIDs. Under
            // the defective ordering the hammering threads hold some of these
            // transiently and at least one of these reservations fails.
            let mut innocent = Vec::with_capacity(TOTAL - HOSTILE_QUOTA);
            for slot in 0..(TOTAL - HOSTILE_QUOTA) {
                let Some(permit) = admission.reserve(2000 + slot as u32) else {
                    // Let the hammering threads finish before unwinding.
                    stop.store(true, Ordering::Relaxed);
                    panic!(
                        "round {round}: an independent UID was refused while a different UID was \
                         merely being refused at its own quota; a per-UID refusal must not consume \
                         global capacity, even transiently"
                    );
                };
                innocent.push(permit);
            }
            drop(innocent);
        }
        stop.store(true, Ordering::Relaxed);
    });

    assert_eq!(
        admission.active_connections(),
        HOSTILE_QUOTA,
        "only the hostile UID's own held permits may remain charged"
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_a_connection_cancels_its_watchdog_rather_than_leaving_it_asleep() {
    // Connection concurrency is bounded by the admission ceiling; connection
    // *churn* is not. A watchdog that only noticed its connection had gone on
    // its next tick would let arbitrarily many detached tasks accumulate, each
    // asleep for up to a second. The guard has to cancel it at drop.
    let admission = ConnectionAdmission::detached(long_lived_limits(8, 4));
    let (activity, watchdog) = admission.start_watchdog();
    let observer = watchdog.abort_handle();
    tokio::task::yield_now().await;
    assert!(
        !observer.is_finished(),
        "the watchdog must run for as long as its connection is alive"
    );

    drop(watchdog);
    drop(activity);

    // The clock is paused, so nothing here can be satisfied by a tick elapsing:
    // the only way this loop finishes is an actual cancellation.
    for _ in 0..64 {
        if observer.is_finished() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("dropping the connection must cancel its watchdog immediately, not on its next tick");
}

#[tokio::test(start_paused = true)]
async fn a_detached_gate_never_force_closes_the_connections_it_admits() {
    // `detached` promises a gate that never force-closes because nothing will
    // signal it. Dropping the sender in the constructor breaks that promise in
    // the most direct way possible: a closed force-close channel is exactly the
    // shutdown signal the watchdog acts on, so every admitted connection would
    // be force-closed because the constructor returned.
    let admission = ConnectionAdmission::detached(long_lived_limits(8, 4));
    let (activity, watchdog) = admission.start_watchdog();
    // Dropped deliberately: the connection, not the gate, is what must keep the
    // channel open, or a caller that retained only its connections would still
    // see them torn down.
    drop(admission);

    for _ in 0..256 {
        tokio::task::yield_now().await;
        assert!(
            !activity.is_closed(),
            "a detached gate must never force-close a connection"
        );
    }
    drop(watchdog);
}

#[tokio::test]
async fn a_stream_admitted_through_a_detached_gate_still_carries_traffic() {
    // The same regression as above, observed the way a real peer would: bytes
    // in, bytes out. Under a dropped force-close sender the first watchdog poll
    // aborts the connection and this read fails with `ConnectionAborted`.
    let admission = ConnectionAdmission::detached(limits(8, 4));
    let (mut peer, gateway_side) = tokio::io::duplex(64);
    let mut admitted = admission
        .admit_io(1000, gateway_side)
        .expect("a fresh gate admits the first connection");

    // Give the watchdog every chance to have run before the first byte moves.
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    peer.write_all(b"hello").await.expect("the peer writes");
    let mut buffer = [0u8; 5];
    admitted
        .read_exact(&mut buffer)
        .await
        .expect("an admitted connection is readable, not force-closed by its own constructor");
    assert_eq!(&buffer, b"hello");
    assert!(!admitted.activity().is_closed());
}

#[tokio::test(start_paused = true)]
async fn the_liveness_word_is_coherent_and_every_read_refreshes_the_deadline() {
    // The flag that selects which deadline applies and the timestamp it is
    // compared against live in one atomic word, so a watchdog can never observe
    // "the peer has spoken" without the timestamp that says when — the shape
    // that closes an actively-read connection on a weakly ordered CPU.
    let activity = ConnectionActivity::new();

    let observed = activity.snapshot();
    assert!(!observed.saw_first_read);
    assert!(observed.since_last_read < Duration::from_millis(50));

    tokio::time::advance(Duration::from_secs(5)).await;
    let observed = activity.snapshot();
    assert!(
        !observed.saw_first_read,
        "a connection that has said nothing is still on its initial deadline"
    );
    assert!(observed.since_last_read >= Duration::from_secs(5));

    activity.mark_read();
    let observed = activity.snapshot();
    assert!(observed.saw_first_read);
    assert!(
        observed.since_last_read < Duration::from_millis(50),
        "the first read must publish its own timestamp, not leave a stale one behind"
    );

    tokio::time::advance(Duration::from_secs(3)).await;
    let observed = activity.snapshot();
    assert!(
        observed.saw_first_read,
        "the first-read flag can never be lost once set"
    );
    assert!(observed.since_last_read >= Duration::from_secs(3));

    // A subsequent read refreshes the idle deadline coherently too.
    activity.mark_read();
    let observed = activity.snapshot();
    assert!(observed.saw_first_read);
    assert!(observed.since_last_read < Duration::from_millis(50));

    // And the close is published exactly once, however many paths reach it.
    assert!(activity.force_close(), "the first close wins");
    assert!(
        !activity.force_close(),
        "a second close must not be counted again"
    );
    assert!(activity.is_closed());
}

/// An inner I/O that is never ready, so every poll of the wrapper takes its
/// `Pending` branch and the wrapper's own waker discipline is what is observed.
struct NeverReadyIo;

impl AsyncRead for NeverReadyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for NeverReadyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[derive(Default)]
struct CountingWaker {
    wakes: AtomicUsize,
}

impl CountingWaker {
    fn wakes(&self) -> usize {
        self.wakes.load(Ordering::SeqCst)
    }
}

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn every_pending_write_side_poll_is_woken_and_resolved_by_the_force_close() {
    // `poll_write` registering the waker is not enough. A connection parked in
    // `poll_flush` or `poll_shutdown` on a peer that has stopped reading is
    // exactly the connection the bounded shutdown has to reach, and a delegated
    // `Pending` registers only the *inner* socket's waker — which nothing wakes.
    let admission = ConnectionAdmission::detached(limits(8, 4));

    // Flush: the force close has to reach it, and it reports the abort.
    {
        let mut admitted = admission
            .admit_io(1000, NeverReadyIo)
            .expect("the gate has capacity");
        let counter = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);

        assert!(
            Pin::new(&mut admitted).poll_flush(&mut cx).is_pending(),
            "an inner I/O that is never ready must park"
        );
        assert_eq!(counter.wakes(), 0, "nothing has happened yet");

        assert!(admitted.activity().force_close(), "this is the first close");
        assert!(
            counter.wakes() >= 1,
            "a parked flush must be woken by the force close, or the connection waits for a peer \
             that is never going to speak"
        );

        match Pin::new(&mut admitted).poll_flush(&mut cx) {
            Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted),
            other => panic!("a force-closed flush must abort, got {other:?}"),
        }
    }

    // Shutdown: woken the same way, but it completes with success — a shutdown
    // racing the force close must finish, not hand the caller an error it
    // cannot act on.
    {
        let mut admitted = admission
            .admit_io(1001, NeverReadyIo)
            .expect("the gate has capacity");
        let counter = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);

        assert!(
            Pin::new(&mut admitted).poll_shutdown(&mut cx).is_pending(),
            "an inner I/O that is never ready must park"
        );
        assert_eq!(counter.wakes(), 0, "nothing has happened yet");

        assert!(admitted.activity().force_close(), "this is the first close");
        assert!(
            counter.wakes() >= 1,
            "a parked shutdown must be woken by the force close"
        );

        match Pin::new(&mut admitted).poll_shutdown(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("shutdown after a force close must report success, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_write_parked_before_the_force_close_is_woken_and_then_aborts() {
    let admission = ConnectionAdmission::detached(limits(8, 4));
    let mut admitted = admission
        .admit_io(1000, NeverReadyIo)
        .expect("the gate has capacity");
    let counter = Arc::new(CountingWaker::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);

    let parked = Pin::new(&mut admitted).poll_write(&mut cx, b"x");
    assert!(parked.is_pending());
    assert!(admitted.activity().force_close());
    assert!(counter.wakes() >= 1);
    match Pin::new(&mut admitted).poll_write(&mut cx, b"x") {
        Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted),
        other => panic!("a force-closed write must abort, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn accept_failures_are_classified_by_what_they_mean_for_the_listener() {
    use ferrum_edge::identity::workload_api::classify_accept_error;

    for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
        assert_eq!(
            classify_accept_error(&io::Error::from_raw_os_error(code)),
            AcceptFailure::Resource,
            "errno {code} is an exhaustion that persists until capacity is released"
        );
    }
    for code in [libc::ECONNABORTED, libc::EINTR, libc::EAGAIN] {
        assert_eq!(
            classify_accept_error(&io::Error::from_raw_os_error(code)),
            AcceptFailure::Transient,
            "errno {code} is a per-connection event, not a broken listener"
        );
    }
    for code in [
        libc::EBADF,
        libc::EINVAL,
        libc::ENOTSOCK,
        libc::EOPNOTSUPP,
        libc::ENOTSUP,
    ] {
        assert_eq!(
            classify_accept_error(&io::Error::from_raw_os_error(code)),
            AcceptFailure::Fatal,
            "errno {code} means the listener itself is unusable and retrying is a spin"
        );
    }
    // An error carrying no OS code is not one of the enumerated recoverable
    // conditions, so it fails closed onto termination rather than into a loop.
    assert_eq!(
        classify_accept_error(&io::Error::other("synthetic")),
        AcceptFailure::Fatal
    );

    // Everything else is `Resource`, and that direction is the load-bearing
    // one: `Fatal` tears down the whole mesh runtime's identity surface, so it
    // may not be the default arm for an errno nobody enumerated. `EPERM` is the
    // concrete case — a firewall or LSM hook can return it *per connection*
    // while the listener stays perfectly valid, so classifying it fatal would
    // let one rejected peer end identity service for the node.
    for code in [
        libc::EPERM,
        libc::EACCES,
        libc::ENETDOWN,
        libc::EHOSTUNREACH,
        libc::ENOSPC,
    ] {
        assert_eq!(
            classify_accept_error(&io::Error::from_raw_os_error(code)),
            AcceptFailure::Resource,
            "errno {code} does not say the listener is broken, so it must back off rather than \
             terminate the Workload API surface"
        );
    }
    // And an errno from no enumerated set at all still backs off rather than
    // terminating. 4093 is not a POSIX errno on any supported platform.
    assert_eq!(
        classify_accept_error(&io::Error::from_raw_os_error(4093)),
        AcceptFailure::Resource,
        "an unrecognized errno must be retried behind the bounded backoff, never treated as a \
         broken listener"
    );
}

#[test]
fn the_accept_retry_policy_backs_off_within_a_bound_and_terminates_on_a_fatal_error() {
    let mut policy = AcceptRetryPolicy::new();

    // A fatal failure ends admission. This is the *decision* only: what turns it
    // into a bounded termination is the accept loop raising the fatal signal and
    // the serve task draining on it, which is a lifecycle this pure state
    // machine cannot observe and does not claim — it is pinned live in
    // `tests/integration/workload_api_admission_tests.rs`
    // (`a_fatal_accept_terminates_the_listener_...`).
    assert_eq!(
        policy.on_error(AcceptFailure::Fatal),
        AcceptDecision::Terminate
    );

    // A short run of transient failures retries at once — that is what an
    // accept loop is supposed to do about a peer that went away.
    let mut policy = AcceptRetryPolicy::new();
    for _ in 0..8 {
        match policy.on_error(AcceptFailure::Transient) {
            AcceptDecision::Retry { backoff, .. } => assert_eq!(backoff, Duration::ZERO),
            AcceptDecision::Terminate => panic!("a transient failure is retryable"),
        }
    }
    // A run long enough to look like a spin is backed off instead.
    match policy.on_error(AcceptFailure::Transient) {
        AcceptDecision::Retry { backoff, .. } => assert!(backoff > Duration::ZERO),
        AcceptDecision::Terminate => panic!("a transient failure is retryable"),
    }

    // Exhaustion backs off from the first occurrence, grows, and saturates —
    // bounded CPU while the condition lasts, and a bounded log rate with it.
    let mut policy = AcceptRetryPolicy::new();
    let mut logged = 0usize;
    let mut previous = Duration::ZERO;
    for attempt in 1..=200u32 {
        match policy.on_error(AcceptFailure::Resource) {
            AcceptDecision::Retry { backoff, log } => {
                assert!(backoff > Duration::ZERO, "attempt {attempt} must pause");
                assert!(
                    backoff <= Duration::from_secs(1),
                    "attempt {attempt} must stay inside the backoff ceiling"
                );
                assert!(backoff >= previous, "the backoff must not shrink mid-run");
                previous = backoff;
                if log {
                    logged += 1;
                }
            }
            AcceptDecision::Terminate => panic!("exhaustion is retryable, not fatal"),
        }
    }
    assert!(
        logged <= 12,
        "a persistent exhaustion must not emit one warning per retry; that is itself a \
         disk-exhaustion primitive. Logged {logged} of 200"
    );
    assert!(logged >= 1, "the run must still be visible at all");
    assert_eq!(policy.consecutive_failures(), 200);

    // A successful accept clears the run, so an isolated later failure does not
    // inherit an old backoff.
    policy.on_accepted();
    assert_eq!(policy.consecutive_failures(), 0);
    match policy.on_error(AcceptFailure::Transient) {
        AcceptDecision::Retry { backoff, .. } => assert_eq!(backoff, Duration::ZERO),
        AcceptDecision::Terminate => panic!("a transient failure is retryable"),
    }
}

/// Rejection logs must never emit a structured `peer_uid =` field: the kernel-
/// attested UID is credential-adjacent metadata and the universal security rule
/// forbids logging it unredacted (or hashed/encoded). Keep this as a static
/// source guard so a future edit cannot reintroduce the field without failing CI.
#[test]
fn admission_rejection_logs_omit_peer_uid_structured_field() {
    let source = include_str!("../../../src/identity/workload_api/admission.rs");
    assert!(
        !source.contains("peer_uid ="),
        "Workload API admission must not log a peer_uid structured field; rejection \
         debug logs may carry only fixed reason/limit context"
    );
}

#[test]
fn the_rpc_defaults_are_sized_for_legitimate_long_lived_stream_occupancy() {
    // The RPC permit is held for the whole life of a *response stream*, not for
    // the duration of a method call, so the ceiling has to be sized against how
    // many streams a well-behaved client keeps open — not against request rate.
    // A default below that would make the shipped configuration contradict
    // itself: the connection ceiling would admit peers the RPC ceiling then had
    // to shed, and the shed would land on SVID renewal rather than on anything
    // abusive.
    const {
        assert!(
            DEFAULT_MAX_CONCURRENT_RPCS >= DEFAULT_MAX_CONNECTIONS * LONG_LIVED_RPCS_PER_CONNECTION,
            "the service-wide RPC default must cover the legitimate long-lived streams on every \
             admitted default connection"
        );
        assert!(
            DEFAULT_MAX_CONCURRENT_RPCS_PER_UID
                >= DEFAULT_MAX_CONNECTIONS_PER_UID * LONG_LIVED_RPCS_PER_CONNECTION,
            "the per-UID RPC default must cover the legitimate long-lived streams on every \
             default connection admitted for one UID"
        );
    }
}

#[test]
fn a_per_uid_rpc_quota_at_or_above_the_service_ceiling_is_refused() {
    // The same fairness rule as for connections, one layer up — and it is the
    // layer that actually matters for identity service, because the bundle RPCs
    // need only the mandatory metadata header, no attestation and no
    // entitlement, to occupy a permit.
    let error = WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: 8,
        max_concurrent_rpcs_per_uid: 8,
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("a per-UID RPC quota equal to the service ceiling is not a fair share")
    .to_string();
    assert!(error.contains("MAX_CONCURRENT_RPCS_PER_UID"));
    assert!(
        error.contains("strictly below"),
        "the diagnostic must say what the operator has to change; got: {error}"
    );

    // The largest fair quota is admitted, so the rule is `<` rather than `<=`
    // spelled pessimistically.
    WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: 8,
        max_concurrent_rpcs_per_uid: 7,
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect("a quota one below the service ceiling is the largest fair share");

    // And a service-wide ceiling of one cannot express a fair share at all.
    let error = WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: 1,
        max_concurrent_rpcs_per_uid: 1,
        ..WorkloadApiAdmissionConfig::default()
    }
    .validate()
    .expect_err("a single-RPC service cannot be fairly shared")
    .to_string();
    assert!(error.contains("MAX_CONCURRENT_RPCS"));
    assert!(error.contains(&MIN_MAX_CONCURRENT_RPCS.to_string()));
}

#[test]
fn rpc_clamping_never_produces_a_quota_that_can_take_every_permit() {
    for max_concurrent_rpcs in [
        0usize,
        1,
        2,
        3,
        512,
        MAX_CONCURRENT_RPCS_CEILING,
        usize::MAX,
    ] {
        for max_concurrent_rpcs_per_uid in [
            0usize,
            1,
            max_concurrent_rpcs,
            max_concurrent_rpcs.saturating_add(1),
            MAX_CONCURRENT_RPCS_PER_UID_CEILING,
            usize::MAX,
        ] {
            let clamped = WorkloadApiAdmissionConfig {
                max_concurrent_rpcs,
                max_concurrent_rpcs_per_uid,
                ..WorkloadApiAdmissionConfig::default()
            }
            .clamped();
            assert!(clamped.max_concurrent_rpcs >= MIN_MAX_CONCURRENT_RPCS);
            assert!(clamped.max_concurrent_rpcs_per_uid >= 1);
            assert!(
                clamped.max_concurrent_rpcs_per_uid < clamped.max_concurrent_rpcs,
                "clamping must never let one UID hold every RPC permit, got {clamped:?}"
            );
            clamped
                .validate()
                .expect("a clamped configuration must itself be acceptable configuration");
        }
    }
}

#[test]
fn the_service_wide_rpc_ceiling_admits_exactly_n_and_refuses_n_plus_one() {
    const TOTAL: usize = 4;
    let admission = RpcAdmission::new(&WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: TOTAL,
        // The largest fair quota, so this test isolates the service-wide bound.
        max_concurrent_rpcs_per_uid: TOTAL - 1,
        ..WorkloadApiAdmissionConfig::default()
    });

    let mut held = Vec::new();
    for index in 0..TOTAL {
        // Distinct uids so the per-UID quota cannot be what is observed.
        held.push(
            admission
                .reserve(1000 + index as u32)
                .expect("every RPC up to the ceiling is admitted"),
        );
    }
    assert_eq!(admission.active_rpcs(), TOTAL);
    assert!(
        admission.reserve(2000).is_none(),
        "RPC N+1 must be shed rather than queued behind the ceiling"
    );

    held.pop();
    assert_eq!(admission.active_rpcs(), TOTAL - 1);
    let recovered = admission
        .reserve(2000)
        .expect("a dropped permit returns capacity to the service-wide pool");
    drop(recovered);
    drop(held);
    assert_eq!(admission.active_rpcs(), 0);
}

#[test]
fn a_saturated_uid_is_shed_while_a_different_uid_still_gets_rpcs() {
    // The finding this closes: with only a per-connection quota, one
    // socket-group UID can hold 32 connections x 64 streams and occupy every
    // service-wide RPC permit — using bundle RPCs, which need no attestation —
    // so no other workload on the node can renew its SVID.
    const TOTAL: usize = 8;
    const PER_UID: usize = 2;
    let admission = RpcAdmission::new(&WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: TOTAL,
        max_concurrent_rpcs_per_uid: PER_UID,
        ..WorkloadApiAdmissionConfig::default()
    });

    let hostile: Vec<_> = (0..PER_UID)
        .map(|_| {
            admission
                .reserve(1000)
                .expect("a peer may use its own RPC quota in full")
        })
        .collect();
    assert!(
        admission.reserve(1000).is_none(),
        "a UID at its quota is shed even though the service-wide pool has room"
    );
    assert!(
        admission.active_rpcs() < TOTAL,
        "the service-wide pool must still have room, or this proves nothing"
    );

    // The property that matters: an innocent peer keeps being served.
    let innocent = admission
        .reserve(2000)
        .expect("a different peer UID must still obtain identity service");

    drop(hostile);
    admission
        .reserve(1000)
        .expect("releasing a permit returns the quota to its own UID");
    drop(innocent);
}

#[test]
fn shed_rpcs_do_not_grow_per_uid_state() {
    // A refused RPC must leave no accounting entry behind, or a probing flood
    // from many uids is itself an unbounded allocation — and an RPC flood is
    // cheaper to mount than a connection flood, since many RPCs ride one socket.
    let admission = RpcAdmission::new(&WorkloadApiAdmissionConfig {
        max_concurrent_rpcs: 2,
        max_concurrent_rpcs_per_uid: 1,
        ..WorkloadApiAdmissionConfig::default()
    });
    let held = vec![
        admission.reserve(1000).expect("first is admitted"),
        admission.reserve(1001).expect("second is admitted"),
    ];
    for uid in 0..5_000u32 {
        assert!(admission.reserve(uid).is_none());
    }
    drop(held);
    assert_eq!(
        admission.active_rpcs(),
        0,
        "no shed or released reservation may remain charged"
    );
    // Every entry is gone with its last permit, so the map is bounded by peers
    // currently holding permits rather than by peers ever seen.
    let rendered = format!("{admission:?}");
    assert!(
        !rendered.contains("1000") && !rendered.contains("1001"),
        "the gate's Debug rendering must not disclose peer UIDs: {rendered}"
    );
}

#[test]
fn permit_and_gate_debug_renderings_disclose_no_peer_identity() {
    // A kernel-attested peer UID is a principal identifier, and the live
    // per-UID map is the node's whole Workload API client census. A derived
    // `Debug` would put both into any diagnostic that renders a permit with
    // `{:?}`, which is exactly what the metric-label and log rules forbid.
    const UID: u32 = 4242;
    let connections = ConnectionAdmission::detached(limits(4, 2));
    let connection_permit = connections
        .reserve(UID)
        .expect("the first connection for this uid is admitted");
    let rpcs = RpcAdmission::new(&WorkloadApiAdmissionConfig::default());
    let rpc_permit = rpcs.reserve(UID).expect("the first RPC is admitted");

    for rendered in [
        format!("{connection_permit:?}"),
        format!("{rpc_permit:?}"),
        format!("{connections:?}"),
        format!("{rpcs:?}"),
    ] {
        assert!(
            !rendered.contains(&UID.to_string()),
            "no admission rendering may disclose a peer UID: {rendered}"
        );
        // The map itself is behind an `Arc<Mutex<..>>`, so its rendering is
        // unmistakable: a derived `Debug` prints the mutex wrapper and every
        // live entry with it.
        assert!(
            !rendered.contains("Mutex") && !rendered.contains("=>"),
            "no admission rendering may expose the per-UID accounting map: {rendered}"
        );
    }

    // A static guard as well, so a future `#[derive(Debug)]` cannot reintroduce
    // the disclosure while the value-based assertions above happen to pass on
    // whatever uid the test picked.
    let source = include_str!("../../../src/identity/workload_api/admission.rs");
    for derived in [
        "#[derive(Debug)]\npub struct ConnectionPermit",
        "#[derive(Debug)]\npub struct RpcPermit",
        "#[derive(Debug)]\npub struct RpcAdmission",
    ] {
        assert!(
            !source.contains(derived),
            "a derived Debug on a UID-bearing admission type renders the peer UID and the live \
             per-UID map: {derived}"
        );
    }
}

#[test]
fn the_watchdog_tick_scales_with_the_deadline_it_enforces() {
    // A fixed one-second tick is a per-connection cost: at the 4096-connection
    // hard ceiling it is 4096 wakeups a second to enforce deadlines measured in
    // seconds and minutes. The derivation is therefore a bounded *fraction* of
    // the shorter deadline rather than a constant.
    let shipped = WorkloadApiAdmissionConfig::default();
    let shipped_deadline = shipped.initial_connection_timeout.min(shipped.idle_timeout);
    assert_eq!(
        watchdog_tick(&shipped),
        shipped_deadline / WATCHDOG_TICK_DIVISOR,
        "at the shipped defaults the tick is a quarter of the initial-connection deadline, not a \
         fixed second"
    );
    assert!(
        watchdog_tick(&shipped) > Duration::from_secs(1),
        "the shipped configuration must not wake every connection once a second"
    );

    for (initial, idle) in [(1u64, 2u64), (2, 4), (10, 900), (60, 3600), (300, 86_400)] {
        let limits = WorkloadApiAdmissionConfig {
            initial_connection_timeout: Duration::from_secs(initial),
            idle_timeout: Duration::from_secs(idle),
            ..WorkloadApiAdmissionConfig::default()
        };
        limits
            .validate()
            .expect("each case must itself be acceptable configuration");
        let tick = watchdog_tick(&limits);
        let deadline = limits.initial_connection_timeout.min(limits.idle_timeout);
        assert!(
            (WATCHDOG_MIN_TICK..=WATCHDOG_MAX_TICK).contains(&tick),
            "the tick stays inside its floor and ceiling, got {tick:?}"
        );
        assert!(
            tick <= deadline / WATCHDOG_TICK_DIVISOR || tick == WATCHDOG_MIN_TICK,
            "detection latency must stay a bounded fraction of the deadline, got {tick:?} for \
             {deadline:?}"
        );
        assert!(
            tick <= deadline,
            "a tick longer than the deadline would delay detection past it, got {tick:?} for \
             {deadline:?}"
        );
    }

    // A compressed test deadline still ticks fast enough to be observable, and
    // a pathological one cannot become a busy loop.
    let compressed = WorkloadApiAdmissionConfig {
        initial_connection_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(2),
        ..WorkloadApiAdmissionConfig::default()
    };
    assert_eq!(watchdog_tick(&compressed), Duration::from_millis(250));
    let floored = WorkloadApiAdmissionConfig {
        initial_connection_timeout: Duration::from_millis(1),
        idle_timeout: Duration::from_millis(2),
        ..WorkloadApiAdmissionConfig::default()
    };
    assert_eq!(watchdog_tick(&floored), WATCHDOG_MIN_TICK);
}
