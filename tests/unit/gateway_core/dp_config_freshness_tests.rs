//! Bounded DP last-known-good configuration age (issue #3726).
//!
//! Every test drives a non-publishing [`DpConfigFreshness`] from an explicit
//! monotonic epoch, so the whole state machine is deterministic: no sleeps, no
//! wall clock, and no dependence on the process-global admission gate that only
//! the installed DP tracker writes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ferrum_edge::dp_config_freshness::{
    ADMISSION_STALE_BIT, CpAuthority, DpConfigFreshness, FreshnessReason, StaleAction,
    publish_monotonic,
};

const MAX_STALE: Duration = Duration::from_secs(600);

/// The complete closed label sets the projection may ever carry.
const REASON_LABELS: [&str; 6] = [
    "ok",
    "awaiting_first_snapshot",
    "cp_disconnected",
    "snapshot_stale",
    "snapshot_rejected",
    "snapshot_apply_failed",
];
const STALE_ACTION_LABELS: [&str; 2] = ["fail_closed", "readiness_only"];
const CP_AUTHORITY_LABELS: [&str; 3] = ["connected", "reconnecting", "lost"];

/// Fixed monotonic base plus a helper for "t seconds after start".
fn epoch() -> Instant {
    Instant::now()
}

fn at(epoch: Instant, seconds: u64) -> Instant {
    epoch + Duration::from_secs(seconds)
}

/// A tracker that has already accepted a snapshot at t=0 and lost every CP at
/// t=0 — the total-outage shape used by most threshold assertions.
fn applied_then_authority_lost(epoch: Instant, action: StaleAction) -> DpConfigFreshness {
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, action);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_authority_lost_at(epoch);
    freshness
}

#[test]
fn ready_before_the_threshold_and_stale_exactly_at_it() {
    let epoch = epoch();
    let freshness = applied_then_authority_lost(epoch, StaleAction::FailClosed);

    let just_before = freshness.evaluate_at(at(epoch, 599));
    assert!(
        !just_before.stale,
        "must stay fresh one second before the bound"
    );
    assert!(!just_before.new_traffic_blocked);
    assert_eq!(just_before.reason, FreshnessReason::CpDisconnected.as_str());
    assert_eq!(just_before.snapshot_age_seconds, 599);

    let at_threshold = freshness.evaluate_at(at(epoch, 600));
    assert!(at_threshold.stale, "must go stale at the bound itself");
    assert!(at_threshold.new_traffic_blocked);
    assert_eq!(at_threshold.reason, FreshnessReason::SnapshotStale.as_str());
    assert_eq!(at_threshold.stale_transitions_total, 1);
}

/// The configured maximum is the boundary. Nothing — no reconnect grace, no
/// outage window — may push admission past it.
#[test]
fn an_already_aged_snapshot_fails_closed_the_moment_authority_is_lost() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);

    // Quiet configuration: the applied snapshot is already far past the bound
    // when the last CP attempt fails.
    let outage = at(epoch, 5_000);
    let snapshot = freshness.evaluate_at(outage);
    assert!(!snapshot.stale, "a connected DP is never stale");

    freshness.record_cp_authority_lost_at(outage);
    let after = freshness.evaluate_at(outage);
    assert!(
        after.stale,
        "past the bound, authority loss must fail closed immediately — not \
         after a further grace period"
    );
    assert!(after.new_traffic_blocked);
}

#[test]
fn heartbeats_reconnects_rejections_and_apply_failures_do_not_reset_the_age() {
    let epoch = epoch();
    let freshness = applied_then_authority_lost(epoch, StaleAction::FailClosed);

    // Everything short of an applied snapshot: repeated failover attempts
    // (which the DP records once per unreachable CP URL), a refused payload,
    // and a snapshot that was admitted and then failed to apply. No heartbeat
    // hook exists at all — heartbeat frames never reach this module.
    for second in [30, 120, 300, 599] {
        freshness.record_cp_authority_lost_at(at(epoch, second));
    }
    freshness.record_snapshot_rejected();
    freshness.record_snapshot_apply_failed();

    let snapshot = freshness.evaluate_at(at(epoch, 600));
    assert!(
        snapshot.stale,
        "none of those events may push the boundary out"
    );
    assert_eq!(snapshot.snapshot_age_seconds, 600);
    assert_eq!(snapshot.rejected_total, 1);
    assert_eq!(snapshot.apply_failed_total, 1);
    assert_eq!(snapshot.applied_total, 1, "no new snapshot was applied");
}

#[test]
fn reconnecting_alone_does_not_clear_a_raised_stale_state() {
    let epoch = epoch();
    let freshness = applied_then_authority_lost(epoch, StaleAction::FailClosed);
    assert!(freshness.evaluate_at(at(epoch, 600)).stale);

    // Transport is back and the CP even sends payloads — but every one of them
    // is refused or fails to apply. Recovery must not happen.
    freshness.record_cp_connected_at(at(epoch, 601));
    freshness.record_snapshot_rejected();
    freshness.record_snapshot_apply_failed();

    let snapshot = freshness.evaluate_at(at(epoch, 601));
    assert!(snapshot.stale, "recovery requires an APPLIED snapshot");
    assert!(snapshot.new_traffic_blocked);
    assert!(snapshot.cp_connected);
    assert_eq!(snapshot.reason, FreshnessReason::SnapshotStale.as_str());
}

#[test]
fn an_applied_snapshot_resets_the_age_and_restores_admission() {
    let epoch = epoch();
    let freshness = applied_then_authority_lost(epoch, StaleAction::FailClosed);
    assert!(freshness.evaluate_at(at(epoch, 600)).stale);

    freshness.record_cp_connected_at(at(epoch, 610));
    freshness.record_snapshot_applied_at(at(epoch, 610));

    let snapshot = freshness.evaluate_at(at(epoch, 611));
    assert!(
        !snapshot.stale,
        "an applied snapshot clears the sticky flag"
    );
    assert!(!snapshot.new_traffic_blocked);
    assert_eq!(snapshot.snapshot_age_seconds, 1);
    assert_eq!(snapshot.reason, FreshnessReason::Ok.as_str());
    assert_eq!(snapshot.applied_total, 2);
    assert_eq!(
        snapshot.stale_transitions_total, 1,
        "the earlier transition stays counted"
    );
}

#[test]
fn losing_one_cp_while_another_stays_authoritative_is_not_stale() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);

    // Primary drops far past the bound; the DP fails over to a fallback that
    // applies a snapshot. The config is quiet afterwards, so the age keeps
    // growing well beyond the bound while connected — which is not staleness.
    freshness.record_cp_reconnecting_at(at(epoch, 700));
    freshness.record_cp_connected_at(at(epoch, 701));
    freshness.record_snapshot_applied_at(at(epoch, 701));

    let snapshot = freshness.evaluate_at(at(epoch, 5_000));
    assert!(
        !snapshot.stale,
        "a connected DP is still receiving revocations"
    );
    assert!(!snapshot.new_traffic_blocked);
    assert_eq!(snapshot.cp_disconnected_seconds, 0);
    assert_eq!(snapshot.snapshot_age_seconds, 4_299);
    assert_eq!(snapshot.reason, FreshnessReason::Ok.as_str());
}

/// The handoff gap of a successful failover must not blip traffic even when the
/// applied snapshot is already older than the bound — and the fix for that is
/// the authority state, not a time window.
#[test]
fn a_successful_failover_handoff_never_latches_an_already_aged_snapshot() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);

    // The stream to the primary ends after having delivered config; the DP is
    // reconnecting, not authority-less, even though the snapshot is ancient.
    freshness.record_cp_reconnecting_at(at(epoch, 5_000));
    let during_handoff = freshness.evaluate_at(at(epoch, 5_000));
    assert!(!during_handoff.stale, "a handoff is not authority loss");
    assert!(!during_handoff.new_traffic_blocked);
    assert_eq!(
        during_handoff.cp_authority,
        CpAuthority::Reconnecting.as_str()
    );

    // The fallback answers. Still no blip, and the applied snapshot the
    // fallback delivers resets the age.
    freshness.record_cp_connected_at(at(epoch, 5_001));
    freshness.record_snapshot_applied_at(at(epoch, 5_001));
    let recovered = freshness.evaluate_at(at(epoch, 5_002));
    assert!(!recovered.stale);
    assert_eq!(recovered.snapshot_age_seconds, 1);

    // The same aged snapshot with a *failed* attempt does fail closed at once.
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_authority_lost_at(at(epoch, 5_003));
    assert!(freshness.evaluate_at(at(epoch, 5_003)).stale);
}

/// `PrimaryRetry` and `TlsReload` are deliberate disconnects from a healthy
/// stream, so they may never be read as authority loss.
#[test]
fn intentional_reconnects_are_not_authority_loss() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);

    freshness.record_cp_reconnecting_at(at(epoch, 601));
    assert_eq!(freshness.cp_authority(), CpAuthority::Reconnecting);
    assert!(!freshness.evaluate_at(at(epoch, 601)).stale);
    assert!(
        freshness.next_stale_deadline_at(at(epoch, 601)).is_none(),
        "no deadline is armed while the DP may still have authority"
    );

    // An intentional reconnect must never *downgrade* an authority loss that
    // was already observed, either.
    freshness.record_cp_authority_lost_at(at(epoch, 602));
    freshness.record_cp_reconnecting_at(at(epoch, 603));
    assert_eq!(freshness.cp_authority(), CpAuthority::Lost);
    assert!(freshness.evaluate_at(at(epoch, 603)).stale);
}

#[test]
fn repeated_failed_cp_cycles_do_not_postpone_the_boundary() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);

    // Every CP URL is unreachable, so the DP records a failed attempt per URL
    // and per cycle. The boundary is the applied-snapshot age, so none of them
    // moves it.
    for second in 1..600 {
        freshness.record_cp_authority_lost_at(at(epoch, second));
    }
    assert!(!freshness.evaluate_at(at(epoch, 599)).stale);

    let snapshot = freshness.evaluate_at(at(epoch, 600));
    assert!(snapshot.stale);
    assert_eq!(
        snapshot.cp_disconnected_seconds, 599,
        "the outage diagnostic keeps the FIRST stamp of the outage"
    );
}

#[test]
fn readiness_only_degrades_readiness_without_blocking_traffic() {
    let epoch = epoch();
    let freshness = applied_then_authority_lost(epoch, StaleAction::ReadinessOnly);

    let snapshot = freshness.evaluate_at(at(epoch, 600));
    assert!(snapshot.stale, "readiness still degrades");
    assert!(
        !snapshot.new_traffic_blocked,
        "the compatibility mode keeps admitting new traffic"
    );
    assert_eq!(snapshot.stale_action, "readiness_only");
    assert_eq!(
        freshness.published_admission_word() & ADMISSION_STALE_BIT,
        0,
        "readiness_only must never publish a blocking admission word"
    );
}

#[test]
fn startup_without_any_snapshot_is_bounded_from_process_start() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    assert_eq!(
        freshness.cp_authority(),
        CpAuthority::Lost,
        "a DP that has never reached a CP has no authority"
    );

    let before = freshness.evaluate_at(at(epoch, 599));
    assert!(!before.stale);
    assert!(!before.applied_snapshot);
    assert_eq!(
        before.reason,
        FreshnessReason::AwaitingFirstSnapshot.as_str()
    );
    assert_eq!(before.snapshot_age_seconds, 599);

    let after = freshness.evaluate_at(at(epoch, 600));
    assert!(
        after.stale,
        "a DP that never reached a CP is bounded by the same rule"
    );
    assert!(after.new_traffic_blocked);
}

#[test]
fn a_disabled_bound_never_goes_stale() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, Duration::ZERO, StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_authority_lost_at(at(epoch, 1));

    assert!(!freshness.enabled());
    let snapshot = freshness.evaluate_at(at(epoch, 10_000_000));
    assert!(!snapshot.stale, "0 is the documented unbounded opt-in");
    assert!(!snapshot.new_traffic_blocked);
    assert_eq!(snapshot.max_stale_seconds, 0);
    assert!(
        freshness
            .next_stale_deadline_at(at(epoch, 10_000_000))
            .is_none()
    );
}

/// An extreme but syntactically valid `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`
/// (`u64::MAX`) must not panic the deadline arithmetic: an Instant that far
/// ahead is unrepresentable, so there is no scheduled deadline, and an ordinary
/// current instant must not latch stale against that astronomical bound.
#[test]
fn astronomical_max_stale_bound_does_not_panic_or_schedule_unrepresentable_deadline() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(
        epoch,
        Duration::from_secs(u64::MAX),
        StaleAction::FailClosed,
    );
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_authority_lost_at(epoch);

    let now = at(epoch, 1);
    let snapshot = freshness.evaluate_at(now);
    assert!(
        !snapshot.stale,
        "an ordinary current instant must not latch against an astronomical bound"
    );
    assert!(!snapshot.new_traffic_blocked);
    assert!(
        freshness.next_stale_deadline_at(now).is_none(),
        "Instant::checked_add overflow yields no representable scheduled deadline"
    );
}

/// [`Duration::MAX`] is the largest representable [`Duration`]; adding it to any
/// [`Instant`] still overflows the platform monotonic range. The tracker must
/// treat that like any other unrepresentable deadline: no panic, no timer armed,
/// and no premature stale latch while the bound remains astronomically far away.
#[test]
fn duration_max_bound_does_not_panic_or_schedule_unrepresentable_deadline() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, Duration::MAX, StaleAction::FailClosed);
    freshness.record_cp_authority_lost_at(epoch);

    let now = at(epoch, 1);
    assert!(
        !freshness.evaluate_at(now).stale,
        "Duration::MAX must not latch stale at an ordinary current instant"
    );
    assert!(
        freshness.next_stale_deadline_at(now).is_none(),
        "epoch + Duration::MAX is not representable as an Instant"
    );
}

/// The monitor is deadline-driven, not tick-driven: the deadline it arms is the
/// exact instant the applied snapshot crosses the configured bound, and it is
/// armed only while the DP has actually lost authority.
#[test]
fn the_pending_deadline_is_the_exact_configured_boundary() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);

    // No applied snapshot yet: the bound runs from process start.
    assert_eq!(
        freshness.next_stale_deadline_at(epoch),
        Some(epoch + MAX_STALE)
    );

    freshness.record_cp_connected_at(at(epoch, 10));
    assert!(
        freshness.next_stale_deadline_at(at(epoch, 10)).is_none(),
        "a connected DP has no pending staleness deadline"
    );

    freshness.record_snapshot_applied_at(at(epoch, 100));
    freshness.record_cp_authority_lost_at(at(epoch, 120));
    assert_eq!(
        freshness.next_stale_deadline_at(at(epoch, 120)),
        Some(at(epoch, 100) + MAX_STALE),
        "the deadline is measured from the applied snapshot, not the outage"
    );

    // A later applied snapshot moves the deadline out by exactly the bound.
    freshness.record_snapshot_applied_at(at(epoch, 200));
    assert_eq!(
        freshness.next_stale_deadline_at(at(epoch, 200)),
        Some(at(epoch, 200) + MAX_STALE)
    );

    // An overdue deadline never resolves into the past, so the monitor wakes
    // immediately instead of spinning on a negative sleep.
    let overdue = at(epoch, 5_000);
    assert_eq!(freshness.next_stale_deadline_at(overdue), Some(overdue));

    // Once latched there is nothing left to schedule.
    assert!(freshness.evaluate_at(overdue).stale);
    assert!(freshness.next_stale_deadline_at(overdue).is_none());
}

/// A valid apply must win over an evaluator that started in the previous
/// generation, whether that evaluator tries to latch or to publish.
#[test]
fn a_stale_evaluation_cannot_commit_after_a_valid_apply() {
    let epoch = epoch();
    let freshness = applied_then_authority_lost(epoch, StaleAction::FailClosed);

    // An evaluator observes generation g and decides "stale" — then stalls.
    let observed = freshness.state_word();

    // The recovery lands first: a validated snapshot applies and clears.
    freshness.record_snapshot_applied_at(at(epoch, 700));
    let recovered_word = freshness.state_word();
    assert!(recovered_word > observed, "the generation must advance");

    // The stalled evaluator now tries to commit its verdict about generation g.
    assert!(
        !freshness.try_latch_stale(observed),
        "an evaluation from an older generation must not latch the recovered one"
    );
    let after = freshness.evaluate_at(at(epoch, 701));
    assert!(!after.stale, "the recovered generation stays fresh");
    assert!(!after.new_traffic_blocked);

    // ...and the same guard holds for publication: a monotonic word install
    // cannot regress a newer generation to a blocked state.
    let slot = AtomicU64::new(recovered_word);
    publish_monotonic(&slot, observed | ADMISSION_STALE_BIT);
    assert_eq!(
        slot.load(Ordering::Relaxed),
        recovered_word,
        "a stale evaluator's blocked word must not overwrite the recovery"
    );
    publish_monotonic(&slot, recovered_word | ADMISSION_STALE_BIT);
    assert_eq!(
        slot.load(Ordering::Relaxed),
        recovered_word | ADMISSION_STALE_BIT,
        "a verdict about the CURRENT generation still installs"
    );
}

/// The same property under real concurrency: whatever the interleaving, the
/// last applied snapshot always wins and no evaluator can leave the tracker
/// blocked afterwards.
#[test]
fn concurrent_evaluators_never_re_block_a_recovered_generation() {
    let epoch = epoch();
    let freshness = Arc::new(applied_then_authority_lost(epoch, StaleAction::FailClosed));
    let stale_now = at(epoch, 10_000);

    let mut handles = Vec::new();
    for _ in 0..4 {
        let freshness = Arc::clone(&freshness);
        handles.push(std::thread::spawn(move || {
            for _ in 0..2_000 {
                freshness.evaluate_at(stale_now);
            }
        }));
    }
    let applier = {
        let freshness = Arc::clone(&freshness);
        std::thread::spawn(move || {
            for _ in 0..2_000 {
                freshness.record_snapshot_applied_at(stale_now);
            }
        })
    };
    for handle in handles {
        handle.join().expect("evaluator thread");
    }
    applier.join().expect("applier thread");

    // Every evaluator has finished, and the last event on the tracker was an
    // apply. Its generation must be the published one, and it must not be
    // blocked — regardless of how many evaluators were mid-flight.
    let published = freshness.published_admission_word();
    let state = freshness.state_word();
    assert_eq!(
        state >> 1,
        published >> 1,
        "the published generation must be the current one"
    );
    assert_eq!(
        published & ADMISSION_STALE_BIT,
        0,
        "no late evaluator may re-block the generation a valid apply recovered"
    );
    assert_eq!(state & ADMISSION_STALE_BIT, 0);
}

#[test]
fn reason_labels_distinguish_the_four_operator_states() {
    let epoch = epoch();
    let freshness = DpConfigFreshness::new_at(epoch, MAX_STALE, StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);
    assert_eq!(
        freshness.evaluate_at(at(epoch, 1)).reason,
        FreshnessReason::Ok.as_str()
    );

    freshness.record_snapshot_rejected();
    assert_eq!(
        freshness.evaluate_at(at(epoch, 2)).reason,
        FreshnessReason::SnapshotRejected.as_str()
    );

    freshness.record_snapshot_apply_failed();
    assert_eq!(
        freshness.evaluate_at(at(epoch, 3)).reason,
        FreshnessReason::SnapshotApplyFailed.as_str()
    );

    freshness.record_cp_authority_lost_at(at(epoch, 4));
    assert_eq!(
        freshness.evaluate_at(at(epoch, 5)).reason,
        FreshnessReason::CpDisconnected.as_str(),
        "losing the CP outranks the last payload outcome"
    );

    assert_eq!(
        freshness.evaluate_at(at(epoch, 600)).reason,
        FreshnessReason::SnapshotStale.as_str(),
        "staleness outranks everything else"
    );
}

#[test]
fn an_age_that_predates_the_epoch_cannot_underflow() {
    // Build the tracker with an epoch in the future of `base` rather than
    // subtracting from an `Instant` (which panics below the clock's origin).
    let base = Instant::now();
    let epoch = base + Duration::from_secs(60);
    let freshness = applied_then_authority_lost(epoch, StaleAction::FailClosed);

    // A monotonic clock cannot actually run backwards, but the arithmetic must
    // saturate rather than wrap if a caller ever hands back an earlier instant.
    let snapshot = freshness.evaluate_at(base);
    assert_eq!(snapshot.snapshot_age_seconds, 0);
    assert!(!snapshot.stale);
}

/// The documented contract is that the accepted values are exactly
/// `fail_closed` and `readiness_only`. No aliases: this setting has no
/// compatibility history to preserve.
#[test]
fn stale_action_parsing_accepts_only_the_two_documented_spellings() {
    assert_eq!(
        StaleAction::parse("fail_closed").expect("fail_closed"),
        StaleAction::FailClosed
    );
    assert_eq!(
        StaleAction::parse("readiness_only").expect("readiness_only"),
        StaleAction::ReadinessOnly
    );
    assert_eq!(StaleAction::FailClosed.as_str(), "fail_closed");
    assert_eq!(StaleAction::ReadinessOnly.as_str(), "readiness_only");

    for rejected in [
        "FAIL_CLOSED",
        "fail-closed",
        "Fail_Closed",
        " fail_closed ",
        "readiness-only",
        "READINESS_ONLY",
        "allow",
        "",
    ] {
        let err = StaleAction::parse(rejected)
            .expect_err("only the exact documented spellings are accepted");
        assert!(err.contains("FERRUM_DP_CONFIG_STALE_ACTION"), "{rejected}");
    }
}

#[test]
fn the_snapshot_projection_carries_no_unbounded_identifiers() {
    let epoch = epoch();
    let freshness = applied_then_authority_lost(epoch, StaleAction::FailClosed);
    let snapshot = freshness.evaluate_at(at(epoch, 600));

    let value = serde_json::to_value(&snapshot).expect("serializable");
    let object = value.as_object().expect("object");
    // Every field is a boolean, a number, or one of the three closed label sets.
    for (key, field) in object {
        let closed_label = matches!(key.as_str(), "reason" | "stale_action" | "cp_authority");
        assert!(
            field.is_boolean() || field.is_number() || closed_label,
            "unexpected free-form field `{key}` in the DP freshness projection"
        );
    }
    assert!(REASON_LABELS.contains(&snapshot.reason));
    assert!(STALE_ACTION_LABELS.contains(&snapshot.stale_action));
    assert!(CP_AUTHORITY_LABELS.contains(&snapshot.cp_authority));
}
