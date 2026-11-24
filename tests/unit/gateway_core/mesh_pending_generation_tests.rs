//! Debounced pending-generation machine shared by the `xds` and `stock_xds`
//! ADS clients (`config_consumer::pending_generation`).
//!
//! Pure-policy half. The live regressions (a NACK inside the debounce window
//! on a real ADS stream) are in `tests/integration/mesh_xds_stream_lifecycle_tests.rs`
//! and `tests/integration/mesh_stock_xds_tests.rs`.

use std::time::Duration;

use ferrum_edge::modes::mesh::config_consumer::pending_generation::{
    PendingGeneration, PendingGenerationAction, PendingGenerationEvent,
};

fn armed_at(
    action: PendingGenerationAction<&'static str>,
) -> (tokio::time::Instant, tokio::time::Instant) {
    match action {
        PendingGenerationAction::ArmDebounce {
            now,
            first_staged_at,
        } => (now, first_staged_at),
        PendingGenerationAction::None | PendingGenerationAction::Commit(_) => {
            panic!("staging must arm the debounce timer")
        }
    }
}

#[test]
fn a_nack_while_staged_keeps_the_acked_generation_and_its_deadline() {
    let t0 = tokio::time::Instant::now();
    let mut pending = PendingGeneration::NoPending;
    let (_, first) = armed_at(pending.transition(PendingGenerationEvent::Stage {
        generation: "v2",
        now: t0,
    }));
    assert_eq!(first, t0);

    // A NACK of a LATER response rolls back only that response. The staged
    // generation was ACKed and complete before it arrived, so it must survive
    // and the timer must be neither re-armed nor disarmed.
    match pending.transition(PendingGenerationEvent::ResponseNacked) {
        PendingGenerationAction::None => {}
        PendingGenerationAction::ArmDebounce { .. } | PendingGenerationAction::Commit(_) => {
            panic!("a NACK neither re-arms nor commits")
        }
    }
    assert!(pending.is_staged());
    assert_eq!(pending.staged().copied(), Some("v2"));

    match pending.transition(PendingGenerationEvent::Commit) {
        PendingGenerationAction::Commit(generation) => assert_eq!(generation, "v2"),
        PendingGenerationAction::None | PendingGenerationAction::ArmDebounce { .. } => {
            panic!("the debounce must commit the generation staged before the NACK")
        }
    }
    assert!(!pending.is_staged());
}

#[test]
fn a_nack_with_nothing_staged_is_a_no_op() {
    let mut pending: PendingGeneration<&'static str> = PendingGeneration::NoPending;
    match pending.transition(PendingGenerationEvent::ResponseNacked) {
        PendingGenerationAction::None => {}
        PendingGenerationAction::ArmDebounce { .. } | PendingGenerationAction::Commit(_) => {
            panic!("nothing staged: nothing to arm or commit")
        }
    }
    assert!(!pending.is_staged());
    match pending.transition(PendingGenerationEvent::Commit) {
        PendingGenerationAction::None => {}
        PendingGenerationAction::ArmDebounce { .. } | PendingGenerationAction::Commit(_) => {
            panic!("committing with nothing staged applies nothing")
        }
    }
}

#[test]
fn a_superseding_stage_replaces_the_generation_but_keeps_the_max_delay_anchor() {
    let t0 = tokio::time::Instant::now();
    let t1 = t0 + Duration::from_millis(10);
    let mut pending = PendingGeneration::NoPending;
    let _ = pending.transition(PendingGenerationEvent::Stage {
        generation: "v2",
        now: t0,
    });
    let (now, first) = armed_at(pending.transition(PendingGenerationEvent::Stage {
        generation: "v3",
        now: t1,
    }));
    assert_eq!(now, t1, "the debounce restarts from the newest stage");
    assert_eq!(
        first, t0,
        "continuous churn must not postpone the commit past the max-delay cap"
    );
    assert_eq!(pending.staged().copied(), Some("v3"));

    // After a commit the anchor resets: the next stage starts a new window.
    let _ = pending.transition(PendingGenerationEvent::Commit);
    let t2 = t1 + Duration::from_millis(10);
    let (_, first) = armed_at(pending.transition(PendingGenerationEvent::Stage {
        generation: "v4",
        now: t2,
    }));
    assert_eq!(first, t2);
}
