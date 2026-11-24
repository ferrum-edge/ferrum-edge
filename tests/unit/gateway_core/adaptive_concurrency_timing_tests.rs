//! Deterministic attempt-relative timing, including intermediate retry outcomes.

use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use ferrum_edge::_test_support::{
    backend_admission_attempt_elapsed_for_test, record_backend_admission_retry_outcome_for_test,
};
use ferrum_edge::plugins::{
    BackendAdmissionOutcome, BackendAdmissionPermit, BackendAdmissionPermitSet,
};
use ferrum_edge::retry::ErrorClass;

#[derive(Debug)]
enum RetryEvent {
    Outcome(BackendAdmissionOutcome),
    Released,
}

struct RetryPermit(mpsc::Sender<RetryEvent>);

impl BackendAdmissionPermit for RetryPermit {
    fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome) {
        self.0
            .send(RetryEvent::Outcome(outcome))
            .expect("record outcome");
    }
}

impl Drop for RetryPermit {
    fn drop(&mut self) {
        self.0.send(RetryEvent::Released).expect("record release");
    }
}

#[test]
fn adaptive_retry_attempt_excludes_its_direct_h2_client_upload_gate() {
    let start = Instant::now();
    let (tx, rx) = mpsc::channel();
    let mut permits = BackendAdmissionPermitSet::new(vec![Arc::new(RetryPermit(tx))]);
    let failed = BackendAdmissionOutcome {
        response_status: 503,
        connection_error: false,
        error_class: Some(ErrorClass::ProtocolError),
        backend_elapsed: Duration::from_millis(8_007),
    };
    record_backend_admission_retry_outcome_for_test(
        &mut permits,
        failed,
        start,
        (start, Duration::from_secs(8)),
    );
    let RetryEvent::Outcome(outcome) = rx.try_recv().expect("failed attempt outcome") else {
        panic!("settlement must precede permit release");
    };
    assert_eq!(outcome.backend_elapsed, Duration::from_millis(7));
    assert_eq!(outcome.response_status, 503);
    assert_eq!(outcome.error_class, Some(ErrorClass::ProtocolError));
    assert!(!outcome.connection_error);
    assert!(matches!(rx.try_recv(), Ok(RetryEvent::Released)));
    assert!(permits.is_none());
    record_backend_admission_retry_outcome_for_test(
        &mut permits,
        failed,
        start,
        (start, Duration::from_secs(8)),
    );
    assert!(
        rx.try_recv().is_err(),
        "the replaced attempt is settled only once"
    );
}

#[test]
fn adaptive_retry_attempt_does_not_subtract_an_earlier_attempts_upload_gate() {
    let first = Instant::now();
    let retry = first + Duration::from_secs(10);
    for gate_wait in [Duration::ZERO, Duration::from_secs(8)] {
        assert_eq!(
            backend_admission_attempt_elapsed_for_test(
                retry,
                Duration::from_millis(23),
                (first, gate_wait),
            ),
            Duration::from_millis(23),
            "an intermediate or final retry samples only its own dispatch"
        );
    }
}

#[test]
fn adaptive_attempt_without_a_gate_keeps_elapsed_and_subtraction_saturates() {
    let start = Instant::now();
    assert_eq!(
        backend_admission_attempt_elapsed_for_test(
            start,
            Duration::from_millis(7),
            (start, Duration::ZERO),
        ),
        Duration::from_millis(7),
    );
    assert_eq!(
        backend_admission_attempt_elapsed_for_test(
            start,
            Duration::from_millis(7),
            (start, Duration::from_secs(8)),
        ),
        Duration::ZERO,
    );
}

/// The helper is pinned behaviorally above; this pins the H1/H2 retry-loop
/// call site that feeds it. A wire test cannot deterministically drive a
/// retried direct-H2 attempt whose client-upload gate is held measurably long,
/// so the arguments are anchored here instead: the replaced attempt is settled
/// with its own dispatch clock and with the gate captured under that same
/// clock, before the loop restarts the clock for the next attempt.
#[test]
fn http_retry_loop_settles_the_replaced_attempt_with_its_own_clock_and_gate() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let squeeze =
        |text: &str| -> String { text.chars().filter(|ch| !ch.is_whitespace()).collect() };
    let loop_start = source
        .find("while retry::should_retry(retry_config, &method, &result, attempt)")
        .expect("HTTP retry loop");
    let loop_tail = &source[loop_start..];
    let loop_body = &loop_tail[..loop_tail
        .find("(result, current_cb_target_key, final_upstream_target)")
        .expect("HTTP retry loop end")];

    let record = loop_body
        .find("record_backend_admission_retry_outcome(")
        .expect("intermediate retry settlement");
    let call = &loop_body[record..];
    let call = squeeze(&call[..call.find(");").expect("settlement call end") + 2]);
    assert!(
        call.contains("backend_elapsed:backend_admission_started_at.elapsed(),"),
        "the replaced attempt must be sampled on its own dispatch clock: {call}"
    );
    assert!(
        call.ends_with("},backend_admission_started_at,direct_h2_client_upload_gate,);"),
        "the settlement must pass that attempt's start and the captured gate: {call}"
    );

    let first_reset = loop_body
        .find(" backend_admission_started_at = Instant::now();")
        .expect("each retry restarts the dispatch clock");
    assert!(
        record < first_reset,
        "the replaced attempt must be settled before the next attempt restarts the clock"
    );

    let mut assignments = 0;
    let mut rest = source;
    while let Some(at) = rest.find("direct_h2_client_upload_gate =") {
        let tail = &rest[at..];
        let end = tail.find(';').expect("gate assignment end") + 1;
        assert_eq!(
            squeeze(&tail[..end]),
            "direct_h2_client_upload_gate=(backend_admission_started_at,client_upload_gate_wait);",
            "the gate must be captured with the clock of the dispatch that measured it"
        );
        assignments += 1;
        rest = &tail[end..];
    }
    assert!(
        assignments >= 1,
        "dispatch must capture the direct-H2 client-upload gate"
    );
}
