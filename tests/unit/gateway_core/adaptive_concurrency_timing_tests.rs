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
