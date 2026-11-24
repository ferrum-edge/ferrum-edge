//! Issue #7030: the typed TCP relay ending and the circuit-breaker policy it
//! drives.
//!
//! An idle-window expiry and a half-close-cap expiry are clean endings on raw
//! TCP, as they are on HBONE (which settles `Success` once its backend connect
//! succeeds and never re-scores the relay end). An authorization-lifetime end
//! is health-neutral and classified as the client-side decision it is, never
//! as an idle timeout.

use std::time::Duration;

use ferrum_edge::_test_support::{
    RelayEndReason, STREAM_RELAY_AUTHORIZATION_EXPIRED_MESSAGE,
    STREAM_RELAY_HALF_CLOSE_CAP_MESSAGE, STREAM_RELAY_IDLE_TIMEOUT_MESSAGE, StreamIoSide,
    bidirectional_copy_for_test, relay_failure_is_half_close_cap,
};
use ferrum_edge::circuit_breaker::{BreakerOutcome, CircuitBreaker};
use ferrum_edge::config::types::CircuitBreakerConfig;
use ferrum_edge::plugins::{Direction, DisconnectCause};
use ferrum_edge::retry::ErrorClass;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type FirstFailure = (Direction, ErrorClass, Option<StreamIoSide>, String);

fn idle_expiry() -> FirstFailure {
    (
        Direction::Unknown,
        ErrorClass::ReadWriteTimeout,
        None,
        STREAM_RELAY_IDLE_TIMEOUT_MESSAGE.to_string(),
    )
}

fn half_close_cap() -> FirstFailure {
    (
        Direction::Unknown,
        ErrorClass::ReadWriteTimeout,
        None,
        STREAM_RELAY_HALF_CLOSE_CAP_MESSAGE.to_string(),
    )
}

fn authorization_expired() -> FirstFailure {
    (
        Direction::ClientToBackend,
        ErrorClass::ReadWriteTimeout,
        Some(StreamIoSide::Read),
        STREAM_RELAY_AUTHORIZATION_EXPIRED_MESSAGE.to_string(),
    )
}

fn client_reset() -> FirstFailure {
    (
        Direction::ClientToBackend,
        ErrorClass::ConnectionReset,
        Some(StreamIoSide::Read),
        "client reset".to_string(),
    )
}

fn backend_reset() -> FirstFailure {
    (
        Direction::BackendToClient,
        ErrorClass::ConnectionReset,
        Some(StreamIoSide::Read),
        "backend reset".to_string(),
    )
}

fn backend_read_deadline() -> FirstFailure {
    (
        Direction::BackendToClient,
        ErrorClass::ReadWriteTimeout,
        Some(StreamIoSide::Read),
        "backend read inactivity timeout".to_string(),
    )
}

/// A breaker that opens on its first counted failure and needs two successes
/// to close, so one ending can be seen to count without closing the cycle.
fn hair_trigger_config() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![502],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    }
}

#[test]
fn every_relay_ending_has_one_typed_reason() {
    assert_eq!(
        RelayEndReason::from_first_failure(None),
        RelayEndReason::Graceful
    );
    assert_eq!(
        RelayEndReason::from_first_failure(Some(&idle_expiry())),
        RelayEndReason::IdleExpiry
    );
    assert_eq!(
        RelayEndReason::from_first_failure(Some(&half_close_cap())),
        RelayEndReason::HalfCloseCap
    );
    assert!(relay_failure_is_half_close_cap(&half_close_cap()));
    assert!(!relay_failure_is_half_close_cap(&idle_expiry()));
    assert_eq!(
        RelayEndReason::from_first_failure(Some(&authorization_expired())),
        RelayEndReason::AuthorizationExpired,
        "the authorization lifetime is its own ending, not a client-socket failure"
    );
    assert!(matches!(
        RelayEndReason::from_first_failure(Some(&client_reset())),
        RelayEndReason::ClientFailure { .. }
    ));
    assert!(matches!(
        RelayEndReason::from_first_failure(Some(&backend_reset())),
        RelayEndReason::BackendFailure { .. }
    ));
    assert!(
        matches!(
            RelayEndReason::from_first_failure(Some(&backend_read_deadline())),
            RelayEndReason::BackendFailure { .. }
        ),
        "a backend read deadline is attributed to the backend, not the idle window"
    );
}

#[test]
fn idle_and_half_close_cap_endings_settle_the_breaker_clean() {
    for failure in [idle_expiry(), half_close_cap()] {
        assert_eq!(
            RelayEndReason::from_first_failure(Some(&failure)).breaker_outcome(),
            BreakerOutcome::Success,
            "{failure:?} must settle exactly what HBONE records for the tunnel"
        );
    }
    assert_eq!(
        RelayEndReason::Graceful.breaker_outcome(),
        BreakerOutcome::Success
    );
    for failure in [authorization_expired(), client_reset()] {
        assert_eq!(
            RelayEndReason::from_first_failure(Some(&failure)).breaker_outcome(),
            BreakerOutcome::Neutral,
            "{failure:?} carries no backend signal"
        );
    }
    for failure in [backend_reset(), backend_read_deadline()] {
        assert_eq!(
            RelayEndReason::from_first_failure(Some(&failure)).breaker_outcome(),
            BreakerOutcome::Failure {
                status_code: 502,
                connection_error: true,
            },
            "{failure:?} is a backend connection-class failure"
        );
    }
}

#[test]
fn idle_and_half_close_cap_endings_never_trip_a_closed_breaker() {
    for failure in [idle_expiry(), half_close_cap()] {
        let cb = CircuitBreaker::new(hair_trigger_config());
        let (ticket, _) = cb.admit().expect("CLOSED admits");
        cb.settle(
            ticket,
            RelayEndReason::from_first_failure(Some(&failure)).breaker_outcome(),
        );
        assert_eq!(
            cb.state_name(),
            "closed",
            "{failure:?} must not trip a breaker that opens on one failure"
        );
        assert_eq!(cb.failure_count(), 0);
    }
}

#[test]
fn a_half_open_probe_ending_idle_or_capped_counts_like_hbone_and_never_reopens() {
    for failure in [idle_expiry(), half_close_cap()] {
        let cb = CircuitBreaker::new(hair_trigger_config());
        cb.record_failure(502, true, false);
        assert_eq!(cb.state_name(), "open");

        // The TCP probe's relay ends on the gateway's own timer.
        let (tcp_probe, _) = cb.admit().expect("timeout 0 admits a probe");
        assert!(tcp_probe.is_probe());
        cb.settle(
            tcp_probe,
            RelayEndReason::from_first_failure(Some(&failure)).breaker_outcome(),
        );
        assert_eq!(
            cb.state_name(),
            "half_open",
            "{failure:?} must not reopen the HALF_OPEN cycle"
        );
        assert_eq!(cb.half_open_in_flight(), 0, "the probe slot is returned");
        assert_eq!(cb.success_count(), 1, "the ending counts toward recovery");

        // An HBONE probe settles `Success` once its backend connect succeeds:
        // the same credit, so the two together close the breaker.
        let (hbone_probe, _) = cb.admit().expect("the freed slot admits");
        cb.settle(hbone_probe, BreakerOutcome::Success);
        assert_eq!(cb.state_name(), "closed");
    }
}

#[test]
fn authorization_expiry_is_relabelled_and_other_endings_keep_their_labels() {
    let auth = RelayEndReason::from_first_failure(Some(&authorization_expired()));
    assert_eq!(auth.disconnect_cause(), DisconnectCause::RecvError);
    assert_ne!(auth.disconnect_cause(), DisconnectCause::IdleTimeout);
    assert_eq!(auth.error_class(), Some(ErrorClass::RequestError));

    // Every other ending keeps the label it always had.
    assert_eq!(
        RelayEndReason::Graceful.disconnect_cause(),
        DisconnectCause::GracefulShutdown
    );
    assert_eq!(RelayEndReason::Graceful.error_class(), None);
    for failure in [idle_expiry(), half_close_cap(), backend_read_deadline()] {
        let reason = RelayEndReason::from_first_failure(Some(&failure));
        assert_eq!(reason.disconnect_cause(), DisconnectCause::IdleTimeout);
        assert_eq!(reason.error_class(), Some(ErrorClass::ReadWriteTimeout));
    }
    assert_eq!(
        RelayEndReason::from_first_failure(Some(&client_reset())).disconnect_cause(),
        DisconnectCause::RecvError
    );
    assert_eq!(
        RelayEndReason::from_first_failure(Some(&backend_reset())).disconnect_cause(),
        DisconnectCause::BackendError
    );
}

#[test]
fn hbone_wire_reset_policy_is_unchanged() {
    // The breaker treats the half-close cap as clean, but it can cut a
    // direction that is still streaming, so the HBONE stream still resets.
    assert!(!RelayEndReason::Graceful.resets_hbone_stream());
    assert!(!RelayEndReason::IdleExpiry.resets_hbone_stream());
    assert!(RelayEndReason::HalfCloseCap.resets_hbone_stream());
    assert!(RelayEndReason::from_first_failure(Some(&backend_reset())).resets_hbone_stream());
}

/// The production relay's own idle and half-close endings classify as clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_relay_idle_and_cap_endings_settle_clean() {
    let (client, _client_peer) = tokio::io::duplex(4096);
    let (backend, _backend_peer) = tokio::io::duplex(4096);
    let idle = bidirectional_copy_for_test(
        client,
        backend,
        Some(Duration::from_millis(300)),
        None,
        8 * 1024,
    )
    .await;
    let idle_reason = RelayEndReason::from_first_failure(idle.first_failure.as_ref());
    assert_eq!(idle_reason, RelayEndReason::IdleExpiry);
    assert_eq!(idle_reason.breaker_outcome(), BreakerOutcome::Success);

    let (client, mut client_peer) = tokio::io::duplex(4096);
    let (backend, mut backend_peer) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = client_peer.write_all(b"REQUEST").await;
        let _ = client_peer.shutdown().await;
        let mut sink = Vec::new();
        let _ = client_peer.read_to_end(&mut sink).await;
    });
    tokio::spawn(async move {
        loop {
            if backend_peer.write_all(b"chunk").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let capped = bidirectional_copy_for_test(
        client,
        backend,
        Some(Duration::from_secs(30)),
        Some(Duration::from_millis(300)),
        8 * 1024,
    )
    .await;
    let cap_reason = RelayEndReason::from_first_failure(capped.first_failure.as_ref());
    assert_eq!(cap_reason, RelayEndReason::HalfCloseCap);
    assert_eq!(cap_reason.breaker_outcome(), BreakerOutcome::Success);
}
