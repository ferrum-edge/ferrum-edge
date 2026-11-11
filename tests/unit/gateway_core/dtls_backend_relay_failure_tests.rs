//! A DTLS-terminating frontend session whose backend leg fails is a backend
//! termination, not a graceful close (issue #7186). The reply task wraps the
//! backend receive error; the accept loop derives class, cause and direction
//! from it exactly as the plain-UDP reply task does.

use ferrum_edge::_test_support::dtls_backend_relay_failure_for_test;
use ferrum_edge::plugins::{Direction, DisconnectCause};
use ferrum_edge::retry::ErrorClass;

#[test]
fn a_refused_plain_udp_backend_ends_the_session_as_a_post_wire_backend_error() {
    let outcome = dtls_backend_relay_failure_for_test(anyhow::Error::from(std::io::Error::from(
        std::io::ErrorKind::ConnectionRefused,
    )));
    assert!(
        outcome.error.starts_with("DTLS backend receive failed: "),
        "{}",
        outcome.error
    );
    // The relay is past the connect phase: an ICMP-driven ECONNREFUSED on the
    // connected socket stays post-wire.
    assert_eq!(outcome.error_class, ErrorClass::ConnectionReset);
    assert_eq!(outcome.disconnect_cause, DisconnectCause::BackendError);
    assert_eq!(outcome.disconnect_direction, Direction::BackendToClient);
    assert_eq!(outcome.setup_kind, None);
}

#[test]
fn an_ended_backend_dtls_association_is_a_backend_error_not_a_graceful_close() {
    // `DtlsConnection::recv` reports every end of the backend association as
    // "DTLS connection closed".
    let outcome = dtls_backend_relay_failure_for_test(anyhow::anyhow!("DTLS connection closed"));
    assert_eq!(
        outcome.error,
        "DTLS backend receive failed: DTLS connection closed"
    );
    assert_eq!(outcome.error_class, ErrorClass::ConnectionClosed);
    assert_eq!(outcome.disconnect_cause, DisconnectCause::BackendError);
    assert_eq!(outcome.disconnect_direction, Direction::BackendToClient);
}

#[test]
fn an_untyped_backend_failure_keeps_the_backend_attribution() {
    let outcome = dtls_backend_relay_failure_for_test(anyhow::anyhow!("engine failure"));
    assert_eq!(outcome.disconnect_cause, DisconnectCause::BackendError);
    assert_eq!(outcome.disconnect_direction, Direction::BackendToClient);
}
