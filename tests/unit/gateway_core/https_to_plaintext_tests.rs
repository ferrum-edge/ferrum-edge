//! Classification of HTTPS-to-plaintext backend handshake failures (issue #5460).

use ferrum_edge::retry::{
    ERROR_REASON_HTTPS_TO_PLAINTEXT, error_looks_like_https_to_plaintext,
    https_to_plaintext_from_message,
};
use std::error::Error as StdError;

fn looks_like(error: impl StdError + 'static) -> bool {
    error_looks_like_https_to_plaintext(&error)
}

#[test]
fn reason_token_is_stable() {
    assert_eq!(
        ERROR_REASON_HTTPS_TO_PLAINTEXT,
        "https_to_plaintext_backend"
    );
}

#[test]
fn typed_rustls_invalid_content_type_is_plaintext_mismatch() {
    let err = rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType);
    assert!(
        looks_like(err),
        "InvalidContentType is the usual rustls shape when HTTP/1.x bytes arrive during TLS"
    );
}

#[test]
fn typed_rustls_unknown_protocol_version_is_plaintext_mismatch() {
    let err = rustls::Error::InvalidMessage(rustls::InvalidMessage::UnknownProtocolVersion);
    assert!(looks_like(err));
}

#[test]
fn typed_rustls_invalid_ccs_is_plaintext_mismatch() {
    let err = rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidCcs);
    assert!(looks_like(err));
}

#[test]
fn rustls_error_wrapped_as_io_error_is_still_detected() {
    let rustls_err = rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType);
    let io_err = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err);
    assert!(
        looks_like(io_err),
        "tokio-rustls/reqwest wrap rustls in io::Error; get_ref() must be walked"
    );
}

#[test]
fn openssl_wrong_version_number_message_is_plaintext_mismatch() {
    assert!(https_to_plaintext_from_message(
        "error:0A00010B:SSL routines::wrong version number"
    ));
    let err: Box<dyn StdError + Send + Sync> =
        "ssl3_get_record:wrong version number".to_string().into();
    assert!(error_looks_like_https_to_plaintext(err.as_ref()));
}

#[test]
fn rustls_display_corrupt_message_is_plaintext_mismatch() {
    assert!(https_to_plaintext_from_message(
        "received corrupt message of type InvalidContentType"
    ));
    assert!(https_to_plaintext_from_message(
        "received corrupt message of type UnknownProtocolVersion"
    ));
}

#[test]
fn http1_status_line_during_handshake_is_plaintext_mismatch() {
    assert!(https_to_plaintext_from_message(
        "invalid TLS record: HTTP/1.1 400 Bad Request"
    ));
    assert!(https_to_plaintext_from_message("peer sent HTTP/1.0 200 OK"));
}

#[test]
fn unrelated_tls_and_connect_failures_are_not_plaintext_mismatch() {
    assert!(
        !https_to_plaintext_from_message("invalid peer certificate: NotValidForName"),
        "certificate errors are real TLS, not a scheme footgun"
    );
    assert!(!https_to_plaintext_from_message(
        "peer sent no certificates"
    ));
    assert!(!https_to_plaintext_from_message(
        "tls handshake didn't make it past the kernel"
    ));
    assert!(!https_to_plaintext_from_message("Connection refused"));
    assert!(!https_to_plaintext_from_message(
        "peer closed connection without sending TLS close_notify"
    ));
    assert!(
        !https_to_plaintext_from_message("TLS peer did not negotiate ALPN h2"),
        "ALPN mismatch is not an HTTP/1.x plaintext backend"
    );

    let cert = rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
    assert!(!looks_like(cert));

    let close = rustls::Error::AlertReceived(rustls::AlertDescription::CloseNotify);
    assert!(!looks_like(close));
}
