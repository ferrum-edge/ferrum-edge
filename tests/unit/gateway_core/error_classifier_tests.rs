//! Unit tests for the HTTP/2-pool and HTTP/3 error classifiers introduced to
//! close audit gaps #2 and #3. These ensure operators see a populated
//! `error_class` in the transaction log for failures on both backend paths.
//!
//! These tests deliberately construct the pool error variants with a *typed*
//! source where possible, so classification verifies the source-chain walk
//! rather than string heuristics. The string-fallback path is also covered
//! with `source: None` variants — production paths always populate a source,
//! but the fallback keeps classification meaningful for hand-rolled tests and
//! rare future wrappers that can't surface a typed cause.

use ferrum_edge::proxy::http2_pool::{
    BackendUnavailableSource, Http2PoolError, InternalSource, classify_http2_pool_error,
};
use ferrum_edge::retry::ErrorClass;
use std::io;

// ── HTTP/2 pool classifier — typed source chain ─────────────────────────

#[test]
fn test_h2_pool_typed_io_connection_refused() {
    // Typed io::Error with ErrorKind::ConnectionRefused — classification
    // must NOT depend on the message wording.
    let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "unrelated wording");
    let err = Http2PoolError::BackendUnavailable {
        message: "the backend was unreachable for reasons".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionRefused
    );
}

#[test]
fn test_h2_pool_typed_io_connection_reset() {
    let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "peer hung up");
    let err = Http2PoolError::BackendUnavailable {
        message: "opaque message with no hint".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::ConnectionReset);
}

#[test]
fn test_h2_pool_typed_io_broken_pipe() {
    let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed");
    let err = Http2PoolError::BackendUnavailable {
        message: "".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionClosed
    );
}

#[test]
fn test_h2_pool_typed_io_connection_aborted_is_closed() {
    let io_err = io::Error::new(io::ErrorKind::ConnectionAborted, "aborted mid-handshake");
    let err = Http2PoolError::BackendUnavailable {
        message: "".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionClosed
    );
}

#[test]
fn test_h2_pool_typed_io_read_timeout_is_readwritetimeout() {
    // Typed io::Error::TimedOut in a NON-BackendTimeout variant — this is a
    // read/write timeout (e.g., h2 frame read stalled), not a connect timeout.
    let io_err = io::Error::new(io::ErrorKind::TimedOut, "frame read stalled");
    let err = Http2PoolError::BackendUnavailable {
        message: "".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_h2_pool_typed_timeout_variant_is_connection_timeout() {
    // BackendTimeout variant with typed TimedOut source — this IS a
    // connect timeout, so we want ConnectionTimeout not ReadWriteTimeout.
    let io_err = io::Error::new(io::ErrorKind::TimedOut, "connect timed out");
    let err = Http2PoolError::BackendTimeout {
        message: "Connect timeout after 5s".to_string(),
        source: Some(io_err),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionTimeout
    );
}

#[test]
fn test_h2_pool_typed_eaddrnotavail_is_port_exhaustion() {
    // EADDRNOTAVAIL appears as raw_os_error(99) on Linux, 49 on BSD/macOS,
    // 10049 on Windows. Any of them in the typed chain should win.
    for raw in [99, 49, 10049] {
        let io_err = io::Error::from_raw_os_error(raw);
        let err = Http2PoolError::BackendUnavailable {
            message: "an attempted connection".to_string(),
            source: Some(BackendUnavailableSource::Io(io_err)),
        };
        assert_eq!(
            classify_http2_pool_error(&err),
            ErrorClass::PortExhaustion,
            "raw_os_error({raw}) should classify as PortExhaustion"
        );
    }
}

#[test]
fn test_h2_pool_typed_tls_source_is_tls_error() {
    // TLS handshake failure surfaced as an io::Error wrapper (what
    // tokio_rustls returns on most paths). The Tls variant marks this
    // explicitly even if the underlying ErrorKind is Other.
    let io_err = io::Error::other("handshake failure: bad cert");
    let err = Http2PoolError::BackendUnavailable {
        message: "TLS handshake failed".to_string(),
        source: Some(BackendUnavailableSource::Tls(io_err)),
    };
    // The io::Error carries no typed kind that our chain recognises, so we
    // fall through to the string fallback — which catches "tls/handshake".
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::TlsError);
}

#[test]
fn test_h2_pool_dns_marker_classifies_as_dns_lookup() {
    // DNS resolution marker — no concrete typed source.
    let err = Http2PoolError::BackendUnavailable {
        message: "unrelated message".to_string(),
        source: Some(BackendUnavailableSource::Dns),
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::DnsLookupError);
}

#[test]
fn test_h2_pool_invalid_dns_name_marker_classifies_as_dns_lookup() {
    let err = Http2PoolError::BackendUnavailable {
        message: "unrelated message".to_string(),
        source: Some(BackendUnavailableSource::InvalidDnsName),
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::DnsLookupError);
}

#[test]
fn test_h2_pool_error_source_chain_is_walkable() {
    // Confirm std::error::Error::source() exposes the typed chain so
    // external consumers (tracing, anyhow) can walk to the root cause.
    let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "nope");
    let err: Http2PoolError = Http2PoolError::BackendUnavailable {
        message: "wrapped".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    let src = std::error::Error::source(&err as &dyn std::error::Error)
        .expect("source should be populated");
    let inner = src.source().expect("inner io::Error should be exposed");
    let io_ref = inner
        .downcast_ref::<std::io::Error>()
        .expect("inner must downcast to io::Error");
    assert_eq!(io_ref.kind(), io::ErrorKind::ConnectionRefused);
}

// ── HTTP/2 pool classifier — string fallback (source: None) ─────────────
//
// These tests lock in the fallback behaviour for hand-constructed errors
// that intentionally omit a typed source. Production paths never hit this
// branch; it exists so synthetic test errors stay classifiable.

#[test]
fn test_h2_pool_backend_timeout_string_fallback_connect() {
    let err = Http2PoolError::BackendTimeout {
        message: "Connect timeout after 5s".to_string(),
        source: None,
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionTimeout
    );
}

#[test]
fn test_h2_pool_backend_timeout_string_fallback_read() {
    let err = Http2PoolError::BackendTimeout {
        message: "Read timed out".to_string(),
        source: None,
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_h2_pool_backend_unavailable_string_fallback_port_exhaustion() {
    let err = Http2PoolError::BackendUnavailable {
        message: "bind: address not available (os error 49)".to_string(),
        source: None,
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::PortExhaustion);
}

#[test]
fn test_h2_pool_backend_unavailable_string_fallback_dns() {
    let err = Http2PoolError::BackendUnavailable {
        message: "DNS resolution failed for api.example.com".to_string(),
        source: None,
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::DnsLookupError);
}

#[test]
fn test_h2_pool_backend_unavailable_string_fallback_tls() {
    let err = Http2PoolError::BackendUnavailable {
        message: "TLS handshake failed: unknown certificate".to_string(),
        source: None,
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::TlsError);
}

#[test]
fn test_h2_pool_backend_unavailable_string_fallback_refused() {
    let err = Http2PoolError::BackendUnavailable {
        message: "connection refused".to_string(),
        source: None,
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionRefused
    );
}

#[test]
fn test_h2_pool_backend_unavailable_string_fallback_reset() {
    let err = Http2PoolError::BackendUnavailable {
        message: "connection reset by peer".to_string(),
        source: None,
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::ConnectionReset);
}

#[test]
fn test_h2_pool_backend_unavailable_string_fallback_broken_pipe() {
    let err = Http2PoolError::BackendUnavailable {
        message: "broken pipe".to_string(),
        source: None,
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionClosed
    );
}

#[test]
fn test_h2_pool_backend_unavailable_string_fallback_goaway() {
    let err = Http2PoolError::BackendUnavailable {
        message: "received GOAWAY frame".to_string(),
        source: None,
    };
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::ProtocolError);
}

#[test]
fn test_h2_pool_internal_unknown_classifies_as_pool_error() {
    let err = Http2PoolError::Internal {
        message: "unclassifiable internal pool state".to_string(),
        source: Some(InternalSource::Message(
            "some config-time helper error".to_string(),
        )),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionPoolError
    );
}

#[test]
fn test_h2_pool_internal_io_propagates_through_chain() {
    // An Internal error with a typed io::Error source (e.g. PEM file read
    // failure) — the outer variant is Internal so classification stays at
    // ConnectionPoolError (this is a config/setup bug, not a transient
    // network issue), but the source chain is still walkable for logs.
    let io_err = io::Error::new(io::ErrorKind::NotFound, "cert file missing");
    let err = Http2PoolError::Internal {
        message: "Failed to read client cert".to_string(),
        source: Some(InternalSource::Io(io_err)),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionPoolError
    );
    // Source chain must still be walkable.
    let chain_has_io = std::error::Error::source(&err as &dyn std::error::Error)
        .and_then(|s| s.source())
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .is_some();
    assert!(chain_has_io, "Internal::Io source chain must be walkable");
}

// ── HTTP/3 classifier ────────────────────────────────────────────────────

use ferrum_edge::http3::client::classify_http3_error;

#[test]
fn test_h3_quinn_timeout() {
    let err = quinn::ConnectionError::TimedOut;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionTimeout);
}

#[test]
fn test_h3_quinn_reset() {
    let err = quinn::ConnectionError::Reset;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionReset);
}

#[test]
fn test_h3_quinn_locally_closed() {
    let err = quinn::ConnectionError::LocallyClosed;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionClosed);
}

#[test]
fn test_h3_quinn_version_mismatch() {
    let err = quinn::ConnectionError::VersionMismatch;
    assert_eq!(classify_http3_error(&err), ErrorClass::ProtocolError);
}

#[test]
fn test_h3_quinn_cids_exhausted() {
    let err = quinn::ConnectionError::CidsExhausted;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionPoolError);
}

#[test]
fn test_h3_fallback_string_tls() {
    // Simulate an anyhow-wrapped h3 error with a TLS message, which won't
    // downcast to a typed quinn variant — classifier should fall back to
    // string heuristics.
    let err: Box<dyn std::error::Error + Send + Sync> =
        "rustls handshake failed: bad certificate".into();
    assert_eq!(classify_http3_error(err.as_ref()), ErrorClass::TlsError);
}

#[test]
fn test_h3_fallback_string_timeout() {
    let err: Box<dyn std::error::Error + Send + Sync> = "read timed out waiting for frame".into();
    assert_eq!(
        classify_http3_error(err.as_ref()),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_h3_fallback_string_goaway() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "received GOAWAY from server, closing stream".into();
    assert_eq!(
        classify_http3_error(err.as_ref()),
        ErrorClass::ProtocolError
    );
}

#[test]
fn test_h3_fallback_string_port_exhaustion() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "bind: address not available (os error 99)".into();
    assert_eq!(
        classify_http3_error(err.as_ref()),
        ErrorClass::PortExhaustion
    );
}
