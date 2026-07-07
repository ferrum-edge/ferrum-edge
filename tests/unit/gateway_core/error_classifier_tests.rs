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

use ferrum_edge::proxy::hbone_pool::HbonePoolError;
use ferrum_edge::proxy::http2_pool::{
    BackendUnavailableSource, Http2PoolError, InternalSource, classify_http2_pool_error,
};
use ferrum_edge::retry::{ErrorClass, classify_boxed_setup_error, request_reached_wire};
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
fn test_h2_pool_typed_io_connection_reset_classifies_as_connection_refused() {
    // The HTTP/2 pool is a pure connection-establishment layer — every
    // io error it surfaces is pre-wire. A SYN-RST'd connect attempt
    // produces io::ErrorKind::ConnectionReset, which would normally
    // classify as `ConnectionReset` (post-wire under the unified
    // `request_reached_wire` boundary). Inside the H2 pool we collapse
    // it to `ConnectionRefused` so `retry_on_connect_failure` fires.
    let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "peer hung up");
    let err = Http2PoolError::BackendUnavailable {
        message: "opaque message with no hint".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionRefused,
        "H2 pool RST is connect-phase — must collapse to ConnectionRefused, not ConnectionReset"
    );
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
fn test_h2_pool_typed_io_timeout_in_backend_unavailable_is_connect_timeout() {
    // The HTTP/2 pool is connect-phase only — it doesn't read frames or
    // forward requests, it just establishes the connection. So an
    // io::ErrorKind::TimedOut surfaced via BackendUnavailable is a
    // connect-phase timeout (e.g., TLS handshake stalled), not a
    // read/write timeout. Classify as ConnectionTimeout so the unified
    // `request_reached_wire` boundary correctly treats this as pre-wire
    // and fires `retry_on_connect_failure`.
    let io_err = io::Error::new(io::ErrorKind::TimedOut, "tls handshake stalled");
    let err = Http2PoolError::BackendUnavailable {
        message: "".to_string(),
        source: Some(BackendUnavailableSource::Io(io_err)),
    };
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionTimeout,
        "H2 pool timeouts are connect-phase — must classify as ConnectionTimeout, not ReadWriteTimeout"
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

// Regression: before narrowing, the fallback classifier matched the bare
// substring "stream" and would mislabel upstream-selection/backend
// failures (which typically embed "upstream" in the error text) as
// `ProtocolError`. Keep the `stream`-adjacent matches anchored to
// tokens h3/quinn actually emit so load-balancer failures don't bleed
// into H3 protocol-error metrics.
#[test]
fn test_h3_fallback_upstream_is_not_protocol_error() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "No healthy targets for upstream some-upstream-id".into();
    assert_eq!(
        classify_http3_error(err.as_ref()),
        ErrorClass::RequestError,
        "upstream-selection text must not match the 'stream' branch"
    );

    let err2: Box<dyn std::error::Error + Send + Sync> = "upstream target connection failed".into();
    assert_eq!(
        classify_http3_error(err2.as_ref()),
        ErrorClass::RequestError,
        "upstream failure must not match the 'stream' branch"
    );
}

#[test]
fn test_h3_fallback_stream_protocol_markers_still_match() {
    // Verify the narrowed matchers still catch the real H3/QUIC stream-
    // protocol signals: reset_stream, stream id, stream closed, h3::,
    // quic — none of which overlap with "upstream".
    for msg in [
        "received RESET_STREAM frame",
        "stream id 42 already in use",
        "stream_id overflow",
        "stream_closed by peer",
        "stream closed with error",
        "h3::Error: bad frame",
        "quic transport error",
    ] {
        let err: Box<dyn std::error::Error + Send + Sync> = msg.into();
        assert_eq!(
            classify_http3_error(err.as_ref()),
            ErrorClass::ProtocolError,
            "expected ProtocolError for {msg:?}"
        );
    }
}

// ── Mesh-transport (HBONE / mesh-mTLS) boxed setup-error classification ──
//
// The WebSocket-over-mesh egress dial returns `HbonePoolError` BOXED to the
// shared WebSocket failure handler, which classifies via
// `retry::classify_boxed_setup_error`. That handler must keep the pre-wire
// connect-failure semantics `HbonePoolError::error_class()` already encodes —
// otherwise pre-wire mesh setup failures (missing gateway SVID, invalid
// `mesh.spiffe_id`, DNS failure, peer without Extended CONNECT) would be
// misclassified as post-wire and corrupt `retry_on_connect_failure`,
// backend-admission `connection_error`, and circuit-breaker passive health.
// These assert the boxed-error downcast added to `classify_typed_chain`.

#[test]
fn test_boxed_hbone_no_svid_is_pre_wire_connection_pool_error() {
    // A missing gateway SVID fails before any dial — pre-wire by construction.
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(HbonePoolError::NoSvid);
    let class = classify_boxed_setup_error(err.as_ref());
    assert_eq!(class, ErrorClass::ConnectionPoolError);
    assert!(
        !request_reached_wire(class),
        "missing-SVID must be treated as pre-wire (the request never crossed the wire)"
    );
}

#[test]
fn test_boxed_hbone_invalid_peer_spiffe_tag_is_pre_wire() {
    // A corrupt pinned `mesh.spiffe_id` fails the dial closed — pre-wire.
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(HbonePoolError::InvalidPeerSpiffeTag {
            value: "not-a-spiffe-id".to_string(),
            message: "missing scheme".to_string(),
        });
    let class = classify_boxed_setup_error(err.as_ref());
    assert_eq!(class, ErrorClass::ConnectionPoolError);
    assert!(!request_reached_wire(class));
}

#[test]
fn test_boxed_hbone_dns_lookup_is_pre_wire_dns_error() {
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(HbonePoolError::DnsLookup {
        host: "svc-b.ferrum.svc.cluster.local".to_string(),
        message: "no addresses".to_string(),
    });
    let class = classify_boxed_setup_error(err.as_ref());
    assert_eq!(class, ErrorClass::DnsLookupError);
    assert!(!request_reached_wire(class));
}

#[test]
fn test_boxed_hbone_extended_connect_unsupported_is_protocol_error() {
    // A peer that never negotiated RFC 8441 (Sidecar WS Extended CONNECT) is a
    // ProtocolError — post-wire by class (the connection established), so it is
    // NOT replayed under `retry_on_connect_failure`. The key assertion is that
    // the downcast routes through `error_class()` rather than the substring
    // fallback (which has no token for this message).
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(HbonePoolError::ExtendedConnectUnsupported {
            authority: "svc-b.ferrum.svc.cluster.local:8080".to_string(),
        });
    assert_eq!(
        classify_boxed_setup_error(err.as_ref()),
        ErrorClass::ProtocolError
    );
}

#[test]
fn test_boxed_hbone_connect_refused_is_pre_wire_connection_refused() {
    // The TCP connect to the peer's transport port was refused — the
    // variant-level `error_class()` maps the inner io kind to a pre-wire
    // class. Asserting via the BOXED path proves the downcast wins over the
    // generic io-error chain arm (which would also need the connect-phase
    // override to land here).
    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(HbonePoolError::Connect {
        addr: "127.0.0.1:15008".to_string(),
        source: io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused"),
    });
    let class = classify_boxed_setup_error(err.as_ref());
    assert_eq!(class, ErrorClass::ConnectionRefused);
    assert!(!request_reached_wire(class));
}

#[test]
fn test_boxed_hbone_missing_cross_cluster_sni_is_pre_wire_connection_pool_error() {
    // A cross-cluster Ambient WebSocket target missing `mesh.eastwest_sni` is
    // refused BEFORE any gateway dial (issue #2010 codex Finding 2). The WS
    // egress path boxes this typed variant so `classify_boxed_setup_error`
    // downcasts it to a PRE-WIRE class — keeping the reject retry-eligible under
    // `retry_on_connect_failure` and recorded as a mesh SETUP failure, not a
    // post-wire backend request failure. Mirrors the Sidecar
    // `MeshMtlsDialError::MissingCrossClusterSni` posture.
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(HbonePoolError::MissingCrossClusterSni);
    let class = classify_boxed_setup_error(err.as_ref());
    assert_eq!(class, ErrorClass::ConnectionPoolError);
    assert!(
        !request_reached_wire(class),
        "a missing cross-cluster SNI override is a pre-wire fail-closed reject (no dial happened)"
    );
}

#[test]
fn test_boxed_hbone_missing_cross_cluster_trust_domain_is_pre_wire_connection_pool_error() {
    // Sibling of the SNI case: a cross-cluster Ambient WebSocket target missing
    // `mesh.trust_domain` is refused pre-dial and must stay pre-wire so the
    // retry / health accounting treats it as a mesh setup failure.
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(HbonePoolError::MissingCrossClusterTrustDomain);
    let class = classify_boxed_setup_error(err.as_ref());
    assert_eq!(class, ErrorClass::ConnectionPoolError);
    assert!(
        !request_reached_wire(class),
        "a missing cross-cluster trust domain is a pre-wire fail-closed reject (no dial happened)"
    );
}

#[test]
fn test_boxed_hbone_missing_cross_cluster_authority_host_is_pre_wire_connection_pool_error() {
    // Third sibling (issue #2010 codex Finding A): a cross-cluster Ambient
    // WebSocket target missing `mesh.hbone_authority_host` would otherwise fall
    // back to the synthetic `mesh-xc-hbone|...` key as the inner CONNECT
    // authority, establishing the east-west TLS/H2 connection FIRST and only
    // failing later. The WS egress path now rejects it BEFORE any dial with this
    // typed variant, which must classify PRE-WIRE (`ConnectionPoolError`) so it is
    // recorded as a mesh setup failure and stays retry-eligible under
    // `retry_on_connect_failure` — never charged to the backend / circuit breaker.
    let err: Box<dyn std::error::Error + Send + Sync> =
        Box::new(HbonePoolError::MissingCrossClusterAuthorityHost);
    let class = classify_boxed_setup_error(err.as_ref());
    assert_eq!(class, ErrorClass::ConnectionPoolError);
    assert!(
        !request_reached_wire(class),
        "a missing cross-cluster authority host is a pre-wire fail-closed reject (no dial happened)"
    );
}
