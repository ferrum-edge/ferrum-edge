//! Classification parity for GenericPool create-failure fan-out (#2950).
//!
//! The creator keeps its full typed/source error. Coalesced waiters receive a
//! cloneable `SharedPoolCreateError` that must reconstruct to the same
//! canonical `ErrorClass` the creator's typed classifier would report.

use ferrum_edge::http3::client::classify_http3_error;
use ferrum_edge::pool::{ShareablePoolCreateError, SharedPoolCreateError, SharedPoolCreateKind};
use ferrum_edge::proxy::grpc_proxy::{GrpcBackendUnavailableKind, GrpcProxyError, GrpcTimeoutKind};
use ferrum_edge::proxy::http2_pool::{
    BackendUnavailableSource, Http2PoolError, classify_http2_pool_error,
};
use ferrum_edge::retry::{ErrorClass, classify_grpc_proxy_error, request_reached_wire};
use std::io;

fn assert_wire_parity(creator_class: ErrorClass, waiter_class: ErrorClass) {
    assert_eq!(
        request_reached_wire(creator_class),
        request_reached_wire(waiter_class),
        "request_reached_wire/connection_error must match across fan-out \
         (creator={creator_class:?}, waiter={waiter_class:?})"
    );
}

fn assert_grpc_waiter_parity(creator: GrpcProxyError) {
    let expected = classify_grpc_proxy_error(&creator);
    let shared = creator.to_shared();
    assert_eq!(
        shared.error_class(),
        expected,
        "shared payload must capture creator ErrorClass ({expected:?})"
    );

    let waiter = GrpcProxyError::from(shared);
    let waiter_class = classify_grpc_proxy_error(&waiter);
    assert_eq!(
        waiter_class, expected,
        "waiter reconstruction must classify like the creator ({expected:?})"
    );
    assert_wire_parity(expected, waiter_class);
}

fn assert_h2_waiter_parity(creator: Http2PoolError) {
    let expected = classify_http2_pool_error(&creator);
    let shared = creator.to_shared();
    assert_eq!(shared.error_class(), expected);

    let waiter = Http2PoolError::from(shared);
    let waiter_class = classify_http2_pool_error(&waiter);
    assert_eq!(
        waiter_class, expected,
        "H2 waiter reconstruction must classify like the creator ({expected:?})"
    );
    assert_wire_parity(expected, waiter_class);
}

#[test]
fn grpc_dns_failure_preserves_classification_for_waiters() {
    let creator = GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::DnsResolution,
        "dns resolution failed for backend.example.com".into(),
    );
    assert_eq!(
        classify_grpc_proxy_error(&creator),
        ErrorClass::DnsLookupError
    );
    assert_grpc_waiter_parity(creator);
}

#[test]
fn grpc_tls_failure_preserves_classification_for_waiters() {
    let creator = GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::TlsHandshake,
        "tls handshake failed".into(),
    );
    assert_eq!(classify_grpc_proxy_error(&creator), ErrorClass::TlsError);
    assert_grpc_waiter_parity(creator);
}

#[test]
fn grpc_connect_timeout_preserves_classification_for_waiters() {
    let creator = GrpcProxyError::BackendTimeout {
        kind: GrpcTimeoutKind::Connect,
        message: "backend connect timeout".into(),
    };
    assert_eq!(
        classify_grpc_proxy_error(&creator),
        ErrorClass::ConnectionTimeout
    );
    assert_grpc_waiter_parity(creator);
}

#[test]
fn grpc_port_exhaustion_preserves_classification_for_waiters() {
    let creator = GrpcProxyError::backend_unavailable_with_source(
        GrpcBackendUnavailableKind::Connect,
        "connection failed".into(),
        io::Error::from_raw_os_error(99),
    );
    assert_eq!(
        classify_grpc_proxy_error(&creator),
        ErrorClass::PortExhaustion
    );
    assert_grpc_waiter_parity(creator);
}

#[test]
fn grpc_egress_policy_denial_preserves_classification_for_waiters() {
    let creator = GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::DnsResolution,
        "backend egress policy denied 169.254.169.254".into(),
    );
    assert_eq!(
        classify_grpc_proxy_error(&creator),
        ErrorClass::DispatchPolicyRejected
    );
    let shared = creator.to_shared();
    assert_grpc_waiter_parity(creator);

    // Structural kind must stay DnsResolution so proxy retry/CB guards that
    // combine `is_connect_class()` with `message.contains("egress policy")`
    // treat waiters like the creator (non-connect / health-neutral).
    let waiter = GrpcProxyError::from(shared);
    match waiter {
        GrpcProxyError::BackendUnavailable {
            kind: GrpcBackendUnavailableKind::DnsResolution,
            message,
            ..
        } => {
            assert!(
                message.contains("egress policy"),
                "egress wording must survive fan-out for connection_error guards"
            );
        }
        other => panic!("expected DnsResolution BackendUnavailable, got {other:?}"),
    }
}

#[test]
fn grpc_creator_retains_typed_unavailable_kind_not_only_shared_payload() {
    // Creator path must keep the original typed kind; only waiters use From.
    let creator = GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::DnsResolution,
        "dns resolution failed".into(),
    );
    let shared = creator.to_shared();
    assert_eq!(shared.kind(), SharedPoolCreateKind::Dns);

    match &creator {
        GrpcProxyError::BackendUnavailable {
            kind: GrpcBackendUnavailableKind::DnsResolution,
            ..
        } => {}
        other => panic!("creator must retain DnsResolution kind, got {other:?}"),
    }
    // Waiter reconstruction still classifies as DNS.
    let waiter = GrpcProxyError::from(shared);
    assert_eq!(
        classify_grpc_proxy_error(&waiter),
        ErrorClass::DnsLookupError
    );
}

#[test]
fn h2_dns_failure_preserves_classification_for_waiters() {
    let creator = Http2PoolError::BackendUnavailable {
        message: "dns resolution failed".into(),
        source: Some(BackendUnavailableSource::Dns),
    };
    assert_eq!(
        classify_http2_pool_error(&creator),
        ErrorClass::DnsLookupError
    );
    assert_h2_waiter_parity(creator);
}

#[test]
fn h2_tls_failure_preserves_classification_for_waiters() {
    let creator = Http2PoolError::BackendUnavailable {
        message: "tls handshake failed".into(),
        source: Some(BackendUnavailableSource::Tls(io::Error::other(
            "certificate verify failed",
        ))),
    };
    assert_eq!(classify_http2_pool_error(&creator), ErrorClass::TlsError);
    assert_h2_waiter_parity(creator);
}

#[test]
fn h2_connect_timeout_preserves_classification_for_waiters() {
    let creator = Http2PoolError::BackendTimeout {
        message: "connect timed out".into(),
        source: Some(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    };
    assert_eq!(
        classify_http2_pool_error(&creator),
        ErrorClass::ConnectionTimeout
    );
    assert_h2_waiter_parity(creator);
}

#[test]
fn h2_port_exhaustion_preserves_classification_for_waiters() {
    let creator = Http2PoolError::BackendUnavailable {
        message: "connect failed".into(),
        source: Some(BackendUnavailableSource::Io(io::Error::from_raw_os_error(
            99,
        ))),
    };
    assert_eq!(
        classify_http2_pool_error(&creator),
        ErrorClass::PortExhaustion
    );
    assert_h2_waiter_parity(creator);
}

#[test]
fn h2_negotiated_http1_preserves_protocol_class_and_pool_key() {
    let creator = Http2PoolError::BackendSelectedHttp1 {
        pool_key: "host|443||||||sni||true".into(),
    };
    assert_eq!(
        classify_http2_pool_error(&creator),
        ErrorClass::ProtocolError
    );
    let shared = creator.to_shared();
    assert_eq!(shared.kind(), SharedPoolCreateKind::NegotiatedHttp1);
    assert_eq!(shared.detail(), Some("host|443||||||sni||true"));
    let waiter = Http2PoolError::from(shared);
    match waiter {
        Http2PoolError::BackendSelectedHttp1 { pool_key } => {
            assert_eq!(pool_key, "host|443||||||sni||true");
        }
        other => panic!("expected BackendSelectedHttp1, got {other:?}"),
    }
}

#[test]
fn h2_connection_closed_preserves_classification_for_waiters() {
    let creator = Http2PoolError::BackendUnavailable {
        message: "peer closed during handshake".into(),
        source: Some(BackendUnavailableSource::Io(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "broken pipe",
        ))),
    };
    assert_eq!(
        classify_http2_pool_error(&creator),
        ErrorClass::ConnectionClosed
    );
    assert_h2_waiter_parity(creator);
}

#[test]
fn h2_connection_refused_preserves_classification_for_waiters() {
    let creator = Http2PoolError::BackendUnavailable {
        message: "connect failed".into(),
        source: Some(BackendUnavailableSource::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))),
    };
    assert_eq!(
        classify_http2_pool_error(&creator),
        ErrorClass::ConnectionRefused
    );
    assert_h2_waiter_parity(creator);
}

#[test]
fn anyhow_h3_timeout_waiter_keeps_typed_shared_classification() {
    let creator = anyhow::Error::from(io::Error::new(
        io::ErrorKind::TimedOut,
        "HTTP/3 backend connect timeout after 5000ms during HTTP/3 handshake",
    ));
    let expected = classify_http3_error(creator.as_ref());
    assert_eq!(expected, ErrorClass::ConnectionTimeout);

    let shared = ShareablePoolCreateError::to_shared(&creator);
    assert_eq!(shared.kind(), SharedPoolCreateKind::TimedOut);
    assert_eq!(shared.error_class(), ErrorClass::ConnectionTimeout);

    // Waiters observe anyhow wrapping SharedPoolCreateError (blanket From).
    let waiter = anyhow::Error::new(shared);
    let waiter_class = classify_http3_error(waiter.as_ref());
    assert_eq!(
        waiter_class,
        ErrorClass::ConnectionTimeout,
        "H3/anyhow waiter must retain typed timeout classification"
    );
    assert_wire_parity(expected, waiter_class);
    assert!(
        !request_reached_wire(waiter_class),
        "H3 create timeout is pre-wire (connection_error=true)"
    );
}

#[test]
fn anyhow_dns_style_setup_failure_preserves_classification_for_waiters() {
    // Capture through the shared anyhow path (boxed setup classifier), then
    // confirm H3 waiter classification reads the stored ErrorClass rather than
    // re-deriving from the message alone.
    let creator: anyhow::Error =
        anyhow::anyhow!("failed to lookup address information: Name or service not known");
    let shared = ShareablePoolCreateError::to_shared(&creator);
    assert_eq!(
        shared.error_class(),
        ErrorClass::DnsLookupError,
        "anyhow capture must use the canonical setup classifier for DNS wording"
    );
    assert_eq!(shared.kind(), SharedPoolCreateKind::Dns);

    let waiter = anyhow::Error::new(shared);
    assert_eq!(
        classify_http3_error(waiter.as_ref()),
        ErrorClass::DnsLookupError,
        "H3 classifier must honor SharedPoolCreateError.error_class for waiters"
    );
}

#[test]
fn shared_pool_create_error_from_classified_round_trips_error_class() {
    let shared = SharedPoolCreateError::from_classified(
        "denied by backend egress policy",
        ErrorClass::DispatchPolicyRejected,
        None,
    );
    assert_eq!(shared.kind(), SharedPoolCreateKind::DispatchPolicyRejected);
    assert_eq!(shared.error_class(), ErrorClass::DispatchPolicyRejected);

    let waiter = anyhow::Error::new(shared);
    let waiter_class = classify_http3_error(waiter.as_ref());
    assert_eq!(waiter_class, ErrorClass::DispatchPolicyRejected);
    assert!(
        request_reached_wire(waiter_class),
        "DispatchPolicyRejected must stay health-neutral (connection_error=false)"
    );
}

#[test]
fn h2_waiter_backend_unavailable_attaches_shared_source_for_classification() {
    let creator = Http2PoolError::BackendUnavailable {
        message: "dns resolution failed".into(),
        source: Some(BackendUnavailableSource::Dns),
    };
    let waiter = Http2PoolError::from(creator.to_shared());
    match waiter {
        Http2PoolError::BackendUnavailable {
            source: Some(BackendUnavailableSource::Shared(shared)),
            ..
        } => {
            assert_eq!(shared.error_class(), ErrorClass::DnsLookupError);
            assert!(!request_reached_wire(shared.error_class()));
        }
        other => panic!("expected Shared BackendUnavailable source, got {other:?}"),
    }
}
