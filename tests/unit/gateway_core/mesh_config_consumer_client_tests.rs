//! Mesh config-consumer client building blocks.
//!
//! * `tonic_tls_config` — the shared mesh control-plane TLS config must trust
//!   the bundled webpki roots when no CA is pinned (tonic's
//!   `ClientTlsConfig::new()` has none), while a pinned CA stays the exclusive
//!   trust anchor set.
//! * `status_report_failure_is_transient` — the one predicate deciding whether
//!   a failed native `ReportMeshSliceStatus` may be retried (issue #6298).

use ferrum_edge::grpc::dp_client::DpGrpcTlsConfig;
use ferrum_edge::modes::mesh::config_consumer::common::tonic_tls_config;
use ferrum_edge::modes::mesh::config_consumer::native_client::status_report_failure_is_transient;

#[test]
fn mesh_cp_tls_selects_webpki_roots_only_without_a_pinned_ca() {
    let no_ca = DpGrpcTlsConfig {
        ca_cert_pem: None,
        client_cert_pem: None,
        client_key_pem: None,
    };
    let rendered = format!("{:?}", tonic_tls_config(&no_ca));
    assert!(
        rendered.contains("with_webpki_roots: true"),
        "no-CA https mesh CP must trust the bundled webpki roots: {rendered}"
    );

    let pinned = DpGrpcTlsConfig {
        ca_cert_pem: Some(
            b"-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n".to_vec(),
        ),
        client_cert_pem: None,
        client_key_pem: None,
    };
    let rendered = format!("{:?}", tonic_tls_config(&pinned));
    assert!(
        rendered.contains("with_webpki_roots: false"),
        "a pinned CA must not be widened with public roots: {rendered}"
    );
}

#[test]
fn status_report_retry_predicate_admits_only_transient_codes() {
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::DeadlineExceeded,
        tonic::Code::ResourceExhausted,
        tonic::Code::Unknown,
    ] {
        assert!(
            status_report_failure_is_transient(code),
            "{code:?} must stay retryable"
        );
    }
    for code in [
        tonic::Code::FailedPrecondition,
        tonic::Code::InvalidArgument,
        tonic::Code::PermissionDenied,
        tonic::Code::Unauthenticated,
        tonic::Code::NotFound,
        tonic::Code::Unimplemented,
        tonic::Code::Internal,
    ] {
        assert!(
            !status_report_failure_is_transient(code),
            "an explicit refusal ({code:?}) must never be retried"
        );
    }
}
