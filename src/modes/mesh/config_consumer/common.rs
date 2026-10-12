use std::time::Duration;

use tonic::transport::{Certificate, Identity};

pub use crate::grpc::dp_client::wait_optional_tls_reload;
use crate::grpc::dp_client::{DpGrpcTlsConfig, DpGrpcTlsReload, build_dp_grpc_tls_config};
pub use crate::util::backoff::{BACKOFF_INITIAL_SECS, jittered_backoff, next_backoff_secs};
#[cfg(test)]
pub(crate) use crate::util::backoff::{BACKOFF_MAX_SECS, jittered_backoff_with_entropy};

/// Maximum inbound gRPC message size for mesh config streams.
///
/// The bound is explicit so large-but-valid slices do not depend on tonic's
/// default, while malformed or oversized control-plane responses still fail
/// closed before unbounded allocation.
pub const MESH_CONFIG_GRPC_MAX_DECODING_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Build the tonic client TLS config for a mesh control-plane endpoint.
///
/// A pinned CA bundle is the ONLY trust anchor set. Without one, the bundled
/// Mozilla (webpki) roots are selected explicitly: tonic's
/// `ClientTlsConfig::new()` starts with no anchors, and the `tls-webpki-roots`
/// Cargo feature only makes the roots available, so a publicly trusted CP
/// certificate would otherwise have nothing to chain to. Verification is never
/// disabled.
pub fn tonic_tls_config(tls: &DpGrpcTlsConfig) -> tonic::transport::ClientTlsConfig {
    let mut client_tls = tonic::transport::ClientTlsConfig::new();

    if let Some(ref ca_pem) = tls.ca_cert_pem {
        client_tls = client_tls.ca_certificate(Certificate::from_pem(ca_pem));
    } else {
        client_tls = client_tls.with_webpki_roots();
    }

    if let (Some(cert_pem), Some(key_pem)) = (&tls.client_cert_pem, &tls.client_key_pem) {
        client_tls = client_tls.identity(Identity::from_pem(cert_pem, key_pem));
    }

    client_tls
}

/// Whether a live stream on a *fallback* CP should race a primary-CP retry future.
///
/// The caller's retry future is responsible for waiting until the first slice is
/// installed before sleeping the configured interval, so a fallback stream that
/// delivers the first slice and stays healthy can still fail back to primary.
pub fn should_race_primary_retry(is_fallback: bool, primary_retry_secs: u64) -> bool {
    is_fallback && primary_retry_secs > 0
}

pub async fn sleep_or_shutdown(
    duration: Duration,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = wait_for_shutdown(&mut shutdown_rx) => true,
    }
}

pub async fn wait_for_shutdown(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

pub fn refresh_dp_grpc_tls_config_if_changed(
    tls_config: &mut Option<DpGrpcTlsConfig>,
    tls_reload: Option<&DpGrpcTlsReload>,
    cp_urls: &[String],
    last_tls_revision: &mut u64,
) {
    let Some(reload) = tls_reload else {
        return;
    };
    let revision = *reload.revision_rx.borrow();
    if revision == *last_tls_revision {
        return;
    }

    *last_tls_revision = revision;
    match build_dp_grpc_tls_config(&reload.env_config, cp_urls, reload.label) {
        Ok(next_config) => {
            *tls_config = next_config;
            tracing::info!(
                revision,
                "{} gRPC TLS material reloaded; reconnecting mesh config stream with rotated material",
                reload.label
            );
        }
        Err(_) => {
            tracing::warn!(
                revision,
                error = "gRPC TLS material rebuild failed (details withheld)",
                "{} gRPC TLS source revision changed but rebuild failed; keeping previous mesh client TLS material",
                reload.label
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod diagnostic_test_support {
    // Same thread-local fmt-writer capture used by the CLI diagnostic tests.
    // Kept here so the scoped inline tests share it without a global subscriber.
    #[derive(Clone, Default)]
    pub(crate) struct DiagnosticLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl DiagnosticLogs {
        pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
            crate::diagnostic_test_interest::ensure_interest_floor();
            tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_target(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(self.clone())
                .finish()
        }

        pub(crate) fn output(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for DiagnosticLogs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DiagnosticLogs {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    crate::diagnostic_test_interest::capture_regression!(
        subscriber = super::DiagnosticLogs,
        tracing::Level::TRACE
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_stream_emission_fields_are_sanitized_individually() {
        // Connecting startup/subscription paths needs a live CP. Pin each
        // scalar field at its emission, not just the presence of one sanitizer
        // elsewhere in the event. Counters and closed protocol labels stay raw.
        let cases: &[(&str, &[&str])] = &[
            (
                include_str!("native_client.rs"),
                &["cp_url", "liveness_bound_secs", "max_silence_secs"],
            ),
            (
                include_str!("xds_client.rs"),
                &["cp_url", "previous_cp_url", "liveness_bound_secs", "nonce"],
            ),
            (
                include_str!("stock_xds_client.rs"),
                &["liveness_bound_secs", "authorization_lifetime_secs"],
            ),
            (
                include_str!("stock_xds_credential.rs"),
                &[
                    "watch_interval_secs",
                    "max_stream_lifetime_secs",
                    "refresh_skew_secs",
                ],
            ),
            (
                include_str!("../federation.rs"),
                &[
                    "cluster",
                    "trust_domain",
                    "endpoint",
                    "poll_interval_seconds",
                    "max_stale_seconds",
                    "fail_open",
                ],
            ),
        ];
        for (source, fields) in cases {
            let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
            for field in *fields {
                let assignment = format!("{field} =");
                let shorthand = format!("{field},");
                let mut emissions = 0;
                let mut in_event = false;
                for line in production.lines().map(str::trim) {
                    in_event |= ["info!(", "warn!(", "error!(", "debug!(", "trace!("]
                        .iter()
                        .any(|event| line.contains(*event));
                    if !in_event {
                        continue;
                    }
                    assert_ne!(line, shorthand, "raw shorthand emission: {field}");
                    if line.starts_with(&assignment) {
                        emissions += 1;
                        assert!(
                            line.contains("sanitize_startup_scalar(")
                                || line.contains("sanitize_startup_cause("),
                            "unsanitized {field} emission: {line}"
                        );
                    }
                    if line.ends_with(");") {
                        in_event = false;
                    }
                }
                assert!(emissions > 0, "field disappeared from diagnostics: {field}");
            }
        }
    }

    #[test]
    fn next_backoff_does_not_increase_after_clean_stream_end() {
        assert_eq!(
            next_backoff_secs(BACKOFF_INITIAL_SECS, false),
            BACKOFF_INITIAL_SECS
        );
        assert_eq!(next_backoff_secs(16, false), BACKOFF_INITIAL_SECS);
    }

    #[test]
    fn next_backoff_increases_after_connection_error_until_cap() {
        assert_eq!(next_backoff_secs(1, true), 2);
        assert_eq!(next_backoff_secs(16, true), 30);
        assert_eq!(next_backoff_secs(30, true), 30);
    }

    #[test]
    fn jittered_backoff_with_entropy_stays_within_expected_range() {
        let samples = [0, 249, 250, 499, u64::MAX];

        for entropy in samples {
            let duration = jittered_backoff_with_entropy(1, entropy);
            assert!(duration >= Duration::from_millis(750));
            assert!(duration < Duration::from_millis(1250));
        }
    }

    #[test]
    fn jittered_backoff_preserves_max_backoff_floor() {
        for entropy in [0, 1, 7_499, u64::MAX] {
            let duration = jittered_backoff_with_entropy(BACKOFF_MAX_SECS, entropy);
            assert!(duration >= Duration::from_millis(22_500));
            assert!(duration < Duration::from_millis(37_500));
        }
    }

    #[test]
    fn jittered_backoff_never_sleeps_below_minimum() {
        assert_eq!(
            jittered_backoff_with_entropy(0, 0),
            Duration::from_millis(100)
        );
    }
}
