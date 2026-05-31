use std::time::Duration;

use tonic::transport::{Certificate, Identity};

use crate::grpc::dp_client::{DpGrpcTlsConfig, DpGrpcTlsReload, build_dp_grpc_tls_config};
pub use crate::util::backoff::{BACKOFF_INITIAL_SECS, jittered_backoff, next_backoff_secs};
#[cfg(test)]
use crate::util::backoff::{BACKOFF_MAX_SECS, jittered_backoff_with_entropy};

pub fn tonic_tls_config(tls: &DpGrpcTlsConfig) -> tonic::transport::ClientTlsConfig {
    let mut client_tls = tonic::transport::ClientTlsConfig::new();

    if let Some(ref ca_pem) = tls.ca_cert_pem {
        client_tls = client_tls.ca_certificate(Certificate::from_pem(ca_pem));
    }

    if let (Some(cert_pem), Some(key_pem)) = (&tls.client_cert_pem, &tls.client_key_pem) {
        client_tls = client_tls.identity(Identity::from_pem(cert_pem, key_pem));
    }

    client_tls
}

/// Whether a live stream on a *fallback* CP should race a primary-CP retry timer.
///
/// Shared by the xDS and native `MeshSubscribe` clients so both honor
/// `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` identically: only retry the primary
/// when (a) we are currently connected to a fallback CP, (b) the operator
/// configured a non-zero retry interval, and (c) a first slice has already been
/// installed — so we never abandon the only reachable CP before we have config.
pub fn should_race_primary_retry(
    is_fallback: bool,
    primary_retry_secs: u64,
    has_first_slice: bool,
) -> bool {
    is_fallback && primary_retry_secs > 0 && has_first_slice
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

pub async fn wait_optional_tls_reload(mut revision_rx: Option<tokio::sync::watch::Receiver<u64>>) {
    let changed = if let Some(revision_rx) = revision_rx.as_mut() {
        revision_rx.changed().await.is_ok()
    } else {
        false
    };
    if !changed {
        std::future::pending::<()>().await;
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
        Err(error) => {
            tracing::warn!(
                revision,
                error = %error,
                "{} gRPC TLS source revision changed but rebuild failed; keeping previous mesh client TLS material",
                reload.label
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
