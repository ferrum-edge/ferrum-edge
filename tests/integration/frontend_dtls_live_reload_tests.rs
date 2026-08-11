//! Frontend DTLS material live reload (issue #3730).
//!
//! Covers file-source fingerprint reload under the shared frontend live-reload
//! subscription contract, and watcher shutdown/cancellation without leaks.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::source::subscription::{
    AsyncMaterialSetReloadConfig, WatchedMaterialSource, request_material_set_reload,
    spawn_async_material_set_reload_task,
};
use ferrum_edge::tls::source::{CertSource, MaterialKind};
use tokio::sync::watch;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn write_ecdsa_material(dir: &std::path::Path, san: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    ensure_crypto_provider();
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![san.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_path = dir.join(format!("{san}-cert.pem"));
    let key_path = dir.join(format!("{san}-key.pem"));
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (cert_path, key_path)
}

fn build_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> ferrum_edge::dtls::FrontendDtlsConfig {
    ferrum_edge::dtls::build_frontend_dtls_config(
        cert_path.to_str().expect("cert utf8"),
        key_path.to_str().expect("key utf8"),
        None,
        &[],
    )
    .expect("build frontend dtls config")
}

#[tokio::test]
async fn dtls_material_watcher_rotates_on_file_change_and_exits_on_shutdown() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_ecdsa_material(dir.path(), "watch");

    let rebuilds = Arc::new(AtomicUsize::new(0));
    let rebuilds_for_task = rebuilds.clone();
    let cert_for_rebuild = cert_path.clone();
    let key_for_rebuild = key_path.clone();

    let (revision_tx, mut revision_rx) = watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = spawn_async_material_set_reload_task(
        AsyncMaterialSetReloadConfig {
            surface: "test_frontend_dtls_reload",
            sources: vec![
                WatchedMaterialSource::new(
                    "dtls_cert",
                    CertSource::parse(
                        cert_path.to_string_lossy().into_owned(),
                        MaterialKind::Cert,
                    ),
                    MaterialKind::Cert,
                ),
                WatchedMaterialSource::new(
                    "dtls_key",
                    CertSource::parse(key_path.to_string_lossy().into_owned(), MaterialKind::Key),
                    MaterialKind::Key,
                ),
            ],
            interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: EnvConfig::default().tls_max_material_size_bytes,
            rebuild: Box::new(move || {
                let rebuilds_for_task = rebuilds_for_task.clone();
                let cert_for_rebuild = cert_for_rebuild.clone();
                let key_for_rebuild = key_for_rebuild.clone();
                Box::pin(async move {
                    // Prove the production builder accepts the rotated bytes as
                    // one candidate generation before any listener publish.
                    let _ = build_config(&cert_for_rebuild, &key_for_rebuild);
                    rebuilds_for_task.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }),
        },
        Some(shutdown_rx),
    );

    // Rotate cert+key content under the same source paths (file:// contract).
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("rotate key");
    let params = rcgen::CertificateParams::new(vec!["watch-rotated".to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    std::fs::write(&cert_path, cert.pem()).expect("rewrite cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("rewrite key");

    assert!(request_material_set_reload("test_frontend_dtls_reload"));
    tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
        .await
        .expect("rotation should bump revision")
        .expect("watcher alive");
    assert_eq!(*revision_rx.borrow(), 1);
    assert_eq!(rebuilds.load(Ordering::SeqCst), 1);

    shutdown_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("watcher should exit on shutdown")
        .expect("watcher join");
}

#[tokio::test]
async fn dtls_material_watcher_keeps_prior_state_when_rebuild_fails() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = write_ecdsa_material(dir.path(), "fail");

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_task = attempts.clone();
    let (revision_tx, mut revision_rx) = watch::channel(0u64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = spawn_async_material_set_reload_task(
        AsyncMaterialSetReloadConfig {
            surface: "test_frontend_dtls_reload_fail",
            sources: vec![
                WatchedMaterialSource::new(
                    "dtls_cert",
                    CertSource::parse(
                        cert_path.to_string_lossy().into_owned(),
                        MaterialKind::Cert,
                    ),
                    MaterialKind::Cert,
                ),
                WatchedMaterialSource::new(
                    "dtls_key",
                    CertSource::parse(key_path.to_string_lossy().into_owned(), MaterialKind::Key),
                    MaterialKind::Key,
                ),
            ],
            interval: Duration::from_secs(3600),
            revision_tx,
            max_material_bytes: EnvConfig::default().tls_max_material_size_bytes,
            rebuild: Box::new(move || {
                let attempts_for_task = attempts_for_task.clone();
                Box::pin(async move {
                    attempts_for_task.fetch_add(1, Ordering::SeqCst);
                    Err(anyhow::anyhow!("simulated malformed DTLS candidate"))
                })
            }),
        },
        Some(shutdown_rx),
    );

    std::fs::write(&cert_path, b"not-a-certificate").expect("corrupt cert");
    assert!(request_material_set_reload("test_frontend_dtls_reload_fail"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        *revision_rx.borrow(),
        0,
        "failed rebuild must not bump the accepted revision"
    );
    assert!(attempts.load(Ordering::SeqCst) >= 1);

    shutdown_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("watcher should exit on shutdown")
        .expect("watcher join");
}

#[test]
fn frontend_dtls_live_reload_defaults_to_static_until_restart() {
    let env = EnvConfig::default();
    assert!(
        !env.frontend_tls_live_reload_enabled,
        "DTLS material stays static until restart unless the shared frontend live-reload flag is enabled"
    );
}
