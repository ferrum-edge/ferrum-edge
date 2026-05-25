//! Opt-in frontend TLS cert/key live reload.
//!
//! Default behavior remains static: cert/key files are read once at startup and
//! rotation requires a restart. When `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`,
//! a background poll task watches the configured TLS material sources for the
//! proxy HTTPS / H2 / H3 listeners and (separately) the admin HTTPS listener.
//! On any material fingerprint change, the task rebuilds the
//! `rustls::ServerConfig` using the caller-supplied closure and atomically
//! swaps it into the shared `SharedFrontendTls` slot. A failed validation
//! (parse / expired / not-yet-valid / key mismatch / closure error) keeps the
//! previous config and emits a `warn!` — the gateway never serves a known-bad
//! TLS config from this path.
//!
//! In-flight TLS sessions keep their original `ServerConfig` clone (rustls
//! consults the config only during handshake; an `ArcSwap` swap does not tear
//! down live sessions). Only newly accepted connections handshake against the
//! new config.
//!
//! The H3 / QUIC listener observes swaps through the same slot via a
//! [`tokio::sync::watch`] revision counter; the H3 task rebuilds its
//! [`quinn::ServerConfig`] and applies it with
//! [`quinn::Endpoint::set_server_config`]. Existing QUIC connections keep
//! serving.
//!
//! Backend client TLS, per-proxy `backend_tls_client_cert_path`, and the DTLS
//! frontend are intentionally NOT live-reloaded here — backend SVID rotation
//! lives in [`crate::proxy`] under the `gateway_svid_*` watch, and DTLS
//! material remains a static startup input.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::tls::source::subscription::{
    MaterialSetReloadConfig, WatchedMaterialSource, spawn_material_set_reload_task,
};

/// Shared frontend `ServerConfig` slot. Listeners load this on each new
/// connection, so a swap takes effect on the next handshake without touching
/// in-flight TLS sessions.
pub type SharedFrontendTls = Arc<ArcSwap<Option<Arc<ServerConfig>>>>;

/// Construct an empty `SharedFrontendTls` slot (no TLS configured). This is
/// the default for plaintext-only listeners and for instances that have not
/// loaded TLS at startup.
pub fn empty_frontend_tls_slot() -> SharedFrontendTls {
    Arc::new(ArcSwap::new(Arc::new(None)))
}

/// Build a `SharedFrontendTls` slot pre-populated with the startup-loaded
/// `Arc<ServerConfig>`.
pub fn frontend_tls_slot_with(initial: Arc<ServerConfig>) -> SharedFrontendTls {
    Arc::new(ArcSwap::new(Arc::new(Some(initial))))
}

/// Configuration for [`spawn_frontend_tls_reload_task`].
pub struct FrontendTlsReloadConfig {
    /// Human-readable identifier for logs ("proxy https", "admin https",
    /// "mesh inbound"). Surfaces emit a Prometheus label off this name when
    /// metrics are wired up.
    pub surface: &'static str,
    /// TLS material sources whose fingerprint changes should trigger a rebuild.
    pub sources: Vec<WatchedMaterialSource>,
    /// Live `SharedFrontendTls` slot the watcher swaps on a validated change.
    pub slot: SharedFrontendTls,
    /// Poll interval; clamp at 1s upstream of this function.
    pub interval: Duration,
    /// Revision sender. Subscribers (e.g., the H3 listener) observe `.changed()`
    /// to rebuild listener-specific TLS material (e.g., `QuicServerConfig`) and
    /// apply it with `Endpoint::set_server_config`. The watcher bumps this
    /// after a successful swap; the value is the rotation generation.
    pub revision_tx: watch::Sender<u64>,
    /// Closure invoked on every change to rebuild the `ServerConfig`.
    /// The closure is responsible for the surface-specific options that
    /// startup applied (ALPN advertisement, early-data, kTLS opt-in, client
    /// CA verification, session tickets). A returned `Err` keeps the previous
    /// config and emits a `warn!`.
    pub rebuild: FrontendTlsRebuildFn,
}

/// Surface-specific rebuild closure.
pub type FrontendTlsRebuildFn =
    Box<dyn Fn() -> Result<Arc<ServerConfig>, anyhow::Error> + Send + Sync + 'static>;

/// Spawn the frontend TLS file-watch task.
///
/// The task polls `interval` and, on every detected file change, calls
/// `rebuild` and either swaps the resulting config into `slot` (success) or
/// keeps the previous config and logs a `warn!` (failure). The first failing
/// fingerprint after a successful state is remembered so the watcher does not
/// re-warn on every poll while a bad state is stable.
///
/// The handle exits cleanly when the shutdown receiver fires.
pub fn spawn_frontend_tls_reload_task(
    config: FrontendTlsReloadConfig,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> JoinHandle<()> {
    let FrontendTlsReloadConfig {
        surface,
        sources,
        slot,
        interval,
        revision_tx,
        rebuild,
    } = config;

    let publish_rebuild = Box::new(move || {
        let new_config = rebuild()?;
        slot.store(Arc::new(Some(new_config)));
        Ok(())
    });

    spawn_material_set_reload_task(
        MaterialSetReloadConfig {
            surface,
            sources,
            interval,
            revision_tx,
            rebuild: publish_rebuild,
        },
        shutdown_rx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn empty_slot_has_none_inside() {
        let slot = empty_frontend_tls_slot();
        assert!(slot.load().is_none());
    }

    #[tokio::test]
    async fn reload_task_swaps_on_change_and_keeps_old_on_failure() {
        use crate::tls::source::{CertSource, MaterialKind};
        use rustls::crypto::ring::default_provider;
        let _ = default_provider().install_default();

        // Build a placeholder initial config so the slot holds Some(..).
        let initial = build_dummy_server_config();
        let slot = frontend_tls_slot_with(initial.clone());

        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, b"placeholder cert").expect("write cert");
        std::fs::write(&key, b"placeholder key").expect("write key");

        // Use an atomic mode flag: on first attempt return Ok with a fresh
        // ServerConfig; on second attempt return Err to simulate a bad
        // rotation. Verify the slot keeps the old config after the failure.
        let attempts = Arc::new(AtomicUsize::new(0));
        let success_config = build_dummy_server_config();

        let attempts_clone = attempts.clone();
        let success_clone = success_config.clone();
        let rebuild: FrontendTlsRebuildFn = Box::new(move || {
            let attempt = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Ok(success_clone.clone())
            } else {
                Err(anyhow::anyhow!("simulated cert expired"))
            }
        });

        let (revision_tx, mut revision_rx) = watch::channel(0u64);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_frontend_tls_reload_task(
            FrontendTlsReloadConfig {
                // Unique surface per test: the force-reload registry is a
                // process-global keyed by surface, so a shared name lets a
                // parallel test's task drop this one's force sender and exit
                // early (`cargo test --lib` runs tests concurrently).
                surface: "test_frontend_reload_swap",
                sources: vec![
                    WatchedMaterialSource::new(
                        "cert",
                        CertSource::parse(cert.to_string_lossy().into_owned(), MaterialKind::Cert),
                        MaterialKind::Cert,
                    ),
                    WatchedMaterialSource::new(
                        "key",
                        CertSource::parse(key.to_string_lossy().into_owned(), MaterialKind::Key),
                        MaterialKind::Key,
                    ),
                ],
                slot: slot.clone(),
                interval: Duration::from_millis(50),
                revision_tx,
                rebuild,
            },
            Some(shutdown_rx),
        );

        // Wait for fingerprint to take, then bump the cert to trigger the
        // first rebuild (success).
        tokio::time::sleep(Duration::from_millis(80)).await;
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(&cert, b"new cert bytes one").expect("rewrite cert");

        // Wait for the watcher to apply the swap + bump the revision.
        tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
            .await
            .expect("revision should bump after successful reload")
            .expect("watcher should still be alive");
        assert_eq!(*revision_rx.borrow(), 1);

        let after_success = slot.load_full().as_ref().clone();
        assert!(after_success.is_some(), "slot should still hold a config");
        let after_success_arc = after_success.unwrap();
        assert!(
            Arc::ptr_eq(&after_success_arc, &success_config),
            "successful reload should swap in the rebuilt config"
        );

        // Now flip the cert again — the rebuild closure returns Err this time.
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(&cert, b"new cert bytes two").expect("rewrite cert");

        // Give the watcher a few ticks to observe + reject.
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Revision should NOT have bumped past 1.
        assert_eq!(*revision_rx.borrow(), 1, "failed reload must not bump");

        // Slot should still hold the previously-successful config.
        let after_failure = slot.load_full().as_ref().clone().expect("slot intact");
        assert!(
            Arc::ptr_eq(&after_failure, &success_config),
            "failed reload must keep the previously-successful config"
        );

        task.abort();
    }

    fn build_dummy_server_config() -> Arc<ServerConfig> {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");

        let cert_pem = cert.pem();
        let mut cert_reader = cert_pem.as_bytes();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(Result::ok)
            .collect();
        let key_pem = key_pair.serialize_pem();
        let mut key_reader = key_pem.as_bytes();
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .expect("read private key")
            .expect("private key present");

        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("server cert"),
        )
    }
}
