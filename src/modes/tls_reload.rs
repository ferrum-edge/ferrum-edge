//! Mode-side helpers to wire opt-in frontend TLS live reload into the proxy
//! and admin HTTPS listeners.
//!
//! Default `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=false` keeps today's
//! static-input behavior: [`prepare_proxy_frontend_tls`] /
//! [`prepare_admin_frontend_tls`] return only the loaded config and no
//! watcher.  When the operator opts in, the helpers additionally build a
//! `SharedFrontendTls` slot pre-populated with the loaded config and spawn a
//! poll task that re-runs the same load (`load_tls_config_with_client_auth`
//! plus the surface-specific post-load options) on cert/key changes,
//! atomically swapping the slot on success and warning-and-keeping the old
//! slot on validation failure.
//!
//! The proxy H3 listener subscribes to the proxy slot's revision channel so
//! it can rebuild the `quinn::ServerConfig` after a swap; see
//! [`crate::http3::server::Http3FrontendTlsReload`].

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::info;

use crate::config::EnvConfig;
use crate::tls::{
    self, CrlList, FrontendTlsRebuildFn, FrontendTlsReloadConfig, SharedFrontendTls, TlsPolicy,
    empty_frontend_tls_slot, frontend_tls_slot_with, spawn_frontend_tls_reload_task,
};

/// Result of wiring the proxy frontend TLS live-reload path. When live reload
/// is disabled (the default) every field is `None`; the caller continues
/// using the startup-loaded `Arc<rustls::ServerConfig>` directly.
pub struct ProxyFrontendTlsReloadHandles {
    /// Pre-populated shared slot the HTTPS / H2 listeners load on each
    /// accept. `Some` only when live reload is enabled.
    pub slot: Option<SharedFrontendTls>,
    /// Subscribe-able revision channel the H3 listener observes. `Some` only
    /// when live reload is enabled.
    pub revision_rx: Option<watch::Receiver<u64>>,
    /// Handle to the spawned watcher task. `Some` only when live reload is
    /// enabled. The watcher self-terminates when the shutdown receiver it
    /// holds fires, so callers may safely detach this handle by dropping it
    /// — the task will exit on its own at gateway shutdown.
    pub watcher_handle: Option<JoinHandle<()>>,
}

/// Build the proxy frontend TLS slot + reload watcher, applying the proxy-
/// frontend-specific post-load options (`enable_early_data`, optional kTLS
/// secret-extraction opt-in).
///
/// The rebuild closure mirrors the startup path:
/// `load_tls_config_with_client_auth(cert, key, client_ca, no_verify, policy,
/// warning_days, crls)` followed by the same `enable_early_data` /
/// `enable_secret_extraction_for_ktls` opt-ins.  Validation failures (parse,
/// expired, not-yet-valid, key mismatch) flow out as the closure's `Err` and
/// keep the previous config — never serving a known-bad TLS config.
pub fn prepare_proxy_frontend_tls(
    tls_config: Arc<ServerConfig>,
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> ProxyFrontendTlsReloadHandles {
    if !env_config.frontend_tls_live_reload_enabled {
        return ProxyFrontendTlsReloadHandles {
            slot: None,
            revision_rx: None,
            watcher_handle: None,
        };
    }

    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.clone(),
        env_config.frontend_tls_key_path.clone(),
    ) else {
        // Live reload requested but no cert/key configured — defensive
        // no-op. The caller's listener startup path would have already
        // skipped HTTPS for the same reason.
        info!(
            "FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true but no frontend cert/key configured; live reload disabled"
        );
        return ProxyFrontendTlsReloadHandles {
            slot: None,
            revision_rx: None,
            watcher_handle: None,
        };
    };

    let slot = frontend_tls_slot_with(tls_config);
    let (revision_tx, revision_rx) = watch::channel(0u64);
    let interval = Duration::from_secs(env_config.frontend_tls_watch_interval_seconds.max(1));

    let rebuild = build_proxy_rebuild_fn(env_config, tls_policy, crls);

    let handle = spawn_frontend_tls_reload_task(
        FrontendTlsReloadConfig {
            surface: "proxy_https",
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            slot: slot.clone(),
            interval,
            revision_tx,
            rebuild,
        },
        shutdown_rx,
    );

    ProxyFrontendTlsReloadHandles {
        slot: Some(slot),
        revision_rx: Some(revision_rx),
        watcher_handle: Some(handle),
    }
}

fn build_proxy_rebuild_fn(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
) -> FrontendTlsRebuildFn {
    let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.clone();
    let warning_days = env_config.tls_cert_expiry_warning_days;
    let ktls_could_be_enabled = env_config.ktls_enabled.could_be_enabled();
    let policy = tls_policy.clone();
    let crls = crls.clone();

    Box::new(
        move |cert_path: &Path, key_path: &Path| -> Result<Arc<ServerConfig>, anyhow::Error> {
            let cert_path_str = cert_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("frontend TLS cert path is not valid UTF-8"))?;
            let key_path_str = key_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("frontend TLS key path is not valid UTF-8"))?;
            let mut config = tls::load_tls_config_with_client_auth(
                cert_path_str,
                key_path_str,
                client_ca_bundle_path.as_deref(),
                false,
                &policy,
                warning_days,
                &crls,
            )?;
            // Reapply the proxy-frontend-specific opt-ins so rotated configs
            // match startup semantics (0-RTT, kTLS secret extraction).
            tls::enable_early_data(&mut config, &policy);
            if ktls_could_be_enabled {
                tls::enable_secret_extraction_for_ktls(&mut config);
            }
            Ok(config)
        },
    )
}

/// Result of wiring the admin frontend TLS live-reload path. When live reload
/// is disabled (the default) every field is `None`; the caller continues
/// using the startup-loaded `Arc<rustls::ServerConfig>` directly.
pub struct AdminFrontendTlsReloadHandles {
    /// Pre-populated shared slot the admin HTTPS listener loads on each
    /// accept. `Some` only when live reload is enabled.
    pub slot: Option<SharedFrontendTls>,
    /// Handle to the spawned watcher task. `Some` only when live reload is
    /// enabled. The watcher self-terminates when the shutdown receiver it
    /// holds fires, so callers may safely detach this handle by dropping
    /// it — the task will exit on its own at gateway shutdown.
    pub watcher_handle: Option<JoinHandle<()>>,
}

/// Build the admin frontend TLS slot + reload watcher. Admin listeners do
/// NOT apply `enable_early_data` (no 425 guard on admin) and do NOT opt into
/// kTLS — the rebuild closure runs the same vanilla path as the startup
/// admin TLS load.
pub fn prepare_admin_frontend_tls(
    tls_config: Arc<ServerConfig>,
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> AdminFrontendTlsReloadHandles {
    if !env_config.frontend_tls_live_reload_enabled {
        return AdminFrontendTlsReloadHandles {
            slot: None,
            watcher_handle: None,
        };
    }

    let (Some(cert_path), Some(key_path)) = (
        env_config.admin_tls_cert_path.clone(),
        env_config.admin_tls_key_path.clone(),
    ) else {
        return AdminFrontendTlsReloadHandles {
            slot: None,
            watcher_handle: None,
        };
    };

    let slot = frontend_tls_slot_with(tls_config);
    let (revision_tx, _revision_rx) = watch::channel(0u64);
    let interval = Duration::from_secs(env_config.frontend_tls_watch_interval_seconds.max(1));

    let rebuild = build_admin_rebuild_fn(env_config, tls_policy, crls);

    let handle = spawn_frontend_tls_reload_task(
        FrontendTlsReloadConfig {
            surface: "admin_https",
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            slot: slot.clone(),
            interval,
            revision_tx,
            rebuild,
        },
        shutdown_rx,
    );

    AdminFrontendTlsReloadHandles {
        slot: Some(slot),
        watcher_handle: Some(handle),
    }
}

fn build_admin_rebuild_fn(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
) -> FrontendTlsRebuildFn {
    let admin_client_ca_bundle_path = env_config.admin_tls_client_ca_bundle_path.clone();
    let admin_no_verify = env_config.admin_tls_no_verify;
    let warning_days = env_config.tls_cert_expiry_warning_days;
    let policy = tls_policy.clone();
    let crls = crls.clone();

    Box::new(
        move |cert_path: &Path, key_path: &Path| -> Result<Arc<ServerConfig>, anyhow::Error> {
            let cert_path_str = cert_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("admin TLS cert path is not valid UTF-8"))?;
            let key_path_str = key_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("admin TLS key path is not valid UTF-8"))?;
            tls::load_tls_config_with_client_auth(
                cert_path_str,
                key_path_str,
                admin_client_ca_bundle_path.as_deref(),
                admin_no_verify,
                &policy,
                warning_days,
                &crls,
            )
        },
    )
}

/// Suppress unused-`empty_frontend_tls_slot` lint when none of the modes
/// touch it in this file.  The slot is exported from `tls::frontend_reload`
/// and used elsewhere; this stub keeps the import honest.
#[allow(dead_code)]
fn _ensure_slot_import_is_live() -> SharedFrontendTls {
    empty_frontend_tls_slot()
}

/// Build the H3-listener-side reload subscription from the proxy reload
/// handles, returning `None` when live reload is disabled. Hands the H3
/// listener both the shared slot (for `Endpoint::set_server_config`
/// rebuilds) and the revision channel (so it wakes on each successful
/// reload).
pub fn build_h3_frontend_tls_reload(
    handles: Option<&ProxyFrontendTlsReloadHandles>,
) -> Option<crate::http3::server::Http3FrontendTlsReload> {
    let handles = handles?;
    let slot = handles.slot.clone()?;
    let revision_rx = handles.revision_rx.clone()?;
    Some(crate::http3::server::Http3FrontendTlsReload {
        tls_slot: slot,
        revision_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;

    fn install_default_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn dummy_server_config() -> Arc<ServerConfig> {
        install_default_crypto_provider();
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

    fn dummy_tls_policy() -> TlsPolicy {
        install_default_crypto_provider();
        TlsPolicy {
            protocol_versions: vec![&rustls::version::TLS13],
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            prefer_server_cipher_order: false,
            session_cache_size: 64,
            early_data_max_size: 0,
        }
    }

    #[test]
    fn proxy_frontend_tls_default_is_no_watch_and_no_slot() {
        let cfg = EnvConfig::default(); // live reload defaults to false
        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let handles = prepare_proxy_frontend_tls(tls_config, &cfg, &policy, &crls, None);

        assert!(
            handles.slot.is_none(),
            "default-off live reload must not allocate a slot"
        );
        assert!(handles.revision_rx.is_none());
        assert!(handles.watcher_handle.is_none());
    }

    #[test]
    fn proxy_frontend_tls_opt_in_without_cert_path_stays_quiet() {
        // Live reload is requested but cert/key paths are unset. The helper
        // should defensively no-op rather than panic; the listener startup
        // path would have already skipped HTTPS in this scenario.
        let cfg = EnvConfig {
            frontend_tls_live_reload_enabled: true,
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            ..EnvConfig::default()
        };
        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let handles = prepare_proxy_frontend_tls(tls_config, &cfg, &policy, &crls, None);

        assert!(handles.slot.is_none());
        assert!(handles.watcher_handle.is_none());
    }

    #[tokio::test]
    async fn proxy_frontend_tls_opt_in_with_paths_returns_slot_and_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        // The watcher only reads file fingerprints at this stage — the
        // closure is only invoked on a detected change, so placeholder
        // bytes are fine for this test.
        std::fs::write(&cert_path, b"placeholder cert").expect("write cert");
        std::fs::write(&key_path, b"placeholder key").expect("write key");

        let cfg = EnvConfig {
            frontend_tls_live_reload_enabled: true,
            frontend_tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
            frontend_tls_key_path: Some(key_path.to_string_lossy().into_owned()),
            frontend_tls_watch_interval_seconds: 60,
            ..EnvConfig::default()
        };

        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handles =
            prepare_proxy_frontend_tls(tls_config, &cfg, &policy, &crls, Some(shutdown_rx));

        let slot = handles.slot.expect("slot present when live reload opt-in");
        assert!(slot.load().is_some(), "slot should be pre-populated");
        assert!(
            handles.revision_rx.is_some(),
            "live reload should expose a revision channel for the H3 listener"
        );
        let handle = handles
            .watcher_handle
            .expect("live reload should spawn a watcher task");
        handle.abort();
    }

    #[test]
    fn admin_frontend_tls_default_is_no_watch_and_no_slot() {
        let cfg = EnvConfig::default();
        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let handles = prepare_admin_frontend_tls(tls_config, &cfg, &policy, &crls, None);

        assert!(handles.slot.is_none());
        assert!(handles.watcher_handle.is_none());
    }
}
