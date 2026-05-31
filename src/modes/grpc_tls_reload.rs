//! CP/DP gRPC TLS source reload support.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::EnvConfig;
use crate::tls::source::MaterialKind;
use crate::tls::source::subscription::{
    MaterialSetReloadConfig, WatchedMaterialSource, material_set_poll_interval,
    source_is_refreshable, spawn_material_set_reload_task,
};
use crate::tls::{
    self, CrlList, FrontendTlsReloadConfig, SharedFrontendTls, TlsPolicy, frontend_tls_slot_with,
    spawn_frontend_tls_reload_task,
};

pub const CP_GRPC_SURFACE: &str = "cp_grpc";
pub const DP_GRPC_SURFACE: &str = "dp_grpc";

pub struct CpGrpcServerTlsReloadHandles {
    pub slot: SharedFrontendTls,
    pub watcher_handle: Option<JoinHandle<()>>,
}

pub struct GrpcTlsReloadHandle {
    pub revision_rx: watch::Receiver<u64>,
    pub watcher_handle: JoinHandle<()>,
}

pub fn build_cp_grpc_server_tls_config(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    let cert_path = env_config
        .cp_grpc_tls_cert_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("FERRUM_CP_GRPC_TLS_CERT_PATH is required"))?;
    let key_path = env_config
        .cp_grpc_tls_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("FERRUM_CP_GRPC_TLS_KEY_PATH is required"))?;

    tls::load_tls_config_with_client_auth(
        cert_path,
        key_path,
        env_config.cp_grpc_tls_client_ca_path.as_deref(),
        false,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
}

pub fn prepare_cp_grpc_server_tls_reload(
    tls_config: Arc<ServerConfig>,
    env_config: Arc<EnvConfig>,
    tls_policy: TlsPolicy,
    crls: CrlList,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> CpGrpcServerTlsReloadHandles {
    let slot = frontend_tls_slot_with(tls_config);
    let watched_sources = cp_grpc_watched_sources(&env_config);
    if watched_sources.is_empty() {
        return CpGrpcServerTlsReloadHandles {
            slot,
            watcher_handle: None,
        };
    }

    if !watched_sources
        .iter()
        .any(|source| source_is_refreshable(&source.source))
    {
        warn!("CP gRPC TLS sources are static inline material; live reload watcher not started");
        return CpGrpcServerTlsReloadHandles {
            slot,
            watcher_handle: None,
        };
    }

    let interval = material_set_poll_interval(
        &watched_sources,
        Duration::from_secs(env_config.backend_tls_watch_interval_seconds),
        Duration::from_secs(env_config.secret_refresh_interval_seconds),
    );
    let (revision_tx, _revision_rx) = watch::channel(0_u64);
    let env_for_rebuild = env_config.clone();
    let policy_for_rebuild = tls_policy.clone();
    let crls_for_rebuild = crls.clone();
    let handle = spawn_frontend_tls_reload_task(
        FrontendTlsReloadConfig {
            surface: CP_GRPC_SURFACE,
            sources: watched_sources,
            slot: slot.clone(),
            interval,
            revision_tx,
            rebuild: Box::new(move || {
                build_cp_grpc_server_tls_config(
                    &env_for_rebuild,
                    &policy_for_rebuild,
                    &crls_for_rebuild,
                )
            }),
        },
        shutdown_rx,
    );

    info!(
        surface = CP_GRPC_SURFACE,
        interval_secs = interval.as_secs(),
        "CP gRPC TLS live reload enabled"
    );
    CpGrpcServerTlsReloadHandles {
        slot,
        watcher_handle: Some(handle),
    }
}

pub fn start_dp_grpc_tls_reload_task(
    env_config: Arc<EnvConfig>,
    cp_urls: Arc<Vec<String>>,
    label: &'static str,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> Option<GrpcTlsReloadHandle> {
    let watched_sources = dp_grpc_watched_sources(&env_config);
    if watched_sources.is_empty() {
        return None;
    }

    if !watched_sources
        .iter()
        .any(|source| source_is_refreshable(&source.source))
    {
        warn!("DP gRPC TLS sources are static inline material; live reload watcher not started");
        return None;
    }

    let interval = material_set_poll_interval(
        &watched_sources,
        Duration::from_secs(env_config.backend_tls_watch_interval_seconds),
        Duration::from_secs(env_config.secret_refresh_interval_seconds),
    );
    let (revision_tx, revision_rx) = watch::channel(0_u64);
    let env_for_rebuild = env_config.clone();
    let urls_for_rebuild = cp_urls.clone();
    let watcher_handle = spawn_material_set_reload_task(
        MaterialSetReloadConfig {
            surface: DP_GRPC_SURFACE,
            sources: watched_sources,
            interval,
            revision_tx,
            rebuild: Box::new(move || {
                crate::grpc::dp_client::build_dp_grpc_tls_config(
                    &env_for_rebuild,
                    &urls_for_rebuild,
                    label,
                )?;
                Ok(())
            }),
        },
        shutdown_rx,
    );

    info!(
        surface = DP_GRPC_SURFACE,
        interval_secs = interval.as_secs(),
        "DP gRPC TLS live reload enabled"
    );
    Some(GrpcTlsReloadHandle {
        revision_rx,
        watcher_handle,
    })
}

pub(crate) fn cp_grpc_watched_sources(env_config: &EnvConfig) -> Vec<WatchedMaterialSource> {
    let mut seen = BTreeSet::new();
    let mut sources = Vec::new();

    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "cp_grpc_cert",
        env_config.cp_grpc_tls_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "cp_grpc_key",
        env_config.cp_grpc_tls_key_path.as_deref(),
        MaterialKind::Key,
    );
    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "cp_grpc_client_ca",
        env_config.cp_grpc_tls_client_ca_path.as_deref(),
        MaterialKind::CaBundle,
    );
    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "cp_grpc_crl",
        env_config.tls_crl_file_path.as_deref(),
        MaterialKind::Crl,
    );

    sources
}

pub(crate) fn dp_grpc_watched_sources(env_config: &EnvConfig) -> Vec<WatchedMaterialSource> {
    let mut seen = BTreeSet::new();
    let mut sources = Vec::new();

    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "dp_grpc_ca",
        env_config.dp_grpc_tls_ca_cert_path.as_deref(),
        MaterialKind::CaBundle,
    );
    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "dp_grpc_client_cert",
        env_config.dp_grpc_tls_client_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "dp_grpc_client_key",
        env_config.dp_grpc_tls_client_key_path.as_deref(),
        MaterialKind::Key,
    );

    sources
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dp_grpc_watched_sources_collects_configured_sources() {
        let env = EnvConfig {
            dp_grpc_tls_ca_cert_path: Some("k8s://edge/cp-ca#ca.crt".to_string()),
            dp_grpc_tls_client_cert_path: Some("/etc/ferrum/dp.crt".to_string()),
            dp_grpc_tls_client_key_path: Some("/etc/ferrum/dp.key".to_string()),
            ..EnvConfig::default()
        };

        let sources = dp_grpc_watched_sources(&env);
        assert_eq!(sources.len(), 3);
        assert_eq!(sources[0].label, "dp_grpc_ca");
        assert_eq!(sources[0].kind, MaterialKind::CaBundle);
        assert_eq!(sources[1].label, "dp_grpc_client_cert");
        assert_eq!(sources[1].kind, MaterialKind::Cert);
        assert_eq!(sources[2].label, "dp_grpc_client_key");
        assert_eq!(sources[2].kind, MaterialKind::Key);
    }

    #[test]
    fn cp_grpc_watched_sources_collects_configured_sources() {
        let env = EnvConfig {
            cp_grpc_tls_cert_path: Some("k8s://edge/cp-tls#tls.crt".to_string()),
            cp_grpc_tls_key_path: Some("k8s://edge/cp-tls#tls.key".to_string()),
            cp_grpc_tls_client_ca_path: Some("/etc/ferrum/dp-ca.pem".to_string()),
            tls_crl_file_path: Some("/etc/ferrum/revoked.crl".to_string()),
            ..EnvConfig::default()
        };

        let sources = cp_grpc_watched_sources(&env);
        assert_eq!(sources.len(), 4);
        assert_eq!(sources[0].label, "cp_grpc_cert");
        assert_eq!(sources[0].kind, MaterialKind::Cert);
        assert_eq!(sources[1].label, "cp_grpc_key");
        assert_eq!(sources[1].kind, MaterialKind::Key);
        assert_eq!(sources[2].label, "cp_grpc_client_ca");
        assert_eq!(sources[2].kind, MaterialKind::CaBundle);
        assert_eq!(sources[3].label, "cp_grpc_crl");
        assert_eq!(sources[3].kind, MaterialKind::Crl);
    }
}
