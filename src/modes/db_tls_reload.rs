//! Database TLS source reload support for DB-backed modes.
//!
//! The watcher fingerprints configured database TLS material sources. On a
//! validated byte change it rebuilds the effective primary DB URL
//! (`FERRUM_DB_URL`) and asks the active database backend to reconnect,
//! letting SQL and MongoDB stores preserve their existing atomic swap
//! behavior. While sticky failover is active, a successful primary TLS
//! reconnect records primary topology (and may emit the opt-in
//! divergence-risk marker); it never labels a failover URL as primary.
//! Failover-URL TLS refresh continues to go through failover reconnect
//! paths after poll failure.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::EnvConfig;
use crate::config::db_backend::{DatabaseBackend, redact_error_text, redact_url};
use crate::tls::source::MaterialKind;
use crate::tls::source::subscription::{
    AsyncMaterialSetReloadConfig, WatchedMaterialSource, material_set_poll_interval,
    source_is_refreshable, spawn_async_material_set_reload_task,
};

const DATABASE_TLS_SURFACE: &str = "database_tls";

pub fn start_db_tls_reload_task(
    env_config: EnvConfig,
    db: Arc<dyn DatabaseBackend>,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> Option<JoinHandle<()>> {
    if !env_config.db_tls_live_reload_enabled {
        return None;
    }

    if tokio::runtime::Handle::try_current().is_err() {
        warn!("Database TLS live reload requested outside a Tokio runtime; watcher not started");
        return None;
    }

    let watched_sources = db_tls_watched_sources(&env_config);
    if watched_sources.is_empty() {
        warn!(
            "FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true but no database TLS sources are configured; watcher not started"
        );
        return None;
    }

    if !watched_sources
        .iter()
        .any(|source| source_is_refreshable(&source.source))
    {
        warn!(
            "FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true but database TLS sources are inline/static; watcher not started"
        );
        return None;
    }

    let interval = material_set_poll_interval(
        &watched_sources,
        Duration::from_secs(env_config.db_tls_watch_interval_seconds),
        Duration::from_secs(env_config.secret_refresh_interval_seconds),
    );
    let (revision_tx, _revision_rx) = watch::channel(0_u64);
    let env_for_reload = env_config.clone();
    let db_for_reload = db.clone();
    let handle = spawn_async_material_set_reload_task(
        AsyncMaterialSetReloadConfig {
            surface: DATABASE_TLS_SURFACE,
            sources: watched_sources,
            interval,
            revision_tx,
            rebuild: Box::new(move || {
                let env_for_reload = env_for_reload.clone();
                let db_for_reload = db_for_reload.clone();
                async move { reload_db_tls_material(&env_for_reload, db_for_reload).await }.boxed()
            }),
        },
        shutdown_rx,
    );

    info!(
        db_type = %db.db_type(),
        interval_secs = interval.as_secs(),
        "Database TLS live reload enabled"
    );
    Some(handle)
}

async fn reload_db_tls_material(
    env_config: &EnvConfig,
    db: Arc<dyn DatabaseBackend>,
) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());

    db.reconnect(&effective_url).await.map_err(|error| {
        let safe_error = redact_error_text(&error, &[&effective_url]);
        anyhow::anyhow!(
            "database TLS reconnect failed for {}: {}",
            redact_url(&effective_url),
            safe_error
        )
    })?;

    if let Some(replica_url) = env_config
        .effective_db_read_replica_url()
        .map_err(anyhow::Error::msg)?
    {
        db.reconnect_read_replica(&replica_url)
            .await
            .map_err(|error| {
                let safe_error = redact_error_text(&error, &[&replica_url]);
                anyhow::anyhow!(
                    "database TLS admin-read replica reconnect failed for {}: {}",
                    redact_url(&replica_url),
                    safe_error
                )
            })?;
    }

    info!(
        db_type = %db.db_type(),
        "Database TLS material reloaded; database connections will use rotated material"
    );
    Ok(())
}

pub(crate) fn db_tls_watched_sources(env_config: &EnvConfig) -> Vec<WatchedMaterialSource> {
    let mut seen = BTreeSet::new();
    let mut sources = Vec::new();

    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "db_ca",
        env_config.db_tls_ca_cert_path.as_deref(),
        MaterialKind::CaBundle,
    );
    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "db_client_cert",
        env_config.db_tls_client_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    super::tls_source_util::push_watched_tls_source(
        &mut sources,
        &mut seen,
        "db_client_key",
        env_config.db_tls_client_key_path.as_deref(),
        MaterialKind::Key,
    );

    sources
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_tls_watched_sources_collects_and_deduplicates_sources() {
        let mut env = EnvConfig {
            db_tls_ca_cert_path: Some("/tmp/db-ca.pem".to_string()),
            db_tls_client_cert_path: Some("/tmp/db-client.pem".to_string()),
            db_tls_client_key_path: Some("/tmp/db-client.pem".to_string()),
            ..EnvConfig::default()
        };

        let sources = db_tls_watched_sources(&env);
        assert_eq!(sources.len(), 3);
        assert_eq!(sources[0].label, "db_ca");
        assert_eq!(sources[0].kind, MaterialKind::CaBundle);
        assert_eq!(sources[1].label, "db_client_cert");
        assert_eq!(sources[1].kind, MaterialKind::Cert);
        assert_eq!(sources[2].label, "db_client_key");
        assert_eq!(sources[2].kind, MaterialKind::Key);

        env.db_tls_client_key_path = Some("/tmp/db-key.pem".to_string());
        let sources = db_tls_watched_sources(&env);
        assert_eq!(sources.len(), 3);
        assert_eq!(sources[2].source.source_id(), "/tmp/db-key.pem");
    }
}
