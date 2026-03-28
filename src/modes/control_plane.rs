use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tonic::transport::Server;
use tonic::transport::server::ServerTlsConfig;
use tonic::transport::{Certificate, Identity};
use tracing::{error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::config::EnvConfig;
use crate::config::db_loader::DatabaseStore;
use crate::grpc::cp_server::CpGrpcServer;
use crate::tls::{self, TlsPolicy};

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let db = DatabaseStore::connect_with_tls_config(
        env_config.db_type.as_deref().unwrap_or("sqlite"),
        &effective_url,
        env_config.db_tls_enabled,
        env_config.db_tls_ca_cert_path.as_deref(),
        env_config.db_tls_client_cert_path.as_deref(),
        env_config.db_tls_client_key_path.as_deref(),
        env_config.db_tls_insecure,
    )
    .await?;

    let config = db.load_full_config().await?;
    info!(
        "CP mode: loaded {} proxies, {} consumers",
        config.proxies.len(),
        config.consumers.len()
    );

    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let db = Arc::new(db);

    let grpc_secret = match env_config.cp_grpc_jwt_secret.clone() {
        Some(secret) if !secret.is_empty() => secret,
        _ => {
            return Err(anyhow::anyhow!(
                "FERRUM_CP_GRPC_JWT_SECRET must be set and non-empty in control plane mode. \
                 Without it, any client can forge valid gRPC authentication tokens."
            ));
        }
    };

    // Create gRPC server
    let (grpc_server, update_tx) = CpGrpcServer::new(config_arc.clone(), grpc_secret);

    // Build TLS hardening policy from environment
    let tls_policy = TlsPolicy::from_env_config(&env_config)?;

    // Start separate listeners for Admin API (HTTP and HTTPS)
    let admin_http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_http_port).parse()?;
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;

    // Shared flag: DB polling loop sets this to false when the database is
    // unreachable, causing the admin API to reject writes early and preserve
    // the cached config until the DB recovers.
    let db_available = Arc::new(AtomicBool::new(true));

    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(config_arc.clone()),
        proxy_state: None,
        mode: "cp".into(),
        read_only: env_config.admin_read_only,
        db_available: Some(db_available.clone()),
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
    };
    let admin_shutdown = shutdown_tx.subscribe();

    // Admin HTTP listener (always enabled)
    let admin_http_handle = tokio::spawn(async move {
        info!("Starting Admin HTTP listener on {}", admin_http_addr);
        if let Err(e) =
            admin::start_admin_listener(admin_http_addr, admin_state, admin_shutdown).await
        {
            error!("Admin HTTP listener error: {}", e);
        }
    });

    // Admin HTTPS listener (only if TLS is configured)
    let admin_https_handle = if let (Some(admin_cert_path), Some(admin_key_path)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) {
        let admin_https_addr: SocketAddr =
            format!("0.0.0.0:{}", env_config.admin_https_port).parse()?;
        let admin_state_for_https = AdminState {
            db: Some(db.clone()),
            jwt_manager: create_jwt_manager_from_env()
                .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?,
            cached_config: Some(config_arc.clone()),
            proxy_state: None,
            mode: "cp".into(),
            read_only: env_config.admin_read_only,
            db_available: Some(db_available.clone()),
            admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        };
        let admin_https_shutdown = shutdown_tx.subscribe();

        // Load admin TLS configuration
        let admin_client_ca_bundle = env_config.admin_tls_client_ca_bundle_path.as_deref();
        let admin_tls_config = match tls::load_tls_config_with_client_auth(
            admin_cert_path,
            admin_key_path,
            admin_client_ca_bundle,
            env_config.admin_tls_no_verify,
            &tls_policy,
        ) {
            Ok(config) => {
                if admin_client_ca_bundle.is_some() {
                    info!(
                        "Admin TLS configuration loaded with client certificate verification (HTTPS with mTLS available)"
                    );
                } else if env_config.admin_tls_no_verify {
                    warn!(
                        "Admin TLS configuration loaded with certificate verification DISABLED (testing mode)"
                    );
                } else {
                    info!(
                        "Admin TLS configuration loaded without client certificate verification (HTTPS available)"
                    );
                }
                Some(config)
            }
            Err(e) => {
                error!("Failed to load admin TLS configuration: {}", e);
                return Err(anyhow::anyhow!("Invalid admin TLS configuration: {}", e));
            }
        };

        Some(tokio::spawn(async move {
            info!("Starting Admin HTTPS listener on {}", admin_https_addr);
            if let Err(e) = admin::start_admin_listener_with_tls(
                admin_https_addr,
                admin_state_for_https,
                admin_https_shutdown,
                admin_tls_config,
            )
            .await
            {
                error!("Admin HTTPS listener error: {}", e);
            }
        }))
    } else {
        info!("Admin TLS not configured - HTTPS listener disabled");
        None
    };

    // gRPC listener (with optional TLS/mTLS)
    let grpc_addr: SocketAddr = env_config
        .cp_grpc_listen_addr
        .as_deref()
        .unwrap_or("0.0.0.0:50051")
        .parse()?;

    let grpc_tls_config = if let (Some(cert_path), Some(key_path)) = (
        &env_config.cp_grpc_tls_cert_path,
        &env_config.cp_grpc_tls_key_path,
    ) {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to read CP gRPC TLS cert {}: {}", cert_path, e))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read CP gRPC TLS key {}: {}", key_path, e))?;

        let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(&cert_pem, &key_pem));

        if let Some(client_ca_path) = &env_config.cp_grpc_tls_client_ca_path {
            let ca_pem = std::fs::read(client_ca_path).map_err(|e| {
                anyhow::anyhow!("Failed to read CP gRPC client CA {}: {}", client_ca_path, e)
            })?;
            tls = tls.client_ca_root(Certificate::from_pem(&ca_pem));
            info!(
                "CP gRPC TLS configured with mTLS (server cert: {}, client CA: {})",
                cert_path, client_ca_path
            );
        } else {
            info!(
                "CP gRPC TLS configured (server cert: {}, no client verification)",
                cert_path
            );
        }
        Some(tls)
    } else {
        if env_config.cp_grpc_tls_client_ca_path.is_some() {
            warn!(
                "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH is set but cert/key are missing — ignoring client CA"
            );
        }
        info!("CP gRPC server running in plaintext mode (no TLS configured)");
        None
    };

    info!("CP gRPC server listening on {}", grpc_addr);
    let grpc_handle = tokio::spawn(async move {
        let mut builder = Server::builder();
        if let Some(tls) = grpc_tls_config {
            builder = match builder.tls_config(tls) {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to configure gRPC TLS: {}", e);
                    return;
                }
            };
        }
        if let Err(e) = builder
            .add_service(grpc_server.into_service())
            .serve(grpc_addr)
            .await
        {
            error!("gRPC server error: {}", e);
        }
    });

    // Database polling loop -> push incremental deltas to DPs (with shutdown).
    //
    // Uses the same incremental polling strategy as database mode: indexed
    // `updated_at > ?` queries + lightweight ID queries for deletion detection.
    // Deltas are broadcast as DELTA updates; DPs apply them via apply_incremental.
    // Falls back to FULL_SNAPSHOT on incremental poll failure.
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let config_poll = config_arc.clone();
    let db_available_poll = db_available.clone();
    let mut cp_poll_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // skip first immediate tick

        // Seed incremental state from the initial config load
        let initial_config = config_poll.load_full();
        let (
            mut known_proxy_ids,
            mut known_consumer_ids,
            mut known_plugin_config_ids,
            mut known_upstream_ids,
        ) = DatabaseStore::extract_known_ids(&initial_config);
        let mut last_poll_at: Option<chrono::DateTime<chrono::Utc>> =
            Some(initial_config.loaded_at);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(since) = last_poll_at {
                        // Incremental poll — only fetch changes since last poll
                        match db_poll.load_incremental_config(
                            since,
                            &known_proxy_ids,
                            &known_consumer_ids,
                            &known_plugin_config_ids,
                            &known_upstream_ids,
                        ).await {
                            Ok(result) => {
                                db_available_poll.store(true, Ordering::Relaxed);
                                if result.is_empty() {
                                    last_poll_at = Some(result.poll_timestamp);
                                    continue;
                                }
                                let poll_ts = result.poll_timestamp;

                                // Update known IDs (add new, remove deleted)
                                update_known_ids(
                                    &mut known_proxy_ids,
                                    &result.added_or_modified_proxies.iter().map(|p| p.id.clone()).collect(),
                                    &result.removed_proxy_ids,
                                );
                                update_known_ids(
                                    &mut known_consumer_ids,
                                    &result.added_or_modified_consumers.iter().map(|c| c.id.clone()).collect(),
                                    &result.removed_consumer_ids,
                                );
                                update_known_ids(
                                    &mut known_plugin_config_ids,
                                    &result.added_or_modified_plugin_configs.iter().map(|pc| pc.id.clone()).collect(),
                                    &result.removed_plugin_config_ids,
                                );
                                update_known_ids(
                                    &mut known_upstream_ids,
                                    &result.added_or_modified_upstreams.iter().map(|u| u.id.clone()).collect(),
                                    &result.removed_upstream_ids,
                                );

                                // Broadcast delta to DPs before updating local config
                                // so that a DP calling GetFullConfig immediately after
                                // receives the new version.
                                let version = poll_ts.to_rfc3339();
                                CpGrpcServer::broadcast_delta(&update_tx, &result, &version);

                                // Apply to CP's own in-memory config (for GetFullConfig
                                // and the Admin API cached_config reads).
                                // Clone current config, apply incremental changes, store.
                                let mut new_config = (*config_poll.load_full()).clone();
                                apply_incremental_to_config(&mut new_config, result);
                                new_config.loaded_at = poll_ts;
                                config_poll.store(Arc::new(new_config));

                                info!("Incremental config update pushed to DPs");
                                last_poll_at = Some(poll_ts);
                            }
                            Err(e) => {
                                warn!(
                                    "Incremental poll failed, falling back to full reload: {}",
                                    e
                                );
                                // Fallback to full config load + full snapshot broadcast
                                match db_poll.load_full_config().await {
                                    Ok(new_config) => {
                                        db_available_poll.store(true, Ordering::Relaxed);
                                        let (p, c, pc, u) = DatabaseStore::extract_known_ids(&new_config);
                                        known_proxy_ids = p;
                                        known_consumer_ids = c;
                                        known_plugin_config_ids = pc;
                                        known_upstream_ids = u;
                                        last_poll_at = Some(new_config.loaded_at);
                                        config_poll.store(Arc::new(new_config.clone()));
                                        CpGrpcServer::broadcast_update(&update_tx, &new_config);
                                        info!("Configuration reloaded from database (full fallback) and pushed to DPs");
                                    }
                                    Err(e2) => {
                                        db_available_poll.store(false, Ordering::Relaxed);
                                        warn!(
                                            "Full config reload also failed (serving cached): {}",
                                            e2
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                _ = cp_poll_shutdown.changed() => {
                    info!("CP database polling shutting down");
                    return;
                }
            }
        }
    });

    tokio::select! {
        _ = admin_http_handle => {}
        _ = grpc_handle => {}
        _ = async {
            if let Some(handle) = admin_https_handle {
                handle.await
            } else {
                std::future::pending().await
            }
        } => {}
    }

    Ok(())
}

/// Apply an incremental result to a config snapshot in-place.
///
/// Removes deleted resources by ID, then upserts added/modified resources.
/// This keeps the CP's in-memory config in sync without a full DB reload.
fn apply_incremental_to_config(
    config: &mut crate::config::types::GatewayConfig,
    result: crate::config::db_loader::IncrementalResult,
) {
    use std::collections::HashSet;

    // Remove deleted resources
    let removed_proxies: HashSet<&str> = result
        .removed_proxy_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    let removed_consumers: HashSet<&str> = result
        .removed_consumer_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    let removed_plugins: HashSet<&str> = result
        .removed_plugin_config_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    let removed_upstreams: HashSet<&str> = result
        .removed_upstream_ids
        .iter()
        .map(|s| s.as_str())
        .collect();

    config
        .proxies
        .retain(|p| !removed_proxies.contains(p.id.as_str()));
    config
        .consumers
        .retain(|c| !removed_consumers.contains(c.id.as_str()));
    config
        .plugin_configs
        .retain(|pc| !removed_plugins.contains(pc.id.as_str()));
    config
        .upstreams
        .retain(|u| !removed_upstreams.contains(u.id.as_str()));

    // Upsert added/modified resources using index for O(1) lookups
    upsert_by_id(&mut config.proxies, result.added_or_modified_proxies, |p| {
        p.id.clone()
    });
    upsert_by_id(
        &mut config.consumers,
        result.added_or_modified_consumers,
        |c| c.id.clone(),
    );
    upsert_by_id(
        &mut config.plugin_configs,
        result.added_or_modified_plugin_configs,
        |pc| pc.id.clone(),
    );
    upsert_by_id(
        &mut config.upstreams,
        result.added_or_modified_upstreams,
        |u| u.id.clone(),
    );
}

/// Upsert items into a vec by ID: replace existing entries, append new ones.
fn upsert_by_id<T>(existing: &mut Vec<T>, updates: Vec<T>, get_id: fn(&T) -> String) {
    let index: std::collections::HashMap<String, usize> = existing
        .iter()
        .enumerate()
        .map(|(i, item)| (get_id(item), i))
        .collect();

    for item in updates {
        let id = get_id(&item);
        if let Some(&pos) = index.get(&id) {
            existing[pos] = item;
        } else {
            existing.push(item);
        }
    }
}

/// Update a known ID set by adding new IDs and removing deleted ones.
fn update_known_ids(
    known: &mut std::collections::HashSet<String>,
    added: &Vec<String>,
    removed: &[String],
) {
    for id in removed {
        known.remove(id);
    }
    for id in added {
        known.insert(id.clone());
    }
}
