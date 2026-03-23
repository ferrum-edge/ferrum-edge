use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Server;
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
    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        cached_config: Some(config_arc.clone()),
        proxy_state: None,
        mode: "cp".into(),
        read_only: env_config.admin_read_only,
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

    // gRPC listener
    let grpc_addr: SocketAddr = env_config
        .cp_grpc_listen_addr
        .as_deref()
        .unwrap_or("0.0.0.0:50051")
        .parse()?;

    info!("CP gRPC server listening on {}", grpc_addr);
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = Server::builder()
            .add_service(grpc_server.into_service())
            .serve(grpc_addr)
            .await
        {
            error!("gRPC server error: {}", e);
        }
    });

    // Database polling loop -> push updates to DPs (with shutdown)
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let config_poll = config_arc.clone();
    let mut cp_poll_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // skip first immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match db_poll.load_full_config().await {
                        Ok(new_config) => {
                            // Store config before broadcasting so that a DP calling
                            // GetFullConfig immediately after receiving the broadcast
                            // reads the new version (not the stale one).
                            config_poll.store(Arc::new(new_config.clone()));
                            CpGrpcServer::broadcast_update(&update_tx, &new_config);
                            info!("Configuration reloaded from database and pushed to DPs");
                        }
                        Err(e) => {
                            warn!(
                                "Failed to reload config from database (serving cached): {}",
                                e
                            );
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
