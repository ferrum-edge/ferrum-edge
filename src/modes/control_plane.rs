use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Server;
use tracing::{error, info, warn};

use crate::admin::{self, AdminState};
use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::config::db_loader::DatabaseStore;
use crate::config::EnvConfig;
use crate::grpc::cp_server::CpGrpcServer;

pub async fn run(env_config: EnvConfig, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Result<(), anyhow::Error> {
    let db = DatabaseStore::connect(
        env_config.db_type.as_deref().unwrap_or("sqlite"),
        env_config.db_url.as_deref().unwrap_or("sqlite://ferrum.db"),
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

    let grpc_secret = env_config
        .cp_grpc_jwt_secret
        .clone()
        .unwrap_or_default();

    // Create gRPC server
    let (grpc_server, update_tx) = CpGrpcServer::new(config_arc.clone(), grpc_secret);

    // Admin listener
    let admin_addr: SocketAddr = format!("0.0.0.0:{}", env_config.admin_http_port).parse()?;
    let jwt_manager = create_jwt_manager_from_env()
        .map_err(|e| anyhow::anyhow!("Failed to create JWT manager: {}", e))?;
    let admin_state = AdminState {
        db: Some(db.clone()),
        jwt_manager,
        proxy_state: None,
        mode: "cp".into(),
    };
    let admin_shutdown = shutdown_tx.subscribe();
    let admin_handle = tokio::spawn(async move {
        if let Err(e) = admin::start_admin_listener(admin_addr, admin_state, admin_shutdown).await {
            error!("Admin listener error: {}", e);
        }
    });

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

    // Database polling loop -> push updates to DPs
    let poll_interval = Duration::from_secs(env_config.db_poll_interval);
    let db_poll = db.clone();
    let config_poll = config_arc.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(poll_interval).await;
            match db_poll.load_full_config().await {
                Ok(new_config) => {
                    CpGrpcServer::broadcast_update(&update_tx, &new_config);
                    config_poll.store(Arc::new(new_config));
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
    });

    tokio::select! {
        _ = admin_handle => {}
        _ = grpc_handle => {}
    }

    Ok(())
}
