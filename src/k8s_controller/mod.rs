//! Kubernetes CRD controller (Layer 8).
//!
//! Watches Istio + Gateway API CRDs via kube-rs reflectors and feeds them
//! through `config_sources::k8s::translate_k8s_objects()` into the canonical
//! Layer 2 mesh model. Enabled in CP mode with `FERRUM_K8S_CONTROLLER_ENABLED=true`.

pub mod convert;
pub mod istio_status;
pub mod metrics;
pub mod reconciler;
pub mod resource_store;
pub mod status;
pub mod watcher;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{broadcast, watch};
use tracing::{error, info};

use crate::config::types::GatewayConfig;
use crate::grpc::cp_server::{CpScope, DpNodeRegistry, NamespaceBroadcasts};
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::grpc::mesh_server::MeshConfigBroadcast;
use istio_status::IstioStatusWriter;
use metrics::ControllerMetrics;
pub use reconciler::ReconcileBroadcasters;
pub use reconciler::{
    CpPublicationGate, K8sOverlaySlot, compose_db_with_k8s_overlay, empty_k8s_overlay_slot,
};
use reconciler::{ReconcilerConfig, spawn_reconcile_loop};
use resource_store::ResourceStoreSet;
use status::GatewayApiStatusWriter;
use watcher::{WatcherSelection, spawn_crd_reprobe_task, start_crd_watchers};

pub struct K8sControllerConfig {
    pub namespace: String,
    pub controller_namespace: String,
    pub trust_domain: String,
    pub cluster_domain: String,
    pub istio_root_namespace: String,
    pub watch_namespaces: Vec<String>,
    pub watch_istio: bool,
    /// `FERRUM_K8S_WATCH_MESH_CONFIG` — opt-out for clusters where the
    /// gateway runs in a different trust boundary from `istio-system` and
    /// cannot easily grant cross-namespace `configmaps` RBAC. Only
    /// effective when `watch_istio` is true (without Istio CRDs there is
    /// no Telemetry resource that would consume meshConfig providers).
    pub watch_mesh_config: bool,
    pub watch_gateway_api: bool,
    pub pod_discovery_enabled: bool,
    pub watch_node_locality: bool,
    pub gateway_api_data_plane_service_namespace: Option<String>,
    pub gateway_api_data_plane_service_name: Option<String>,
    pub gateway_api_status_address: Option<String>,
    /// Effective Sidecar `ingress[]` materialization gate
    /// (`FERRUM_MESH_SIDECAR_ENFORCED && !FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN`).
    /// Threaded to the Istio status writer so it reports `ingress_modeled` only
    /// when the data plane actually materializes the listeners (F6 §6.2),
    /// matching the slice builder's ingress gate.
    pub mesh_sidecar_ingress_enforced: bool,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
    pub kubeconfig_path: Option<String>,
}

pub struct K8sControllerHandle {
    pub metrics: Arc<ControllerMetrics>,
    watcher_handles: Vec<tokio::task::JoinHandle<()>>,
    reconciler_handle: tokio::task::JoinHandle<()>,
    reprobe_handle: tokio::task::JoinHandle<()>,
}

impl K8sControllerHandle {
    pub async fn join(self) {
        for handle in self.watcher_handles {
            let _ = handle.await;
        }
        let _ = self.reconciler_handle.await;
        let _ = self.reprobe_handle.await;
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_k8s_controller(
    controller_config: K8sControllerConfig,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    overlay_slot: K8sOverlaySlot,
    broadcasts: Arc<NamespaceBroadcasts>,
    cp_scope: CpScope,
    dp_registry: Arc<DpNodeRegistry>,
    mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
    publication_gate: CpPublicationGate,
    shutdown: watch::Receiver<bool>,
) -> Result<K8sControllerHandle, anyhow::Error> {
    info!(
        watch_istio = controller_config.watch_istio,
        watch_gateway_api = controller_config.watch_gateway_api,
        pod_discovery_enabled = controller_config.pod_discovery_enabled,
        watch_node_locality = controller_config.watch_node_locality,
        gateway_api_data_plane_service_namespace = ?controller_config
            .gateway_api_data_plane_service_namespace,
        gateway_api_data_plane_service_name = ?controller_config.gateway_api_data_plane_service_name,
        gateway_api_status_address = ?controller_config.gateway_api_status_address,
        istio_root_namespace = %controller_config.istio_root_namespace,
        watch_namespaces = ?controller_config.watch_namespaces,
        namespace = controller_config.namespace,
        controller_namespace = controller_config.controller_namespace,
        "Starting Kubernetes controller"
    );

    let client = build_kube_client(&controller_config.kubeconfig_path).await?;

    let store_set = Arc::new(tokio::sync::Mutex::new(ResourceStoreSet::new()));
    let metrics = Arc::new(ControllerMetrics::new());
    let watcher_selection = WatcherSelection {
        watch_istio: controller_config.watch_istio,
        watch_gateway_api: controller_config.watch_gateway_api,
        watch_core: controller_config.pod_discovery_enabled,
        watch_gateway_api_data_plane_service: controller_config.watch_gateway_api
            && controller_config
                .gateway_api_data_plane_service_namespace
                .is_some()
            && controller_config
                .gateway_api_data_plane_service_name
                .is_some(),
        watch_node_locality: controller_config.watch_node_locality,
        // Without Istio CRDs there is no Telemetry resource that would
        // consume meshConfig providers, so the configmaps watch and its
        // associated RBAC requirement are skipped automatically.
        watch_mesh_config: controller_config.watch_istio && controller_config.watch_mesh_config,
    };
    let controller_namespace = controller_config.controller_namespace.clone();
    let istio_root_namespace = controller_config.istio_root_namespace.clone();
    let gateway_api_data_plane_service_namespace = controller_config
        .gateway_api_data_plane_service_namespace
        .clone();

    let watcher_handles = start_crd_watchers(
        client.clone(),
        store_set.clone(),
        watcher_selection,
        controller_config.watch_namespaces.clone(),
        controller_namespace.clone(),
        istio_root_namespace.clone(),
        gateway_api_data_plane_service_namespace.clone(),
        shutdown.clone(),
    )
    .await;

    info!(watchers = watcher_handles.len(), "CRD watchers started");

    let reconciler_config = ReconcilerConfig {
        namespace: controller_config.namespace,
        controller_namespace: controller_config.controller_namespace,
        trust_domain: controller_config.trust_domain,
        cluster_domain: controller_config.cluster_domain,
        istio_root_namespace: controller_config.istio_root_namespace,
        watch_namespaces: controller_config.watch_namespaces.clone(),
        debounce_ms: controller_config.debounce_ms,
        full_sync_interval_secs: controller_config.full_sync_interval_secs,
        pod_discovery_enabled: controller_config.pod_discovery_enabled,
        gateway_api_data_plane_service_namespace: controller_config
            .gateway_api_data_plane_service_namespace,
        gateway_api_data_plane_service_name: controller_config.gateway_api_data_plane_service_name,
        gateway_api_status_address: controller_config.gateway_api_status_address,
        mesh_sidecar_ingress_enforced: controller_config.mesh_sidecar_ingress_enforced,
    };
    let gateway_status_writer = controller_config
        .watch_gateway_api
        .then(|| GatewayApiStatusWriter::new(client.clone()));
    // T2-B: the Istio status writer mirrors the Gateway API writer's
    // construction — only build it when the controller is actually
    // watching Istio CRDs, so non-Istio installs don't pay the (tiny)
    // overhead of an unused writer carrying a kube client clone.
    let istio_status_writer = controller_config
        .watch_istio
        .then(|| IstioStatusWriter::new(client.clone()));

    let reconciler_handle = spawn_reconcile_loop(
        store_set.clone(),
        config_arc,
        overlay_slot,
        ReconcileBroadcasters {
            broadcasts,
            cp_scope,
            dp_registry,
            mesh_update_tx,
            mesh_registry,
            publication_gate,
        },
        reconciler_config,
        gateway_status_writer,
        istio_status_writer,
        metrics.clone(),
        shutdown.clone(),
    );

    let reprobe_handle = spawn_crd_reprobe_task(
        client,
        store_set,
        watcher_selection,
        controller_config.watch_namespaces,
        controller_namespace,
        istio_root_namespace,
        gateway_api_data_plane_service_namespace,
        shutdown,
        Duration::from_secs(300),
    );

    Ok(K8sControllerHandle {
        metrics,
        watcher_handles,
        reconciler_handle,
        reprobe_handle,
    })
}

async fn build_kube_client(
    kubeconfig_path: &Option<String>,
) -> Result<kube::Client, anyhow::Error> {
    let config = if let Some(path) = kubeconfig_path {
        info!(path, "Loading kubeconfig from explicit path");
        let kubeconfig = kube::config::Kubeconfig::read_from(path)?;
        kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default()).await?
    } else {
        match kube::Config::incluster() {
            Ok(c) => {
                info!("Using in-cluster Kubernetes config");
                c
            }
            Err(in_cluster_err) => match kube::Config::infer().await {
                Ok(c) => {
                    info!("Using inferred kubeconfig (not in-cluster)");
                    c
                }
                Err(infer_err) => {
                    error!(
                        in_cluster_error = %in_cluster_err,
                        infer_error = %infer_err,
                        "Failed to build Kubernetes client config"
                    );
                    return Err(anyhow::anyhow!(
                        "Cannot create Kubernetes client: in-cluster failed ({in_cluster_err}), \
                         kubeconfig inference failed ({infer_err}). \
                         Set FERRUM_K8S_KUBECONFIG_PATH for out-of-cluster use."
                    ));
                }
            },
        }
    };

    Ok(kube::Client::try_from(config)?)
}
