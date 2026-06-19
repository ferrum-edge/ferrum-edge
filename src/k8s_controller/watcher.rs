use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt;
use kube::api::{ApiResource, DynamicObject};
use kube::discovery;
use kube::runtime::reflector;
use kube::runtime::watcher;
use kube::{Api, Client};
use tracing::{debug, error, info, warn};

use super::resource_store::{CrdResourceStore, ResourceStoreSet};

pub struct CrdSpec {
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub plural: &'static str,
    pub namespaced: bool,
}

pub struct CoreResourceSpec {
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub plural: &'static str,
    pub namespaced: bool,
    /// Optional Kubernetes field selector applied to the watcher. Used to
    /// scope a namespaced watcher to a single named object (e.g.,
    /// `metadata.name=istio`) so unrelated objects in that namespace don't
    /// trigger no-op reconciliations. `None` watches every object in scope.
    pub field_selector: Option<&'static str>,
}

#[derive(Clone, Copy)]
pub struct WatcherSelection {
    pub watch_istio: bool,
    pub watch_gateway_api: bool,
    pub watch_core: bool,
    pub watch_node_locality: bool,
    pub watch_mesh_config: bool,
}

pub const ISTIO_CRDS: &[CrdSpec] = &[
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "AuthorizationPolicy",
        plural: "authorizationpolicies",
        namespaced: true,
    },
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "PeerAuthentication",
        plural: "peerauthentications",
        namespaced: true,
    },
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "RequestAuthentication",
        plural: "requestauthentications",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "VirtualService",
        plural: "virtualservices",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "DestinationRule",
        plural: "destinationrules",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "ServiceEntry",
        plural: "serviceentries",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "WorkloadEntry",
        plural: "workloadentries",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "Sidecar",
        plural: "sidecars",
        namespaced: true,
    },
    CrdSpec {
        group: "telemetry.istio.io",
        version: "v1",
        kind: "Telemetry",
        plural: "telemetries",
        namespaced: true,
    },
];

pub const GATEWAY_API_CRDS: &[CrdSpec] = &[
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "GatewayClass",
        plural: "gatewayclasses",
        namespaced: false,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "GatewayClass",
        plural: "gatewayclasses",
        namespaced: false,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "Gateway",
        plural: "gateways",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "Gateway",
        plural: "gateways",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "HTTPRoute",
        plural: "httproutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "HTTPRoute",
        plural: "httproutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "GRPCRoute",
        plural: "grpcroutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1alpha2",
        kind: "TLSRoute",
        plural: "tlsroutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1alpha2",
        kind: "TCPRoute",
        plural: "tcproutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "ReferenceGrant",
        plural: "referencegrants",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "ReferenceGrant",
        plural: "referencegrants",
        namespaced: true,
    },
];

pub const K8S_CORE_RESOURCES: &[CoreResourceSpec] = &[
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Pod",
        plural: "pods",
        namespaced: true,
        field_selector: None,
    },
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Service",
        plural: "services",
        namespaced: true,
        field_selector: None,
    },
    CoreResourceSpec {
        group: "discovery.k8s.io",
        version: "v1",
        kind: "EndpointSlice",
        plural: "endpointslices",
        namespaced: true,
        field_selector: None,
    },
];

pub const K8S_NAMESPACE_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "",
    version: "v1",
    kind: "Namespace",
    plural: "namespaces",
    namespaced: false,
    field_selector: None,
}];

pub const GATEWAY_API_CORE_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "",
    version: "v1",
    kind: "Secret",
    plural: "secrets",
    namespaced: true,
    field_selector: None,
}];

pub const K8S_NODE_LOCALITY_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "",
    version: "v1",
    kind: "Node",
    plural: "nodes",
    namespaced: false,
    field_selector: None,
}];

// The only ConfigMap Ferrum consumes from the istio root namespace is the
// `istio` MeshConfig. Scoping the watch with a name field selector means
// unrelated ConfigMap churn (CA root cert, sidecar injector, dashboards, ...)
// does not trigger no-op reconciliations.
pub const ISTIO_MESH_CONFIG_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "",
    version: "v1",
    kind: "ConfigMap",
    plural: "configmaps",
    namespaced: true,
    field_selector: Some("metadata.name=istio"),
}];

// Node labels can enrich workloads with topology.kubernetes.io/{region,zone},
// but locality is optional. Keep Node out of the unconditional pod-discovery
// watcher set so namespaced discovery does not require cluster-scoped RBAC.
fn selected_core_resources(watch_node_locality: bool) -> Vec<&'static CoreResourceSpec> {
    let mut resources: Vec<&'static CoreResourceSpec> = K8S_CORE_RESOURCES.iter().collect();
    if watch_node_locality {
        resources.extend(K8S_NODE_LOCALITY_RESOURCES);
    }
    resources
}

fn watch_scopes(namespaces: &[String]) -> Vec<Option<String>> {
    if namespaces.is_empty() {
        return vec![None];
    }
    namespaces.iter().cloned().map(Some).collect()
}

fn watch_scope_label(scope: Option<&str>) -> String {
    match scope {
        Some(namespace) => format!("namespace:{namespace}"),
        None => "all".to_string(),
    }
}

pub(crate) fn namespaces_with_istio_root(
    namespaces: &[String],
    istio_root_namespace: &str,
) -> Vec<String> {
    if namespaces.is_empty() {
        return Vec::new();
    }

    let mut merged = namespaces.to_vec();
    if !istio_root_namespace.is_empty()
        && !merged
            .iter()
            .any(|namespace| namespace == istio_root_namespace)
    {
        merged.push(istio_root_namespace.to_string());
    }
    merged
}

fn crd_watch_namespaces(
    crd: &CrdSpec,
    namespaces: &[String],
    istio_root_namespace: &str,
) -> Vec<String> {
    if crd.group.ends_with(".istio.io") {
        namespaces_with_istio_root(namespaces, istio_root_namespace)
    } else {
        namespaces.to_vec()
    }
}

fn build_apis_for_resource(
    client: &Client,
    ar: &ApiResource,
    namespaces: &[String],
    namespaced: bool,
) -> Vec<(Api<DynamicObject>, ApiResource, String)> {
    let scopes = if namespaced {
        watch_scopes(namespaces)
    } else {
        vec![None]
    };
    scopes
        .into_iter()
        .map(|scope| {
            let api = match scope.as_deref() {
                Some(namespace) => Api::namespaced_with(client.clone(), namespace, ar),
                None => Api::all_with(client.clone(), ar),
            };
            let scope_label = watch_scope_label(scope.as_deref());
            (api, ar.clone(), scope_label)
        })
        .collect()
}

fn find_crd_resource(api_group: &discovery::ApiGroup, crd: &CrdSpec) -> Option<ApiResource> {
    api_group
        .versioned_resources(crd.version)
        .into_iter()
        .map(|(ar, _caps)| ar)
        .find(|ar| ar.kind == crd.kind && ar.plural == crd.plural)
}

pub async fn start_crd_watchers(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    selection: WatcherSelection,
    namespaces: Vec<String>,
    istio_root_namespace: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    let mut crd_specs: Vec<&CrdSpec> = Vec::new();
    if selection.watch_istio {
        crd_specs.extend(ISTIO_CRDS);
    }
    if selection.watch_gateway_api {
        crd_specs.extend(GATEWAY_API_CRDS);
    }

    // Deduplicate discovery by group, but gate watcher registration by the
    // exact served kind/version below. A cluster can expose a group without
    // serving every optional CRD version Ferrum knows about.
    let mut checked_groups = HashSet::new();
    let mut installed_groups: HashMap<&'static str, discovery::ApiGroup> = HashMap::new();

    for crd in &crd_specs {
        if !checked_groups.insert(crd.group) {
            continue;
        }
        match discovery::oneshot::group(&client, crd.group).await {
            Ok(api_group) => {
                installed_groups.insert(crd.group, api_group);
                info!(group = crd.group, "CRD group detected");
            }
            Err(e) => {
                warn!(
                    group = crd.group,
                    error = %e,
                    "CRD group not installed, its resources will not be watched. \
                     Install the CRDs and restart the controller to enable."
                );
            }
        }
    }

    for crd in crd_specs {
        let Some(api_group) = installed_groups.get(crd.group) else {
            continue;
        };
        let api_version = format!("{}/{}", crd.group, crd.version);
        let kind = crd.kind.to_string();

        let Some(ar) = find_crd_resource(api_group, crd) else {
            debug!(
                group = crd.group,
                version = crd.version,
                kind = crd.kind,
                "CRD kind/version not served, skipping watcher registration"
            );
            continue;
        };

        let crd_namespaces = crd_watch_namespaces(crd, &namespaces, &istio_root_namespace);
        for (api, ar, scope) in
            build_apis_for_resource(&client, &ar, &crd_namespaces, crd.namespaced)
        {
            if store_set
                .lock()
                .await
                .has_store_for_scope(&api_version, &kind, &scope)
            {
                debug!(
                    kind = %kind,
                    api_version = %api_version,
                    scope = %scope,
                    "CRD watcher already running, skipping duplicate start"
                );
                continue;
            }

            let writer = reflector::store::Writer::new(ar.clone());
            let store = writer.as_reader();
            let crd_store = Arc::new(CrdResourceStore::new_scoped(
                api_version.clone(),
                kind.clone(),
                scope.clone(),
                store,
            ));

            let change_notifier = {
                let mut set = store_set.lock().await;
                if !set.add_store(crd_store) {
                    debug!(
                        kind = %kind,
                        api_version = %api_version,
                        scope = %scope,
                        "CRD watcher already running, skipping duplicate start"
                    );
                    continue;
                }
                set.change_notifier()
            };

            let mut watcher_shutdown = shutdown.clone();
            let cleanup_scope = scope.clone();
            let task_kind = kind.clone();
            let task_api_version = api_version.clone();
            let task_store_set = store_set.clone();
            let watcher_config = watcher::Config::default();

            let handle = tokio::spawn(async move {
                let stream = reflector::reflector(writer, watcher(api, watcher_config));

                tokio::pin!(stream);

                loop {
                    tokio::select! {
                        biased;
                        _ = watcher_shutdown.changed() => {
                            if *watcher_shutdown.borrow() {
                                debug!(kind = %task_kind, scope = %cleanup_scope, "Watcher shutting down");
                                return;
                            }
                        }
                        item = stream.try_next() => {
                            match item {
                                Ok(Some(_event)) => {
                                    change_notifier.notify_change();
                                }
                                Ok(None) => {
                                    error!(
                                        kind = %task_kind,
                                        api_version = %task_api_version,
                                        scope = %cleanup_scope,
                                        "CRD watcher stream ended unexpectedly; \
                                         removing stale store so reprobe will restart"
                                    );
                                    let removed = task_store_set
                                        .lock()
                                        .await
                                        .remove_store_for_scope(
                                            &task_api_version,
                                            &task_kind,
                                            &cleanup_scope,
                                        );
                                    if !removed {
                                        debug!(
                                            kind = %task_kind,
                                            api_version = %task_api_version,
                                            scope = %cleanup_scope,
                                            "Stale store already absent at stream end"
                                        );
                                    }
                                    return;
                                }
                                Err(e) => {
                                    error!(
                                        kind = %task_kind,
                                        scope = %cleanup_scope,
                                        error = %e,
                                        "Watch error, kube-rs will retry with backoff"
                                    );
                                }
                            }
                        }
                    }
                }
            });

            handles.push(handle);
            info!(
                kind = crd.kind,
                group = crd.group,
                scope = %scope,
                "Started CRD watcher"
            );
        }
    }

    let mut core_watch_plan: Vec<(&CoreResourceSpec, Vec<String>)> = Vec::new();
    if selection.watch_core {
        core_watch_plan.extend(
            selected_core_resources(selection.watch_node_locality)
                .into_iter()
                .map(|resource| (resource, namespaces.clone())),
        );
    }
    if selection.watch_gateway_api {
        core_watch_plan.extend(
            K8S_NAMESPACE_RESOURCES
                .iter()
                .map(|resource| (resource, Vec::new())),
        );
        core_watch_plan.extend(
            GATEWAY_API_CORE_RESOURCES
                .iter()
                .map(|resource| (resource, namespaces.clone())),
        );
    }
    if selection.watch_mesh_config {
        core_watch_plan.extend(
            ISTIO_MESH_CONFIG_RESOURCES
                .iter()
                .map(|resource| (resource, vec![istio_root_namespace.clone()])),
        );
    }

    if !core_watch_plan.is_empty() {
        for (resource, resource_namespaces) in core_watch_plan {
            let api_version = if resource.group.is_empty() {
                resource.version.to_string()
            } else {
                format!("{}/{}", resource.group, resource.version)
            };
            let ar = ApiResource {
                group: resource.group.to_string(),
                version: resource.version.to_string(),
                api_version: api_version.clone(),
                kind: resource.kind.to_string(),
                plural: resource.plural.to_string(),
            };
            let kind = resource.kind.to_string();

            for (api, ar, scope) in
                build_apis_for_resource(&client, &ar, &resource_namespaces, resource.namespaced)
            {
                if store_set
                    .lock()
                    .await
                    .has_store_for_scope(&api_version, &kind, &scope)
                {
                    debug!(
                        kind = %kind,
                        api_version = %api_version,
                        scope = %scope,
                        "K8s core watcher already running, skipping duplicate start"
                    );
                    continue;
                }

                let writer = reflector::store::Writer::new(ar.clone());
                let store = writer.as_reader();
                let crd_store = Arc::new(CrdResourceStore::new_scoped(
                    api_version.clone(),
                    kind.clone(),
                    scope.clone(),
                    store,
                ));

                let change_notifier = {
                    let mut set = store_set.lock().await;
                    if !set.add_store(crd_store) {
                        debug!(
                            kind = %kind,
                            api_version = %api_version,
                            scope = %scope,
                            "K8s core watcher already running, skipping duplicate start"
                        );
                        continue;
                    }
                    set.change_notifier()
                };

                let mut watcher_shutdown = shutdown.clone();
                let cleanup_scope = scope.clone();
                let task_kind = kind.clone();
                let task_api_version = api_version.clone();
                let task_store_set = store_set.clone();
                let watcher_config = match resource.field_selector {
                    Some(selector) => watcher::Config::default().fields(selector),
                    None => watcher::Config::default(),
                };

                let handle = tokio::spawn(async move {
                    let stream = reflector::reflector(writer, watcher(api, watcher_config));

                    tokio::pin!(stream);

                    loop {
                        tokio::select! {
                            biased;
                            _ = watcher_shutdown.changed() => {
                                if *watcher_shutdown.borrow() {
                                    debug!(kind = %task_kind, scope = %cleanup_scope, "Watcher shutting down");
                                    return;
                                }
                            }
                            item = stream.try_next() => {
                                match item {
                                    Ok(Some(_event)) => {
                                        change_notifier.notify_change();
                                    }
                                    Ok(None) => {
                                        error!(
                                            kind = %task_kind,
                                            api_version = %task_api_version,
                                            scope = %cleanup_scope,
                                            "K8s core watcher stream ended unexpectedly; \
                                             removing stale store so reprobe will restart"
                                        );
                                        let removed = task_store_set
                                            .lock()
                                            .await
                                            .remove_store_for_scope(
                                                &task_api_version,
                                                &task_kind,
                                                &cleanup_scope,
                                            );
                                        if !removed {
                                            debug!(
                                                kind = %task_kind,
                                                api_version = %task_api_version,
                                                scope = %cleanup_scope,
                                                "Stale store already absent at stream end"
                                            );
                                        }
                                        return;
                                    }
                                    Err(e) => {
                                        error!(
                                            kind = %task_kind,
                                            scope = %cleanup_scope,
                                            error = %e,
                                            "Watch error, kube-rs will retry with backoff"
                                        );
                                    }
                                }
                            }
                        }
                    }
                });

                handles.push(handle);
                info!(
                    kind = resource.kind,
                    group = resource.group,
                    scope = %scope,
                    "Started K8s core watcher"
                );
            }
        }
    }

    handles
}

pub fn spawn_crd_reprobe_task(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    selection: WatcherSelection,
    namespaces: Vec<String>,
    istio_root_namespace: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    let mut reprobe_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.tick().await; // skip first

        loop {
            tokio::select! {
                biased;
                _ = reprobe_shutdown.changed() => {
                    if *reprobe_shutdown.borrow() {
                        return;
                    }
                }
                _ = timer.tick() => {
                    debug!("Re-probing CRD group availability");
                    let new_handles = start_crd_watchers(
                        client.clone(),
                        store_set.clone(),
                        selection,
                        namespaces.clone(),
                        istio_root_namespace.clone(),
                        shutdown.clone(),
                    ).await;
                    // New handles run independently; we don't need to track
                    // them here since they self-manage via shutdown.
                    drop(new_handles);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_scopes_uses_all_namespaces_when_unset() {
        assert_eq!(watch_scopes(&[]), vec![None]);
    }

    #[test]
    fn watch_scopes_preserves_each_configured_namespace() {
        assert_eq!(
            watch_scopes(&["default".to_string(), "prod".to_string()]),
            vec![Some("default".to_string()), Some("prod".to_string())]
        );
        assert_eq!(
            watch_scope_label(Some("prod")),
            "namespace:prod".to_string()
        );
    }

    #[test]
    fn istio_watch_namespaces_include_root_namespace_when_namespaced() {
        assert_eq!(
            namespaces_with_istio_root(&["default".to_string()], "istio-system"),
            vec!["default".to_string(), "istio-system".to_string()]
        );
        assert_eq!(
            namespaces_with_istio_root(
                &["default".to_string(), "istio-system".to_string()],
                "istio-system"
            ),
            vec!["default".to_string(), "istio-system".to_string()]
        );
    }

    #[test]
    fn istio_watch_namespaces_keep_cluster_wide_scope_when_unset() {
        assert!(
            namespaces_with_istio_root(&[], "istio-system").is_empty(),
            "empty namespace list means Api::all and already includes root"
        );
    }

    #[test]
    fn crd_watch_namespaces_only_add_root_for_istio_crds() {
        let authz = ISTIO_CRDS
            .iter()
            .find(|resource| resource.kind == "AuthorizationPolicy")
            .expect("AuthorizationPolicy spec");
        let http_route = GATEWAY_API_CRDS
            .iter()
            .find(|resource| resource.kind == "HTTPRoute")
            .expect("HTTPRoute spec");

        assert_eq!(
            crd_watch_namespaces(authz, &["default".to_string()], "istio-system"),
            vec!["default".to_string(), "istio-system".to_string()]
        );
        assert_eq!(
            crd_watch_namespaces(http_route, &["default".to_string()], "istio-system"),
            vec!["default".to_string()]
        );
    }

    #[test]
    fn k8s_core_resources_cover_required_namespaced_pod_discovery_inputs() {
        let kinds: HashSet<&str> = K8S_CORE_RESOURCES
            .iter()
            .map(|resource| resource.kind)
            .collect();
        assert!(kinds.contains("Pod"));
        assert!(kinds.contains("Service"));
        assert!(kinds.contains("EndpointSlice"));
        assert!(
            !kinds.contains("Node"),
            "Node locality is optional and must not require cluster-scoped RBAC for pod discovery"
        );
    }

    #[test]
    fn selected_core_resources_adds_node_only_for_locality_enrichment() {
        let base_kinds: HashSet<&str> = selected_core_resources(false)
            .into_iter()
            .map(|resource| resource.kind)
            .collect();
        let locality_kinds: HashSet<&str> = selected_core_resources(true)
            .into_iter()
            .map(|resource| resource.kind)
            .collect();

        assert!(!base_kinds.contains("Node"));
        assert!(locality_kinds.contains("Node"));
        assert!(locality_kinds.contains("Pod"));
        assert!(locality_kinds.contains("Service"));
        assert!(locality_kinds.contains("EndpointSlice"));
    }

    #[test]
    fn gateway_api_watches_gateway_class_cluster_scoped() {
        let gateway_class = GATEWAY_API_CRDS
            .iter()
            .find(|resource| resource.kind == "GatewayClass")
            .expect("GatewayClass watcher spec");

        assert!(!gateway_class.namespaced);
        assert_eq!(gateway_class.plural, "gatewayclasses");
    }

    #[test]
    fn gateway_api_core_resources_include_secrets_for_certificate_refs() {
        let secret = GATEWAY_API_CORE_RESOURCES
            .iter()
            .find(|resource| resource.kind == "Secret")
            .expect("Secret watcher spec");

        assert!(secret.namespaced);
        assert_eq!(secret.plural, "secrets");
    }

    #[test]
    fn gateway_api_watches_served_v1beta1_compatibility_versions() {
        assert!(GATEWAY_API_CRDS.iter().any(|resource| {
            resource.kind == "Gateway" && resource.version == "v1beta1" && resource.namespaced
        }));
        assert!(GATEWAY_API_CRDS.iter().any(|resource| {
            resource.kind == "HTTPRoute" && resource.version == "v1beta1" && resource.namespaced
        }));
        assert!(GATEWAY_API_CRDS.iter().any(|resource| {
            resource.kind == "ReferenceGrant" && resource.version == "v1" && resource.namespaced
        }));
    }

    #[test]
    fn mesh_config_watcher_resource_is_root_namespace_configmap_only() {
        assert_eq!(ISTIO_MESH_CONFIG_RESOURCES.len(), 1);
        let resource = &ISTIO_MESH_CONFIG_RESOURCES[0];
        assert_eq!(resource.group, "");
        assert_eq!(resource.version, "v1");
        assert_eq!(resource.kind, "ConfigMap");
        assert_eq!(resource.plural, "configmaps");
        assert!(
            resource.namespaced,
            "Istio meshConfig lives in the root namespace ConfigMap"
        );
        assert_eq!(
            resource.field_selector,
            Some("metadata.name=istio"),
            "mesh-config watcher must be name-scoped so unrelated ConfigMaps in \
             the istio root namespace do not trigger no-op reconciliations"
        );
    }

    #[test]
    fn k8s_core_resources_have_no_field_selector() {
        for resource in K8S_CORE_RESOURCES {
            assert!(
                resource.field_selector.is_none(),
                "core resource {} should match every object in scope",
                resource.kind
            );
        }
        for resource in K8S_NODE_LOCALITY_RESOURCES {
            assert!(
                resource.field_selector.is_none(),
                "node-locality resource {} should match every object in scope",
                resource.kind
            );
        }
    }
}
