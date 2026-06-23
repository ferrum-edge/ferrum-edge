use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::config::{
    AppProtocol, MeshService, ServicePort, ServiceTargetPort, Workload, WorkloadPort, WorkloadRef,
    WorkloadSelector,
};

use super::{
    K8sAccumulator, K8sObject, K8sServiceKey, K8sTranslateError, RouteBackend, port_from_u64,
    string_field,
};

#[derive(Debug, Default)]
pub(super) struct CoreState {
    services: HashMap<K8sServiceKey, CoreService>,
    secrets: HashMap<K8sServiceKey, CoreSecret>,
    pods: HashMap<PodKey, CorePod>,
    pod_by_ip: HashMap<String, PodKey>,
    endpoint_slices: Vec<CoreEndpointSlice>,
    node_localities: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct PodKey {
    namespace: String,
    name: String,
}

impl PodKey {
    fn new(namespace: impl Into<String>, name: impl Into<String>) -> Option<Self> {
        let namespace = namespace.into();
        let name = name.into();
        if namespace.trim().is_empty() || name.trim().is_empty() {
            return None;
        }
        Some(Self { namespace, name })
    }
}

#[derive(Debug)]
struct CoreService {
    ports: Vec<ServicePort>,
    has_selector: bool,
    /// `spec.clusterIPs` (fallback `spec.clusterIP`), excluding the headless
    /// sentinel `"None"` and empty strings. Raw-TCP egress maps captured
    /// original destinations to services through these VIPs.
    cluster_ips: Vec<String>,
}

#[derive(Debug)]
struct CoreSecret {
    valid_tls_certificate: bool,
    tls_material_digest: Option<String>,
}

#[derive(Debug)]
struct CorePod {
    namespace: String,
    name: String,
    /// Kubernetes `metadata.uid`; threaded onto each per-pod `Workload` so the
    /// node-waypoint resolver can key policy scope by the exact pod UID the
    /// eBPF capture stamps. Empty when the pod object carried no UID.
    uid: String,
    labels: HashMap<String, String>,
    service_account: String,
    addresses: Vec<String>,
    ports: Vec<WorkloadPort>,
    node_name: Option<String>,
    ready: bool,
}

#[derive(Debug)]
struct CoreEndpointSlice {
    service_key: K8sServiceKey,
    ports: Vec<CoreEndpointSlicePort>,
    endpoints: Vec<CoreEndpoint>,
}

#[derive(Debug)]
struct CoreEndpointSlicePort {
    name: Option<String>,
    port: Option<u16>,
}

#[derive(Debug)]
struct CoreEndpoint {
    pod_key: Option<PodKey>,
    addresses: Vec<String>,
    ready: bool,
    node_name: Option<String>,
}

#[derive(Debug)]
struct CoreAutoWorkload {
    pod_key: PodKey,
    workload: Workload,
}

pub(super) fn is_core_resource_kind(kind: &str) -> bool {
    matches!(
        kind,
        "Pod" | "Service" | "EndpointSlice" | "Node" | "Namespace" | "Secret"
    )
}

pub(super) fn is_cluster_scoped_core_resource_kind(kind: &str) -> bool {
    matches!(kind, "Node" | "Namespace")
}

pub(super) fn collect(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    match object.kind.as_str() {
        "Service" => collect_service(acc, object),
        "Secret" => {
            collect_secret(acc, object);
            Ok(())
        }
        "Pod" => {
            collect_pod(acc, object);
            Ok(())
        }
        "EndpointSlice" => {
            collect_endpoint_slice(acc, object);
            Ok(())
        }
        "Node" => {
            collect_node(acc, object);
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn finalize(acc: &mut K8sAccumulator) -> Result<(), K8sTranslateError> {
    let mut service_keys: Vec<K8sServiceKey> = acc.core.services.keys().cloned().collect();
    service_keys.sort();

    let mut endpoint_slice_indices_by_service: HashMap<K8sServiceKey, Vec<usize>> = HashMap::new();
    for (index, slice) in acc.core.endpoint_slices.iter().enumerate() {
        endpoint_slice_indices_by_service
            .entry(slice.service_key.clone())
            .or_default()
            .push(index);
    }

    let mut workload_refs_by_service: HashMap<K8sServiceKey, Vec<String>> = HashMap::new();
    for workload in &acc.mesh.workloads {
        if let Some(key) =
            K8sServiceKey::new(workload.namespace.clone(), workload.service_name.clone())
        {
            // Keep duplicate SPIFFE IDs: replicated pods can share one service
            // account identity while still requiring distinct WorkloadRefs.
            workload_refs_by_service
                .entry(key)
                .or_default()
                .push(workload.spiffe_id.as_str().to_string());
        }
    }

    let mut service_backed_pod_keys = BTreeSet::new();

    for key in service_keys {
        if acc.explicit_service_entries.contains(&key) {
            continue;
        }

        let Some(service) = acc.core.services.get(&key) else {
            continue;
        };
        let mut workload_ref_strings = workload_refs_by_service.remove(&key).unwrap_or_default();

        if !acc.explicit_workload_services.contains(&key) {
            let auto_workloads = auto_workloads_for_service(
                acc,
                &key,
                endpoint_slice_indices_by_service
                    .get(&key)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?;
            for auto in auto_workloads {
                service_backed_pod_keys.insert(auto.pod_key);
                workload_ref_strings.push(auto.workload.spiffe_id.as_str().to_string());
                acc.mesh.workloads.push(auto.workload);
            }
        }

        let workloads = workload_ref_strings
            .into_iter()
            .filter_map(|spiffe| SpiffeId::new(spiffe).ok())
            .map(|spiffe_id| WorkloadRef { spiffe_id })
            .collect();

        acc.mesh.services.push(MeshService {
            name: key.name.clone(),
            namespace: key.namespace.clone(),
            ports: service.ports.clone(),
            workloads,
            protocol_overrides: HashMap::new(),
            cluster_ips: service.cluster_ips.clone(),
        });
    }

    add_identity_only_workloads(acc, &service_backed_pod_keys)?;

    Ok(())
}

fn collect_service(acc: &mut K8sAccumulator, object: &K8sObject) -> Result<(), K8sTranslateError> {
    let Some(key) = K8sServiceKey::new(
        object.metadata.namespace.clone(),
        object.metadata.name.clone(),
    ) else {
        return Ok(());
    };
    let ports = object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .map(|ports| ports.as_slice())
        .unwrap_or(&[]);
    let mut service_ports = Vec::new();
    for port_entry in ports {
        let Some(raw_port) = port_entry.get("port").and_then(Value::as_u64) else {
            continue;
        };
        let port = port_from_u64(object, raw_port, "Service.spec.ports[].port")?;
        let name = string_field(port_entry, "name").map(ToOwned::to_owned);
        let protocol = service_app_protocol(port_entry, name.as_deref());
        // `targetPort` is IntOrString: a numeric container port or a named one.
        let target_port = match port_entry.get("targetPort") {
            Some(Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .map(ServiceTargetPort::Number),
            Some(Value::String(s)) if !s.is_empty() => Some(ServiceTargetPort::Name(s.clone())),
            _ => None,
        };
        service_ports.push(ServicePort {
            port,
            protocol,
            name,
            target_port,
        });
    }
    // `spec.clusterIPs` carries the dual-stack VIP list; older objects may
    // only have the singular `spec.clusterIP`. Headless services declare the
    // literal string "None" — skip it (and empties): an absent VIP list means
    // "not raw-TCP-egress routable", never an invalid address.
    let mut cluster_ips: Vec<String> = object
        .spec
        .get("clusterIPs")
        .and_then(Value::as_array)
        .map(|ips| {
            ips.iter()
                .filter_map(Value::as_str)
                .filter(|ip| !ip.is_empty() && *ip != "None")
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if cluster_ips.is_empty()
        && let Some(ip) = string_field(&object.spec, "clusterIP")
        && !ip.is_empty()
        && ip != "None"
    {
        cluster_ips.push(ip.to_owned());
    }
    acc.core.services.insert(
        key,
        CoreService {
            ports: service_ports,
            has_selector: object
                .spec
                .get("selector")
                .and_then(Value::as_object)
                .is_some_and(|selector| !selector.is_empty()),
            cluster_ips,
        },
    );
    Ok(())
}

fn collect_pod(acc: &mut K8sAccumulator, object: &K8sObject) {
    let Some(key) = PodKey::new(
        object.metadata.namespace.clone(),
        object.metadata.name.clone(),
    ) else {
        return;
    };
    let addresses = pod_addresses(object);
    for address in &addresses {
        if let Some(previous) = acc.core.pod_by_ip.insert(address.clone(), key.clone())
            && previous != key
        {
            tracing::debug!(
                ip = %address,
                previous_namespace = %previous.namespace,
                previous_pod = %previous.name,
                replacement_namespace = %key.namespace,
                replacement_pod = %key.name,
                "Kubernetes pod IP mapping overwritten by later pod"
            );
        }
    }
    let pod = CorePod {
        namespace: object.metadata.namespace.clone(),
        name: object.metadata.name.clone(),
        uid: object.metadata.uid.clone(),
        labels: object.metadata.labels.clone(),
        service_account: string_field(&object.spec, "serviceAccountName")
            .filter(|value| !value.is_empty())
            .unwrap_or("default")
            .to_string(),
        addresses,
        ports: pod_ports(object),
        node_name: string_field(&object.spec, "nodeName").map(ToOwned::to_owned),
        ready: pod_is_ready(object),
    };
    acc.core.pods.insert(key, pod);
}

fn collect_endpoint_slice(acc: &mut K8sAccumulator, object: &K8sObject) {
    let service_name = object
        .metadata
        .labels
        .get("kubernetes.io/service-name")
        .cloned()
        .or_else(|| string_field(&object.spec, "serviceName").map(ToOwned::to_owned));
    let Some(service_name) = service_name else {
        return;
    };
    let Some(service_key) = K8sServiceKey::new(object.metadata.namespace.clone(), service_name)
    else {
        return;
    };

    let ports = object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|port| {
            let name = string_field(port, "name")
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned);
            let port = port
                .get("port")
                .and_then(Value::as_u64)
                .filter(|port| *port != 0 && *port <= u16::MAX as u64)
                .map(|port| port as u16);
            if name.is_none() && port.is_none() {
                None
            } else {
                Some(CoreEndpointSlicePort { name, port })
            }
        })
        .collect();

    let endpoints = object
        .spec
        .get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|endpoint| {
            let pod_key = endpoint.get("targetRef").and_then(|target| {
                if string_field(target, "kind").unwrap_or("Pod") != "Pod" {
                    return None;
                }
                let namespace = string_field(target, "namespace").unwrap_or(&service_key.namespace);
                let name = string_field(target, "name")?;
                PodKey::new(namespace.to_string(), name.to_string())
            });
            CoreEndpoint {
                pod_key,
                addresses: string_array_from_value(endpoint, "addresses"),
                ready: endpoint_is_ready(endpoint),
                node_name: string_field(endpoint, "nodeName").map(ToOwned::to_owned),
            }
        })
        .collect();

    acc.core.endpoint_slices.push(CoreEndpointSlice {
        service_key,
        ports,
        endpoints,
    });
}

pub(super) fn secret_is_valid_tls_certificate(
    acc: &K8sAccumulator,
    namespace: &str,
    name: &str,
) -> bool {
    K8sServiceKey::new(namespace.to_string(), name.to_string())
        .and_then(|key| acc.core.secrets.get(&key))
        .is_some_and(|secret| secret.valid_tls_certificate)
}

pub(super) fn secret_tls_material_digest<'a>(
    acc: &'a K8sAccumulator,
    namespace: &str,
    name: &str,
) -> Option<&'a str> {
    K8sServiceKey::new(namespace.to_string(), name.to_string())
        .and_then(|key| acc.core.secrets.get(&key))
        .and_then(|secret| secret.tls_material_digest.as_deref())
}

fn collect_secret(acc: &mut K8sAccumulator, object: &K8sObject) {
    let Some(key) = K8sServiceKey::new(
        object.metadata.namespace.clone(),
        object.metadata.name.clone(),
    ) else {
        return;
    };
    let valid_tls_certificate = secret_object_is_valid_tls_certificate(object);
    acc.core.secrets.insert(
        key,
        CoreSecret {
            valid_tls_certificate,
            tls_material_digest: valid_tls_certificate
                .then(|| secret_tls_material_digest_for_object(object))
                .flatten(),
        },
    );
}

fn secret_tls_material_digest_for_object(secret: &K8sObject) -> Option<String> {
    let data = secret.spec.get("data").and_then(Value::as_object)?;
    let cert = data.get("tls.crt").and_then(Value::as_str)?;
    let key = data.get("tls.key").and_then(Value::as_str)?;
    let mut digest = Sha256::new();
    digest.update(cert.as_bytes());
    digest.update([0]);
    digest.update(key.as_bytes());
    Some(hex::encode(digest.finalize()))
}

pub(crate) fn secret_object_is_valid_tls_certificate(secret: &K8sObject) -> bool {
    if secret.spec.get("type").and_then(Value::as_str) != Some("kubernetes.io/tls") {
        return false;
    }
    let Some(data) = secret.spec.get("data").and_then(Value::as_object) else {
        return false;
    };
    let Some(cert) = data.get("tls.crt").and_then(Value::as_str) else {
        return false;
    };
    let Some(key) = data.get("tls.key").and_then(Value::as_str) else {
        return false;
    };
    secret_data_decodes_to_valid_tls_pair(cert, key)
}

fn secret_data_decodes_to_valid_tls_pair(cert_value: &str, key_value: &str) -> bool {
    let Some(certs) = secret_data_decodes_to_certificate_chain(cert_value) else {
        return false;
    };
    let Some(key) = secret_data_decodes_to_private_key(key_value) else {
        return false;
    };
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    rustls::sign::CertifiedKey::from_der(certs, key, &provider).is_ok()
}

fn secret_data_decodes_to_certificate_chain(
    value: &str,
) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
    secret_data_decodes_to_bytes(value, |bytes| {
        let mut reader = std::io::Cursor::new(bytes);
        let Ok(certs) = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>() else {
            return None;
        };
        (!certs.is_empty()).then_some(certs)
    })
}

fn secret_data_decodes_to_private_key(
    value: &str,
) -> Option<rustls::pki_types::PrivateKeyDer<'static>> {
    secret_data_decodes_to_bytes(value, |bytes| {
        let mut reader = std::io::Cursor::new(bytes);
        rustls_pemfile::private_key(&mut reader).ok().flatten()
    })
}

fn secret_data_decodes_to_bytes<T>(
    value: &str,
    predicate: impl FnOnce(&[u8]) -> Option<T>,
) -> Option<T> {
    use base64::Engine as _;

    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(value) else {
        return None;
    };
    predicate(&bytes)
}

pub(super) fn endpoint_route_backends_for_service(
    acc: &K8sAccumulator,
    namespace: &str,
    service_name: &str,
    service_port: u16,
    weight: u32,
) -> Vec<RouteBackend> {
    if !acc.options.pod_discovery_enabled {
        return Vec::new();
    }
    let Some(service_key) = K8sServiceKey::new(namespace.to_string(), service_name.to_string())
    else {
        return Vec::new();
    };
    let Some(service) = acc.core.services.get(&service_key) else {
        return Vec::new();
    };
    if service.has_selector && !service.cluster_ips.is_empty() {
        return Vec::new();
    }

    let service_port_spec = service
        .ports
        .iter()
        .find(|candidate| candidate.port == service_port);
    let mut seen = BTreeSet::new();
    let mut backends = Vec::new();
    for slice in acc
        .core
        .endpoint_slices
        .iter()
        .filter(|slice| slice.service_key == service_key)
    {
        let Some(target_port) = endpoint_backend_port(service_port_spec, service_port, slice)
        else {
            continue;
        };
        for endpoint in slice.endpoints.iter().filter(|endpoint| endpoint.ready) {
            for address in &endpoint.addresses {
                if address.is_empty() {
                    continue;
                }
                if seen.insert((address.clone(), target_port)) {
                    backends.push(RouteBackend {
                        host: address.clone(),
                        port: target_port,
                        weight,
                        service_namespace: Some(namespace.to_string()),
                        service_name: Some(service_name.to_string()),
                        service_port: Some(service_port),
                    });
                }
            }
        }
    }
    backends
}

fn endpoint_backend_port(
    service_port_spec: Option<&ServicePort>,
    service_port: u16,
    slice: &CoreEndpointSlice,
) -> Option<u16> {
    match service_port_spec.and_then(|port| port.target_port.as_ref()) {
        Some(ServiceTargetPort::Number(port)) if *port != 0 => Some(*port),
        Some(ServiceTargetPort::Name(name)) => slice
            .ports
            .iter()
            .find(|port| port.name.as_deref() == Some(name.as_str()))
            .and_then(|port| port.port),
        Some(ServiceTargetPort::Number(_)) => None,
        None => {
            if let Some(name) = service_port_spec.and_then(|port| port.name.as_deref())
                && let Some(port) = slice
                    .ports
                    .iter()
                    .find(|port| port.name.as_deref() == Some(name))
                    .and_then(|port| port.port)
            {
                return Some(port);
            }
            Some(service_port)
        }
    }
}

fn collect_node(acc: &mut K8sAccumulator, object: &K8sObject) {
    let Some(locality) = node_locality(&object.metadata.labels) else {
        return;
    };
    acc.core
        .node_localities
        .insert(object.metadata.name.clone(), locality);
}

fn auto_workloads_for_service(
    acc: &K8sAccumulator,
    service_key: &K8sServiceKey,
    endpoint_slice_indices: &[usize],
) -> Result<Vec<CoreAutoWorkload>, K8sTranslateError> {
    let mut endpoints_by_pod = BTreeMap::new();
    let mut seen_endpoint_addresses: BTreeMap<PodKey, HashSet<String>> = BTreeMap::new();
    for &slice_index in endpoint_slice_indices {
        let Some(slice) = acc.core.endpoint_slices.get(slice_index) else {
            continue;
        };
        for endpoint in &slice.endpoints {
            if !endpoint.ready {
                continue;
            }
            let pod_key = endpoint
                .pod_key
                .clone()
                .or_else(|| pod_key_for_endpoint_addresses(&acc.core, &endpoint.addresses));
            let Some(pod_key) = pod_key else {
                continue;
            };
            let merged = endpoints_by_pod
                .entry(pod_key.clone())
                .or_insert_with(|| CoreEndpoint {
                    pod_key: Some(pod_key.clone()),
                    addresses: Vec::new(),
                    ready: true,
                    node_name: endpoint.node_name.clone(),
                });
            let seen_addresses = seen_endpoint_addresses.entry(pod_key).or_default();
            for address in &endpoint.addresses {
                if seen_addresses.insert(address.clone()) {
                    merged.addresses.push(address.clone());
                }
            }
            if merged.node_name.is_none() {
                merged.node_name = endpoint.node_name.clone();
            }
        }
    }

    let mut workloads = Vec::with_capacity(endpoints_by_pod.len());
    for (pod_key, endpoint) in endpoints_by_pod {
        let Some(pod) = acc.core.pods.get(&pod_key) else {
            continue;
        };
        // EndpointSlice readiness controls service membership, while pod readiness
        // keeps stale cache entries from resurfacing terminating pods.
        if !pod.ready {
            continue;
        }
        workloads.push(CoreAutoWorkload {
            pod_key,
            workload: workload_from_pod(acc, service_key, pod, &endpoint)?,
        });
    }
    Ok(workloads)
}

fn add_identity_only_workloads(
    acc: &mut K8sAccumulator,
    service_backed_pod_keys: &BTreeSet<PodKey>,
) -> Result<(), K8sTranslateError> {
    let mut pod_keys: Vec<PodKey> = acc.core.pods.keys().cloned().collect();
    pod_keys.sort();
    for pod_key in pod_keys {
        if service_backed_pod_keys.contains(&pod_key) {
            continue;
        }
        let Some(pod) = acc.core.pods.get(&pod_key) else {
            continue;
        };
        if !pod.ready || pod.uid.is_empty() {
            continue;
        }
        acc.mesh
            .workloads
            .push(identity_only_workload_from_pod(acc, pod)?);
    }
    Ok(())
}

fn workload_from_pod(
    acc: &K8sAccumulator,
    service_key: &K8sServiceKey,
    pod: &CorePod,
    endpoint: &CoreEndpoint,
) -> Result<Workload, K8sTranslateError> {
    let path = format!("ns/{}/sa/{}", pod.namespace, pod.service_account);
    let spiffe_id = SpiffeId::from_parts(&acc.options.trust_domain, &path)
        .map_err(|e| invalid_resource_for_core_pod(pod, format!("invalid pod SPIFFE ID: {e}")))?;
    let mut addresses = if endpoint.addresses.is_empty() {
        pod.addresses.clone()
    } else {
        endpoint.addresses.clone()
    };
    addresses.sort();
    addresses.dedup();
    let node_name = endpoint.node_name.as_deref().or(pod.node_name.as_deref());
    let locality = node_name.and_then(|node| acc.core.node_localities.get(node).cloned());

    Ok(Workload {
        spiffe_id,
        selector: WorkloadSelector {
            labels: pod.labels.clone(),
            namespace: Some(pod.namespace.clone()),
        },
        service_name: service_key.name.clone(),
        addresses,
        ports: pod.ports.clone(),
        trust_domain: acc.options.trust_domain.clone(),
        namespace: pod.namespace.clone(),
        network: None,
        cluster: None,
        weight: None,
        locality,
        service_account: Some(pod.service_account.clone()),
        // Per-pod UID for node-waypoint scope keying; `None` when the pod
        // object carried no UID so the resolver falls back to SPIFFE scope.
        pod_uid: (!pod.uid.is_empty()).then(|| pod.uid.clone()),
        node_waypoint: None,
        remote_provenance: false,
    })
}

fn identity_only_workload_from_pod(
    acc: &K8sAccumulator,
    pod: &CorePod,
) -> Result<Workload, K8sTranslateError> {
    let path = format!("ns/{}/sa/{}", pod.namespace, pod.service_account);
    let spiffe_id = SpiffeId::from_parts(&acc.options.trust_domain, &path)
        .map_err(|e| invalid_resource_for_core_pod(pod, format!("invalid pod SPIFFE ID: {e}")))?;
    let locality = pod
        .node_name
        .as_deref()
        .and_then(|node| acc.core.node_localities.get(node).cloned());

    Ok(Workload {
        spiffe_id,
        selector: WorkloadSelector {
            labels: pod.labels.clone(),
            namespace: Some(pod.namespace.clone()),
        },
        service_name: pod.name.clone(),
        // Identity-only pods feed node-waypoint source identity and scoped
        // authz. They are not Service backends, so keep them out of direct
        // Pod-IP routing and outbound registries.
        addresses: Vec::new(),
        ports: Vec::new(),
        trust_domain: acc.options.trust_domain.clone(),
        namespace: pod.namespace.clone(),
        network: None,
        cluster: None,
        weight: None,
        locality,
        service_account: Some(pod.service_account.clone()),
        pod_uid: Some(pod.uid.clone()),
        node_waypoint: None,
        remote_provenance: false,
    })
}

fn invalid_resource_for_core_pod(pod: &CorePod, message: impl Into<String>) -> K8sTranslateError {
    K8sTranslateError::InvalidResource {
        kind: "Pod".to_string(),
        namespace: pod.namespace.clone(),
        name: pod.name.clone(),
        message: message.into(),
    }
}

fn pod_key_for_endpoint_addresses(state: &CoreState, addresses: &[String]) -> Option<PodKey> {
    addresses
        .iter()
        .find_map(|address| state.pod_by_ip.get(address).cloned())
}

fn pod_addresses(object: &K8sObject) -> Vec<String> {
    let mut addresses = Vec::new();
    if let Some(pod_ip) = string_field(&object.status, "podIP")
        && !pod_ip.is_empty()
    {
        addresses.push(pod_ip.to_string());
    }
    for ip in object
        .status
        .get("podIPs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| string_field(entry, "ip"))
    {
        if !addresses.iter().any(|existing| existing == ip) {
            addresses.push(ip.to_string());
        }
    }
    addresses
}

fn pod_ports(object: &K8sObject) -> Vec<WorkloadPort> {
    let mut ports = Vec::new();
    for container in object
        .spec
        .get("containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for port_entry in container
            .get("ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(raw_port) = port_entry.get("containerPort").and_then(Value::as_u64) else {
                continue;
            };
            if raw_port == 0 || raw_port > u16::MAX as u64 {
                continue;
            }
            ports.push(WorkloadPort {
                port: raw_port as u16,
                protocol: workload_port_protocol(string_field(port_entry, "protocol")),
                name: string_field(port_entry, "name").map(ToOwned::to_owned),
            });
        }
    }
    ports
}

fn pod_is_ready(object: &K8sObject) -> bool {
    if object.metadata.deletion_timestamp.is_some() {
        return false;
    }
    if matches!(
        string_field(&object.status, "phase"),
        Some("Pending" | "Failed" | "Succeeded")
    ) {
        return false;
    }
    let conditions = object
        .status
        .get("conditions")
        .and_then(Value::as_array)
        .map(|conditions| conditions.as_slice())
        .unwrap_or(&[]);
    if !condition_is_true(conditions, "Ready") {
        return false;
    }
    for gate in object
        .spec
        .get("readinessGates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|gate| string_field(gate, "conditionType"))
    {
        if !condition_is_true(conditions, gate) {
            return false;
        }
    }
    true
}

fn condition_is_true(conditions: &[Value], condition_type: &str) -> bool {
    conditions.iter().any(|condition| {
        string_field(condition, "type") == Some(condition_type)
            && string_field(condition, "status") == Some("True")
    })
}

fn endpoint_is_ready(endpoint: &Value) -> bool {
    let Some(conditions) = endpoint.get("conditions") else {
        return true;
    };
    if conditions
        .get("terminating")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    // EndpointSlice readiness fields are tri-state; Kubernetes treats omitted
    // `ready`/`serving` as true for endpoints that are not terminating.
    let ready = conditions.get("ready").and_then(Value::as_bool);
    let serving = conditions
        .get("serving")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| ready.unwrap_or(true));
    ready.unwrap_or(true) && serving
}

fn string_array_from_value(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn service_app_protocol(port_entry: &Value, port_name: Option<&str>) -> AppProtocol {
    // L4 transport wins over any L7 naming/appProtocol hint: a Service port with
    // `protocol: UDP` is UDP regardless of an `appProtocol: http` or a name like
    // `http3`, because those L7 hints describe the application protocol carried
    // OVER the transport, not the transport itself. Classifying a UDP port as
    // HTTP-family from a hint would route it into TCP/H2 route materialization
    // instead of the inert UDP lane. Check the L4 protocol FIRST and short-circuit
    // when it is a non-HTTP-routable transport (today: `Udp`). TCP stays
    // hint-overridable (the long-standing convention — a `protocol: TCP` port
    // named `http` is an HTTP listener over TCP), so only `Udp` pre-empts here.
    let l4 = workload_port_protocol(string_field(port_entry, "protocol"));
    if matches!(l4, AppProtocol::Udp) {
        return l4;
    }
    if let Some(protocol) = string_field(port_entry, "appProtocol").and_then(app_protocol_from_hint)
    {
        return protocol;
    }
    if let Some(protocol) = port_name.and_then(app_protocol_from_hint) {
        return protocol;
    }
    l4
}

fn workload_port_protocol(protocol: Option<&str>) -> AppProtocol {
    match protocol.unwrap_or("TCP").to_ascii_uppercase().as_str() {
        "TCP" => AppProtocol::Tcp,
        // UDP is modeled as a distinct L4 transport so it partitions out of both
        // HTTP-family routing and the raw-TCP stream lane (it was previously
        // swallowed as `Unknown`, i.e. silently treated as HTTP-family).
        // Capture/egress for UDP arrives in a later F3 §3.3 stage; the variant
        // is inert today, so a UDP port simply materializes no routes.
        "UDP" => AppProtocol::Udp,
        // Other K8s Service protocols (e.g. SCTP) have no mesh transport model
        // yet; keep them unknown until a stage consumes them.
        _ => AppProtocol::Unknown,
    }
}

fn app_protocol_from_hint(value: &str) -> Option<AppProtocol> {
    let value = value.to_ascii_lowercase();
    if value.contains("grpc") {
        Some(AppProtocol::Grpc)
    } else if value.contains("http2") || value.contains("h2c") {
        Some(AppProtocol::Http2)
    } else if value.starts_with("tls") || value == "https" {
        // Keep this before generic HTTP prefix matching so service hints like
        // `https` keep their TLS transport semantics instead of becoming HTTP.
        Some(AppProtocol::Tls)
    } else if value.starts_with("http")
        || value == "kubernetes.io/ws"
        || value == "ws"
        || value == "wss"
    {
        Some(AppProtocol::Http)
    } else if value.starts_with("mongo") {
        Some(AppProtocol::Mongo)
    } else if value.starts_with("redis") {
        Some(AppProtocol::Redis)
    } else if value.starts_with("mysql") {
        Some(AppProtocol::Mysql)
    } else if value.starts_with("postgres") {
        Some(AppProtocol::Postgres)
    } else if value.starts_with("tcp") {
        Some(AppProtocol::Tcp)
    } else {
        None
    }
}

fn node_locality(labels: &HashMap<String, String>) -> Option<String> {
    let region = labels
        .get("topology.kubernetes.io/region")
        .or_else(|| labels.get("failure-domain.beta.kubernetes.io/region"))?;
    let zone = labels
        .get("topology.kubernetes.io/zone")
        .or_else(|| labels.get("failure-domain.beta.kubernetes.io/zone"));
    let sub_zone = labels.get("topology.kubernetes.io/subzone");

    let mut locality = region.clone();
    if let Some(zone) = zone {
        locality.push('/');
        locality.push_str(zone);
        if let Some(sub_zone) = sub_zone {
            locality.push('/');
            locality.push_str(sub_zone);
        }
    }
    Some(locality)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions, translate_k8s_objects};
    use crate::identity::spiffe::TrustDomain;
    use serde_json::json;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
        .with_source_namespaces(Vec::new())
        .with_pod_discovery_enabled(true)
    }

    fn object(kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: if kind == "EndpointSlice" {
                "discovery.k8s.io/v1".to_string()
            } else {
                "v1".to_string()
            },
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: String::new(),
                namespace: namespace.to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec,
            status: Value::Object(serde_json::Map::new()),
        }
    }

    fn ready_pod(name: &str, ip: &str) -> K8sObject {
        let mut pod = object(
            "Pod",
            "default",
            name,
            json!({
                "serviceAccountName": "reviews",
                "nodeName": "node-a",
                "containers": [{
                    "ports": [{"name": "http", "containerPort": 9080, "protocol": "TCP"}]
                }]
            }),
        );
        pod.metadata
            .labels
            .insert("app".to_string(), "reviews".to_string());
        pod.status = json!({
            "phase": "Running",
            "podIP": ip,
            "conditions": [{"type": "Ready", "status": "True"}]
        });
        pod
    }

    fn service() -> K8sObject {
        object(
            "Service",
            "default",
            "reviews",
            json!({
                "ports": [{
                    "name": "http",
                    "port": 9080,
                    "targetPort": 9080,
                    "appProtocol": "http"
                }]
            }),
        )
    }

    #[test]
    fn app_protocol_hints_classify_https_as_tls_before_generic_http() {
        assert_eq!(app_protocol_from_hint("https"), Some(AppProtocol::Tls));
        assert_eq!(app_protocol_from_hint("HTTPS"), Some(AppProtocol::Tls));
        assert_eq!(app_protocol_from_hint("http"), Some(AppProtocol::Http));
        assert_eq!(app_protocol_from_hint("http2"), Some(AppProtocol::Http2));
        assert_eq!(app_protocol_from_hint("ws"), Some(AppProtocol::Http));
        assert_eq!(app_protocol_from_hint("wss"), Some(AppProtocol::Http));
        assert_eq!(
            app_protocol_from_hint("kubernetes.io/ws"),
            Some(AppProtocol::Http)
        );
    }

    fn endpoint_slice(pods: Vec<(&str, &str)>) -> K8sObject {
        let endpoints: Vec<Value> = pods
            .into_iter()
            .map(|(pod, ip)| {
                json!({
                    "addresses": [ip],
                    "targetRef": {"kind": "Pod", "name": pod, "namespace": "default"},
                    "conditions": {"ready": true}
                })
            })
            .collect();
        let mut slice = object(
            "EndpointSlice",
            "default",
            "reviews-abc",
            json!({
                "addressType": "IPv4",
                "endpoints": endpoints,
                "ports": [{"name": "http", "port": 9080}]
            }),
        );
        slice.metadata.labels.insert(
            "kubernetes.io/service-name".to_string(),
            "reviews".to_string(),
        );
        slice
    }

    #[test]
    fn core_service_pod_and_endpoint_slice_materialize_mesh_service() {
        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services.len(), 1);
        assert_eq!(mesh.services[0].name, "reviews");
        assert_eq!(mesh.services[0].ports[0].port, 9080);
        // The Service `targetPort` is captured for inbound backend resolution.
        assert_eq!(
            mesh.services[0].ports[0].target_port,
            Some(crate::modes::mesh::config::ServiceTargetPort::Number(9080))
        );
        assert_eq!(mesh.services[0].workloads.len(), 1);
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(mesh.workloads[0].addresses, vec!["10.1.0.10"]);
        assert_eq!(
            mesh.workloads[0].spiffe_id.as_str(),
            "spiffe://cluster.local/ns/default/sa/reviews"
        );
    }

    #[test]
    fn source_only_ready_pod_materializes_identity_without_service_ref() {
        let mut dst = ready_pod("reviews-v1", "10.1.0.10");
        dst.metadata.uid = "11111111-1111-4111-8111-111111111111".to_string();

        let mut src = ready_pod("src-a", "10.1.0.20");
        src.metadata.uid = "22222222-2222-4222-8222-222222222222".to_string();
        src.spec["serviceAccountName"] = json!("src-a");
        src.metadata
            .labels
            .insert("app".to_string(), "src-a".to_string());

        let translation = translate_k8s_objects(
            &[
                service(),
                dst,
                src,
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services.len(), 1);
        assert_eq!(mesh.services[0].workloads.len(), 1);
        assert_eq!(mesh.workloads.len(), 2);

        let source = mesh
            .workloads
            .iter()
            .find(|workload| {
                workload.pod_uid.as_deref() == Some("22222222-2222-4222-8222-222222222222")
            })
            .expect("source-only pod identity workload");
        assert_eq!(
            source.spiffe_id.as_str(),
            "spiffe://cluster.local/ns/default/sa/src-a"
        );
        assert_eq!(
            source.selector.labels.get("app").map(String::as_str),
            Some("src-a")
        );
        assert!(source.addresses.is_empty());
        assert!(source.ports.is_empty());
        assert!(
            mesh.services[0]
                .workloads
                .iter()
                .all(|workload| workload.spiffe_id != source.spiffe_id),
            "source-only identity workload must not be added to service workload refs"
        );
    }

    #[test]
    fn workload_port_protocol_classifies_udp_distinctly() {
        // A K8s Service `protocol: UDP` port must map to the distinct `Udp`
        // transport, NOT the `Unknown` (HTTP-family) bucket it was silently
        // swallowed into before. TCP keeps mapping to `Tcp`; an unknown
        // transport (e.g. SCTP) still falls through to `Unknown`.
        assert_eq!(workload_port_protocol(Some("UDP")), AppProtocol::Udp);
        assert_eq!(workload_port_protocol(Some("udp")), AppProtocol::Udp);
        assert_eq!(workload_port_protocol(Some("TCP")), AppProtocol::Tcp);
        assert_eq!(workload_port_protocol(None), AppProtocol::Tcp);
        assert_eq!(workload_port_protocol(Some("SCTP")), AppProtocol::Unknown);
    }

    #[test]
    fn service_app_protocol_l4_udp_overrides_l7_name_and_appprotocol_hints() {
        // L4 `protocol: UDP` must WIN over any L7 appProtocol / port-name hint:
        // a UDP port carrying `appProtocol: http` or a name like `http3` is still
        // the UDP transport (the hint describes what rides OVER UDP, not the
        // transport), so it must classify `Udp` and partition out of HTTP route
        // materialization rather than becoming HTTP-family.
        let udp_with_http_appprotocol = json!({
            "name": "metrics",
            "port": 8125,
            "protocol": "UDP",
            "appProtocol": "http"
        });
        assert_eq!(
            service_app_protocol(&udp_with_http_appprotocol, Some("metrics")),
            AppProtocol::Udp,
            "protocol: UDP must override an appProtocol: http hint"
        );

        let udp_named_http3 = json!({
            "name": "http3",
            "port": 443,
            "protocol": "UDP"
        });
        assert_eq!(
            service_app_protocol(&udp_named_http3, Some("http3")),
            AppProtocol::Udp,
            "protocol: UDP must override an http3 port-name hint"
        );

        // Regression guard: a TCP port keeps the long-standing hint-override
        // convention (a `protocol: TCP` port named `http` is an HTTP listener),
        // so only Udp pre-empts the L7 hint — not every L4 protocol.
        let tcp_named_http = json!({
            "name": "http",
            "port": 80,
            "protocol": "TCP"
        });
        assert_eq!(
            service_app_protocol(&tcp_named_http, Some("http")),
            AppProtocol::Http,
            "protocol: TCP must stay hint-overridable (http name → HTTP)"
        );

        // And a UDP port with NO HTTP hint still classifies Udp via the L4 field.
        let bare_udp = json!({ "name": "dns", "port": 53, "protocol": "UDP" });
        assert_eq!(
            service_app_protocol(&bare_udp, Some("dns")),
            AppProtocol::Udp
        );
    }

    #[test]
    fn core_service_udp_port_translates_to_udp_app_protocol() {
        // End-to-end: a K8s Service with a `protocol: UDP` port (no
        // HTTP-classifying appProtocol/name hint) materializes a mesh service
        // whose port carries `AppProtocol::Udp` — so it partitions out of HTTP
        // route materialization instead of being mis-routed as HTTP.
        let udp_service = object(
            "Service",
            "default",
            "dns",
            json!({
                "ports": [{
                    "name": "dns",
                    "port": 53,
                    "targetPort": 53,
                    "protocol": "UDP"
                }]
            }),
        );
        let translation = translate_k8s_objects(
            &[udp_service, ready_pod("dns-v1", "10.1.0.11"), {
                let mut slice = endpoint_slice(vec![("dns-v1", "10.1.0.11")]);
                slice.metadata.name = "dns-abc".to_string();
                slice
                    .metadata
                    .labels
                    .insert("kubernetes.io/service-name".to_string(), "dns".to_string());
                slice.spec["ports"] = json!([{"name": "dns", "port": 53}]);
                slice
            }],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        let svc = mesh
            .services
            .iter()
            .find(|s| s.name == "dns")
            .expect("dns service materialized");
        assert_eq!(svc.ports[0].port, 53);
        assert_eq!(
            svc.ports[0].protocol,
            AppProtocol::Udp,
            "Service protocol: UDP port must classify as AppProtocol::Udp"
        );
    }

    #[test]
    fn auto_workload_identity_uses_referenced_pod_namespace() {
        let mut pod = ready_pod("reviews-v1", "10.1.0.10");
        pod.metadata.namespace = "workloads".to_string();
        let mut slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        slice.spec["endpoints"][0]["targetRef"]["namespace"] = json!("workloads");

        let translation = translate_k8s_objects(&[service(), pod, slice], options())
            .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services.len(), 1);
        assert_eq!(mesh.services[0].namespace, "default");
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(mesh.workloads[0].namespace, "workloads");
        assert_eq!(
            mesh.workloads[0].selector.namespace.as_deref(),
            Some("workloads")
        );
        assert_eq!(
            mesh.workloads[0].spiffe_id.as_str(),
            "spiffe://cluster.local/ns/workloads/sa/reviews"
        );
    }

    #[test]
    fn auto_workload_merges_addresses_from_multiple_endpoint_slices() {
        let mut ipv4_slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        ipv4_slice.metadata.name = "reviews-ipv4".to_string();
        let mut ipv6_slice = endpoint_slice(vec![("reviews-v1", "fd00::10")]);
        ipv6_slice.metadata.name = "reviews-ipv6".to_string();
        ipv6_slice.spec["addressType"] = json!("IPv6");

        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                ipv4_slice,
                ipv6_slice,
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(
            mesh.workloads[0].addresses,
            vec!["10.1.0.10".to_string(), "fd00::10".to_string()]
        );
        assert_eq!(mesh.services[0].workloads.len(), 1);
    }

    #[test]
    fn replicated_pods_with_same_service_account_keep_distinct_workload_refs() {
        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                ready_pod("reviews-v2", "10.1.0.11"),
                endpoint_slice(vec![
                    ("reviews-v1", "10.1.0.10"),
                    ("reviews-v2", "10.1.0.11"),
                ]),
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads.len(), 2);
        assert_eq!(mesh.services[0].workloads.len(), 2);
        assert_eq!(
            mesh.services[0].workloads[0].spiffe_id, mesh.services[0].workloads[1].spiffe_id,
            "replicated Pods share the same service-account SPIFFE ID"
        );
        let addresses: Vec<&str> = mesh
            .workloads
            .iter()
            .flat_map(|workload| workload.addresses.iter().map(String::as_str))
            .collect();
        assert_eq!(addresses, vec!["10.1.0.10", "10.1.0.11"]);
    }

    #[test]
    fn pod_without_ready_condition_is_not_surfaced() {
        let mut pod = ready_pod("reviews-v1", "10.1.0.10");
        pod.status = json!({
            "phase": "Running",
            "podIP": "10.1.0.10",
            "conditions": [{"type": "Ready", "status": "False"}]
        });

        let translation = translate_k8s_objects(
            &[
                service(),
                pod,
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services[0].workloads.len(), 0);
        assert_eq!(mesh.workloads.len(), 0);
    }

    #[test]
    fn pod_with_deletion_timestamp_is_not_surfaced() {
        let mut pod = ready_pod("reviews-v1", "10.1.0.10");
        pod.metadata.deletion_timestamp = Some("2026-05-14T12:00:00Z".to_string());

        let translation = translate_k8s_objects(
            &[
                service(),
                pod,
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services[0].workloads.len(), 0);
        assert_eq!(mesh.workloads.len(), 0);
    }

    #[test]
    fn endpoint_slice_ready_false_is_not_surfaced() {
        let mut slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        slice.spec["endpoints"][0]["conditions"]["ready"] = json!(false);

        let translation = translate_k8s_objects(
            &[service(), ready_pod("reviews-v1", "10.1.0.10"), slice],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services[0].workloads.len(), 0);
        assert_eq!(mesh.workloads.len(), 0);
    }

    #[test]
    fn endpoint_slice_terminating_is_not_surfaced() {
        let mut slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        slice.spec["endpoints"][0]["conditions"]["terminating"] = json!(true);

        let translation = translate_k8s_objects(
            &[service(), ready_pod("reviews-v1", "10.1.0.10"), slice],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services[0].workloads.len(), 0);
        assert_eq!(mesh.workloads.len(), 0);
    }

    #[test]
    fn endpoint_slice_serving_inherits_unready_when_ready_absent() {
        let mut slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        slice.spec["endpoints"][0]["conditions"] = json!({"ready": false});

        let translation = translate_k8s_objects(
            &[service(), ready_pod("reviews-v1", "10.1.0.10"), slice],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services[0].workloads.len(), 0);
        assert_eq!(mesh.workloads.len(), 0);
    }

    #[test]
    fn node_topology_labels_project_workload_locality() {
        let mut node = object("Node", "default", "node-a", json!({}));
        node.metadata.namespace = "default".to_string();
        node.metadata.labels.insert(
            "topology.kubernetes.io/region".to_string(),
            "us-east1".to_string(),
        );
        node.metadata.labels.insert(
            "topology.kubernetes.io/zone".to_string(),
            "us-east1-b".to_string(),
        );

        let translation = translate_k8s_objects(
            &[
                node,
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.workloads[0].locality.as_deref(),
            Some("us-east1/us-east1-b")
        );
    }

    #[test]
    fn cluster_scoped_node_survives_namespace_filter_for_pod_discovery() {
        let mut node = object("Node", "", "node-a", json!({}));
        node.metadata.labels.insert(
            "topology.kubernetes.io/region".to_string(),
            "us-east1".to_string(),
        );
        node.metadata.labels.insert(
            "topology.kubernetes.io/zone".to_string(),
            "us-east1-b".to_string(),
        );
        let mut service = service();
        service.metadata.namespace = "prod".to_string();
        let mut pod = ready_pod("reviews-v1", "10.1.0.10");
        pod.metadata.namespace = "prod".to_string();
        let mut slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        slice.metadata.namespace = "prod".to_string();
        slice.spec["endpoints"][0]["targetRef"]["namespace"] = json!("prod");

        let translation = translate_k8s_objects(
            &[node, service, pod, slice],
            K8sTranslationOptions::new(
                "prod".to_string(),
                TrustDomain::new("cluster.local").expect("test trust domain"),
            )
            .with_source_namespaces(vec!["prod".to_string()])
            .with_pod_discovery_enabled(true),
        )
        .expect("core translation succeeds");

        assert_eq!(translation.config.known_namespaces, vec!["prod"]);
        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.workloads[0].locality.as_deref(),
            Some("us-east1/us-east1-b")
        );
    }

    #[test]
    fn endpoint_zone_without_node_region_does_not_emit_locality() {
        let mut slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        slice.spec["endpoints"][0]["zone"] = json!("us-east1-b");

        let translation = translate_k8s_objects(
            &[service(), ready_pod("reviews-v1", "10.1.0.10"), slice],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads[0].locality, None);
    }

    #[test]
    fn explicit_workload_entry_overrides_auto_pod_workload() {
        let workload_entry = K8sObject {
            kind: "WorkloadEntry".to_string(),
            api_version: "networking.istio.io/v1".to_string(),
            metadata: K8sMetadata {
                name: "vm-reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: json!({
                "service": "reviews",
                "address": "10.2.0.1",
                "serviceAccount": "reviews"
            }),
            status: Value::Object(serde_json::Map::new()),
        };

        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
                workload_entry,
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(mesh.workloads[0].addresses, vec!["10.2.0.1"]);
        assert_eq!(mesh.services[0].workloads.len(), 1);
    }

    #[test]
    fn explicit_workload_entry_qualified_service_overrides_auto_pod_workload() {
        let workload_entry = K8sObject {
            kind: "WorkloadEntry".to_string(),
            api_version: "networking.istio.io/v1".to_string(),
            metadata: K8sMetadata {
                name: "vm-reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: json!({
                "service": "reviews.default.svc.cluster.local",
                "address": "10.2.0.1",
                "serviceAccount": "reviews"
            }),
            status: Value::Object(serde_json::Map::new()),
        };

        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
                workload_entry,
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(mesh.workloads[0].addresses, vec!["10.2.0.1"]);
        assert_eq!(mesh.services[0].workloads.len(), 1);
    }

    #[test]
    fn explicit_workload_entry_same_namespace_service_host_overrides_auto_pod_workload() {
        let workload_entry = K8sObject {
            kind: "WorkloadEntry".to_string(),
            api_version: "networking.istio.io/v1".to_string(),
            metadata: K8sMetadata {
                name: "vm-reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: json!({
                "service": "reviews.default",
                "address": "10.2.0.1",
                "serviceAccount": "reviews"
            }),
            status: Value::Object(serde_json::Map::new()),
        };

        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
                workload_entry,
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads.len(), 1);
        assert_eq!(mesh.workloads[0].addresses, vec!["10.2.0.1"]);
        assert_eq!(mesh.services[0].workloads.len(), 1);
    }

    #[test]
    fn explicit_service_entry_overrides_auto_service() {
        let service_entry = K8sObject {
            kind: "ServiceEntry".to_string(),
            api_version: "networking.istio.io/v1".to_string(),
            metadata: K8sMetadata {
                name: "manual-reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "ports": [{"number": 9080, "name": "http", "protocol": "HTTP"}]
            }),
            status: Value::Object(serde_json::Map::new()),
        };

        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
                service_entry,
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert!(mesh.services.is_empty());
        assert_eq!(mesh.service_entries.len(), 1);
    }

    #[test]
    fn explicit_service_entry_same_namespace_service_host_overrides_auto_service() {
        let service_entry = K8sObject {
            kind: "ServiceEntry".to_string(),
            api_version: "networking.istio.io/v1".to_string(),
            metadata: K8sMetadata {
                name: "manual-reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: json!({
                "hosts": ["reviews.default"],
                "ports": [{"number": 9080, "name": "http", "protocol": "HTTP"}]
            }),
            status: Value::Object(serde_json::Map::new()),
        };

        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
                service_entry,
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert!(mesh.services.is_empty());
        assert_eq!(mesh.service_entries.len(), 1);
    }

    #[test]
    fn explicit_service_entry_cross_namespace_service_host_does_not_override_auto_service() {
        let service_entry = K8sObject {
            kind: "ServiceEntry".to_string(),
            api_version: "networking.istio.io/v1".to_string(),
            metadata: K8sMetadata {
                name: "manual-reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: json!({
                "hosts": ["reviews.prod.svc.cluster.local"],
                "ports": [{"number": 9080, "name": "http", "protocol": "HTTP"}]
            }),
            status: Value::Object(serde_json::Map::new()),
        };
        let mut prod_service = service();
        prod_service.metadata.namespace = "prod".to_string();
        let mut prod_pod = ready_pod("reviews-v1", "10.1.0.10");
        prod_pod.metadata.namespace = "prod".to_string();
        let mut prod_slice = endpoint_slice(vec![("reviews-v1", "10.1.0.10")]);
        prod_slice.metadata.namespace = "prod".to_string();
        prod_slice.spec["endpoints"][0]["targetRef"]["namespace"] = json!("prod");

        let translation = translate_k8s_objects(
            &[prod_service, prod_pod, prod_slice, service_entry],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services.len(), 1);
        assert_eq!(mesh.services[0].name, "reviews");
        assert_eq!(mesh.services[0].namespace, "prod");
        assert_eq!(mesh.service_entries.len(), 1);
    }

    #[test]
    fn service_entry_name_matching_service_does_not_override_unrelated_hosts() {
        let service_entry = K8sObject {
            kind: "ServiceEntry".to_string(),
            api_version: "networking.istio.io/v1".to_string(),
            metadata: K8sMetadata {
                name: "reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: json!({
                "hosts": ["api.external.example.com"],
                "ports": [{"number": 443, "name": "https", "protocol": "HTTPS"}]
            }),
            status: Value::Object(serde_json::Map::new()),
        };

        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
                service_entry,
            ],
            options(),
        )
        .expect("core translation succeeds");

        let mesh = translation.config.mesh.expect("mesh config");
        assert_eq!(mesh.services.len(), 1);
        assert_eq!(mesh.services[0].name, "reviews");
        assert_eq!(mesh.service_entries.len(), 1);
    }

    #[test]
    fn pod_discovery_is_disabled_by_default() {
        let translation = translate_k8s_objects(
            &[
                service(),
                ready_pod("reviews-v1", "10.1.0.10"),
                endpoint_slice(vec![("reviews-v1", "10.1.0.10")]),
            ],
            K8sTranslationOptions::new(
                "default".to_string(),
                TrustDomain::new("cluster.local").expect("test trust domain"),
            )
            .with_source_namespaces(Vec::new()),
        )
        .expect("translation succeeds");

        assert!(translation.config.mesh.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_translation_10k_pod_fixture_stays_under_memory_budget() {
        let mut objects = Vec::with_capacity(10_102);
        objects.push(service());
        for node_index in 0..2 {
            let mut node = object("Node", "default", &format!("node-{node_index}"), json!({}));
            node.metadata.labels.insert(
                "topology.kubernetes.io/region".to_string(),
                "us-east1".to_string(),
            );
            node.metadata.labels.insert(
                "topology.kubernetes.io/zone".to_string(),
                format!("us-east1-{node_index}"),
            );
            objects.push(node);
        }
        for pod_index in 0..10_000 {
            let mut pod = ready_pod(
                &format!("reviews-{pod_index}"),
                &format!("10.42.{}.{}", pod_index / 250, pod_index % 250),
            );
            pod.spec["nodeName"] = json!(format!("node-{}", pod_index % 2));
            objects.push(pod);
        }
        for slice_index in 0..100 {
            let endpoints: Vec<Value> = (0..100)
                .map(|offset| {
                    let pod_index = slice_index * 100 + offset;
                    json!({
                        "addresses": [format!("10.42.{}.{}", pod_index / 250, pod_index % 250)],
                        "targetRef": {
                            "kind": "Pod",
                            "name": format!("reviews-{pod_index}"),
                            "namespace": "default"
                        },
                        "conditions": {"ready": true}
                    })
                })
                .collect();
            let mut slice = object(
                "EndpointSlice",
                "default",
                &format!("reviews-{slice_index}"),
                json!({
                    "addressType": "IPv4",
                    "endpoints": endpoints,
                    "ports": [{"name": "http", "port": 9080}]
                }),
            );
            slice.metadata.labels.insert(
                "kubernetes.io/service-name".to_string(),
                "reviews".to_string(),
            );
            objects.push(slice);
        }

        let translation =
            translate_k8s_objects(&objects, options()).expect("10k pod translation succeeds");
        let mesh = translation.config.mesh.expect("mesh config");

        assert_eq!(mesh.services.len(), 1);
        assert_eq!(mesh.workloads.len(), 10_000);
        assert!(
            peak_rss_bytes() < 2 * 1024 * 1024 * 1024,
            "synthetic 10k-pod translation should keep peak RSS below 2 GiB"
        );
    }

    #[cfg(target_os = "linux")]
    fn peak_rss_bytes() -> u64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the provided rusage struct on success.
        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if result != 0 {
            return 0;
        }
        // SAFETY: result == 0 means getrusage initialized usage.
        let usage = unsafe { usage.assume_init() };
        (usage.ru_maxrss as u64) * 1024
    }
}
