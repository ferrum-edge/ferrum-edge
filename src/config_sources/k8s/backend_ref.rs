//! Typed Gateway API `backendRef` kind resolution.
//!
//! Route translation and Gateway API `ResolvedRefs` status share this adapter
//! boundary so status cannot claim support that traffic does not receive.
//! Classification is Route-kind-aware: HTTPRoute/GRPCRoute/TCPRoute/TLSRoute
//! admit MCS `ServiceImport`, while UDPRoute remains core-Service-only.
//! Resolution and materialization run at reconcile/load time only.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use serde_json::Value;

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, RouteBackend, invalid_resource, service_dns_name,
    string_field,
};

/// MCS Multi-Cluster Services API group for `ServiceImport` (GEP-1748).
pub(crate) const SERVICE_IMPORT_GROUP: &str = "multicluster.x-k8s.io";
pub(crate) const SERVICE_IMPORT_KIND: &str = "ServiceImport";

/// Fixed MCS ClusterSet DNS suffix. Unlike cluster-local Services, this is not
/// derived from `cluster_domain` — MCS DNS publishes `*.svc.clusterset.local`.
pub(crate) const SERVICE_IMPORT_CLUSTERSET_DOMAIN: &str = "clusterset.local";

/// L4 protocol admission retained from an MCS `ServiceImport` port.
///
/// Gateway API HTTP, gRPC, TCP, and TLS backends all require a TCP transport.
/// Keep every other or malformed protocol as an explicit rejection instead of
/// collapsing it into mere port existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceImportPortProtocol {
    Tcp,
    Unsupported,
}

/// One collected `ServiceImport.spec.ports[]` entry.
///
/// `ServiceImport` deliberately omits `targetPort` (it is not meaningful to a
/// consumer), so the port *name* is the only mapping from the ClusterSet port
/// onto the backing container port published by MCS-derived EndpointSlices.
/// Keep it alongside the protocol or EndpointSlice expansion has nothing to
/// resolve a named port against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceImportPort {
    pub(crate) protocol: ServiceImportPortProtocol,
    /// `None` when the entry is unnamed or two entries for the same port
    /// number disagree on their name (ambiguous — resolve conservatively).
    pub(crate) name: Option<String>,
}

/// Field-specific failure while resolving a `ServiceImport` backend port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceImportPortError {
    BackendNotFound,
    UnsupportedProtocol,
}

/// Supported Gateway API `backendRef` target kinds Ferrum can materialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendKind {
    /// Core Kubernetes `Service` (`group: ""`, `kind: Service`).
    Service,
    /// MCS `ServiceImport` (`group: multicluster.x-k8s.io`, GEP-1748 Extended).
    ServiceImport,
}

impl BackendKind {
    pub(crate) fn group(self) -> &'static str {
        match self {
            Self::Service => "",
            Self::ServiceImport => SERVICE_IMPORT_GROUP,
        }
    }

    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Service => "Service",
            Self::ServiceImport => SERVICE_IMPORT_KIND,
        }
    }
}

/// Classify a `backendRef` `(group, kind)` pair against the global inventory of
/// kinds Ferrum understands at all.
///
/// Prefer [`classify_backend_kind_for_route`] at translation and status call
/// sites: a globally known kind may still be unsupported for a concrete Route
/// family (UDPRoute never materializes `ServiceImport`).
pub(crate) fn classify_backend_kind(group: &str, kind: &str) -> Result<BackendKind, ()> {
    match (group, kind) {
        ("", "Service") => Ok(BackendKind::Service),
        (SERVICE_IMPORT_GROUP, SERVICE_IMPORT_KIND) => Ok(BackendKind::ServiceImport),
        _ => Err(()),
    }
}

/// Whether this Gateway API Route kind can materialize MCS `ServiceImport`.
///
/// HTTPRoute, GRPCRoute, TCPRoute, and TLSRoute retain GEP-1748 support.
/// UDPRoute stays core-Service-only: datagram translation rejects every
/// non-Service backend, and status must report the same `InvalidKind`.
pub(crate) fn route_supports_service_import(route_kind: &str) -> bool {
    matches!(
        route_kind,
        "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute"
    )
}

/// Whether a classified backend kind can be materialized for this Route kind.
///
/// Shared by translation and `ResolvedRefs` so status cannot claim a backend
/// resolved when the Route family refuses to accept it.
pub(crate) fn route_supports_backend_kind(route_kind: &str, kind: BackendKind) -> bool {
    match kind {
        BackendKind::Service => true,
        BackendKind::ServiceImport => route_supports_service_import(route_kind),
    }
}

/// Classify a `backendRef` `(group, kind)` pair for a concrete Route kind.
///
/// Unknown combinations and kinds the Route cannot materialize remain
/// fail-closed; callers map [`Err`] to `InvalidKind` for both translation
/// faults and route status. Capability is evaluated before ReferenceGrant so a
/// grant cannot authorize a target the Route will never accept.
pub(crate) fn classify_backend_kind_for_route(
    route_kind: &str,
    group: &str,
    kind: &str,
) -> Result<BackendKind, ()> {
    let backend_kind = classify_backend_kind(group, kind)?;
    if route_supports_backend_kind(route_kind, backend_kind) {
        Ok(backend_kind)
    } else {
        Err(())
    }
}

/// Field-specific diagnostics for an unsupported `backendRef` target kind.
///
/// Message text is Route-kind-aware so UDPRoute operators are not told that
/// `ServiceImport` is supported when translation and status both reject it.
pub(crate) fn unsupported_backend_kind_message(
    route_kind: &str,
    group: &str,
    kind: &str,
) -> String {
    if route_supports_service_import(route_kind) {
        format!(
            "unsupported backendRef target group {group:?} kind {kind:?}; \
             supported kinds are core Service and {SERVICE_IMPORT_GROUP}/{SERVICE_IMPORT_KIND}"
        )
    } else {
        format!(
            "unsupported backendRef target group {group:?} kind {kind:?}; \
             {route_kind} only supports core Service backendRefs"
        )
    }
}

/// Stable tokens matched by status/translator fault classification. Keep these
/// substrings stable — Gateway API `ResolvedRefs` reason mapping depends on them.
pub(crate) fn message_is_unsupported_backend_kind(message: &str) -> bool {
    message.contains("unsupported backendRef target group")
}

/// Deliberately disjoint from [`message_is_unsupported_backend_kind`] and
/// [`message_is_unsupported_backend_protocol`]: a `"backendRef target"`
/// substring would also match the unsupported-kind message (`unsupported
/// backendRef target group …`), and every protocol message names
/// `backendRef ServiceImport`. Callers map a message to exactly one
/// `ResolvedRefs` reason, so keep these three predicates non-overlapping
/// rather than relying on `match` arm order.
pub(crate) fn message_is_backend_not_found(message: &str) -> bool {
    if message_is_unsupported_backend_protocol(message) {
        return false;
    }
    message.contains("backendRef Service")
        || message.contains("backendRef ServiceImport")
        || (message.contains("backendRef") && message.contains("was not found"))
}

/// Authorize a cross-namespace `backendRef` and return its resolved namespace.
///
/// Same-namespace refs skip ReferenceGrant. Cross-namespace refs require an
/// exact grant for the typed `(group, kind)` pair. Unknown kinds and kinds the
/// Route cannot materialize fail closed before grant evaluation so an overly
/// broad grant cannot bless them.
pub(crate) fn checked_backend_namespace(
    object: &K8sObject,
    backend_ref: &Value,
    acc: &K8sAccumulator,
    from_kind: &str,
) -> Result<(BackendKind, String), K8sTranslateError> {
    let backend_namespace =
        string_field(backend_ref, "namespace").unwrap_or(&object.metadata.namespace);
    let to_group = string_field(backend_ref, "group").unwrap_or_default();
    let to_kind = string_field(backend_ref, "kind").unwrap_or("Service");
    let backend_kind =
        classify_backend_kind_for_route(from_kind, to_group, to_kind).map_err(|()| {
            invalid_resource(
                object,
                unsupported_backend_kind_message(from_kind, to_group, to_kind),
            )
        })?;

    let backend_name = string_field(backend_ref, "name");
    if backend_namespace != object.metadata.namespace
        && !acc.reference_grant_allows(
            &object.metadata.namespace,
            api_group(&object.api_version),
            from_kind,
            backend_namespace,
            backend_kind.group(),
            backend_kind.kind(),
            backend_name,
        )
    {
        return Err(invalid_resource(
            object,
            format!(
                "{from_kind} backendRef to {} in namespace {backend_namespace:?} requires a \
                 matching ReferenceGrant",
                backend_kind.kind()
            ),
        ));
    }

    // An ExternalName Service is a DNS alias that can name any host — another
    // namespace's Service or the gateway's own loopback — so dialing it would
    // bypass the ReferenceGrant boundary above. Gateway API guidance is that
    // implementations should not support it; refuse it fail-closed.
    if backend_kind == BackendKind::Service
        && let Some(name) = backend_name
        && acc.service_is_external_name(backend_namespace, name)
    {
        return Err(invalid_resource(
            object,
            external_name_backend_message(backend_namespace, name),
        ));
    }

    Ok((backend_kind, backend_namespace.to_string()))
}

/// Whether a core/v1 Service object is `type: ExternalName`.
pub(crate) fn service_object_is_external_name(object: &K8sObject) -> bool {
    string_field(&object.spec, "type") == Some("ExternalName")
}

fn external_name_backend_message(namespace: &str, name: &str) -> String {
    format!(
        "backendRef Service {namespace:?}/{name:?} has type ExternalName, which is not a \
         supported backend (unsupported protocol)"
    )
}

/// Stable classification of the ExternalName refusal. Kept disjoint from the
/// unsupported-kind predicate; folded into
/// [`message_is_unsupported_backend_protocol`] so `ResolvedRefs` reports
/// `UnsupportedProtocol` and never `BackendNotFound`.
pub(crate) fn message_is_external_name_backend(message: &str) -> bool {
    message.contains("backendRef Service") && message.contains("has type ExternalName")
}

fn api_group(api_version: &str) -> &str {
    api_version
        .split_once('/')
        .map(|(group, _version)| group)
        .unwrap_or_default()
}

/// Whether this object is an MCS `ServiceImport` from the exact API group.
///
/// Version is deliberately independent, but a same-kind object from another
/// API group must never satisfy target existence or status resolution.
pub(crate) fn is_service_import_object(object: &K8sObject) -> bool {
    object.kind == SERVICE_IMPORT_KIND && api_group(&object.api_version) == SERVICE_IMPORT_GROUP
}

/// DNS hostname for a resolved backend target.
pub(crate) fn backend_dns_name(
    kind: BackendKind,
    name: &str,
    namespace: &str,
    cluster_domain: &str,
) -> String {
    match kind {
        BackendKind::Service => service_dns_name(name, namespace, cluster_domain),
        BackendKind::ServiceImport => {
            format!("{name}.{namespace}.svc.{SERVICE_IMPORT_CLUSTERSET_DOMAIN}")
        }
    }
}

/// Whether a typed backend target exists with the requested port.
///
/// * `Service` keeps the historical soft check: when no Services were observed
///   in the snapshot (common in focused unit fixtures), existence is not
///   enforced and DNS materialization proceeds.
/// * `ServiceImport` is always enforced against the collected index so a missing
///   MCS import cannot silently become a clusterset DNS blackhole while the
///   rest of the inventory is present — and so an absent MCS CRD (empty index)
///   fails closed.
pub(crate) fn backend_target_missing(
    acc: &K8sAccumulator,
    kind: BackendKind,
    namespace: &str,
    name: &str,
    port: u16,
) -> bool {
    match kind {
        BackendKind::Service => {
            acc.has_observed_services()
                && (!acc.service_exists(namespace, name)
                    || !acc.service_port_exists(namespace, name, port))
        }
        BackendKind::ServiceImport => {
            resolve_service_import_port(acc, namespace, name, Some(port)).is_err()
        }
    }
}

/// Resolve an explicit or derived TCP port for one collected `ServiceImport`.
///
/// A missing `backendRef.port` is accepted only when the import exposes exactly
/// one valid TCP port. This follows the Gateway API custom-backend derivation
/// contract without inheriting the core-Service HTTP/gRPC defaults.
pub(crate) fn resolve_service_import_port(
    acc: &K8sAccumulator,
    namespace: &str,
    name: &str,
    requested_port: Option<u16>,
) -> Result<u16, ServiceImportPortError> {
    let Some(ports) = acc.service_import_port_index(namespace, name) else {
        return Err(ServiceImportPortError::BackendNotFound);
    };
    resolve_service_import_port_entries(ports, requested_port)
}

fn resolve_service_import_port_entries(
    ports: &HashMap<u16, ServiceImportPort>,
    requested_port: Option<u16>,
) -> Result<u16, ServiceImportPortError> {
    if let Some(requested_port) = requested_port {
        return match ports.get(&requested_port).map(|entry| entry.protocol) {
            Some(ServiceImportPortProtocol::Tcp) => Ok(requested_port),
            Some(ServiceImportPortProtocol::Unsupported) => {
                Err(ServiceImportPortError::UnsupportedProtocol)
            }
            None => Err(ServiceImportPortError::BackendNotFound),
        };
    }

    let mut tcp_ports = ports.iter().filter_map(|(port, entry)| {
        (entry.protocol == ServiceImportPortProtocol::Tcp).then_some(*port)
    });
    let Some(port) = tcp_ports.next() else {
        return if ports.is_empty() {
            Err(ServiceImportPortError::BackendNotFound)
        } else {
            Err(ServiceImportPortError::UnsupportedProtocol)
        };
    };
    if tcp_ports.next().is_some() {
        return Err(ServiceImportPortError::BackendNotFound);
    }
    Ok(port)
}

pub(crate) fn service_import_port_error_message(
    namespace: &str,
    name: &str,
    requested_port: Option<u16>,
    error: ServiceImportPortError,
) -> String {
    match (error, requested_port) {
        (ServiceImportPortError::UnsupportedProtocol, Some(port)) => format!(
            "backendRef ServiceImport {namespace:?}/{name:?} port \"{port}\" uses an unsupported \
             protocol"
        ),
        (ServiceImportPortError::UnsupportedProtocol, None) => format!(
            "backendRef ServiceImport {namespace:?}/{name:?} does not expose a supported TCP port"
        ),
        (ServiceImportPortError::BackendNotFound, Some(port)) => {
            format!("backendRef ServiceImport {namespace:?}/{name:?} port \"{port}\" was not found")
        }
        (ServiceImportPortError::BackendNotFound, None) => format!(
            "backendRef ServiceImport {namespace:?}/{name:?} must expose exactly one TCP port \
             when backendRefs[].port is omitted"
        ),
    }
}

pub(crate) fn message_is_unsupported_backend_protocol(message: &str) -> bool {
    message_is_external_name_backend(message)
        || (message.contains("backendRef ServiceImport")
            && (message.contains("unsupported protocol")
                || message.contains("does not expose a supported TCP port")))
}

/// Materialize one authorized, port-resolved backend into route backends.
///
/// Service targets may expand onto ready EndpointSlice addresses when pod
/// discovery is enabled. When expansion is empty, ClusterIP Services fall
/// back to Service DNS on `backendRefs[].port` (kube-proxy maps it), while
/// headless Services fall back to Service DNS on `targetPort` because CoreDNS
/// returns pod IPs that listen on the container port. ServiceImport targets
/// expand onto MCS-labeled EndpointSlices when present; otherwise they use
/// ClusterSet DNS.
pub(crate) fn materialize_backend(
    acc: &K8sAccumulator,
    kind: BackendKind,
    namespace: &str,
    name: &str,
    port: u16,
    weight: u32,
) -> Vec<RouteBackend> {
    match kind {
        BackendKind::Service => {
            let endpoint_backends =
                acc.endpoint_route_backends_for_service(namespace, name, port, weight);
            if !endpoint_backends.is_empty() {
                return endpoint_backends;
            }
            // Headless Services resolve to pod IPs via DNS; dial targetPort.
            // ClusterIP Services keep `port` so kube-proxy can DNAT it.
            let dial_port = acc.service_dns_fallback_dial_port(namespace, name, port);
            vec![RouteBackend {
                host: backend_dns_name(kind, name, namespace, &acc.options.cluster_domain),
                port: dial_port,
                weight,
                service_namespace: Some(namespace.to_string()),
                service_name: Some(name.to_string()),
                service_port: Some(port),
            }]
        }
        BackendKind::ServiceImport => {
            let endpoint_backends =
                acc.endpoint_route_backends_for_service_import(namespace, name, port, weight);
            if !endpoint_backends.is_empty() {
                return endpoint_backends;
            }
            // Do not stamp Service identity tags: BackendTLSPolicy /
            // BackendLBPolicy attach to core Services only, and a same-named
            // local Service must not inherit policy from an Import backend.
            vec![RouteBackend {
                host: backend_dns_name(kind, name, namespace, &acc.options.cluster_domain),
                port,
                weight,
                service_namespace: None,
                service_name: None,
                service_port: None,
            }]
        }
    }
}

/// Status-side view of backend inventories used by `ResolvedRefs` planning.
///
/// Mirrors translator indexes so status and traffic share one predicate.
pub(crate) struct BackendRefStatusInventory<'a> {
    pub services_by_ns_name: &'a std::collections::HashMap<(&'a str, &'a str), &'a K8sObject>,
    pub service_imports_by_ns_name:
        &'a std::collections::HashMap<(&'a str, &'a str), &'a K8sObject>,
    pub has_any_service: bool,
}

/// Shared `ResolvedRefs` reason for one non-zero-weight `backendRef`.
///
/// Returns `None` when the ref is resolved. Reasons match Gateway API
/// `RouteConditionReason` vocabulary (`InvalidKind`, `RefNotPermitted`,
/// `BackendNotFound`, `UnsupportedProtocol` — the last also for an
/// `ExternalName` Service, which translation refuses).
///
/// Kind capability uses the same Route-kind predicate as translation, so a
/// present `ServiceImport` stays `InvalidKind` on UDPRoute. ReferenceGrant is
/// evaluated only after that capability gate.
///
/// `reference_grant_allows` receives `(to_namespace, to_group, to_kind, to_name)`.
pub(crate) fn unresolved_backend_ref_reason<'a, F>(
    route: &K8sObject,
    backend_ref: &Value,
    inventory: &BackendRefStatusInventory<'a>,
    mut reference_grant_allows: F,
) -> Option<&'static str>
where
    F: FnMut(&str, &str, &str, Option<&str>) -> bool,
{
    let to_group = backend_ref
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to_kind = backend_ref
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("Service");
    // Route-kind capability shares the translator predicate: a present
    // ServiceImport stays InvalidKind on UDPRoute even when inventory and a
    // ReferenceGrant would otherwise authorize it.
    let Ok(backend_kind) = classify_backend_kind_for_route(route.kind.as_str(), to_group, to_kind)
    else {
        return Some("InvalidKind");
    };

    let backend_namespace = backend_ref
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(&route.metadata.namespace);
    let backend_name = backend_ref.get("name").and_then(Value::as_str);

    if backend_namespace != route.metadata.namespace
        && !reference_grant_allows(
            backend_namespace,
            backend_kind.group(),
            backend_kind.kind(),
            backend_name,
        )
    {
        return Some("RefNotPermitted");
    }

    let requested_port = backend_ref
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok());

    match backend_kind {
        BackendKind::Service => {
            let backend_port =
                requested_port.unwrap_or(if route.kind == "GRPCRoute" { 50051 } else { 80 });
            if !inventory.has_any_service {
                return None;
            }
            let Some(backend_name) = backend_name else {
                return Some("BackendNotFound");
            };
            let Some(service) = inventory
                .services_by_ns_name
                .get(&(backend_namespace, backend_name))
            else {
                return Some("BackendNotFound");
            };
            if service_object_is_external_name(service) {
                return Some("UnsupportedProtocol");
            }
            if !object_has_numeric_port(service, backend_port) {
                return Some("BackendNotFound");
            }
        }
        BackendKind::ServiceImport => {
            let Some(backend_name) = backend_name else {
                return Some("BackendNotFound");
            };
            let Some(import) = inventory
                .service_imports_by_ns_name
                .get(&(backend_namespace, backend_name))
            else {
                return Some("BackendNotFound");
            };
            match resolve_service_import_object_port(import, requested_port) {
                Ok(_) => {}
                Err(ServiceImportPortError::BackendNotFound) => return Some("BackendNotFound"),
                Err(ServiceImportPortError::UnsupportedProtocol) => {
                    return Some("UnsupportedProtocol");
                }
            }
        }
    }

    None
}

fn resolve_service_import_object_port(
    object: &K8sObject,
    requested_port: Option<u16>,
) -> Result<u16, ServiceImportPortError> {
    let mut ports = HashMap::new();
    for entry in object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(port) = entry
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
        else {
            continue;
        };
        record_service_import_port(&mut ports, port, service_import_port_entry(entry));
    }
    resolve_service_import_port_entries(&ports, requested_port)
}

fn service_import_port_entry(port_entry: &Value) -> ServiceImportPort {
    ServiceImportPort {
        protocol: match port_entry.get("protocol") {
            None => ServiceImportPortProtocol::Tcp,
            Some(Value::String(protocol)) if protocol == "TCP" => ServiceImportPortProtocol::Tcp,
            Some(_) => ServiceImportPortProtocol::Unsupported,
        },
        name: string_field(port_entry, "name")
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned),
    }
}

fn record_service_import_port(
    ports: &mut HashMap<u16, ServiceImportPort>,
    port: u16,
    incoming: ServiceImportPort,
) {
    match ports.entry(port) {
        Entry::Occupied(mut occupied) => {
            let existing = occupied.get_mut();
            if existing.protocol != incoming.protocol {
                existing.protocol = ServiceImportPortProtocol::Unsupported;
            }
            if existing.name != incoming.name {
                // Two entries for one port number disagreeing on the name give
                // no unambiguous EndpointSlice mapping; fall back to the
                // ClusterSet DNS target rather than guessing one.
                existing.name = None;
            }
        }
        Entry::Vacant(vacant) => {
            vacant.insert(incoming);
        }
    }
}

fn object_has_numeric_port(object: &K8sObject, port: u16) -> bool {
    object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| entry.get("port").and_then(Value::as_u64) == Some(u64::from(port)))
}

/// Collect MCS `ServiceImport` port inventory for backendRef resolution.
pub(crate) fn collect_service_import(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let ports = object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .map(|arr| arr.as_slice())
        .unwrap_or(&[]);
    let mut port_numbers = HashMap::new();
    for port_entry in ports {
        let Some(raw) = port_entry.get("port").and_then(Value::as_u64) else {
            continue;
        };
        // Reuse the same 1..=65535 port gate as Service collection.
        let port = super::port_from_u64(object, raw, "ServiceImport.spec.ports[].port")?;
        record_service_import_port(
            &mut port_numbers,
            port,
            service_import_port_entry(port_entry),
        );
    }
    acc.record_service_import_ports(
        object.metadata.namespace.clone(),
        object.metadata.name.clone(),
        port_numbers,
    );
    Ok(())
}
