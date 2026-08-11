//! Gateway API `ListenerSet` attachment, merge/conflict, and status projection.
//!
//! ListenerSets add listeners to a managed Gateway that explicitly opts in via
//! `spec.allowedListeners`. Routes attach by parentRef to the ListenerSet
//! (optionally with `sectionName`). Listener policies reuse the same
//! [`super::GatewayApiListenerPolicy`] map as Gateway listeners so HTTP/L4
//! route materialization stays one engine.
//!
//! Precedence for conflict resolution (pinned Gateway API v1.5.1):
//! 1. Parent Gateway listeners
//! 2. ListenerSets by oldest `metadata.creationTimestamp`
//! 3. ListenerSets by `{namespace}/{name}`

use std::collections::{BTreeMap, HashMap};

use chrono::DateTime;
use serde_json::Value;

use super::gateway_api::{
    allowed_route_namespaces, collect_gateway_frontend_tls, gateway_api_section_name_is_valid,
    listener_allowed_route_kinds, listener_app_protocol, listener_is_materializable,
    listener_protocol_mode_is_supported, listener_requires_frontend_tls,
    listener_selected_frontend_tls_source, namespace_selector, namespace_selector_matches,
    normalize_gateway_hostname, validate_listenerset_listener_entry,
};
use super::{
    GatewayApiAllowedRoutesNamespaces, GatewayApiListenerConflict, GatewayApiListenerKey,
    GatewayApiListenerParentKind, GatewayApiListenerPolicy, GatewayApiListenerSetStatus,
    K8sAccumulator, K8sObject, K8sResourceKey, K8sTranslateError, includes_object_namespace,
    string_field,
};
use crate::modes::mesh::config::{MeshService, ServicePort};

const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";
const LISTENERSET_STATUS_OWNER_MARKER: &str = "[ferrum-edge]";
/// Pinned Gateway API v1.5.1 ListenerSetSpec.Listeners MaxItems.
const MAX_LISTENERSET_LISTENERS: usize = 64;

fn ferrum_listenerset_status_message(message: &str) -> String {
    format!("{LISTENERSET_STATUS_OWNER_MARKER} {message}")
}

/// Collect ListenerSets from a snapshot, resolving parent Gateways from the
/// same snapshot. Call after Gateway listener policies are indexed.
pub(crate) fn collect_listenersets_from_snapshot(
    acc: &mut K8sAccumulator,
    objects: &[&K8sObject],
) -> Result<(), K8sTranslateError> {
    let gateways: HashMap<(String, String), &K8sObject> = objects
        .iter()
        .filter(|object| object.kind == "Gateway")
        .filter(|object| includes_object_namespace(&acc.options, object))
        .filter(|object| acc.gateway_is_managed_by_ferrum(object))
        .map(|object| {
            (
                (
                    object.metadata.namespace.clone(),
                    object.metadata.name.clone(),
                ),
                *object,
            )
        })
        .collect();

    for object in objects {
        if object.kind != "ListenerSet" || !includes_object_namespace(&acc.options, object) {
            continue;
        }
        collect_one_listenerset(acc, object, &gateways)?;
    }
    finalize_listenerset_conflicts(acc, objects);
    Ok(())
}

fn collect_one_listenerset(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    gateways: &HashMap<(String, String), &K8sObject>,
) -> Result<(), K8sTranslateError> {
    let resource = K8sResourceKey::from_object(object);
    let Some(parent_ref) = object.spec.get("parentRef") else {
        record_listenerset_status(
            acc,
            resource,
            None,
            false,
            false,
            "Invalid",
            "ListenerSet spec.parentRef is required",
            false,
            "Invalid",
            "ListenerSet spec.parentRef is required",
        );
        return Ok(());
    };

    let parent = match parse_parent_gateway_ref(object, parent_ref) {
        Ok(parent) => parent,
        Err(message) => {
            record_listenerset_status(
                acc, resource, None, false, false, "Invalid", &message, false, "Invalid", &message,
            );
            return Ok(());
        }
    };

    let Some(gateway) = gateways.get(&(parent.namespace.clone(), parent.name.clone())) else {
        record_listenerset_status(
            acc,
            resource,
            Some((parent.namespace.clone(), parent.name.clone())),
            false,
            false,
            "ParentNotAccepted",
            "ListenerSet parentRef does not select a Ferrum-managed Gateway",
            false,
            "ParentNotProgrammed",
            "ListenerSet parentRef does not select a Ferrum-managed Gateway",
        );
        return Ok(());
    };

    if !allowed_listeners_permits(acc, gateway, object) {
        record_listenerset_status(
            acc,
            resource,
            Some((parent.namespace.clone(), parent.name.clone())),
            false,
            false,
            "NotAllowed",
            "Gateway spec.allowedListeners does not permit this ListenerSet",
            false,
            "Invalid",
            "Gateway spec.allowedListeners does not permit this ListenerSet",
        );
        return Ok(());
    }

    let Some(listeners) = object.spec.get("listeners").and_then(Value::as_array) else {
        record_listenerset_status(
            acc,
            resource,
            Some((parent.namespace.clone(), parent.name.clone())),
            false,
            false,
            "Invalid",
            "ListenerSet spec.listeners must be a non-empty array",
            false,
            "Invalid",
            "ListenerSet spec.listeners must be a non-empty array",
        );
        return Ok(());
    };
    if listeners.is_empty() {
        record_listenerset_status(
            acc,
            resource,
            Some((parent.namespace.clone(), parent.name.clone())),
            false,
            false,
            "Invalid",
            "ListenerSet spec.listeners must be a non-empty array",
            false,
            "Invalid",
            "ListenerSet spec.listeners must be a non-empty array",
        );
        return Ok(());
    }
    if listeners.len() > MAX_LISTENERSET_LISTENERS {
        record_listenerset_status(
            acc,
            resource,
            Some((parent.namespace.clone(), parent.name.clone())),
            false,
            false,
            "Invalid",
            "ListenerSet spec.listeners must contain at most 64 listeners",
            false,
            "Invalid",
            "ListenerSet spec.listeners must contain at most 64 listeners",
        );
        return Ok(());
    }
    if listenerset_listener_names_are_duplicated(listeners) {
        record_listenerset_status(
            acc,
            resource,
            Some((parent.namespace.clone(), parent.name.clone())),
            false,
            false,
            "Invalid",
            "ListenerSet spec.listeners[].name values must be unique",
            false,
            "Invalid",
            "ListenerSet spec.listeners[].name values must be unique",
        );
        return Ok(());
    }

    let mut saw_valid_listener = false;
    for listener in listeners {
        // Never invent a default listener name. Unnamed / invalid SectionName
        // entries stay unindexed so they cannot materialize traffic or steal
        // sectionName attachment from a valid sibling.
        let Some(listener_name) = string_field(listener, "name")
            .filter(|name| !name.is_empty() && gateway_api_section_name_is_valid(name))
        else {
            acc.warnings.push(format!(
                "Gateway API ListenerSet {}/{} listener rejected: spec.listeners[].name is required and must be a valid SectionName",
                object.metadata.namespace, object.metadata.name
            ));
            continue;
        };
        let requires_frontend_tls = listener_requires_frontend_tls(listener);
        let (namespaces, validation_error) = match validate_listenerset_listener_entry(listener) {
            Ok(()) => match allowed_route_namespaces(listener) {
                Ok(namespaces) => (namespaces, None),
                Err(error) => (GatewayApiAllowedRoutesNamespaces::Invalid, Some(error)),
            },
            Err(error) => {
                acc.warnings.push(format!(
                    "Gateway API ListenerSet {}/{} listener {} rejected: {}",
                    object.metadata.namespace, object.metadata.name, listener_name, error
                ));
                (GatewayApiAllowedRoutesNamespaces::Invalid, Some(error))
            }
        };
        if !listener_protocol_mode_is_supported(listener) {
            acc.warnings.push(format!(
                "Gateway API ListenerSet {}/{} listener {} rejected: spec.listeners[].tls.mode must be Passthrough for protocol TLS",
                object.metadata.namespace, object.metadata.name, listener_name
            ));
        }
        // Missing protocol is a shape error above; never default to HTTP.
        let protocol = string_field(listener, "protocol")
            .map(|protocol| protocol.to_ascii_uppercase())
            .unwrap_or_default();
        let frontend_tls_source = if requires_frontend_tls {
            listener_selected_frontend_tls_source(acc, object, listener)
        } else {
            None
        };
        let spec_accepted = validation_error.is_none()
            && !protocol.is_empty()
            && listener_protocol_mode_is_supported(listener);
        let materializable = spec_accepted && listener_is_materializable(acc, object, listener);
        if spec_accepted {
            saw_valid_listener = true;
        }
        let policy = GatewayApiListenerPolicy {
            namespaces,
            validation_error,
            spec_accepted,
            hostname: string_field(listener, "hostname")
                .filter(|hostname| !hostname.is_empty())
                .map(normalize_gateway_hostname),
            port: listener.get("port").and_then(Value::as_u64),
            protocol,
            route_kinds: listener_allowed_route_kinds(listener),
            materializable,
            routes_materializable: materializable,
            requires_frontend_tls,
            conflict_reason: None,
            parent_gateway: Some((parent.namespace.clone(), parent.name.clone())),
            frontend_tls_source,
        };
        acc.gateway_api_listener_policies.insert(
            GatewayApiListenerKey {
                namespace: object.metadata.namespace.clone(),
                parent_kind: GatewayApiListenerParentKind::ListenerSet,
                gateway: object.metadata.name.clone(),
                listener: listener_name.to_string(),
            },
            policy,
        );
    }

    collect_gateway_frontend_tls(acc, object);

    let accepted = saw_valid_listener;
    record_listenerset_status(
        acc,
        resource,
        Some((parent.namespace, parent.name)),
        accepted,
        accepted,
        if accepted {
            "Accepted"
        } else {
            "ListenersNotValid"
        },
        if accepted {
            "Ferrum accepted this ListenerSet on the parent Gateway"
        } else {
            "Every ListenerSet listener was invalid or unsupported"
        },
        false,
        if accepted {
            "Pending"
        } else {
            "ListenersNotValid"
        },
        if accepted {
            "Waiting for ListenerSet listeners to be programmed"
        } else {
            "Every ListenerSet listener was invalid or unsupported"
        },
    );
    Ok(())
}

/// Apply Gateway→ListenerSet precedence and mark conflicted listeners.
pub(crate) fn finalize_listenerset_conflicts(acc: &mut K8sAccumulator, objects: &[&K8sObject]) {
    let listenerset_order = listenerset_precedence_index(objects);
    let mut by_gateway: HashMap<(String, String), Vec<ConflictCandidate>> = HashMap::new();

    for (key, policy) in &acc.gateway_api_listener_policies {
        let Some(port) = policy.port else {
            continue;
        };
        let protocol = policy.protocol.as_str();
        let gateway = match key.parent_kind {
            GatewayApiListenerParentKind::Gateway => (key.namespace.clone(), key.gateway.clone()),
            GatewayApiListenerParentKind::ListenerSet => match &policy.parent_gateway {
                Some(parent) => parent.clone(),
                None => continue,
            },
        };
        let precedence = match key.parent_kind {
            GatewayApiListenerParentKind::Gateway => 0u64,
            GatewayApiListenerParentKind::ListenerSet => {
                1 + listenerset_order
                    .get(&(key.namespace.clone(), key.gateway.clone()))
                    .copied()
                    .unwrap_or(u64::MAX / 2)
            }
        };
        by_gateway
            .entry(gateway)
            .or_default()
            .push(ConflictCandidate {
                key: key.clone(),
                precedence,
                port,
                protocol: protocol.to_ascii_uppercase(),
                hostname: policy.hostname.clone(),
                eligible: policy.materializable && policy.conflict_reason.is_none(),
            });
    }

    let mut conflicted: HashMap<GatewayApiListenerKey, &'static str> = HashMap::new();

    // ProtocolConflict is physical and process-wide: socket ownership is not
    // parent-Gateway-scoped (`GatewayListenerPlan::from_config` builds one
    // global stream_ports set). For each numeric TCP port across every eligible
    // managed Gateway and attached ListenerSet claim in this accumulator, if any
    // eligible HTTP-family claim coexists with any eligible raw TCP/TLS-stream
    // claim, every eligible claim in those two families is refused. UDP is a
    // separate transport and is never withdrawn by this rule. A sequential
    // accept/remove walk is wrong for 3+ claims (HTTP, TCP, HTTP): removing the
    // first pair from `accepted` would let a later same-family sibling survive
    // depending on listener/name order.
    let mut tcp_family_by_port: BTreeMap<u64, Vec<&ConflictCandidate>> = BTreeMap::new();
    for candidates in by_gateway.values() {
        for candidate in candidates.iter() {
            if !candidate.eligible {
                continue;
            }
            match listener_port_family(candidate.protocol.as_str()) {
                Some(ListenerPortFamily::Http | ListenerPortFamily::TcpStream) => {
                    tcp_family_by_port
                        .entry(candidate.port)
                        .or_default()
                        .push(candidate);
                }
                Some(ListenerPortFamily::Udp) | None => {}
            }
        }
    }
    for port_candidates in tcp_family_by_port.values() {
        let has_http = port_candidates.iter().any(|candidate| {
            listener_port_family(candidate.protocol.as_str()) == Some(ListenerPortFamily::Http)
        });
        let has_tcp_stream = port_candidates.iter().any(|candidate| {
            listener_port_family(candidate.protocol.as_str()) == Some(ListenerPortFamily::TcpStream)
        });
        if has_http && has_tcp_stream {
            for candidate in port_candidates {
                conflicted.insert(candidate.key.clone(), "ProtocolConflict");
            }
        }
    }

    // HostnameConflict keeps Gateway→ListenerSet precedence (only the later
    // claim loses) among otherwise compatible same-protocol claims that
    // survived family arbitration, scoped to the parent Gateway exactly as
    // before. Distinct Gateway hostnames (including catch-all plus named
    // siblings) do not conflict because `hostnames_conflict` only matches equal
    // values. Plaintext-vs-TLS HTTP-family refusal stays in
    // `refuse_incompatible_same_port_listeners` so messages stay one decision
    // per physical shape.
    for candidates in by_gateway.values_mut() {
        candidates.sort_by(|left, right| {
            (
                left.precedence,
                left.key.namespace.as_str(),
                left.key.gateway.as_str(),
                left.key.listener.as_str(),
            )
                .cmp(&(
                    right.precedence,
                    right.key.namespace.as_str(),
                    right.key.gateway.as_str(),
                    right.key.listener.as_str(),
                ))
        });

        let mut accepted: Vec<&ConflictCandidate> = Vec::new();
        for candidate in candidates.iter() {
            if !candidate.eligible || conflicted.contains_key(&candidate.key) {
                continue;
            }
            // Exact-duplicate same-protocol claims (equal hostname values on the
            // same port) lose here for both Gateway and ListenerSet parents —
            // later claim only, preserving Gateway→ListenerSet precedence.
            // Catch-all (`None`) versus a named hostname does not conflict
            // (`hostnames_conflict` requires equal values), so HTTPS catch-all
            // + hostname siblings stay materializable. Process-wide HTTP-family
            // vs raw TCP/TLS ProtocolConflict was already decided above; this
            // walk only applies same-protocol HostnameConflict.
            if let Some(reason) = conflict_against_accepted(candidate, &accepted) {
                conflicted.insert(candidate.key.clone(), reason);
                continue;
            }
            accepted.push(candidate);
        }
    }

    for (key, reason) in &conflicted {
        {
            let Some(policy) = acc.gateway_api_listener_policies.get_mut(key) else {
                continue;
            };
            policy.conflict_reason = Some(*reason);
            policy.materializable = false;
            policy.routes_materializable = false;
        }
        acc.warnings.push(format!(
            "Gateway API {} {}/{} listener {} rejected: {reason}",
            key.parent_kind.as_str(),
            key.namespace,
            key.gateway,
            key.listener
        ));
        // Gateway.status.listeners[] reads only `gateway_api_listener_conflicts`.
        // Withdrawal without an entry leaves Conflicted=False / Accepted=True
        // while no traffic materializes.
        let message = match *reason {
            "ProtocolConflict" => {
                let port = acc
                    .gateway_api_listener_policies
                    .get(key)
                    .and_then(|policy| policy.port)
                    .unwrap_or(0);
                // Deterministic bounded wording: numeric port + families only.
                // Never echo object/listener/hostname names (cross-tenant risk).
                format!(
                    "Port {port} is claimed by incompatible protocol families on the same TCP \
                     transport (HTTP-family vs raw stream), so every conflicting claim on this \
                     port is refused (Conflicted)."
                )
            }
            "HostnameConflict" => {
                "Listener hostname conflicts with a higher-precedence listener on the same port."
                    .to_string()
            }
            other => format!("Gateway API listener rejected: {other}"),
        };
        acc.gateway_api_listener_conflicts
            .insert(key.clone(), GatewayApiListenerConflict { reason, message });
    }

    refresh_listenerset_status_after_conflicts(acc);
}

/// Materialize mesh listener services for one accepted ListenerSet.
pub(crate) fn materialize_listenerset_mesh_services(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let attached = acc
        .listenerset_statuses
        .iter()
        .find(|status| status.resource.matches_object(object))
        .is_some_and(|status| status.attached);
    if !attached {
        return Ok(());
    }

    for listener in object
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(listener_name) = string_field(listener, "name")
            .filter(|name| !name.is_empty() && gateway_api_section_name_is_valid(name))
        else {
            continue;
        };
        let key = GatewayApiListenerKey {
            namespace: object.metadata.namespace.clone(),
            parent_kind: GatewayApiListenerParentKind::ListenerSet,
            gateway: object.metadata.name.clone(),
            listener: listener_name.to_string(),
        };
        let Some(policy) = acc.gateway_api_listener_policies.get(&key) else {
            continue;
        };
        if !policy.materializable
            || !policy.routes_materializable
            || policy.conflict_reason.is_some()
        {
            continue;
        }
        if policy.validation_error.is_some() {
            continue;
        }
        if !listener_protocol_mode_is_supported(listener) {
            continue;
        }
        if listener_requires_frontend_tls(listener)
            && !listener_is_materializable(acc, object, listener)
        {
            acc.warnings.push(format!(
                "Gateway API ListenerSet {}/{} listener {} has unresolved TLS material and will not be exposed",
                object.metadata.namespace, object.metadata.name, listener_name
            ));
            continue;
        }
        let Some(raw_port) = listener.get("port").and_then(Value::as_u64) else {
            continue;
        };
        let port = super::port_from_u64(object, raw_port, "listeners[].port")?;
        acc.mesh.services.push(MeshService {
            // Gateway and ListenerSet are distinct Kubernetes resources and
            // may legally share namespace/name/listener. Keep the synthetic
            // service identity kind-scoped so one resource can never masquerade
            // as the other's materialization in downstream consumers.
            name: format!("listenerset-{}-{listener_name}", object.metadata.name),
            namespace: object.metadata.namespace.clone(),
            ports: vec![ServicePort {
                port,
                protocol: listener_app_protocol(string_field(listener, "protocol")),
                name: Some(listener_name.to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        });
        if let Some(status) = acc
            .listenerset_statuses
            .iter_mut()
            .find(|status| status.resource.matches_object(object))
        {
            if !status
                .programmed_listeners
                .iter()
                .any(|name| name == listener_name)
            {
                status.programmed_listeners.push(listener_name.to_string());
            }
            status.programmed = true;
            status.programmed_reason = "Programmed".to_string();
            status.programmed_message = ferrum_listenerset_status_message(
                "Ferrum programmed at least one ListenerSet listener",
            );
        }
    }
    Ok(())
}

/// Whether `gateway.spec.allowedListeners` selects `listenerset`.
pub(crate) fn allowed_listeners_permits(
    acc: &K8sAccumulator,
    gateway: &K8sObject,
    listenerset: &K8sObject,
) -> bool {
    let Some(allowed) = gateway.spec.get("allowedListeners") else {
        return false;
    };
    let Some(namespaces) = allowed.get("namespaces") else {
        return false;
    };
    let from = match namespaces.get("from") {
        None => "None",
        Some(Value::String(from)) => from.as_str(),
        Some(_) => return false,
    };
    match from {
        "All" => true,
        "Same" => gateway.metadata.namespace == listenerset.metadata.namespace,
        "None" => false,
        "Selector" => {
            let Some(selector) = namespaces.get("selector") else {
                return false;
            };
            let Ok(selector) = namespace_selector(selector) else {
                return false;
            };
            acc.namespace_labels
                .get(&listenerset.metadata.namespace)
                .is_some_and(|labels| namespace_selector_matches(labels, &selector))
        }
        _ => false,
    }
}

pub(super) fn refresh_listenerset_status_after_conflicts(acc: &mut K8sAccumulator) {
    for status in &mut acc.listenerset_statuses {
        let ns = status.resource.namespace.clone();
        let name = status.resource.name.clone();
        let mut any_materializable = false;
        let mut any_conflicted = false;
        let mut any_spec_accepted = false;
        let mut any_unconflicted_spec_accepted = false;
        let mut saw_listener = false;
        let mut listener_conflicts = Vec::new();
        for (key, policy) in &acc.gateway_api_listener_policies {
            if key.parent_kind != GatewayApiListenerParentKind::ListenerSet
                || key.namespace != ns
                || key.gateway != name
            {
                continue;
            }
            saw_listener = true;
            if policy.spec_accepted {
                any_spec_accepted = true;
                if policy.conflict_reason.is_none() {
                    any_unconflicted_spec_accepted = true;
                }
            }
            if let Some(reason) = policy.conflict_reason {
                any_conflicted = true;
                listener_conflicts.push((key.listener.clone(), reason.to_string()));
            }
            if policy.materializable {
                any_materializable = true;
            }
        }
        status.listener_conflicts = listener_conflicts;
        if !status.accepted && status.accepted_reason != "Accepted" && !saw_listener {
            continue;
        }
        if !saw_listener {
            continue;
        }
        if any_materializable {
            status.attached = true;
            status.accepted = true;
            status.accepted_reason = "Accepted".to_string();
            status.accepted_message = ferrum_listenerset_status_message(
                "Ferrum accepted this ListenerSet on the parent Gateway",
            );
        } else if any_conflicted && any_spec_accepted && !any_unconflicted_spec_accepted {
            status.attached = false;
            status.accepted = false;
            status.accepted_reason = "ListenersNotValid".to_string();
            status.accepted_message = ferrum_listenerset_status_message(
                "Every ListenerSet listener conflicted with a higher-precedence listener",
            );
            status.programmed = false;
            status.programmed_reason = "ListenersNotValid".to_string();
            status.programmed_message = status.accepted_message.clone();
            status.programmed_listeners.clear();
        }
    }
}

fn conflict_against_accepted(
    candidate: &ConflictCandidate,
    accepted: &[&ConflictCandidate],
) -> Option<&'static str> {
    for prior in accepted {
        if prior.port != candidate.port {
            continue;
        }
        // ProtocolConflict (HTTP-family vs raw TCP/TLS stream) is decided
        // order-independently per numeric TCP port across the whole accumulator
        // before this walk. Same protocol family: hostname distinctness only.
        // HTTP vs HTTPS on one port is plaintext-vs-TLS physical refusal owned
        // by `refuse_incompatible_same_port_listeners`, not a family conflict.
        if prior.protocol.eq_ignore_ascii_case(&candidate.protocol)
            && hostnames_conflict(prior.hostname.as_deref(), candidate.hostname.as_deref())
        {
            return Some("HostnameConflict");
        }
    }
    None
}

/// OS/datapath family for Gateway API listener protocol conflict arbitration.
///
/// TCP and UDP may share a numeric port (different transports). Within TCP,
/// HTTP-family accept loops cannot share a socket with raw TCP / TLS-passthrough
/// stream listeners. Compatible HTTP-family siblings and opaque TCP/TLS stream
/// siblings are not ProtocolConflict here — plaintext-vs-TLS HTTP shapes are
/// refused by [`super::gateway_api::refuse_incompatible_same_port_listeners`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerPortFamily {
    Http,
    TcpStream,
    Udp,
}

fn listener_port_family(protocol: &str) -> Option<ListenerPortFamily> {
    match protocol.to_ascii_uppercase().as_str() {
        "HTTP" | "HTTPS" | "GRPC" | "GRPCS" => Some(ListenerPortFamily::Http),
        "TCP" | "TLS" => Some(ListenerPortFamily::TcpStream),
        "UDP" => Some(ListenerPortFamily::Udp),
        _ => None,
    }
}

fn hostnames_conflict(left: Option<&str>, right: Option<&str>) -> bool {
    // Pinned Gateway listener distinctness: exact, wildcard, and fallback
    // (empty/unset hostname) are distinct values. Only equal hostname values
    // conflict on the same protocol+port; runtime precedence handles overlap.
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left == right,
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn listenerset_listener_names_are_duplicated(listeners: &[Value]) -> bool {
    let mut seen = HashMap::new();
    for listener in listeners {
        let Some(name) = string_field(listener, "name")
            .filter(|name| !name.is_empty() && gateway_api_section_name_is_valid(name))
        else {
            continue;
        };
        if seen.insert(name, ()).is_some() {
            return true;
        }
    }
    false
}

struct ConflictCandidate {
    key: GatewayApiListenerKey,
    precedence: u64,
    port: u64,
    protocol: String,
    hostname: Option<String>,
    eligible: bool,
}

struct ParentGatewayRef {
    namespace: String,
    name: String,
}

fn parse_parent_gateway_ref(
    object: &K8sObject,
    parent_ref: &Value,
) -> Result<ParentGatewayRef, String> {
    let group = string_field(parent_ref, "group").unwrap_or(GATEWAY_API_GROUP);
    let kind = string_field(parent_ref, "kind").unwrap_or("Gateway");
    if group != GATEWAY_API_GROUP || kind != "Gateway" {
        return Err(format!(
            "ListenerSet spec.parentRef must reference {GATEWAY_API_GROUP}/Gateway"
        ));
    }
    let Some(name) = string_field(parent_ref, "name") else {
        return Err("ListenerSet spec.parentRef.name is required".to_string());
    };
    let namespace =
        string_field(parent_ref, "namespace").unwrap_or(object.metadata.namespace.as_str());
    Ok(ParentGatewayRef {
        namespace: namespace.to_string(),
        name: name.to_string(),
    })
}

fn listenerset_precedence_index(objects: &[&K8sObject]) -> BTreeMap<(String, String), u64> {
    let mut entries: Vec<_> = objects
        .iter()
        .filter(|object| object.kind == "ListenerSet")
        .map(|object| {
            (
                *object,
                object
                    .metadata
                    .creation_timestamp
                    .as_deref()
                    .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok()),
                object.metadata.namespace.as_str(),
                object.metadata.name.as_str(),
            )
        })
        .collect();
    entries.sort_by(|left, right| {
        (left.1.is_none(), left.1.as_ref(), left.2, left.3).cmp(&(
            right.1.is_none(),
            right.1.as_ref(),
            right.2,
            right.3,
        ))
    });
    entries
        .into_iter()
        .enumerate()
        .map(|(index, (_, _, namespace, name))| {
            ((namespace.to_string(), name.to_string()), index as u64)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn record_listenerset_status(
    acc: &mut K8sAccumulator,
    resource: K8sResourceKey,
    parent_gateway: Option<(String, String)>,
    attached: bool,
    accepted: bool,
    accepted_reason: &str,
    accepted_message: &str,
    programmed: bool,
    programmed_reason: &str,
    programmed_message: &str,
) {
    acc.listenerset_statuses
        .retain(|status| status.resource != resource);
    acc.listenerset_statuses.push(GatewayApiListenerSetStatus {
        resource,
        parent_gateway,
        attached,
        accepted,
        accepted_reason: accepted_reason.to_string(),
        accepted_message: ferrum_listenerset_status_message(accepted_message),
        programmed,
        programmed_reason: programmed_reason.to_string(),
        programmed_message: ferrum_listenerset_status_message(programmed_message),
        programmed_listeners: Vec::new(),
        listener_conflicts: Vec::new(),
    });
}
