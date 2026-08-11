use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::config::types::{
    BackendScheme, FrontendTlsCertificateSource, MAX_FRONTEND_TLS_CERTIFICATE_SOURCES,
    MAX_ID_LENGTH, MAX_TARGET_WEIGHT,
};
use crate::modes::mesh::config::{
    AppProtocol, MeshService, MeshWaypointBinding, MeshWaypointServiceRef, ServicePort,
};
use crate::plugins::utils::route_header_transform::route_header_transform_rules_to_json;

use super::{
    GatewayApiAllowedRoutesNamespaces, GatewayApiListenerConflict, GatewayApiListenerKey,
    GatewayApiListenerParentKind, GatewayApiListenerPolicy, GatewayApiListenerValidationError,
    GatewayApiNamespaceSelector, GatewayApiNamespaceSelectorExpression,
    GatewayApiNamespaceSelectorOperator, GatewayApiRouteConflict, GatewayApiRouteConflictKey,
    GatewayApiRouteSlot, GatewaySessionPersistence, K8sAccumulator, K8sObject, K8sResourceKey,
    K8sTranslateError, K8sTranslationOptions, MeshRouteDispatchDestination, RouteBackend,
    RouteProxySpec, SourceKind, UNSUPPORTED_SHAPE_MARKER, attach_route_plugins_to_proxy,
    exact_path_listen_path, invalid_resource, mesh_route_dispatch_plugin_from_rules,
    namespaced_resource_key, optional_port_field, optional_target_weight_field,
    parse_istio_duration_ms, port_from_u64, proxy_for_route, resource_id,
    route_backends_require_node_waypoint_authz, route_request_transformer_plugin_for_proxy,
    service_dns_name, string_array, string_field, upstream_for_route,
    upstream_for_route_with_session,
};
use crate::config::db_backend::NamespacedResourceId;
use crate::config::types::{HashOnCookieConfig, PluginConfig, Proxy};

// Use an absolute DNS name (trailing dot) so resolvers must query this exact
// label and cannot append search domains from resolv.conf.
const ZERO_WEIGHT_BACKEND_HOST: &str = "ferrum-zero-weight.invalid.";
const ZERO_WEIGHT_BACKEND_PORT: u16 = 65535;
const GATEWAY_API_DISPATCH_PRECEDENCE_KEY: &str = "_ferrum_gateway_api_precedence";
const GATEWAY_API_REDIRECT_REPLACE_PREFIX_MATCH_KEY: &str =
    "_ferrum_gateway_api_replace_prefix_match";

/// `Gateway.spec.gatewayClassName` values that mark a GAMMA Waypoint
/// Gateway. Both the Istio canonical value and a Ferrum-native alias are
/// honored so operators migrating from Istio do not have to retag.
const WAYPOINT_GATEWAY_CLASS_NAMES: &[&str] = &["istio-waypoint", "ferrum-waypoint"];

pub(crate) fn is_supported_waypoint_gateway_class(name: &str) -> bool {
    WAYPOINT_GATEWAY_CLASS_NAMES
        .iter()
        .any(|expected| expected.eq_ignore_ascii_case(name))
}

/// Service label naming the GAMMA Waypoint a Service routes through.
/// `None` (the literal string) opts the Service out of any inherited
/// namespace-level waypoint binding. Annotations are accepted as a
/// compatibility fallback for file/native sources that already use them.
const KEY_USE_WAYPOINT: &str = "istio.io/use-waypoint";

/// Optional Service label that points `istio.io/use-waypoint` at a waypoint
/// Gateway in a namespace other than the Service's namespace. Annotations are
/// accepted as a compatibility fallback.
const KEY_USE_WAYPOINT_NAMESPACE: &str = "istio.io/use-waypoint-namespace";

/// Gateway/Service label setting which traffic the waypoint handles:
/// `service` (default), `workload`, `all`, or `none`. Stored verbatim on
/// the binding so future Istio enum additions don't require a Ferrum-side
/// schema change. Annotations are accepted as a compatibility fallback.
const KEY_WAYPOINT_FOR: &str = "istio.io/waypoint-for";

#[derive(Debug, Clone)]
struct GatewayApiRouteConflictCandidate {
    resource: K8sResourceKey,
    creation_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RouteMatchDescriptor {
    listen_path: String,
    match_signature: String,
}

#[derive(Debug, Clone)]
struct RouteMatchEntryDescriptor {
    match_index: usize,
    descriptor: RouteMatchDescriptor,
}

#[derive(Debug, Clone)]
struct RouteHostScope {
    proxy_hosts: Vec<String>,
    conflict_hostname: String,
    parent_refs: Vec<String>,
    /// The Gateway listener this scope materializes on. `None` only for the
    /// deliberately parentless legacy shape (`spec.parentRefs` absent): a
    /// declared Gateway parentRef that resolves no concrete listener must
    /// emit no scope at all rather than a listener-less claim.
    listener: Option<GatewayApiListenerKey>,
    /// `listener`'s numeric port — the runtime `Proxy.listen_port` stamp.
    listen_port: Option<u16>,
    /// Whether `listener` terminates frontend TLS. Read from that listener's
    /// own policy, never inferred from any other listener sharing the port.
    requires_tls: bool,
    suffix: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendRefFaultReason {
    InvalidKind,
    BackendNotFound,
    UnsupportedProtocol,
    RefNotPermitted,
    NoServiceableBackend,
    InvalidBackendTlsPolicy,
}

#[derive(Default)]
struct RouteBackendResolution {
    backends: Vec<RouteBackend>,
    fault_reason: Option<BackendRefFaultReason>,
    invalid_weight: u32,
    valid_weight: u32,
}

/// One Gateway listener's claim on an SNI hostname, used by the shared
/// certificate-cap/hostname admission decision.
///
/// Translation publishes that decision's exact loser map in
/// `K8sTranslation::frontend_tls_hostname_conflicts`; Gateway status consumes
/// the map and does not rebuild claims from raw objects. The per-certificate
/// identity is opaque and only ever compared for equality.
#[derive(Debug, Clone)]
struct FrontendTlsHostnameClaim {
    key: GatewayApiListenerKey,
    /// Namespace of the physical Gateway TLS plan. This normally matches the
    /// resource namespace, but a cross-namespace ListenerSet serves through
    /// its attached Gateway's namespace.
    serving_namespace: String,
    /// Listener `hostname`, ASCII-lowercased. `None` (a catch-all listener)
    /// never collides: it claims no specific SNI name.
    hostname: Option<String>,
    creation_timestamp: Option<DateTime<Utc>>,
    certificate_identity: Vec<String>,
}

/// Deterministic claim order: Gateway owners before ListenerSet extensions,
/// then oldest resource first (Gateway API's own tiebreak), then the complete
/// listener key. This preserves ListenerSet's parent-precedence rule while
/// keeping the result independent of informer order.
fn compare_frontend_tls_claims(
    left: &FrontendTlsHostnameClaim,
    right: &FrontendTlsHostnameClaim,
) -> Ordering {
    left.key
        .parent_kind
        .cmp(&right.key.parent_kind)
        // Shares the route-conflict tiebreak: an observed timestamp outranks
        // an absent one, so a resource with no stamp never silently displaces
        // one that has a real (necessarily later) stamp.
        .then_with(|| {
            compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp)
        })
        .then_with(|| left.key.cmp(&right.key))
}

fn sort_frontend_tls_hostname_claims(claims: &mut [FrontendTlsHostnameClaim]) {
    claims.sort_by(compare_frontend_tls_claims);
}

/// One deterministic decision for resident-certificate capacity and explicit
/// SNI ownership. Physical-port preview and final certificate materialization
/// both consume this result, so a listener the cap refused can never reserve a
/// hostname in either phase.
#[derive(Debug, Default)]
struct FrontendTlsListenerAdmission {
    ordered_listener_keys: Vec<GatewayApiListenerKey>,
    admitted_listeners: BTreeSet<GatewayApiListenerKey>,
    certificate_cap_losers: BTreeSet<GatewayApiListenerKey>,
    hostname_conflict_losers: BTreeMap<GatewayApiListenerKey, GatewayApiListenerKey>,
}

fn frontend_tls_listener_admission(
    acc: &K8sAccumulator,
    listeners: &[PendingFrontendTlsListener],
) -> FrontendTlsListenerAdmission {
    let mut claims: Vec<FrontendTlsHostnameClaim> = listeners
        .iter()
        .filter(|listener| {
            acc.gateway_api_listener_policies
                .get(&listener.key)
                .is_some_and(|policy| policy.materializable)
        })
        .map(|listener| listener.hostname_claim(acc))
        .collect();
    sort_frontend_tls_hostname_claims(&mut claims);

    let mut admission = FrontendTlsListenerAdmission {
        ordered_listener_keys: claims.iter().map(|claim| claim.key.clone()).collect(),
        ..FrontendTlsListenerAdmission::default()
    };
    let mut winners: HashMap<(&str, &str), usize> = HashMap::new();
    // The CP accumulator can contain several tenants. Keep admission budgets
    // independent so one namespace cannot withdraw another namespace's TLS
    // listeners before the per-DP namespace projection runs.
    let mut source_counts: HashMap<&str, usize> = HashMap::new();
    for (index, claim) in claims.iter().enumerate() {
        let source_count = source_counts
            .entry(claim.serving_namespace.as_str())
            .or_default();
        // A listener's complete certificateRefs group must fit before its
        // explicit hostname can become visible to collision arbitration.
        if source_count.saturating_add(claim.certificate_identity.len())
            > MAX_FRONTEND_TLS_CERTIFICATE_SOURCES
        {
            admission.certificate_cap_losers.insert(claim.key.clone());
            continue;
        }

        if let Some(hostname) = claim.hostname.as_deref() {
            match winners.get(&(claim.serving_namespace.as_str(), hostname)) {
                None => {
                    winners.insert((claim.serving_namespace.as_str(), hostname), index);
                }
                Some(&winner_index) => {
                    let winner = &claims[winner_index];
                    if winner.certificate_identity != claim.certificate_identity {
                        admission
                            .hostname_conflict_losers
                            .insert(claim.key.clone(), winner.key.clone());
                        continue;
                    }
                }
            }
        }

        *source_count += claim.certificate_identity.len();
        admission.admitted_listeners.insert(claim.key.clone());
    }
    admission
}

/// A resolved listener TLS claim awaiting snapshot-wide finalization.
///
/// Held on the accumulator rather than written straight into the config: the
/// winner of a hostname collision, the deterministic default certificate, and
/// the per-namespace cap all depend on the whole snapshot, and deciding them
/// per object would make the result depend on informer/list order.
#[derive(Debug, Clone)]
pub(crate) struct PendingFrontendTlsListener {
    pub key: GatewayApiListenerKey,
    pub hostname: Option<String>,
    pub creation_timestamp: Option<DateTime<Utc>>,
    /// `(cert_source, key_source)` per `certificateRefs` entry, in spec order.
    pub certificates: Vec<(String, String)>,
}

impl PendingFrontendTlsListener {
    fn hostname_claim(&self, acc: &K8sAccumulator) -> FrontendTlsHostnameClaim {
        let serving_namespace = acc
            .gateway_api_listener_policies
            .get(&self.key)
            .map_or_else(
                || self.key.namespace.clone(),
                |policy| gateway_frontend_tls_slot_namespace(&self.key, policy).to_string(),
            );
        FrontendTlsHostnameClaim {
            key: self.key.clone(),
            serving_namespace,
            hostname: self.hostname.clone(),
            creation_timestamp: self.creation_timestamp,
            certificate_identity: self
                .certificates
                .iter()
                .map(|(cert_source, _)| cert_source.clone())
                .collect(),
        }
    }
}

struct RouteBackendGroup {
    total_weight: u32,
    backends: Vec<RouteBackend>,
    expanded_endpoints: bool,
}

const GATEWAY_API_BACKEND_WEIGHT_SCALE: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayApiDispatchRulePrecedence {
    has_precedence: bool,
    method_match: bool,
    header_count: usize,
    query_param_count: usize,
    creation_timestamp: Option<DateTime<Utc>>,
    namespace: String,
    name: String,
    rule_index: usize,
    match_index: usize,
}

pub(super) fn translate(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<bool, K8sTranslateError> {
    match object.kind.as_str() {
        "Gateway" => {
            if is_waypoint_gateway(object) {
                add_waypoint_binding(acc, object);
            }
            if acc.gateway_is_managed_by_ferrum(object) {
                for service in mesh_services_from_gateway(acc, object)? {
                    acc.mesh.services.push(service);
                }
            }
            Ok(true)
        }
        "ListenerSet" => {
            super::listenerset::materialize_listenerset_mesh_services(acc, object)?;
            Ok(true)
        }
        // GRPCRoute shares HTTPRoute's materialization path: gRPC predicates
        // that cannot be a listen path land on the `/` listener as ordered
        // `mesh_route_dispatch` rules, so the same-(hosts, listen_path)
        // collapse is what preserves rule ordering and fall-through between
        // gRPC rules of the *same* kind.
        //
        // Gateway API v1.5.1 `GRPCRouteRule` is explicit that "Merging MUST
        // not be done between GRPCRoutes and HTTPRoutes", so the collapse is
        // keyed on source kind. This also preserves listener isolation because
        // HTTP-family proxies do not retain the listener that admitted them.
        "HTTPRoute" | "GRPCRoute" => {
            let (proxies, plugins) = http_route_resources(object, acc)?;
            upsert_http_route_resources(acc, proxies, plugins, &object.kind);
            Ok(true)
        }
        "TCPRoute" => {
            for proxy in l4_route_proxies(object, acc, BackendScheme::Tcp)? {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        "TLSRoute" => {
            // Gateway API TLSRoute is SNI-matched TLS passthrough on TLS
            // listeners (typically `tls.mode: Passthrough`): peek ClientHello
            // SNI against route hostnames and forward encrypted bytes with no
            // termination — same stream+SNI machinery as VirtualService tls[]
            // and east-west passthrough. BackendScheme::Tcp + passthrough is
            // required; Tcps without passthrough would terminate or originate
            // TLS and ignore hostname SNI selection.
            for mut proxy in l4_route_proxies(object, acc, BackendScheme::Tcp)? {
                proxy.passthrough = true;
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        // UDPRoute shares the L4 materialization path with TCPRoute/TLSRoute:
        // the route carries no request-level predicate, so the Gateway listener
        // port is the entire match and the rule's `backendRefs` set is the
        // weighted datagram peer set (see `udp_rule_backends`).
        // The stream scheme is what makes the materialized proxy a UDP
        // listener/relay rather than a TCP one; datagram semantics (no
        // connection state, per-session idle expiry) are preserved by the
        // existing UDP data path.
        //
        // The response-amplification guard is NOT engaged here: it is the
        // opt-in per-proxy `udp_max_response_amplification_factor`, Gateway
        // API defines no field that maps onto it, and `proxy_for_route`
        // leaves it unset — the same default a hand-authored UDP proxy gets.
        // Do not describe it as in force for a generated UDPRoute proxy.
        "UDPRoute" => {
            for proxy in l4_route_proxies(object, acc, BackendScheme::Udp)? {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        "ReferenceGrant" | "BackendTLSPolicy" => Ok(true),
        // Collected in the pre-pass; acknowledged here so the main translate
        // loop does not warn about an "unsupported" kind.
        "BackendLBPolicy" | "XBackendTrafficPolicy" => Ok(true),
        _ => Ok(false),
    }
}

/// Default session token name when `sessionPersistence.sessionName` is omitted
/// (Gateway API marks the field implementation-specific).
const DEFAULT_SESSION_NAME: &str = "ferrum-session";

/// Accepted/rejected BackendLB / XBackendTraffic policy attachment for a Service.
#[derive(Debug, Clone)]
pub(crate) struct GatewayBackendSessionPolicy {
    pub resource: K8sResourceKey,
    pub creation_timestamp: Option<DateTime<Utc>>,
    /// `Ok(None)` = policy accepted but carries no `sessionPersistence`.
    /// `Err` = field-specific rejection reason.
    pub session: Result<Option<GatewaySessionPersistence>, String>,
}

fn backend_lb_policy_kinds(kind: &str) -> bool {
    matches!(kind, "BackendLBPolicy" | "XBackendTrafficPolicy")
}

/// Collect `BackendLBPolicy` / `XBackendTrafficPolicy` into the accumulator.
///
/// Gateway API removed `BackendLBPolicy` from the experimental channel in
/// v1.3+ (replaced by `XBackendTrafficPolicy` on `gateway.networking.x-k8s.io`).
/// Ferrum watches and translates both shapes so operators on older CRDs and on
/// the pinned v1.5.1 experimental channel get the same session-persistence
/// semantics. `retryConstraint` is not representable today and rejects the
/// entire policy fail-closed (no sessionPersistence projection either).
pub(super) fn collect_backend_lb_policy(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    if !backend_lb_policy_kinds(&object.kind) {
        return Ok(());
    }

    let target_refs = object
        .spec
        .get("targetRefs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_resource(
                object,
                "spec.targetRefs is required and must be a non-empty array",
            )
        })?;
    if target_refs.is_empty() {
        return Err(invalid_resource(
            object,
            "spec.targetRefs is required and must be a non-empty array",
        ));
    }
    if target_refs.len() > 16 {
        return Err(invalid_resource(
            object,
            "spec.targetRefs must contain at most 16 entries",
        ));
    }

    let mut service_targets = BTreeSet::new();
    for (index, target) in target_refs.iter().enumerate() {
        if !target.is_object() {
            return Err(invalid_resource(
                object,
                format!("spec.targetRefs[{index}] must be an object"),
            ));
        }
        for field in ["group", "kind", "name"] {
            if target.get(field).is_some_and(|value| !value.is_string()) {
                return Err(invalid_resource(
                    object,
                    format!("spec.targetRefs[{index}].{field} must be a string"),
                ));
            }
        }
        let kind = string_field(target, "kind").unwrap_or("Service");
        let group = string_field(target, "group").unwrap_or("");
        let name = string_field(target, "name")
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                invalid_resource(
                    object,
                    format!("spec.targetRefs[{index}].name is required and must not be empty"),
                )
            })?;
        if kind != "Service" || !group.is_empty() {
            return Err(invalid_resource(
                object,
                format!(
                    "spec.targetRefs[{index}] must target core group Service; \
                     other backend kinds are not supported"
                ),
            ));
        }
        if !service_targets.insert(name.to_string()) {
            return Err(invalid_resource(
                object,
                format!("spec.targetRefs[{index}] duplicates an earlier Service targetRef"),
            ));
        }
    }

    if object.spec.get("retryConstraint").is_some() {
        // Unrepresentable retry budgets must not fail open: rejecting the
        // whole policy also withholds sessionPersistence rather than applying
        // sticky affinity while ignoring the budget constraint.
        return Err(invalid_resource(
            object,
            "spec.retryConstraint is not supported; Ferrum does not enforce \
             retry budgets and rejects the entire backend traffic policy \
             fail-closed (sessionPersistence is not applied)",
        ));
    }

    let session = object
        .spec
        .get("sessionPersistence")
        .map(|value| parse_session_persistence(object, value))
        .transpose()?;

    let resource = K8sResourceKey::from_object(object);
    let record = GatewayBackendSessionPolicy {
        resource: resource.clone(),
        creation_timestamp: object
            .metadata
            .creation_timestamp
            .as_deref()
            .and_then(parse_k8s_timestamp),
        session: Ok(session),
    };

    // Remember the policy's FULL Service target set. Precedence below is
    // resolved per Service, so a policy targeting `[a, b]` can win `a` while
    // losing `b` to an older policy — but the status writer reports Direct
    // attachment ATOMICALLY (`backend_lb_policy_conflict_losers` marks a policy
    // Conflicted the moment it loses any one target). `finalize_backend_lb_policies`
    // uses this set to withdraw such a policy everywhere, so a policy the
    // operator was told is `Accepted=False` cannot still steer live traffic.
    acc.gateway_api_backend_session_policy_targets
        .insert(resource.clone(), service_targets.clone());

    for service_name in service_targets {
        let key = (object.metadata.namespace.clone(), service_name);
        let existing = acc
            .gateway_api_backend_session_policies
            .get(&key)
            .map(|policy| {
                (
                    backend_policy_is_preferred(&record, policy),
                    policy.resource.clone(),
                )
            });
        match existing {
            None => {
                acc.gateway_api_backend_session_policies
                    .insert(key, record.clone());
            }
            Some((true, old)) => {
                acc.warnings.push(format!(
                    "{} {}/{} replaces older backend session policy {}/{} \
                     for Service {}/{}",
                    object.kind,
                    object.metadata.namespace,
                    object.metadata.name,
                    old.namespace,
                    old.name,
                    key.0,
                    key.1
                ));
                acc.gateway_api_backend_session_policies
                    .insert(key, record.clone());
            }
            Some((false, old)) => {
                acc.warnings.push(format!(
                    "{} {}/{} ignored for Service {}/{}; older policy {}/{} wins",
                    object.kind,
                    object.metadata.namespace,
                    object.metadata.name,
                    key.0,
                    key.1,
                    old.namespace,
                    old.name
                ));
            }
        }
    }

    Ok(())
}

/// Withdraw every backend session policy that lost at least one of its targeted
/// Services from ALL of the Services it won.
///
/// [`collect_backend_lb_policy`] resolves GEP-713 None-merge precedence one
/// Service at a time, so a policy targeting `[api, cart]` can win `api` while
/// losing `cart` to an older policy. Ferrum's Direct-attachment status is
/// deliberately atomic — [`backend_lb_policy_conflict_losers`] marks such a
/// policy `Accepted=False` / `Conflicted` — so leaving it applied to `api`
/// would steer live traffic with a policy the operator was told was rejected.
///
/// After this pass the Services carrying persistence are exactly those whose
/// policy reports `Accepted=True`. No cascade is needed: the challenger a
/// withdrawn policy beat on some Service lost that Service under the same
/// atomic rule and is itself `Conflicted`, so that Service correctly ends up
/// with no persistence at all.
///
/// Runs once per translation over the collected policy set, never on a request
/// path.
pub(super) fn finalize_backend_lb_policies(acc: &mut K8sAccumulator) {
    if acc.gateway_api_backend_session_policy_targets.is_empty() {
        return;
    }
    // `BTreeSet` so the emitted warnings are deterministic across watch order.
    let mut withdrawn: BTreeSet<K8sResourceKey> = BTreeSet::new();
    for (resource, targets) in &acc.gateway_api_backend_session_policy_targets {
        for service_name in targets {
            let key = (resource.namespace.clone(), service_name.clone());
            let winner = acc.gateway_api_backend_session_policies.get(&key);
            if winner.is_none_or(|policy| policy.resource != *resource) {
                withdrawn.insert(resource.clone());
                break;
            }
        }
    }
    if withdrawn.is_empty() {
        return;
    }
    acc.gateway_api_backend_session_policies
        .retain(|_, policy| !withdrawn.contains(&policy.resource));
    for resource in withdrawn {
        acc.warnings.push(format!(
            "{} {}/{} lost at least one targeted Service under BackendLB/XBackendTraffic \
             oldest-wins precedence; its session persistence is withdrawn from every \
             targeted Service to match the atomic Accepted=False/Conflicted status",
            resource.kind, resource.namespace, resource.name
        ));
    }
}

fn backend_policy_is_preferred(
    candidate: &GatewayBackendSessionPolicy,
    existing: &GatewayBackendSessionPolicy,
) -> bool {
    match (candidate.creation_timestamp, existing.creation_timestamp) {
        (Some(c), Some(e)) => match c.cmp(&e) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => candidate.resource.cmp(&existing.resource).is_lt(),
        },
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => candidate.resource.cmp(&existing.resource).is_lt(),
    }
}

fn is_valid_session_cookie_name(name: &str) -> bool {
    crate::config::types::is_valid_http_token(name)
}

fn is_valid_session_header_name(name: &str) -> bool {
    crate::config::types::is_valid_http_token(name)
}

fn parse_session_persistence(
    object: &K8sObject,
    value: &Value,
) -> Result<GatewaySessionPersistence, K8sTranslateError> {
    if !value.is_object() {
        return Err(invalid_resource(
            object,
            "sessionPersistence must be an object",
        ));
    }
    for field in ["sessionName", "type", "absoluteTimeout"] {
        if value.get(field).is_some_and(|field| !field.is_string()) {
            return Err(invalid_resource(
                object,
                format!("sessionPersistence.{field} must be a string"),
            ));
        }
    }
    if let Some(cookie_config) = value.get("cookieConfig") {
        if !cookie_config.is_object() {
            return Err(invalid_resource(
                object,
                "sessionPersistence.cookieConfig must be an object",
            ));
        }
        if cookie_config
            .get("lifetimeType")
            .is_some_and(|field| !field.is_string())
        {
            return Err(invalid_resource(
                object,
                "sessionPersistence.cookieConfig.lifetimeType must be a string",
            ));
        }
    }
    if value.get("idleTimeout").is_some() {
        return Err(invalid_resource(
            object,
            "sessionPersistence.idleTimeout is not supported; Ferrum sticky \
             sessions do not track idle expiry",
        ));
    }

    let persistence_type = string_field(value, "type").unwrap_or("Cookie");
    let session_name = string_field(value, "sessionName")
        .map(str::to_string)
        .unwrap_or_else(|| DEFAULT_SESSION_NAME.to_string());
    if session_name.is_empty() || session_name.len() > 128 {
        return Err(invalid_resource(
            object,
            "sessionPersistence.sessionName must be 1..=128 characters",
        ));
    }

    match persistence_type {
        "Cookie" => {
            if !is_valid_session_cookie_name(&session_name) {
                return Err(invalid_resource(
                    object,
                    "sessionPersistence.sessionName must be a valid HTTP cookie name \
                     (ASCII token characters only; control bytes and separators \
                     such as space, tab, CR, LF, ;, and = are rejected)",
                ));
            }
            let lifetime = value
                .get("cookieConfig")
                .and_then(|cfg| string_field(cfg, "lifetimeType"))
                .unwrap_or("Session");
            let absolute_timeout = string_field(value, "absoluteTimeout");
            let mut cookie_config = HashOnCookieConfig {
                session_cookie: lifetime == "Session",
                ..HashOnCookieConfig::default()
            };
            match lifetime {
                "Session" => {
                    if absolute_timeout.is_some() {
                        return Err(invalid_resource(
                            object,
                            "sessionPersistence.absoluteTimeout with \
                             cookieConfig.lifetimeType Session is not supported; \
                             Ferrum cannot enforce an absolute lifetime for a \
                             browser session cookie",
                        ));
                    }
                }
                "Permanent" => {
                    let Some(raw) = absolute_timeout else {
                        return Err(invalid_resource(
                            object,
                            "sessionPersistence.absoluteTimeout is required when \
                             cookieConfig.lifetimeType is Permanent",
                        ));
                    };
                    cookie_config.session_cookie = false;
                    cookie_config.ttl_seconds =
                        parse_gateway_api_duration_secs(object, raw, "absoluteTimeout")?;
                }
                _ => {
                    return Err(invalid_resource(
                        object,
                        "sessionPersistence.cookieConfig.lifetimeType must be \
                         Session or Permanent"
                            .to_string(),
                    ));
                }
            }
            Ok(GatewaySessionPersistence {
                hash_on: format!("cookie:{session_name}"),
                cookie_config: Some(cookie_config),
            })
        }
        "Header" => {
            if !is_valid_session_header_name(&session_name) {
                return Err(invalid_resource(
                    object,
                    "sessionPersistence.sessionName must be a valid HTTP header name \
                     (ASCII token characters only; control bytes and separators \
                     such as space, tab, CR, LF, and : are rejected)",
                ));
            }
            if value.get("cookieConfig").is_some() {
                return Err(invalid_resource(
                    object,
                    "sessionPersistence.cookieConfig can only be set with type Cookie",
                ));
            }
            if string_field(value, "absoluteTimeout").is_some() {
                // AbsoluteTimeout without a cookie has no Set-Cookie surface;
                // refuse rather than silently ignore.
                return Err(invalid_resource(
                    object,
                    "sessionPersistence.absoluteTimeout is only supported with type Cookie",
                ));
            }
            Err(invalid_resource(
                object,
                "sessionPersistence.type Header is not supported; Ferrum does \
                 not synthesize a response session token and cannot provide \
                 Gateway API header session-persistence semantics",
            ))
        }
        _ => Err(invalid_resource(
            object,
            "sessionPersistence.type must be Cookie or Header".to_string(),
        )),
    }
}

fn parse_gateway_api_duration_secs(
    object: &K8sObject,
    raw: &str,
    field: &str,
) -> Result<u64, K8sTranslateError> {
    // Diagnostics name the field and system cap only — never echo the operator
    // duration string (which may carry hostile/control content into status).
    if !is_gateway_api_duration(raw) {
        return Err(invalid_resource(
            object,
            format!("sessionPersistence.{field} is not a valid Gateway API duration"),
        ));
    }
    let ms = parse_istio_duration_ms(raw).ok_or_else(|| {
        invalid_resource(
            object,
            format!("sessionPersistence.{field} is not a valid Gateway API duration"),
        )
    })?;
    if ms == 0 {
        return Err(invalid_resource(
            object,
            format!("sessionPersistence.{field} must be greater than 0s"),
        ));
    }
    let secs = ms.div_ceil(1000);
    if secs > crate::config::types::MAX_TIMEOUT_SECONDS {
        return Err(invalid_resource(
            object,
            format!(
                "sessionPersistence.{field} exceeds the sticky-cookie ttl cap of {}s",
                crate::config::types::MAX_TIMEOUT_SECONDS
            ),
        ));
    }
    Ok(secs)
}

/// Gateway API Duration is one to four integer+unit groups, each integer at
/// most five digits, with units h/m/s/ms. This intentionally rejects the wider
/// duration grammar accepted by the Istio parser (for example decimals).
fn is_gateway_api_duration(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut offset = 0;
    let mut groups = 0;
    while offset < bytes.len() && groups < 4 {
        let digits_start = offset;
        while offset < bytes.len() && bytes[offset].is_ascii_digit() {
            offset += 1;
        }
        let digits = offset - digits_start;
        if !(1..=5).contains(&digits) {
            return false;
        }
        if bytes
            .get(offset..)
            .is_some_and(|remainder| remainder.starts_with(b"ms"))
        {
            offset += 2;
        } else if bytes
            .get(offset)
            .is_some_and(|unit| matches!(*unit, b'h' | b'm' | b's'))
        {
            offset += 1;
        } else {
            return false;
        }
        groups += 1;
    }
    offset == bytes.len() && groups > 0
}

fn resolve_rule_session_persistence(
    object: &K8sObject,
    rule: &Value,
    rule_index: usize,
    backends: &[RouteBackend],
    acc: &mut K8sAccumulator,
) -> Result<Option<GatewaySessionPersistence>, K8sTranslateError> {
    if let Some(value) = rule.get("sessionPersistence") {
        let parsed = parse_session_persistence(object, value)?;
        return Ok(Some(scope_cookie_session_to_route(
            object, rule_index, parsed,
        )));
    }

    let mut service_keys = BTreeSet::new();
    for backend in backends {
        let (Some(ns), Some(name)) = (
            backend.service_namespace.as_deref(),
            backend.service_name.as_deref(),
        ) else {
            continue;
        };
        service_keys.insert((ns.to_string(), name.to_string()));
    }
    if service_keys.is_empty() {
        return Ok(None);
    }

    let mut resolved: Option<((String, String), GatewaySessionPersistence)> = None;
    for key in &service_keys {
        let Some(policy) = acc.gateway_api_backend_session_policies.get(key) else {
            continue;
        };
        match &policy.session {
            Ok(Some(session)) => {
                if let Some((ref prior_key, ref existing)) = resolved {
                    if existing != session {
                        return Err(invalid_resource(
                            object,
                            format!(
                                "backendRefs target Services with conflicting \
                                 BackendLB/XBackendTraffic sessionPersistence \
                                 (Service {}/{} vs Service {}/{})",
                                prior_key.0, prior_key.1, key.0, key.1
                            ),
                        ));
                    }
                } else {
                    resolved = Some((key.clone(), session.clone()));
                }
            }
            Ok(None) => {}
            Err(message) => {
                return Err(invalid_resource(
                    object,
                    format!(
                        "backend Service {}/{} has rejected session policy \
                         {}/{}: {message}",
                        key.0, key.1, policy.resource.namespace, policy.resource.name
                    ),
                ));
            }
        }
    }
    Ok(resolved.map(|(_, session)| scope_cookie_session_to_route(object, rule_index, session)))
}

/// A Service-attached policy applies independently to each route rule. Scope
/// the browser-visible cookie name to the exact route rule so two rules (or two
/// routes) cannot accidentally consume the same persistent session. Gateway
/// API marks `sessionName` implementation-specific and permits it to be
/// reflected rather than requiring an exact wire name.
fn scope_cookie_session_to_route(
    object: &K8sObject,
    rule_index: usize,
    mut session: GatewaySessionPersistence,
) -> GatewaySessionPersistence {
    let Some(session_name) = session.hash_on.strip_prefix("cookie:").map(str::to_owned) else {
        return session;
    };
    let identity = format!(
        "{}|{}|{}|{}|{}",
        object.api_version,
        object.kind,
        object.metadata.namespace,
        object.metadata.name,
        rule_index
    );
    let digest = hex::encode(crate::fips::approved::Sha256::digest(identity.as_bytes()));
    const ROUTE_SUFFIX_LEN: usize = 16;
    const ROUTE_MARKER: &str = "-fe-";
    let max_base_len = 128 - ROUTE_MARKER.len() - ROUTE_SUFFIX_LEN;
    let base = &session_name[..session_name.len().min(max_base_len)];
    session.hash_on = format!("cookie:{base}{ROUTE_MARKER}{}", &digest[..ROUTE_SUFFIX_LEN]);
    session
}

/// Fixed Accepted=False / Conflicted message for GEP-713 None-merge losers.
/// Must not echo policy identity, Service names, or operator-authored values.
const BACKEND_LB_POLICY_CONFLICTED_MESSAGE: &str = "Another BackendLBPolicy or XBackendTrafficPolicy already targets one or more of the same Services and merging is not supported";

/// Controller name stamped on every `status.ancestors` entry Ferrum owns.
const FERRUM_GATEWAY_CONTROLLER_NAME: &str = "ferrum.io/gateway-controller";

/// Gateway API `PolicyStatus.ancestors` upper bound (`+kubebuilder:validation:MaxItems=16`).
///
/// The spec forbids adding another entry when the shared list is full. This
/// limit is only an output constraint for the status writer; status owned by
/// other controllers must not influence translation or session-persistence
/// projection.
const POLICY_ANCESTOR_MAX_ITEMS: usize = 16;

/// Policies that lose at least one Service target under the same GEP-713 None
/// merge / oldest-wins precedence used by [`collect_backend_lb_policy`].
///
/// Only syntactically valid, in-scope `BackendLBPolicy` / `XBackendTrafficPolicy`
/// objects participate. Invalid policies are excluded so they cannot occupy a
/// Service slot or convert a field-level rejection into Accepted/Conflicted.
/// Participant processing is sorted by full resource identity so watch/input
/// order cannot change winners.
pub(crate) fn backend_lb_policy_conflict_losers<'a>(
    objects: impl IntoIterator<Item = &'a K8sObject>,
    options: &K8sTranslationOptions,
) -> HashSet<K8sResourceKey> {
    let mut participants: Vec<(GatewayBackendSessionPolicy, BTreeSet<String>)> = Vec::new();

    for object in objects
        .into_iter()
        .filter(|object| super::includes_object_namespace(options, object))
        .filter(|object| backend_lb_policy_kinds(&object.kind))
    {
        // Validation first: invalid objects never participate in conflict.
        if validate_backend_lb_policy_for_status(object).is_err() {
            continue;
        }
        let targets = object
            .spec
            .get("targetRefs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|target| {
                string_field(target, "name")
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
            })
            .collect::<BTreeSet<_>>();
        participants.push((
            GatewayBackendSessionPolicy {
                resource: K8sResourceKey::from_object(object),
                creation_timestamp: object
                    .metadata
                    .creation_timestamp
                    .as_deref()
                    .and_then(parse_k8s_timestamp),
                session: Ok(None),
            },
            targets,
        ));
    }

    participants.sort_by(|left, right| left.0.resource.cmp(&right.0.resource));

    let mut winners: BTreeMap<(String, String), GatewayBackendSessionPolicy> = BTreeMap::new();
    for (record, targets) in &participants {
        for service_name in targets {
            let key = (record.resource.namespace.clone(), service_name.clone());
            match winners.get(&key) {
                None => {
                    winners.insert(key, record.clone());
                }
                Some(existing) if backend_policy_is_preferred(record, existing) => {
                    winners.insert(key, record.clone());
                }
                Some(_) => {}
            }
        }
    }

    let mut losers = HashSet::new();
    for (record, targets) in &participants {
        for service_name in targets {
            let key = (record.resource.namespace.clone(), service_name.clone());
            let Some(winner) = winners.get(&key) else {
                continue;
            };
            if winner.resource != record.resource {
                losers.insert(record.resource.clone());
                break;
            }
        }
    }
    losers
}

/// Build `status.ancestors` for BackendLBPolicy / XBackendTrafficPolicy.
///
/// Ancestor is the targeted Service (Direct policy attachment). Status
/// evaluation order is deterministic:
/// 1. Field validation / unsupported values → `Accepted=False` /
///    `UnsupportedValue` (including unsupported `retryConstraint`)
/// 2. GEP-713 None-merge conflicts → `Accepted=False` / `Conflicted` when
///    `conflicted` is true because this policy lost at least one Service target
///
/// Invalid policies therefore never report Accepted because of a conflict
/// check. With Ferrum's atomic direct-policy behavior, a multi-target policy
/// that loses any Service is rejected entirely rather than partially accepted.
///
/// The result is reconciled against the object's live `status` through
/// [`merge_backend_lb_policy_status`], so an unchanged condition keeps its
/// `lastTransitionTime` (no per-reconcile status churn) and ancestor entries
/// owned by another implementation are carried through untouched.
pub(crate) fn backend_lb_policy_status(object: &K8sObject, conflicted: bool) -> Value {
    let (accepted, reason, message) = match validate_backend_lb_policy_for_status(object) {
        Ok(()) if conflicted => (
            false,
            "Conflicted",
            BACKEND_LB_POLICY_CONFLICTED_MESSAGE.to_string(),
        ),
        Ok(()) => (
            true,
            "Accepted",
            "Ferrum accepted this backend traffic policy".to_string(),
        ),
        Err(message) => (false, "UnsupportedValue", message),
    };

    let target_refs = object
        .spec
        .get("targetRefs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut ancestors = Vec::new();
    for target in target_refs {
        let Some(name) = string_field(&target, "name") else {
            continue;
        };
        let kind = string_field(&target, "kind").unwrap_or("Service");
        let group = string_field(&target, "group").unwrap_or("");
        ancestors.push(backend_lb_policy_ancestor(
            object,
            json!({
                "group": group,
                "kind": kind,
                "name": name,
                "namespace": object.metadata.namespace,
            }),
            accepted,
            reason,
            &message,
        ));
    }
    if ancestors.is_empty() {
        ancestors.push(backend_lb_policy_ancestor(
            object,
            json!({
                "group": "",
                "kind": "Service",
                "name": object.metadata.name,
                "namespace": object.metadata.namespace,
            }),
            accepted,
            reason,
            &message,
        ));
    }

    merge_backend_lb_policy_status(&json!({ "ancestors": ancestors }), Some(&object.status))
}

/// One Ferrum-owned `status.ancestors` entry, carrying the live
/// `lastTransitionTime` forward when the condition's value did not change.
fn backend_lb_policy_ancestor(
    object: &K8sObject,
    ancestor_ref: Value,
    accepted: bool,
    reason: &str,
    message: &str,
) -> Value {
    let existing = live_ferrum_ancestor_condition(&object.status, &ancestor_ref, "Accepted");
    let condition = condition_value(object, "Accepted", accepted, reason, message, existing);
    json!({
        "ancestorRef": ancestor_ref,
        "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
        "conditions": [condition],
    })
}

/// Whether an ancestor entry is one Ferrum owns and may rewrite.
fn is_ferrum_policy_ancestor(ancestor: &Value) -> bool {
    ancestor.get("controllerName").and_then(Value::as_str) == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
}

/// One `ancestorRef` field, with an absent optional field read as empty so a
/// server-normalized live entry still matches the desired one.
fn ancestor_ref_field<'a>(ancestor_ref: &'a Value, field: &str) -> &'a str {
    ancestor_ref
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Field-wise `ancestorRef` identity.
fn policy_ancestor_ref_matches(left: &Value, right: &Value) -> bool {
    for field in ["group", "kind", "name", "namespace"] {
        if ancestor_ref_field(left, field) != ancestor_ref_field(right, field) {
            return false;
        }
    }
    true
}

fn condition_has_type(condition: &Value, condition_type: &str) -> bool {
    condition.get("type").and_then(Value::as_str) == Some(condition_type)
}

/// `lastTransitionTime` for a condition that really did change, in the
/// `Z`-suffixed RFC 3339 form the Kubernetes API server persists.
fn condition_transition_now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Live Ferrum-owned condition for one `ancestorRef`, used to preserve
/// `lastTransitionTime` across reconciles.
fn live_ferrum_ancestor_condition<'a>(
    live_status: &'a Value,
    ancestor_ref: &Value,
    condition_type: &str,
) -> Option<&'a Value> {
    let ancestors = live_status.get("ancestors").and_then(Value::as_array)?;
    for ancestor in ancestors {
        if !is_ferrum_policy_ancestor(ancestor) {
            continue;
        }
        let Some(live_ref) = ancestor.get("ancestorRef") else {
            continue;
        };
        if !policy_ancestor_ref_matches(live_ref, ancestor_ref) {
            continue;
        }
        let conditions = ancestor.get("conditions").and_then(Value::as_array);
        for condition in conditions.into_iter().flatten() {
            if condition_has_type(condition, condition_type) {
                return Some(condition);
            }
        }
    }
    None
}

/// Reconcile Ferrum's desired policy `status.ancestors` with the live array.
///
/// `PolicyStatus.ancestors` is a SHARED, atomic list: GEP-713 lets several
/// implementations report on one policy and forbids an implementation from
/// modifying or removing entries it does not own. Ferrum writes policy status
/// with a forced server-side apply over the whole array, so a foreign entry has
/// to be carried through the applied document or the API server drops it.
///
/// Ferrum-owned entries keep their live position, which — together with the
/// preserved `lastTransitionTime` — is what makes a steady-state desired status
/// compare equal to the live one so the planner stops re-patching it.
///
/// Idempotent: when a fresh live status is unavailable, foreign entries already
/// present in `desired` become the preservation source, so re-merging an
/// already-merged document neither drops nor duplicates them.
pub(crate) fn merge_backend_lb_policy_status(
    desired: &Value,
    live_status: Option<&Value>,
) -> Value {
    let mut owned: Vec<Value> = Vec::new();
    if let Some(ancestors) = desired.get("ancestors").and_then(Value::as_array) {
        for ancestor in ancestors {
            if is_ferrum_policy_ancestor(ancestor) {
                owned.push(ancestor.clone());
            }
        }
    }
    let desired_ancestors = desired.get("ancestors").and_then(Value::as_array);
    let live = live_status
        .and_then(|status| status.get("ancestors"))
        .and_then(Value::as_array)
        .or(desired_ancestors)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut emitted = vec![false; owned.len()];
    let mut merged: Vec<Value> = Vec::with_capacity(POLICY_ANCESTOR_MAX_ITEMS);
    // Gateway API requires implementations to leave entries owned by other
    // controllers untouched. If the shared 16-entry list is full, an
    // implementation MUST NOT add another entry. Reserve capacity for every
    // valid live foreign ancestor first and spend only what remains on Ferrum's
    // own desired entries. A persisted CRD-valid list cannot itself exceed 16;
    // the `take` keeps a malformed synthetic value from producing an invalid
    // apply document.
    let foreign_count = live
        .iter()
        .filter(|ancestor| !is_ferrum_policy_ancestor(ancestor))
        .take(POLICY_ANCESTOR_MAX_ITEMS)
        .count();
    let mut owned_budget = POLICY_ANCESTOR_MAX_ITEMS.saturating_sub(foreign_count);
    for ancestor in live {
        if !is_ferrum_policy_ancestor(ancestor) {
            if merged.len() < POLICY_ANCESTOR_MAX_ITEMS {
                merged.push(ancestor.clone());
            }
            continue;
        }
        if owned_budget == 0 {
            continue;
        }
        let live_ref = ancestor.get("ancestorRef");
        // Ferrum-owned slot: keep the live position for an ancestorRef that is
        // still targeted. A removed targetRef simply drops out.
        for (index, candidate) in owned.iter().enumerate() {
            if emitted[index] {
                continue;
            }
            let same_ref = match (candidate.get("ancestorRef"), live_ref) {
                (Some(want), Some(have)) => policy_ancestor_ref_matches(have, want),
                _ => false,
            };
            if same_ref {
                merged.push(candidate.clone());
                emitted[index] = true;
                owned_budget -= 1;
                break;
            }
        }
    }
    for (index, candidate) in owned.into_iter().enumerate() {
        if !emitted[index] && owned_budget > 0 {
            merged.push(candidate);
            owned_budget -= 1;
        }
    }
    json!({ "ancestors": merged })
}

fn validate_backend_lb_policy_for_status(object: &K8sObject) -> Result<(), String> {
    let target_refs = object
        .spec
        .get("targetRefs")
        .and_then(Value::as_array)
        .ok_or_else(|| "spec.targetRefs is required and must be a non-empty array".to_string())?;
    if target_refs.is_empty() {
        return Err("spec.targetRefs is required and must be a non-empty array".to_string());
    }
    if target_refs.len() > 16 {
        return Err("spec.targetRefs must contain at most 16 entries".to_string());
    }
    let mut service_targets = BTreeSet::new();
    for (index, target) in target_refs.iter().enumerate() {
        if !target.is_object() {
            return Err(format!("spec.targetRefs[{index}] must be an object"));
        }
        for field in ["group", "kind", "name"] {
            if target.get(field).is_some_and(|value| !value.is_string()) {
                return Err(format!("spec.targetRefs[{index}].{field} must be a string"));
            }
        }
        let kind = string_field(target, "kind").unwrap_or("Service");
        let group = string_field(target, "group").unwrap_or("");
        let Some(name) = string_field(target, "name").filter(|name| !name.is_empty()) else {
            return Err(format!(
                "spec.targetRefs[{index}].name is required and must not be empty"
            ));
        };
        if kind != "Service" || !group.is_empty() {
            return Err(format!(
                "spec.targetRefs[{index}] must target core group Service"
            ));
        }
        if !service_targets.insert(name) {
            return Err(format!(
                "spec.targetRefs[{index}] duplicates an earlier Service targetRef"
            ));
        }
    }
    if object.spec.get("retryConstraint").is_some() {
        return Err(
            "spec.retryConstraint is not supported; Ferrum does not enforce \
             retry budgets and rejects the entire backend traffic policy \
             fail-closed (sessionPersistence is not applied)"
                .to_string(),
        );
    }
    if let Some(value) = object.spec.get("sessionPersistence") {
        parse_session_persistence(object, value).map_err(|err| match err {
            K8sTranslateError::InvalidResource { message, .. } => message,
            other => other.to_string(),
        })?;
    }
    Ok(())
}

/// Build one status condition, reusing `existing`'s `lastTransitionTime` when
/// the condition's VALUE (status/reason/message) is unchanged.
///
/// Kubernetes requires `lastTransitionTime` to advance only on a real
/// transition. It is also what keeps the status planner quiet: it emits a patch
/// whenever the desired status differs from the live one, so re-stamping `now()`
/// on every reconcile would re-patch every policy object forever — an unbounded
/// API write loop, and a flapping timestamp for operators watching the resource.
/// The format matches the API server's `Z`-suffixed RFC 3339 form so a
/// re-emitted unchanged condition compares equal to what was persisted.
fn condition_value(
    object: &K8sObject,
    condition_type: &str,
    accepted: bool,
    reason: &str,
    message: &str,
    existing: Option<&Value>,
) -> Value {
    let status = if accepted { "True" } else { "False" };
    let observed = object.metadata.generation.unwrap_or(0);
    let last_transition_time = existing
        .filter(|condition| {
            condition.get("status").and_then(Value::as_str) == Some(status)
                && condition.get("reason").and_then(Value::as_str) == Some(reason)
                && condition.get("message").and_then(Value::as_str) == Some(message)
        })
        .and_then(|condition| condition.get("lastTransitionTime"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(condition_transition_now);
    json!({
        "type": condition_type,
        "status": status,
        "reason": reason,
        "message": message,
        "observedGeneration": observed,
        "lastTransitionTime": last_transition_time,
    })
}

/// Borrowed, validated ReferenceGrant from×to permission cell.
///
/// Shared by canonical translation and status indexing so both sides consume
/// one interpretation of Gateway API ReferenceGrant permissions (#2397).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValidatedReferenceGrantPermission<'a> {
    pub from_namespace: &'a str,
    pub from_group: &'a str,
    pub from_kind: &'a str,
    pub to_group: &'a str,
    pub to_kind: &'a str,
    /// `None` = Gateway API wildcard (absent `to.name`); `Some` = named grant.
    pub to_name: Option<&'a str>,
}

/// Whole-object ReferenceGrant validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReferenceGrantParseError {
    pub message: &'static str,
}

fn reference_grant_required_string<'a>(
    entry: &'a Value,
    field: &str,
    message: &'static str,
) -> Result<&'a str, ReferenceGrantParseError> {
    match entry.get(field) {
        Some(Value::String(value)) => Ok(value.as_str()),
        _ => Err(ReferenceGrantParseError { message }),
    }
}

/// Optional ReferenceGrant `to.name` without allocating.
///
/// - absent → `Ok(None)` (Gateway API wildcard)
/// - string → `Ok(Some(name))` (named grant)
/// - present non-string → `Err` (must never become wildcard)
fn reference_grant_optional_to_name(to: &Value) -> Result<Option<&str>, ReferenceGrantParseError> {
    match to.get("name") {
        None => Ok(None),
        Some(Value::String(name)) => Ok(Some(name.as_str())),
        Some(_) => Err(ReferenceGrantParseError {
            message: "ReferenceGrant spec.to[].name must be a string when present",
        }),
    }
}

/// Parse ReferenceGrant permissions with whole-object fail-closed semantics.
///
/// - Missing/non-array top-level `from` → `Ok([])` (no permissions).
/// - Present `from[]` entries are validated first; a malformed present `from`
///   entry returns `Err` even when top-level `to` is missing/non-array.
/// - Valid `from` with missing/non-array `to` → `Ok([])` (authorizes nothing).
/// - Every present from/to entry requires explicit string `namespace`/`group`/
///   `kind` (from) and `group`/`kind` (to); absent `to.name` is the valid
///   wildcard; present non-string `to.name` is invalid.
/// - Any malformed present entry rejects the **entire** grant (no partial
///   cells). Callers must grant nothing on `Err`.
pub(crate) fn parse_reference_grant_permissions<'a>(
    object: &'a K8sObject,
) -> Result<Vec<ValidatedReferenceGrantPermission<'a>>, ReferenceGrantParseError> {
    let Some(from_entries) = object.spec.get("from").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    // Validate every present from[] entry before consulting `to`, matching the
    // pre-shared-parser collect loop: a malformed from must fail closed even
    // when `to` is absent or non-array.
    let mut validated_from = Vec::with_capacity(from_entries.len());
    for from in from_entries {
        let from_namespace = reference_grant_required_string(
            from,
            "namespace",
            "ReferenceGrant spec.from[].namespace is required",
        )?;
        let from_group = reference_grant_required_string(
            from,
            "group",
            "ReferenceGrant spec.from[].group is required",
        )?;
        let from_kind = reference_grant_required_string(
            from,
            "kind",
            "ReferenceGrant spec.from[].kind is required",
        )?;
        validated_from.push((from_namespace, from_group, from_kind));
    }

    let Some(to_entries) = object.spec.get("to").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut permissions = Vec::new();
    for (from_namespace, from_group, from_kind) in validated_from {
        for to in to_entries {
            let to_kind = reference_grant_required_string(
                to,
                "kind",
                "ReferenceGrant spec.to[].kind is required",
            )?;
            let to_group = reference_grant_required_string(
                to,
                "group",
                "ReferenceGrant spec.to[].group is required",
            )?;
            let to_name = reference_grant_optional_to_name(to)?;
            permissions.push(ValidatedReferenceGrantPermission {
                from_namespace,
                from_group,
                from_kind,
                to_group,
                to_kind,
                to_name,
            });
        }
    }
    Ok(permissions)
}

pub(super) fn collect_reference_grant(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    // Validate the whole object before inserting any permission cell so a
    // later malformed entry cannot leave earlier cells in the accumulator
    // (status conflict context ignores Err with `let _ =`).
    let permissions = parse_reference_grant_permissions(object)
        .map_err(|err| invalid_resource(object, err.message))?;
    for permission in permissions {
        acc.add_reference_grant(
            permission.from_namespace.to_string(),
            permission.from_group.to_string(),
            permission.from_kind.to_string(),
            object.metadata.namespace.clone(),
            permission.to_group.to_string(),
            permission.to_kind.to_string(),
            permission.to_name.map(str::to_owned),
        );
    }
    Ok(())
}

pub(super) fn collect_gateway_listener_policy(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let Some(listeners) = object.spec.get("listeners").and_then(Value::as_array) else {
        return Ok(());
    };
    for listener in listeners {
        let listener_name = string_field(listener, "name").unwrap_or("listener");
        let requires_frontend_tls = listener_requires_frontend_tls(listener);
        let (namespaces, validation_error) = match allowed_route_namespaces(listener) {
            Ok(namespaces) => (namespaces, None),
            Err(error) => {
                acc.warnings.push(format!(
                    "Gateway API Gateway {}/{} listener {} rejected: {}",
                    object.metadata.namespace, object.metadata.name, listener_name, error
                ));
                (GatewayApiAllowedRoutesNamespaces::Invalid, Some(error))
            }
        };
        if !listener_protocol_mode_is_supported(listener) {
            acc.warnings.push(format!(
                "Gateway API Gateway {}/{} listener {} rejected: spec.listeners[].tls.mode must be Passthrough for protocol TLS",
                object.metadata.namespace, object.metadata.name, listener_name
            ));
        }
        let frontend_tls_source = if requires_frontend_tls {
            listener_selected_frontend_tls_source(acc, object, listener)
        } else {
            None
        };
        let spec_accepted =
            validation_error.is_none() && listener_protocol_mode_is_supported(listener);
        let materializable = spec_accepted && listener_is_materializable(acc, object, listener);
        let policy = GatewayApiListenerPolicy {
            namespaces,
            validation_error,
            spec_accepted,
            hostname: string_field(listener, "hostname").map(normalize_gateway_hostname),
            port: listener.get("port").and_then(Value::as_u64),
            protocol: string_field(listener, "protocol")
                .unwrap_or("HTTP")
                .to_ascii_uppercase(),
            route_kinds: listener_allowed_route_kinds(listener),
            materializable,
            routes_materializable: materializable,
            requires_frontend_tls,
            conflict_reason: None,
            parent_gateway: None,
            frontend_tls_source,
        };
        acc.gateway_api_listener_policies.insert(
            GatewayApiListenerKey {
                namespace: object.metadata.namespace.clone(),
                parent_kind: GatewayApiListenerParentKind::Gateway,
                gateway: object.metadata.name.clone(),
                listener: listener_name.to_string(),
            },
            policy,
        );
    }
    collect_gateway_frontend_tls(acc, object);
    Ok(())
}

/// Aggregate frontend TLS credentials admitted for each serving namespace.
///
/// This is used only for physical same-port compatibility. It never selects a
/// namespace winner: every listener-owned certificate remains available to the
/// SNI resolver, including multi-certificate listeners and independent
/// Gateways in one namespace.
#[derive(Debug, Clone, Default)]
struct GatewayFrontendTlsNamespaceSlotPlan {
    serving_by_namespace_port: BTreeMap<(String, u16), BTreeSet<(String, String)>>,
    admitted_listeners: BTreeSet<GatewayApiListenerKey>,
}

/// Physical frontend-TLS serving is scoped to the attached Gateway namespace.
/// A cross-namespace ListenerSet keeps its own namespace in its listener key
/// (for identity, status, routes, and Secret resolution), but it must compete
/// for the parent Gateway's serving slot rather than minting a foreign slot.
fn gateway_frontend_tls_slot_namespace<'a>(
    key: &'a GatewayApiListenerKey,
    policy: &'a GatewayApiListenerPolicy,
) -> &'a str {
    if key.parent_kind == GatewayApiListenerParentKind::ListenerSet
        && let Some((namespace, _)) = policy.parent_gateway.as_ref()
    {
        namespace
    } else {
        &key.namespace
    }
}

/// Build the shared namespace credential plan from fully collected listeners.
fn plan_gateway_frontend_tls_namespace_slots(
    acc: &K8sAccumulator,
) -> GatewayFrontendTlsNamespaceSlotPlan {
    let admitted_listeners = planned_frontend_tls_admitted_listeners(acc);
    let mut plan = GatewayFrontendTlsNamespaceSlotPlan {
        admitted_listeners,
        ..GatewayFrontendTlsNamespaceSlotPlan::default()
    };
    for listener in &acc.gateway_api_frontend_tls_listeners {
        if !plan.admitted_listeners.contains(&listener.key) {
            continue;
        }
        let Some(policy) = acc.gateway_api_listener_policies.get(&listener.key) else {
            continue;
        };
        if !policy.materializable || !policy.requires_frontend_tls {
            continue;
        }
        let Some(port) = policy.port.and_then(|port| u16::try_from(port).ok()) else {
            continue;
        };
        let namespace = gateway_frontend_tls_slot_namespace(&listener.key, policy).to_string();
        let credentials = plan
            .serving_by_namespace_port
            .entry((namespace, port))
            .or_default();
        for credential in &listener.certificates {
            credentials.insert(credential.clone());
        }
    }
    plan
}

/// Listener keys that the deterministic SNI collision and resident-source cap
/// will admit. Physical port arbitration uses this preview so a listener that
/// finalization will withdraw cannot poison an otherwise valid sibling.
fn planned_frontend_tls_admitted_listeners(
    acc: &K8sAccumulator,
) -> BTreeSet<GatewayApiListenerKey> {
    frontend_tls_listener_admission(acc, &acc.gateway_api_frontend_tls_listeners).admitted_listeners
}

fn listener_is_effective_tls_serving_claim(
    key: &GatewayApiListenerKey,
    policy: &GatewayApiListenerPolicy,
    plan: &GatewayFrontendTlsNamespaceSlotPlan,
) -> bool {
    let Some(port) = policy.port.and_then(|port| u16::try_from(port).ok()) else {
        return false;
    };
    policy.requires_frontend_tls
        && plan.admitted_listeners.contains(key)
        && plan
            .serving_by_namespace_port
            .get(&(
                gateway_frontend_tls_slot_namespace(key, policy).to_string(),
                port,
            ))
            .is_some_and(|credentials| !credentials.is_empty())
}

/// Fail closed on Gateway listeners that claim one numeric port with
/// physically incompatible shapes.
///
/// Port-aware routing gives each *listener* its own route-table identity, but
/// the operating system still gives one socket per port. Two listener
/// definitions can therefore be individually valid and jointly unservable.
/// Only two shapes qualify:
///
/// - **`ProtocolConflict`** — the port is claimed both plaintext and by an
///   admitted TLS listener. A socket is one or the other, so
///   every physically competing claim on it is refused.
/// - **`HostnameConflict`** — two or more Gateway namespaces have effective
///   TLS serving sets on the port that resolve to different credential sets.
///   Several credentials in one namespace are valid SNI candidates; only a
///   cross-namespace physical-plan disagreement is refused.
///
/// Differing raw `tls.certificateRefs` alone are deliberately **not** a
/// conflict. Gateway API v1.5.1 defines listener distinctness on
/// `(port, hostname)` for the HTTP family and states outright that "the `tls`
/// field is not used for determining if a listener is distinct". Sibling
/// HTTPS listeners with disjoint hostnames and different `certificateRefs`
/// are therefore distinct and stay Accepted. Unresolved listeners contribute
/// no effective claim, so they cannot poison a healthy physical slot.
///
/// Refusals are order-independent: they are decided from the fully collected
/// listener-policy set and complete namespace credential plan, and every
/// physically competing effective claim is refused rather than guessing a
/// winner. Canonical translation publishes this helper's conflicts in
/// `K8sTranslation`; the status-only conflict context also runs it solely to
/// keep route-conflict indexing aligned. Gateway listener status consumes the
/// published physical and hostname conflict maps instead of independently
/// recomputing ownership from raw objects.
///
/// Unresolved / unsupported listeners contribute no claim, so a broken sibling
/// cannot take down a healthy listener. Listeners already recorded in
/// `gateway_api_listener_conflicts` by ListenerSet/Gateway family arbitration
/// (HTTP-family vs raw TCP/TLS stream on one TCP port) are skipped here so
/// status and warnings stay one decision per physical shape — never a second
/// plaintext-vs-TLS message for claims already withdrawn as family conflicts.
pub(super) fn refuse_incompatible_same_port_listeners(acc: &mut K8sAccumulator) {
    #[derive(Default)]
    struct PortClaims {
        plaintext: Vec<GatewayApiListenerKey>,
        /// Materializable TLS listeners on this physical port.
        effective_tls: Vec<GatewayApiListenerKey>,
        /// Namespaces with an effective TLS serving claim on this port.
        effective_tls_namespaces: BTreeSet<String>,
        /// Distinct complete namespace credential sets used by those claims.
        effective_tls_credentials: BTreeSet<BTreeSet<(String, String)>>,
    }

    // Certificate-cap admission and physical-port admission depend on one
    // another. Refusing an earlier TLS listener can free resident-certificate
    // capacity for a later listener; that newly admitted listener must then be
    // checked against the plaintext/TLS and cross-namespace shape on its own
    // port before finalization can materialize it. Iterate to a fixed point.
    // Every non-terminal pass makes at least one materializable policy false,
    // so this is bounded by the number of listener policies in the snapshot.
    loop {
        let plan = plan_gateway_frontend_tls_namespace_slots(acc);
        let mut claims_by_port: BTreeMap<u16, PortClaims> = BTreeMap::new();
        // Family arbitration (HTTP-family vs raw TCP/TLS stream) already
        // withdrew these and recorded Gateway status conflicts; do not
        // re-claim them into plaintext-vs-TLS arbitration.
        let already_conflicted: BTreeSet<GatewayApiListenerKey> =
            acc.gateway_api_listener_conflicts.keys().cloned().collect();
        for (key, policy) in &acc.gateway_api_listener_policies {
            if already_conflicted.contains(key) {
                continue;
            }
            // Only the HTTP family shares the HTTP-route socket set — the same
            // protocols `listener_route_kinds_for_protocol` admits HTTPRoute /
            // GRPCRoute on. A TLS-passthrough or L4 listener on the same number
            // is a different datapath entirely and must not be dragged in here.
            if !policy.materializable
                || !matches!(
                    policy.protocol.as_str(),
                    "HTTP" | "HTTPS" | "GRPC" | "GRPCS"
                )
            {
                continue;
            }
            let Some(port) = policy.port.and_then(|port| u16::try_from(port).ok()) else {
                continue;
            };
            let claims = claims_by_port.entry(port).or_default();
            if policy.requires_frontend_tls {
                if listener_is_effective_tls_serving_claim(key, policy, &plan) {
                    claims.effective_tls.push(key.clone());
                    claims
                        .effective_tls_namespaces
                        .insert(gateway_frontend_tls_slot_namespace(key, policy).to_string());
                    if let Some(source) = plan.serving_by_namespace_port.get(&(
                        gateway_frontend_tls_slot_namespace(key, policy).to_string(),
                        port,
                    )) {
                        claims.effective_tls_credentials.insert(source.clone());
                    }
                }
            } else {
                claims.plaintext.push(key.clone());
            }
        }

        let mut refused: Vec<(GatewayApiListenerKey, GatewayApiListenerConflict)> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        for (port, claims) in claims_by_port {
            let protocol_conflict =
                !claims.plaintext.is_empty() && !claims.effective_tls.is_empty();
            // Compare complete per-namespace serving sets. Multi-certificate SNI
            // serving inside one namespace is valid and must not create a conflict.
            let credential_conflict = claims.effective_tls_namespaces.len() > 1
                && claims.effective_tls_credentials.len() > 1
                && !protocol_conflict;
            if !protocol_conflict && !credential_conflict {
                continue;
            }
            // Deterministic bounded wording: numeric port + fixed conflict
            // category only. Never join listener keys or echo namespace /
            // Gateway / ListenerSet / listener / hostname / credential strings
            // (cross-tenant disclosure on Gateway.status.listeners[]).
            let (reason, refused_keys, message) = if protocol_conflict {
                (
                    "ProtocolConflict",
                    claims
                        .plaintext
                        .iter()
                        .chain(claims.effective_tls.iter())
                        .cloned()
                        .collect::<Vec<_>>(),
                    format!(
                        "Port {port} is claimed by both plaintext and an effective TLS-serving \
                         frontend shape, so every conflicting claim on this port is refused \
                         (Conflicted)."
                    ),
                )
            } else {
                (
                    "HostnameConflict",
                    claims.effective_tls,
                    format!(
                        "Port {port} has incompatible effective TLS credential sets across \
                         namespaces, so every conflicting claim on this port is refused \
                         (Conflicted)."
                    ),
                )
            };
            warnings.push(message.clone());
            refused.extend(refused_keys.into_iter().map(|key| {
                (
                    key,
                    GatewayApiListenerConflict {
                        reason,
                        message: message.clone(),
                    },
                )
            }));
        }

        if refused.is_empty() {
            break;
        }
        acc.warnings.extend(warnings);
        for (key, conflict) in refused {
            if let Some(policy) = acc.gateway_api_listener_policies.get_mut(&key) {
                policy.materializable = false;
                policy.routes_materializable = false;
                policy.conflict_reason = Some(conflict.reason);
            }
            // Recorded for `Gateway.status.listeners[]`: a listener refused
            // here must report `Conflicted=True` / `Programmed=False`, never
            // `Accepted=True` / `NoConflicts`.
            acc.gateway_api_listener_conflicts.insert(key, conflict);
        }
    }
    // ListenerSet status is first derived during ListenerSet precedence
    // admission. Refresh it after physical port admission as well so a
    // ListenerSet refused by the shared socket/TLS rules cannot remain
    // Accepted or report Conflicted=False while no traffic materializes.
    super::listenerset::refresh_listenerset_status_after_conflicts(acc);
}

pub(crate) fn listener_is_materializable(
    acc: &K8sAccumulator,
    object: &K8sObject,
    listener: &Value,
) -> bool {
    if !listener_protocol_mode_is_supported(listener) {
        return false;
    }
    if !listener_requires_frontend_tls(listener) {
        return true;
    }
    listener_frontend_tls_sources(acc, object, listener).is_some_and(|sources| !sources.is_empty())
}

/// The first resolved source for compatibility with policy metadata that only
/// needs to know whether a TLS listener has usable material. Multi-certificate
/// ownership remains in `gateway_api_frontend_tls_listeners`; this projection
/// never limits or selects the runtime certificate set.
pub(crate) fn listener_selected_frontend_tls_source(
    acc: &K8sAccumulator,
    object: &K8sObject,
    listener: &Value,
) -> Option<(String, String)> {
    listener_frontend_tls_sources(acc, object, listener)?
        .into_iter()
        .next()
}

/// Record every terminating-TLS listener's resolved certificate set.
///
/// Nothing is written into the config here: hostname collisions, the default
/// certificate, and the snapshot cap are decided in
/// [`finalize_frontend_tls_certificates`] once every Gateway and ListenerSet has
/// been seen, so the outcome cannot depend on informer/list order.
pub(crate) fn collect_gateway_frontend_tls(acc: &mut K8sAccumulator, object: &K8sObject) {
    let Some(listeners) = object.spec.get("listeners").and_then(Value::as_array) else {
        return;
    };
    let parent_kind = if object.kind == "ListenerSet" {
        GatewayApiListenerParentKind::ListenerSet
    } else {
        GatewayApiListenerParentKind::Gateway
    };
    let mut pending = Vec::new();
    let mut warnings = Vec::new();
    for listener in listeners
        .iter()
        .filter(|listener| listener_requires_frontend_tls(listener))
    {
        let listener_name = string_field(listener, "name").unwrap_or("listener");
        let key = GatewayApiListenerKey {
            namespace: object.metadata.namespace.clone(),
            parent_kind,
            gateway: object.metadata.name.clone(),
            listener: listener_name.to_string(),
        };
        let Some(certificates) = listener_frontend_tls_sources(acc, object, listener) else {
            warnings.push(format!(
                "Gateway API {} {}/{} listener {} field spec.listeners[].tls.certificateRefs has at least one reference that is not an authorized, valid kubernetes.io/tls Secret; leaving this listener's frontend TLS unmaterialized",
                object.kind, object.metadata.namespace, object.metadata.name, listener_name
            ));
            continue;
        };
        if certificates.is_empty() {
            warnings.push(format!(
                "Gateway API {} {}/{} listener {} field spec.listeners[].tls.certificateRefs is empty on a Terminate-mode listener; leaving this listener's frontend TLS unmaterialized",
                object.kind, object.metadata.namespace, object.metadata.name, listener_name
            ));
            continue;
        }
        // Certificate ownership must follow the same listener-admission
        // decision as route materialization. Otherwise an invalid listener can
        // consume the snapshot cap or win a hostname collision and evict a
        // valid listener even though it can never serve its own routes.
        if !acc
            .gateway_api_listener_policies
            .get(&key)
            .is_some_and(|policy| policy.materializable)
        {
            continue;
        }
        pending.push(PendingFrontendTlsListener {
            key,
            hostname: string_field(listener, "hostname").map(normalize_gateway_hostname),
            creation_timestamp: object
                .metadata
                .creation_timestamp
                .as_deref()
                .and_then(parse_k8s_timestamp),
            certificates,
        });
    }
    acc.warnings.extend(warnings);
    acc.gateway_api_frontend_tls_listeners.extend(pending);
}

/// Resolve every collected listener claim into the snapshot's certificate set.
///
/// Runs once, after every Gateway and ListenerSet listener policy has been
/// collected and before any route is translated:
///
/// 1. Order claims deterministically (Gateway before ListenerSet, then oldest
///    resource, then key).
/// 2. Walk that order once, reserving each complete `certificateRefs` group
///    under the per-serving-namespace
///    [`MAX_FRONTEND_TLS_CERTIFICATE_SOURCES`] budget before it may claim an
///    SNI hostname. Cap losers and hostname losers consume neither capacity
///    nor hostname ownership.
/// 3. Mark one deterministic default certificate per namespace (a catch-all
///    listener when one exists, otherwise the first claim), and project the
///    lexicographically-first namespace's default into the legacy
///    `frontend_tls_*` fields for single-namespace deployments.
pub(crate) fn finalize_frontend_tls_certificates(acc: &mut K8sAccumulator) {
    let mut pending = std::mem::take(&mut acc.gateway_api_frontend_tls_listeners);
    // ListenerSet precedence and physical same-port arbitration run before
    // finalization. A refused listener cannot consume the resident cap, win an
    // SNI collision, or own certificate material.
    pending.retain(|listener| {
        acc.gateway_api_listener_policies
            .get(&listener.key)
            .is_some_and(|policy| policy.materializable)
    });
    if pending.is_empty() {
        return;
    }
    let admission = frontend_tls_listener_admission(acc, &pending);
    acc.gateway_api_frontend_tls_hostname_conflicts = admission.hostname_conflict_losers.clone();
    for key in &admission.ordered_listener_keys {
        if let Some(winner) = admission.hostname_conflict_losers.get(key) {
            let hostname = pending
                .iter()
                .find(|listener| &listener.key == key)
                .and_then(|listener| listener.hostname.as_deref())
                .unwrap_or("");
            acc.warnings.push(format!(
                "Gateway API {} {}/{} listener {} field spec.listeners[].hostname '{}' is already served with a different certificate by {} {}/{} listener {}; reporting the conflict and leaving route traffic on this listener unmaterialized",
                key.parent_kind.as_str(),
                key.namespace,
                key.gateway,
                key.listener,
                hostname,
                winner.parent_kind.as_str(),
                winner.namespace,
                winner.gateway,
                winner.listener,
            ));
            if let Some(policy) = acc.gateway_api_listener_policies.get_mut(key) {
                policy.routes_materializable = false;
                if key.parent_kind == GatewayApiListenerParentKind::ListenerSet {
                    policy.materializable = false;
                    policy.conflict_reason = Some("HostnameConflict");
                }
            }
        } else if admission.certificate_cap_losers.contains(key) {
            acc.warnings.push(format!(
                "Gateway API {} {}/{} listener {} field spec.listeners[].tls.certificateRefs exceeds the {} Gateway frontend TLS certificate limit for its serving namespace; leaving this listener's certificate set and route traffic unmaterialized",
                key.parent_kind.as_str(),
                key.namespace,
                key.gateway,
                key.listener,
                MAX_FRONTEND_TLS_CERTIFICATE_SOURCES
            ));
            if let Some(policy) = acc.gateway_api_listener_policies.get_mut(key) {
                policy.routes_materializable = false;
            }
        }
    }
    pending.retain(|listener| admission.admitted_listeners.contains(&listener.key));

    let order: HashMap<&GatewayApiListenerKey, usize> = admission
        .ordered_listener_keys
        .iter()
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect();
    pending.sort_by_key(|listener| order.get(&listener.key).copied().unwrap_or(usize::MAX));

    let mut sources: Vec<FrontendTlsCertificateSource> = Vec::new();
    for listener in &pending {
        // The shared admission decision already reserved this complete group;
        // preview and finalization therefore cannot disagree at this bound.
        for (cert_path, key_path) in &listener.certificates {
            let Some(policy) = acc.gateway_api_listener_policies.get(&listener.key) else {
                continue;
            };
            let namespace = gateway_frontend_tls_slot_namespace(&listener.key, policy).to_string();
            let owner = match listener.key.parent_kind {
                GatewayApiListenerParentKind::Gateway => listener.key.gateway.clone(),
                GatewayApiListenerParentKind::ListenerSet => {
                    // Namespace and Object names cannot contain `:`.
                    // The kind prefix is therefore disjoint from every valid
                    // Gateway name, and the separator preserves the original
                    // ListenerSet identity components without ambiguity.
                    format!(
                        "ListenerSet:{}:{}",
                        listener.key.namespace, listener.key.gateway
                    )
                }
            };
            sources.push(FrontendTlsCertificateSource {
                namespace,
                gateway: owner,
                listener: listener.key.listener.clone(),
                hostname: listener.hostname.clone(),
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                default_certificate: false,
            });
        }
    }
    super::listenerset::refresh_listenerset_status_after_conflicts(acc);

    // One deterministic fallback per namespace. A catch-all listener (no
    // `hostname`) is the natural default because it is the only listener whose
    // operator did not name the traffic it serves; with none, the first claim
    // in the deterministic order takes the slot.
    let mut defaulted: HashSet<String> = HashSet::new();
    for prefer_catch_all in [true, false] {
        for source in &mut sources {
            if prefer_catch_all && source.hostname.is_some() {
                continue;
            }
            if defaulted.contains(&source.namespace) {
                continue;
            }
            defaulted.insert(source.namespace.clone());
            source.default_certificate = true;
        }
    }

    // Single-namespace deployments (and every DP after namespace filtering)
    // read the fallback certificate from `frontend_tls_*`. Project the
    // lexicographically-first namespace's default so a multi-namespace CP
    // snapshot is still deterministic; the per-DP filter re-projects the
    // subscribing namespace's own default before the data plane sees it.
    if let Some(default_source) = sources
        .iter()
        .filter(|source| source.default_certificate)
        .min_by(|left, right| left.namespace.cmp(&right.namespace))
    {
        acc.config.frontend_tls_cert_path = Some(default_source.cert_path.clone());
        acc.config.frontend_tls_key_path = Some(default_source.key_path.clone());
        acc.config.frontend_tls_source_namespace = Some(default_source.namespace.clone());
    }
    acc.config.frontend_tls_certificate_sources = sources;
}

fn listener_is_terminating_tls(listener: &Value) -> bool {
    let Some(protocol) = string_field(listener, "protocol") else {
        return false;
    };
    if !protocol.eq_ignore_ascii_case("HTTPS")
        && !protocol.eq_ignore_ascii_case("GRPCS")
        && !protocol.eq_ignore_ascii_case("TLS")
    {
        return false;
    }
    let Some(tls) = listener.get("tls") else {
        return true;
    };
    string_field(tls, "mode")
        .unwrap_or("Terminate")
        .eq_ignore_ascii_case("Terminate")
}

fn listener_is_tls_protocol(listener: &Value) -> bool {
    string_field(listener, "protocol").is_some_and(|protocol| protocol.eq_ignore_ascii_case("TLS"))
}

/// Ferrum implements the Gateway API TLSRoute core behavior: encrypted SNI
/// passthrough. The separate TLSRouteModeTerminate feature is not advertised
/// and must not be materialized as passthrough or poison the HTTPS certificate
/// slot until its decrypt-and-forward semantics are implemented end to end.
pub(crate) fn listener_protocol_mode_is_supported(listener: &Value) -> bool {
    !listener_is_tls_protocol(listener)
        || listener
            .get("tls")
            .and_then(|tls| string_field(tls, "mode"))
            .is_some_and(|mode| mode.eq_ignore_ascii_case("Passthrough"))
}

pub(crate) fn listener_requires_frontend_tls(listener: &Value) -> bool {
    listener_is_terminating_tls(listener) && !listener_is_tls_protocol(listener)
}

/// Every `(cert_source, key_source)` pair a listener's `certificateRefs` name,
/// in spec order.
///
/// `None` means the listener is **invalid**: `certificateRefs` is present but
/// not an array, or at least one reference is not an authorized, structurally
/// valid `kubernetes.io/tls` Secret. `Some(vec![])` means the listener names no
/// certificate at all. Both leave a Terminate-mode listener unserved; they are
/// distinguished only so the operator gets the right diagnostic.
///
/// A partially resolvable set never yields a partial result — one bad reference
/// withdraws the whole listener, so a Gateway can never end up serving a subset
/// of the certificates the operator asked for.
fn listener_frontend_tls_sources(
    acc: &K8sAccumulator,
    object: &K8sObject,
    listener: &Value,
) -> Option<Vec<(String, String)>> {
    let Some(certificate_refs) = listener
        .get("tls")
        .and_then(|tls| tls.get("certificateRefs"))
    else {
        return Some(Vec::new());
    };
    let certificate_refs = certificate_refs.as_array()?;
    let mut out = Vec::with_capacity(certificate_refs.len());
    for reference in certificate_refs {
        out.push(gateway_tls_secret_ref(acc, object, reference)?);
    }
    Some(out)
}

fn gateway_tls_secret_ref(
    acc: &K8sAccumulator,
    object: &K8sObject,
    reference: &Value,
) -> Option<(String, String)> {
    let group = string_field(reference, "group").unwrap_or_default();
    let kind = string_field(reference, "kind").unwrap_or("Secret");
    if !group.is_empty() || kind != "Secret" {
        return None;
    }
    let name = string_field(reference, "name")?;
    let namespace = string_field(reference, "namespace").unwrap_or(&object.metadata.namespace);
    // ReferenceGrants are not inherited across Gateway ↔ ListenerSet. A
    // ListenerSet certificateRef must be authorized with from.kind=ListenerSet.
    let from_kind = if object.kind == "ListenerSet" {
        "ListenerSet"
    } else {
        "Gateway"
    };
    if namespace != object.metadata.namespace
        && !acc.reference_grant_allows(
            &object.metadata.namespace,
            "gateway.networking.k8s.io",
            from_kind,
            namespace,
            "",
            "Secret",
            Some(name),
        )
    {
        return None;
    }
    if !acc.secret_is_valid_tls_certificate(namespace, name) {
        return None;
    }
    let digest = acc.secret_tls_material_digest(namespace, name)?;
    Some((
        format!("k8s://{namespace}/{name}#tls.crt?sha256={digest}"),
        format!("k8s://{namespace}/{name}#tls.key?sha256={digest}"),
    ))
}

pub(crate) fn allowed_route_namespaces(
    listener: &Value,
) -> Result<GatewayApiAllowedRoutesNamespaces, GatewayApiListenerValidationError> {
    let Some(allowed_routes) = listener.get("allowedRoutes") else {
        return Ok(GatewayApiAllowedRoutesNamespaces::Same);
    };
    let Some(allowed_routes) = allowed_routes.as_object() else {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes",
            "must be an object",
        ));
    };
    let Some(namespaces) = allowed_routes.get("namespaces") else {
        return Ok(GatewayApiAllowedRoutesNamespaces::Same);
    };
    let Some(namespaces) = namespaces.as_object() else {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces",
            "must be an object",
        ));
    };
    let from = match namespaces.get("from") {
        None => "Same",
        Some(Value::String(from)) => from.as_str(),
        Some(_) => {
            return Err(listener_validation_error(
                "spec.listeners[].allowedRoutes.namespaces.from",
                "must be one of All, Same, or Selector",
            ));
        }
    };
    match from {
        "All" => Ok(GatewayApiAllowedRoutesNamespaces::All),
        "Same" => Ok(GatewayApiAllowedRoutesNamespaces::Same),
        "Selector" => namespaces
            .get("selector")
            .ok_or_else(|| {
                listener_validation_error(
                    "spec.listeners[].allowedRoutes.namespaces.selector",
                    "must be an object when namespaces.from is Selector",
                )
            })
            .and_then(namespace_selector)
            .map(GatewayApiAllowedRoutesNamespaces::Selector),
        _ => Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.from",
            "must be one of All, Same, or Selector",
        )),
    }
}

pub(crate) fn namespace_selector(
    selector: &Value,
) -> Result<GatewayApiNamespaceSelector, GatewayApiListenerValidationError> {
    let Some(selector) = selector.as_object() else {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.selector",
            "must be an object when namespaces.from is Selector",
        ));
    };
    if selector
        .keys()
        .any(|key| key != "matchLabels" && key != "matchExpressions")
    {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.selector",
            "may contain only matchLabels and matchExpressions",
        ));
    }

    let mut match_labels = HashMap::new();
    if let Some(labels) = selector.get("matchLabels") {
        let Some(labels) = labels.as_object() else {
            return Err(listener_validation_error(
                "spec.listeners[].allowedRoutes.namespaces.selector.matchLabels",
                "must be an object",
            ));
        };
        for (key, value) in labels {
            if !valid_kubernetes_label_key(key) {
                return Err(listener_validation_error(
                    "spec.listeners[].allowedRoutes.namespaces.selector.matchLabels key",
                    "must be a valid Kubernetes label key",
                ));
            }
            let Some(value) = value.as_str() else {
                return Err(listener_validation_error(
                    "spec.listeners[].allowedRoutes.namespaces.selector.matchLabels value",
                    "must be a string",
                ));
            };
            if !valid_kubernetes_label_value(value) {
                return Err(listener_validation_error(
                    "spec.listeners[].allowedRoutes.namespaces.selector.matchLabels value",
                    "must be a valid Kubernetes label value",
                ));
            }
            match_labels.insert(key.clone(), value.to_string());
        }
    }

    let mut match_expressions = Vec::new();
    if let Some(expressions) = selector.get("matchExpressions") {
        let Some(expressions) = expressions.as_array() else {
            return Err(listener_validation_error(
                "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions",
                "must be an array",
            ));
        };
        match_expressions.reserve(expressions.len());
        for expression in expressions {
            match_expressions.push(namespace_selector_expression(expression)?);
        }
    }

    Ok(GatewayApiNamespaceSelector {
        match_labels,
        match_expressions,
    })
}

fn namespace_selector_expression(
    value: &Value,
) -> Result<GatewayApiNamespaceSelectorExpression, GatewayApiListenerValidationError> {
    let Some(expression) = value.as_object() else {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[]",
            "entries must be objects",
        ));
    };
    if expression
        .keys()
        .any(|key| key != "key" && key != "operator" && key != "values")
    {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[]",
            "may contain only key, operator, and values",
        ));
    }
    let Some(key) = expression.get("key").and_then(Value::as_str) else {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].key",
            "is required and must be a string",
        ));
    };
    if !valid_kubernetes_label_key(key) {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].key",
            "must be a valid Kubernetes label key",
        ));
    }
    let Some(operator) = expression.get("operator").and_then(Value::as_str) else {
        return Err(listener_validation_error(
            "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].operator",
            "is required and must be one of In, NotIn, Exists, or DoesNotExist",
        ));
    };
    let operator = match operator {
        "In" => GatewayApiNamespaceSelectorOperator::In,
        "NotIn" => GatewayApiNamespaceSelectorOperator::NotIn,
        "Exists" => GatewayApiNamespaceSelectorOperator::Exists,
        "DoesNotExist" => GatewayApiNamespaceSelectorOperator::DoesNotExist,
        _ => {
            return Err(listener_validation_error(
                "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].operator",
                "is required and must be one of In, NotIn, Exists, or DoesNotExist",
            ));
        }
    };
    let values = match expression.get("values") {
        None => Vec::new(),
        Some(values) => {
            let Some(values) = values.as_array() else {
                return Err(listener_validation_error(
                    "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].values",
                    "must be an array of strings",
                ));
            };
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let Some(value) = value.as_str() else {
                    return Err(listener_validation_error(
                        "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].values",
                        "must be an array of strings",
                    ));
                };
                if !valid_kubernetes_label_value(value) {
                    return Err(listener_validation_error(
                        "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].values",
                        "must contain only valid Kubernetes label values",
                    ));
                }
                parsed.push(value.to_string());
            }
            parsed
        }
    };
    match operator {
        GatewayApiNamespaceSelectorOperator::In | GatewayApiNamespaceSelectorOperator::NotIn
            if values.is_empty() =>
        {
            return Err(listener_validation_error(
                "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].values",
                "In and NotIn require at least one value",
            ));
        }
        GatewayApiNamespaceSelectorOperator::Exists
        | GatewayApiNamespaceSelectorOperator::DoesNotExist
            if !values.is_empty() =>
        {
            return Err(listener_validation_error(
                "spec.listeners[].allowedRoutes.namespaces.selector.matchExpressions[].values",
                "Exists and DoesNotExist require no values",
            ));
        }
        _ => {}
    }
    Ok(GatewayApiNamespaceSelectorExpression {
        key: key.to_string(),
        operator,
        values,
    })
}

const fn listener_validation_error(
    field: &'static str,
    message: &'static str,
) -> GatewayApiListenerValidationError {
    GatewayApiListenerValidationError::new(field, message)
}

fn valid_kubernetes_label_key(value: &str) -> bool {
    let (prefix, name) = match value.split_once('/') {
        Some((prefix, name)) => (Some(prefix), name),
        None => (None, value),
    };
    if !valid_kubernetes_label_name(name) {
        return false;
    }
    prefix.is_none_or(valid_kubernetes_dns_subdomain)
}

fn valid_kubernetes_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
        })
}

fn valid_kubernetes_label_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

fn valid_kubernetes_label_value(value: &str) -> bool {
    value.is_empty() || valid_kubernetes_label_name(value)
}

/// True when this Gateway is a GAMMA Waypoint Gateway (gatewayClassName is
/// one of `istio-waypoint` / `ferrum-waypoint`). Slice projection only
/// considers waypoint Gateways when computing `MeshConfig.waypoint_bindings`.
pub(super) fn is_waypoint_gateway(object: &K8sObject) -> bool {
    let Some(class) = string_field(&object.spec, "gatewayClassName") else {
        return false;
    };
    WAYPOINT_GATEWAY_CLASS_NAMES
        .iter()
        .any(|expected| class.eq_ignore_ascii_case(expected))
}

/// Insert (or update) a `MeshWaypointBinding` for this Gateway. Gateway
/// resources contribute the binding shell — `name` + `namespace` — and
/// honor a label/annotation-level `istio.io/waypoint-for` default if present.
/// Bound services are added later by `add_service_waypoint_binding` from
/// `collect_service`.
pub(super) fn add_waypoint_binding(acc: &mut super::K8sAccumulator, object: &K8sObject) {
    let waypoint_for = metadata_key(object, KEY_WAYPOINT_FOR)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "service".to_string());
    let gateway_class_name = string_field(&object.spec, "gatewayClassName").map(ToOwned::to_owned);
    if let Some(existing) = acc
        .mesh
        .waypoint_bindings
        .iter_mut()
        .find(|b| b.name == object.metadata.name && b.namespace == object.metadata.namespace)
    {
        // Gateway-level label/annotation always wins over service-supplied
        // defaults because the Gateway is the canonical owner of the
        // waypoint identity.
        existing.waypoint_for = waypoint_for;
        if gateway_class_name.is_some() {
            existing.gateway_class_name = gateway_class_name;
        }
    } else {
        acc.mesh.waypoint_bindings.push(MeshWaypointBinding {
            name: object.metadata.name.clone(),
            namespace: object.metadata.namespace.clone(),
            waypoint_for,
            gateway_class_name,
            services: Vec::new(),
        });
    }
}

/// Append this Service to the matching waypoint binding when the
/// `istio.io/use-waypoint` label/annotation is set (and not `None`). Creates the
/// binding shell when the Gateway hasn't been observed yet so service +
/// gateway translation can land in either order.
pub(super) fn add_service_waypoint_binding(acc: &mut super::K8sAccumulator, object: &K8sObject) {
    let Some(waypoint) =
        metadata_key(object, KEY_USE_WAYPOINT).filter(|s| !s.eq_ignore_ascii_case("none"))
    else {
        return;
    };
    let waypoint_name = waypoint.to_string();
    let waypoint_namespace = metadata_key(object, KEY_USE_WAYPOINT_NAMESPACE)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| object.metadata.namespace.clone());
    let waypoint_for_override = metadata_key(object, KEY_WAYPOINT_FOR).map(ToOwned::to_owned);

    let service_ref = MeshWaypointServiceRef {
        namespace: object.metadata.namespace.clone(),
        name: object.metadata.name.clone(),
    };

    if let Some(existing) = acc
        .mesh
        .waypoint_bindings
        .iter_mut()
        .find(|b| b.name == waypoint_name && b.namespace == waypoint_namespace)
    {
        if !existing.services.contains(&service_ref) {
            existing.services.push(service_ref);
        }
        return;
    }
    acc.mesh.waypoint_bindings.push(MeshWaypointBinding {
        name: waypoint_name,
        namespace: waypoint_namespace,
        waypoint_for: waypoint_for_override.unwrap_or_else(|| "service".to_string()),
        gateway_class_name: None,
        services: vec![service_ref],
    });
}

fn metadata_key<'a>(object: &'a K8sObject, key: &str) -> Option<&'a str> {
    object
        .metadata
        .labels
        .get(key)
        .or_else(|| object.metadata.annotations.get(key))
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn route_conflicts<'a>(
    objects: impl IntoIterator<Item = &'a K8sObject>,
    options: &K8sTranslationOptions,
    acc: Option<&K8sAccumulator>,
) -> Vec<GatewayApiRouteConflict> {
    let mut candidates_by_key: HashMap<
        GatewayApiRouteConflictKey,
        Vec<GatewayApiRouteConflictCandidate>,
    > = HashMap::new();
    let mut route_entries: Vec<CrossKindRouteEntry> = Vec::new();
    let mut udp_entries: Vec<UdpRouteConflictEntry> = Vec::new();

    for object in objects
        .into_iter()
        .filter(|object| super::includes_object_namespace(options, object))
        .filter(|object| matches!(object.kind.as_str(), "HTTPRoute" | "GRPCRoute" | "UDPRoute"))
    {
        let resource = K8sResourceKey::from_object(object);
        let creation_timestamp = object
            .metadata
            .creation_timestamp
            .as_deref()
            .and_then(parse_k8s_timestamp);
        let candidate = GatewayApiRouteConflictCandidate {
            resource: resource.clone(),
            creation_timestamp,
        };
        if object.kind == "UDPRoute" {
            // UDPRoute arbitration is listener-identity scoped (below), not
            // keyed by the literal parentRef selector spelling.
            udp_entries.push(UdpRouteConflictEntry {
                candidate,
                claims: udp_route_conflict_claims(object, acc),
            });
            continue;
        }
        let key_set = route_conflict_key_set(object, acc);
        for key in &key_set.keys {
            candidates_by_key.entry(key.clone()).or_default().push(
                GatewayApiRouteConflictCandidate {
                    resource: resource.clone(),
                    creation_timestamp,
                },
            );
        }
        route_entries.push(CrossKindRouteEntry {
            candidate,
            keys: key_set.keys,
            listeners: key_set.listeners,
        });
    }

    let mut conflicts = cross_kind_route_conflicts(&route_entries);
    conflicts.extend(udp_route_conflicts(&udp_entries));
    for (key, mut candidates) in candidates_by_key {
        candidates.sort_by(compare_conflict_candidates);
        candidates.dedup_by(|left, right| left.resource == right.resource);
        let Some(winner) = candidates.first().cloned() else {
            continue;
        };
        for loser in candidates.into_iter().skip(1) {
            conflicts.push(GatewayApiRouteConflict {
                key: key.clone(),
                winner: winner.resource.clone(),
                loser: loser.resource,
            });
        }
    }
    conflicts.sort_by(|left, right| {
        (&left.loser, &left.key, &left.winner).cmp(&(&right.loser, &right.key, &right.winner))
    });
    conflicts.dedup_by(|left, right| left.loser == right.loser && left.key == right.key);
    conflicts
}

pub(crate) fn route_conflict_keys(object: &K8sObject) -> Vec<GatewayApiRouteConflictKey> {
    route_conflict_keys_for_acc(object, None)
}

/// One HTTPRoute / GRPCRoute participating in cross-kind conflict resolution,
/// carrying the conflict keys it claims across every parent reference plus the
/// concrete Gateway listeners each `(parentRef, hostname)` claim resolved to.
struct CrossKindRouteEntry {
    candidate: GatewayApiRouteConflictCandidate,
    keys: Vec<GatewayApiRouteConflictKey>,
    /// parentRef key -> conflict hostname -> the accepted listeners behind it.
    listeners: BTreeMap<String, BTreeMap<String, BTreeSet<GatewayApiListenerKey>>>,
}

impl CrossKindRouteEntry {
    /// The listeners this route attaches to for one `(parentRef, hostname)`
    /// claim. Resolved listeners are the arbitration domain. The literal
    /// parentRef fallback is only for claims that legitimately lack listener
    /// identity: the deliberately parentless legacy shape, or a context-free
    /// (`acc: None`) helper call. A declared Gateway parent that resolves no
    /// concrete listener contributes no conflict key at all when an
    /// accumulator is present, so it never reaches this fallback.
    fn listeners_for(&self, parent_ref: &str, hostname: &str) -> BTreeSet<CrossKindListener> {
        match self
            .listeners
            .get(parent_ref)
            .and_then(|by_hostname| by_hostname.get(hostname))
        {
            Some(listeners) if !listeners.is_empty() => listeners
                .iter()
                .cloned()
                .map(CrossKindListener::Listener)
                .collect(),
            _ => BTreeSet::from([CrossKindListener::ParentRef(parent_ref.to_string())]),
        }
    }

    /// The single arbitration domain a conflict key attaches to.
    ///
    /// The key carries the resolved [`GatewayApiListenerKey`] itself, so this
    /// is an identity match — never a numeric-port match. Two sibling
    /// listeners that happen to share a port stay distinct domains, so one
    /// listener's cross-kind loss cannot withdraw the other's claim.
    fn listeners_for_key(&self, key: &GatewayApiRouteConflictKey) -> BTreeSet<CrossKindListener> {
        self.listeners_for(&key.parent_ref, &key.hostname)
            .into_iter()
            .filter(|listener| match (listener, &key.listener) {
                (CrossKindListener::Listener(resolved), Some(claimed)) => resolved == claimed,
                (CrossKindListener::ParentRef(_), None) => true,
                _ => false,
            })
            .collect()
    }
}

/// The domain cross-kind arbitration runs in.
///
/// A route parentRef is a *selector*, not an identity: a wildcard reference
/// (no `sectionName`, no `port`) and a reference pinning a section or port can
/// name the very same listener, and two wildcard references on one Gateway can
/// reach disjoint listeners once `allowedRoutes.kinds` filters them. Arbitrating
/// on the literal selector string would therefore both miss real overlaps and
/// invent conflicts between routes that never share a listener, so the domain
/// is the resolved listener wherever one is known. Identity is the listener
/// key — never its numeric port — so port-aware materialization can retain
/// sibling claims that merely share a port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CrossKindListener {
    /// A concrete accepted Gateway listener the parentRef resolved to.
    Listener(GatewayApiListenerKey),
    /// Listener-less claim identity: parentless legacy shape, or a context-free
    /// helper without an accumulator. Not used for declared Gateways that fail
    /// to resolve when translation/status has a populated accumulator.
    ParentRef(String),
}

/// Resolve HTTPRoute vs GRPCRoute overlap on a shared listener.
///
/// Gateway API v1.5.1 requires that when an HTTPRoute and a GRPCRoute attach
/// to the same listener with intersecting hostnames, exactly one **entire**
/// Route is accepted on that listener — resolved by the oldest
/// `metadata.creationTimestamp`, then `{namespace}/{name}` — and that rules
/// are never merged between the two kinds. The decision is deliberately
/// whole-route and hostname-scoped on the shared listener: it does not look
/// at rule paths or match predicates, so an HTTPRoute catch-all and a
/// GRPCRoute on the same host can never both materialize there.
///
/// With port-aware route representation, a loss is confined to the
/// `(parentRef, listener)` claims that actually overlapped. Surviving
/// claims on other listeners keep their proxies, upstreams, plugins, and
/// materialized-parent records. Conflict keys carry `listen_port` so
/// materialization and status can retain healthy siblings.
///
/// Resolution is greedy over the total `(creationTimestamp, namespace, name)`
/// order across whole Routes, so it is independent of the order objects arrive
/// in: a route is rejected on a listener only when it overlaps an
/// already-accepted route of the other kind on that same listener. A route
/// that overlaps only a *rejected* opposite-kind route still wins there,
/// because a Route rejected on one listener is never admitted as a winner on
/// another.
///
/// Arbitration runs per resolved `CrossKindListener`, never per parentRef
/// selector string, so a wildcard reference and a `sectionName` / `port`
/// reference that name one listener contend with each other, while wildcard
/// references reaching disjoint `allowedRoutes.kinds`-filtered listeners do
/// not.
fn cross_kind_route_conflicts(entries: &[CrossKindRouteEntry]) -> Vec<GatewayApiRouteConflict> {
    // HTTPRoute and GRPCRoute cannot contend unless both kinds are present.
    // Skip claim materialization and the greedy acceptance scan when only one
    // kind is in the snapshot — every comparison would reject same-kind pairs.
    let has_http = entries
        .iter()
        .any(|entry| entry.candidate.resource.kind == "HTTPRoute");
    let has_grpc = entries
        .iter()
        .any(|entry| entry.candidate.resource.kind == "GRPCRoute");
    if !has_http || !has_grpc {
        return Vec::new();
    }

    // Build each Route's concrete listener -> hostname claims once. Two
    // different parentRef shapes selecting one listener land in the same
    // bucket. Parentless / context-free listener-less keys keep a literal
    // parentRef domain; declared Gateways that resolve no listener contribute
    // no keys when an accumulator was present, so they never invent ownership.
    let route_claims = entries
        .iter()
        .map(|entry| {
            let mut claims: BTreeMap<CrossKindListener, BTreeSet<&str>> = BTreeMap::new();
            for key in &entry.keys {
                for listener in entry.listeners_for(&key.parent_ref, &key.hostname) {
                    claims
                        .entry(listener)
                        .or_default()
                        .insert(key.hostname.as_str());
                }
            }
            claims
        })
        .collect::<Vec<_>>();

    // Whole-Route order for greedy acceptance, but losses stay per-listener.
    // Process the total Gateway API order once so a loser on listener A cannot
    // displace a later valid Route on listener A after being withdrawn — while
    // still allowing that Route to win (or keep) listener B.
    let mut route_order = (0..entries.len()).collect::<Vec<_>>();
    route_order.sort_by(|left, right| {
        let left = &entries[*left].candidate;
        let right = &entries[*right].candidate;
        compare_conflict_candidates(left, right)
            .then_with(|| left.resource.kind.cmp(&right.resource.kind))
    });

    // listener -> accepted route indices that claim it
    let mut accepted_on_listener: HashMap<CrossKindListener, Vec<usize>> = HashMap::new();
    // (route_index, listener) -> winner
    let mut listener_losses: HashMap<(usize, CrossKindListener), K8sResourceKey> = HashMap::new();
    for index in route_order {
        let entry = &entries[index];
        for (listener, hostnames) in &route_claims[index] {
            let winner = accepted_on_listener
                .get(listener)
                .into_iter()
                .flatten()
                .find_map(|accepted_index| {
                    let accepted_entry = &entries[*accepted_index];
                    if accepted_entry.candidate.resource.kind == entry.candidate.resource.kind {
                        return None;
                    }
                    let overlaps = route_claims[*accepted_index].get(listener).is_some_and(
                        |accepted_hostnames| {
                            cross_kind_hostnames_overlap(hostnames, accepted_hostnames)
                        },
                    );
                    overlaps.then(|| accepted_entry.candidate.resource.clone())
                });

            if let Some(winner) = winner {
                listener_losses.insert((index, listener.clone()), winner);
            } else {
                accepted_on_listener
                    .entry(listener.clone())
                    .or_default()
                    .push(index);
            }
        }
    }

    // Project each per-listener loss onto the conflict keys that attach to
    // that listener only — sibling listener claims stay materializable.
    let mut conflicts = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        for key in &entry.keys {
            for listener in entry.listeners_for_key(key) {
                let Some(winner) = listener_losses.get(&(index, listener)) else {
                    continue;
                };
                conflicts.push(GatewayApiRouteConflict {
                    key: key.clone(),
                    winner: winner.clone(),
                    loser: entry.candidate.resource.clone(),
                });
            }
        }
    }
    conflicts.sort_by(|left, right| {
        (&left.loser, &left.key, &left.winner).cmp(&(&right.loser, &right.key, &right.winner))
    });
    conflicts.dedup_by(|left, right| left.loser == right.loser && left.key == right.key);
    conflicts
}

/// Do two routes claim any hostname in common on one listener? Conflict-key
/// hostnames are already the listener-intersected effective hostnames (with
/// `*` standing for "the route did not constrain the hostname"), so this is
/// the same wildcard-aware intersection the listener attachment uses.
fn cross_kind_hostnames_overlap(left: &BTreeSet<&str>, right: &BTreeSet<&str>) -> bool {
    left.iter().any(|left| {
        right
            .iter()
            .any(|right| intersect_hostnames(left, right).is_some())
    })
}

/// One UDPRoute participating in same-listener conflict resolution.
///
/// Claims carry both the status-facing conflict key (keyed by the authored
/// parentRef spelling) and the concrete Gateway listener that parentRef
/// resolved to. Arbitration runs on the listener identity; status and
/// materialization suppression key on the conflict key.
struct UdpRouteConflictEntry {
    candidate: GatewayApiRouteConflictCandidate,
    claims: Vec<(GatewayApiRouteConflictKey, GatewayApiListenerKey)>,
}

/// Resolve UDPRoute vs UDPRoute ownership of a concrete UDP Gateway listener.
///
/// A UDP listener has no hostname/SNI/path discriminator, so two UDPRoutes
/// that attach to the same listener cannot both receive traffic. Gateway API
/// picks the oldest `metadata.creationTimestamp`, then `{namespace}/{name}`.
/// Ferrum materializes that decision fail-closed: the loser emits neither a
/// stream proxy nor a generated upstream for the conflicted listener.
/// Status distinguishes attachment from traffic ownership: both otherwise-valid
/// routes report `Accepted=True`; the non-effective newer route reports
/// `Programmed=False` with conflict evidence (and Ferrum's `Conflicted=True`
/// extension). A multi-listener route that loses on only some listeners keeps
/// `Accepted=True` / `Programmed=True` while still surfacing partial conflict.
///
/// Arbitration is scoped to resolved [`GatewayApiListenerKey`] identity, not
/// the literal parentRef selector string, so a wildcard reference and a
/// `sectionName` / `port` reference that name one listener contend with each
/// other. Distinct listeners stay independent: a route that loses on one
/// listener may still materialize on another non-conflicting listener.
fn udp_route_conflicts(entries: &[UdpRouteConflictEntry]) -> Vec<GatewayApiRouteConflict> {
    let mut claimants_by_listener: BTreeMap<
        GatewayApiListenerKey,
        Vec<(usize, GatewayApiRouteConflictKey)>,
    > = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        for (key, listener) in &entry.claims {
            claimants_by_listener
                .entry(listener.clone())
                .or_default()
                .push((index, key.clone()));
        }
    }

    let mut conflicts = Vec::new();
    for claimants in claimants_by_listener.into_values() {
        // Collapse one route that reaches the same listener through multiple
        // parentRef spellings into a single ownership candidate, preserving
        // every claim key so each losing parentRef reports Conflicted.
        let mut by_resource: BTreeMap<K8sResourceKey, (usize, Vec<GatewayApiRouteConflictKey>)> =
            BTreeMap::new();
        for (index, key) in claimants {
            let resource = entries[index].candidate.resource.clone();
            let slot = by_resource
                .entry(resource)
                .or_insert_with(|| (index, Vec::new()));
            slot.1.push(key);
        }

        let mut ordered = by_resource.into_iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            compare_conflict_candidates(&entries[left.1.0].candidate, &entries[right.1.0].candidate)
                .then_with(|| left.0.cmp(&right.0))
        });
        let Some((_, (winner_index, _))) = ordered.first() else {
            continue;
        };
        let winner = entries[*winner_index].candidate.resource.clone();
        for (_, (index, keys)) in ordered.into_iter().skip(1) {
            let mut keys = keys;
            keys.sort();
            keys.dedup();
            for key in keys {
                conflicts.push(GatewayApiRouteConflict {
                    key,
                    winner: winner.clone(),
                    loser: entries[index].candidate.resource.clone(),
                });
            }
        }
    }
    conflicts
}

/// Conflict-key + concrete-listener claims for one UDPRoute.
fn udp_route_conflict_claims(
    object: &K8sObject,
    acc: Option<&K8sAccumulator>,
) -> Vec<(GatewayApiRouteConflictKey, GatewayApiListenerKey)> {
    let Some(acc) = acc else {
        // Without listener policy the concrete listener is unknown; fall back
        // to a parentRef-shaped synthetic key so status still has a stable
        // identity, matching the HTTP unresolved-parentRef fallback.
        return route_parent_ref_keys(object)
            .into_iter()
            .map(|parent_ref| {
                let listener = GatewayApiListenerKey {
                    namespace: object.metadata.namespace.clone(),
                    parent_kind: GatewayApiListenerParentKind::Gateway,
                    gateway: "*".to_string(),
                    listener: parent_ref.clone(),
                };
                (
                    udp_route_conflict_key(&parent_ref, &listener, None),
                    listener,
                )
            })
            .collect();
    };

    let mut claims = Vec::new();
    for claim in udp_route_listener_claims(object, acc) {
        claims.push((
            udp_route_conflict_key(&claim.parent_ref, &claim.listener, Some(claim.port)),
            claim.listener,
        ));
    }
    claims.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    claims.dedup();
    claims
}

fn udp_route_conflict_key(
    parent_ref: &str,
    listener: &GatewayApiListenerKey,
    listen_port: Option<u16>,
) -> GatewayApiRouteConflictKey {
    GatewayApiRouteConflictKey {
        route_family: "udproute".to_string(),
        parent_ref: parent_ref.to_string(),
        hostname: "*".to_string(),
        listen_path: format!(
            "udp-listener:{}/{}/{}/{}",
            listener.parent_kind.as_str(),
            listener.namespace,
            listener.gateway,
            listener.listener
        ),
        match_signature: String::new(),
        // A missing port means this is the listener-shaped unresolved fallback
        // used without an accumulator, not a resolved Gateway listener claim.
        listener: listen_port.map(|_| listener.clone()),
        listen_port,
    }
}

/// One concrete UDP Gateway listener a UDPRoute attaches to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UdpListenerClaim {
    parent_ref: String,
    listener: GatewayApiListenerKey,
    port: u16,
}

/// Resolve every materializable UDP listener a UDPRoute attaches to, preserving
/// the authored parentRef spelling that selected it.
fn udp_route_listener_claims(object: &K8sObject, acc: &K8sAccumulator) -> Vec<UdpListenerClaim> {
    let mut claims = Vec::new();
    for parent_ref in object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        let parent_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        if string_field(parent_ref, "name").is_none() {
            continue;
        };
        if route_parent_ref_disallow_error(acc, object, parent_ref).is_some() {
            continue;
        }
        let parent_ref_key = route_parent_ref_key_for_parent(object, parent_ref);
        for (key, policy) in &acc.gateway_api_listener_policies {
            if listener_key_matches_parent_ref(key, parent_namespace, parent_ref)
                && parent_ref_matches_listener_policy(parent_ref, key, policy)
                && route_listener_policy_materializes_route(acc, object, parent_namespace, policy)
                && let Some(port) = policy.port.and_then(|port| u16::try_from(port).ok())
            {
                claims.push(UdpListenerClaim {
                    parent_ref: parent_ref_key.clone(),
                    listener: key.clone(),
                    port,
                });
            }
        }
    }
    claims.sort();
    claims.dedup();
    claims
}

pub(crate) fn route_conflict_keys_for_acc(
    object: &K8sObject,
    acc: Option<&K8sAccumulator>,
) -> Vec<GatewayApiRouteConflictKey> {
    route_conflict_key_set(object, acc).keys
}

/// A route's conflict keys plus the concrete listeners behind each
/// `(parentRef, hostname)` claim.
///
/// The keys are the route's public identity — status conditions, materialized
/// parents, and losing-match suppression all key on the literal parentRef they
/// carry — while the listener resolution is only consumed by cross-kind
/// arbitration, which must not mistake a selector shape for a listener.
struct RouteConflictKeySet {
    keys: Vec<GatewayApiRouteConflictKey>,
    /// parentRef key -> conflict hostname -> the accepted listeners behind it.
    /// A pair with no entry either resolved no listener (and, with an
    /// accumulator, contributed no key for a declared Gateway) or is the
    /// parentless / context-free listener-less shape.
    listeners: BTreeMap<String, BTreeMap<String, BTreeSet<GatewayApiListenerKey>>>,
}

fn route_conflict_key_set(object: &K8sObject, acc: Option<&K8sAccumulator>) -> RouteConflictKeySet {
    if object.kind == "UDPRoute" {
        let claims = udp_route_conflict_claims(object, acc);
        let mut keys = Vec::new();
        let mut listeners: BTreeMap<String, BTreeMap<String, BTreeSet<GatewayApiListenerKey>>> =
            BTreeMap::new();
        for (key, listener) in claims {
            listeners
                .entry(key.parent_ref.clone())
                .or_default()
                .entry(key.hostname.clone())
                .or_default()
                .insert(listener);
            keys.push(key);
        }
        keys.sort();
        keys.dedup();
        return RouteConflictKeySet { keys, listeners };
    }

    let requested_hostnames = route_hostnames(object);
    let hostnames = acc
        .and_then(|acc| {
            route_effective_hostnames(object, acc, &requested_hostnames, None)
                .map(|hostnames| conflict_hostnames_for_proxy_hosts(&hostnames))
        })
        .unwrap_or_else(|| requested_hostnames.clone());
    let default_parent_refs = route_parent_ref_keys(object);
    let route_family = object.kind.to_ascii_lowercase();

    // Attachment depends on the hostname, not on the rule or match, so resolve
    // each conflict hostname once instead of per rule x match.
    //
    // Mirror the materialization gate: with a real accumulator, only parentRefs
    // that resolve concrete listeners contribute conflict keys / cross-kind
    // claims. A declared Gateway that resolves nothing invents no ownership
    // domain. Parentless legacy and `acc: None` keep listener-less keys.
    let mut parent_refs_by_hostname: HashMap<&str, Vec<String>> = HashMap::new();
    let mut listeners: BTreeMap<String, BTreeMap<String, BTreeSet<GatewayApiListenerKey>>> =
        BTreeMap::new();
    for hostname in &hostnames {
        let parent_refs = match acc {
            Some(acc) => {
                let resolved = route_allowed_parent_listeners_for_hostname(
                    object,
                    acc,
                    &requested_hostnames,
                    None,
                    hostname,
                );
                let with_listeners: BTreeMap<String, BTreeSet<GatewayApiListenerKey>> = resolved
                    .into_iter()
                    .filter(|(_, listener_keys)| !listener_keys.is_empty())
                    .collect();
                if with_listeners.is_empty() {
                    if route_declares_gateway_parent_ref(object) {
                        Vec::new()
                    } else {
                        default_parent_refs.clone()
                    }
                } else {
                    let parent_refs: Vec<String> = with_listeners.keys().cloned().collect();
                    for (parent_ref, listener_keys) in with_listeners {
                        listeners
                            .entry(parent_ref)
                            .or_default()
                            .entry(hostname.clone())
                            .or_default()
                            .extend(listener_keys);
                    }
                    parent_refs
                }
            }
            None => default_parent_refs.clone(),
        };
        parent_refs_by_hostname.insert(hostname.as_str(), parent_refs);
    }

    let mut keys = Vec::new();
    for rule in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for descriptor in route_match_descriptors(object, rule) {
            for hostname in &hostnames {
                let Some(parent_refs) = parent_refs_by_hostname.get(hostname.as_str()) else {
                    continue;
                };
                for parent_ref in parent_refs {
                    // One conflict key per resolved *listener*, not per port:
                    // sibling listeners sharing a numeric port stay independent
                    // claims. The parentless legacy shape (and `acc: None`)
                    // keeps a single listener-less key that predates listener
                    // resolution. Declared Gateways with no resolved listener
                    // never reach here when an accumulator is present.
                    let resolved: Vec<Option<GatewayApiListenerKey>> = listeners
                        .get(parent_ref.as_str())
                        .and_then(|by_host| by_host.get(hostname.as_str()))
                        .map(|listener_keys| listener_keys.iter().cloned().map(Some).collect())
                        .unwrap_or_default();
                    let resolved = if resolved.is_empty() {
                        vec![None]
                    } else {
                        resolved
                    };
                    for listener in resolved {
                        let listen_port = listener
                            .as_ref()
                            .and_then(|key| acc.and_then(|acc| listener_policy_port(acc, key)));
                        keys.push(GatewayApiRouteConflictKey {
                            route_family: route_family.clone(),
                            parent_ref: parent_ref.clone(),
                            hostname: hostname.clone(),
                            listen_path: descriptor.listen_path.clone(),
                            match_signature: route_conflict_match_signature(&descriptor),
                            listener,
                            listen_port,
                        });
                    }
                }
            }
        }
    }

    keys.sort();
    keys.dedup();
    RouteConflictKeySet { keys, listeners }
}

/// Numeric port of one listener, read from that listener's **own** policy.
///
/// Never scan `gateway_api_listener_policies` for "some policy with this port"
/// — that is exactly the sibling-taint bug port-aware identity exists to
/// prevent.
fn listener_policy_port(acc: &K8sAccumulator, key: &GatewayApiListenerKey) -> Option<u16> {
    acc.gateway_api_listener_policies
        .get(key)
        .and_then(|policy| policy.port)
        .and_then(|port| u16::try_from(port).ok())
}

/// Whether one listener terminates frontend TLS, read from its own policy.
fn listener_policy_requires_tls(acc: &K8sAccumulator, key: &GatewayApiListenerKey) -> bool {
    acc.gateway_api_listener_policies
        .get(key)
        .is_some_and(|policy| policy.requires_frontend_tls)
}

fn route_conflict_match_signature(descriptor: &RouteMatchDescriptor) -> String {
    descriptor.match_signature.clone()
}

fn upsert_http_route_resources(
    acc: &mut K8sAccumulator,
    proxies: Vec<Proxy>,
    plugins: Vec<PluginConfig>,
    route_kind: &str,
) {
    let mut plugins_by_proxy: HashMap<NamespacedResourceId, Vec<PluginConfig>> = HashMap::new();
    for plugin in plugins {
        if let Some(proxy_id) = plugin.proxy_id.clone() {
            let Some(key) = namespaced_resource_key(&plugin.namespace, &proxy_id) else {
                acc.warnings.push(format!(
                    "route plugin '{}/{}' with empty namespace or proxy_id was ignored",
                    plugin.namespace, plugin.id
                ));
                continue;
            };
            plugins_by_proxy.entry(key).or_default().push(plugin);
        } else {
            acc.config.plugin_configs.push(plugin);
        }
    }

    for proxy in proxies {
        let route_plugins = namespaced_resource_key(&proxy.namespace, &proxy.id)
            .and_then(|key| plugins_by_proxy.remove(&key))
            .unwrap_or_default();
        let proxy_key = namespaced_resource_key(&proxy.namespace, &proxy.id);
        // The exact `(route, parentRef, listener)` claims this proxy carries.
        // Both the refusal and the materialization branches below report
        // through them, so the data plane and Route status can never disagree.
        let attachments = proxy_key
            .as_ref()
            .map(|key| acc.gateway_api_route_proxy_attachments_of(key))
            .unwrap_or_default();
        let slot = route_slot_of(&proxy);
        // A slot already refused for listener ambiguity stays refused for the
        // rest of this pass, so the outcome cannot depend on which claim the
        // translator happened to observe first.
        if acc.gateway_api_refused_route_slots.contains(&slot) {
            acc.warnings.push(format!(
                "Gateway API route proxy '{}/{}' is refused: its host+path claim on this listener \
                 port was already refused because two different Gateway API listeners claim it",
                proxy.namespace, proxy.id
            ));
            if let Some(key) = proxy_key {
                acc.gateway_api_route_proxy_listeners.remove(&key);
            }
            acc.record_gateway_api_refused_route_attachments(attachments);
            continue;
        }
        if let Some(merged_into) =
            merge_http_route_proxy(acc, proxy.clone(), &route_plugins, route_kind)
        {
            // The claim materializes through the proxy it collapsed into, so
            // credit that proxy: withdrawing the survivor must take the merged
            // claim's status down with it.
            acc.record_gateway_api_materialized_route_attachments(&merged_into, &attachments);
            continue;
        }
        if let Some(conflict) = conflicting_slot_claim(acc, &proxy) {
            // Two different Gateway API listeners materialize one physical
            // route-table slot. Gateway API attached each Route to exactly one
            // of them, so neither may absorb the other's rules, and one socket
            // cannot serve two contradictory contracts on the same host+path.
            // Refuse both sides rather than letting observation order decide.
            acc.warnings.push(format!(
                "Gateway API route proxies '{}/{}' and '{}/{}' claim the same host+path on \
                 listener port {:?} from different Gateway API listeners; the claim is \
                 physically ambiguous, so both are refused (Conflicted)",
                conflict.0, conflict.1, proxy.namespace, proxy.id, proxy.listen_port
            ));
            // Everything the withdrawn side was serving — its own claims plus
            // any claim merged into it — is refused too, captured before the
            // withdrawal uncredits them.
            let withdrawn = namespaced_resource_key(&conflict.0, &conflict.1)
                .map(|key| acc.gateway_api_route_attachments_materialized_by(&key))
                .unwrap_or_default();
            acc.withdraw_proxy(&conflict.0, &conflict.1);
            if let Some(key) = proxy_key {
                acc.gateway_api_route_proxy_listeners.remove(&key);
            }
            acc.record_gateway_api_refused_route_attachments(withdrawn);
            acc.record_gateway_api_refused_route_attachments(attachments);
            acc.gateway_api_refused_route_slots.insert(slot);
            continue;
        }
        acc.upsert_proxy(proxy, SourceKind::GatewayApi);
        acc.config.plugin_configs.extend(route_plugins);
        if let Some(key) = proxy_key {
            acc.gateway_api_route_proxy_kinds
                .insert(key.clone(), route_kind.to_string());
            acc.record_gateway_api_materialized_route_attachments(&key, &attachments);
        }
    }

    for (_, plugins) in plugins_by_proxy {
        acc.config.plugin_configs.extend(plugins);
    }
}

/// Collapse one route proxy into a same-kind, same-listener sibling.
///
/// Returns the identity of the proxy the claim merged into, so the caller can
/// credit the merged claim to the proxy that actually serves it; `None` when no
/// merge happened and the caller must materialize the proxy itself.
fn merge_http_route_proxy(
    acc: &mut K8sAccumulator,
    proxy: Proxy,
    route_plugins: &[PluginConfig],
    route_kind: &str,
) -> Option<NamespacedResourceId> {
    let existing_index = acc
        .config
        .proxies
        .iter()
        .position(|existing| can_merge_http_route_proxy(acc, existing, &proxy, route_kind))?;

    let new_dispatch = route_plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch");
    let existing_id = acc.config.proxies[existing_index].id.clone();
    let existing_namespace = acc.config.proxies[existing_index].namespace.clone();
    let mut route_action_plugins: Vec<PluginConfig> = route_plugins
        .iter()
        .filter(|plugin| plugin.plugin_name != "mesh_route_dispatch")
        .filter_map(|plugin| retarget_route_action_plugin(plugin.clone(), &existing_id))
        .collect();
    let existing_dispatch_index = dispatch_plugin_index(
        &acc.config.plugin_configs,
        &existing_namespace,
        &existing_id,
    );
    if new_dispatch.is_none() && existing_dispatch_index.is_none() {
        return None;
    }

    let new_has_default = dispatch_reject_unmatched(new_dispatch) == Some(false)
        || (new_dispatch.is_none() && route_plugins.is_empty());
    let existing_has_default = existing_dispatch_index
        .and_then(|index| dispatch_reject_unmatched(Some(&acc.config.plugin_configs[index])))
        != Some(true);

    if new_has_default {
        replace_proxy_default_route(&mut acc.config.proxies[existing_index], &proxy);
    }

    if let Some(plugin) = new_dispatch {
        let new_rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(index) = existing_dispatch_index {
            append_dispatch_rules(&mut acc.config.plugin_configs[index], new_rules);
            set_dispatch_reject_unmatched(
                &mut acc.config.plugin_configs[index],
                !(existing_has_default || new_has_default),
            );
        } else {
            let mut plugin = retarget_dispatch_plugin(plugin.clone(), &existing_id);
            set_dispatch_reject_unmatched(&mut plugin, false);
            sort_dispatch_rules(&mut plugin);
            attach_route_plugins_to_proxy(
                &mut acc.config.proxies[existing_index],
                std::slice::from_ref(&plugin),
            );
            acc.config.plugin_configs.push(plugin);
        }
    } else if let Some(index) = existing_dispatch_index {
        set_dispatch_reject_unmatched(&mut acc.config.plugin_configs[index], false);
    }

    route_action_plugins.retain(|plugin| {
        !acc.config.plugin_configs.iter().any(|existing| {
            existing.plugin_name == plugin.plugin_name
                && existing.namespace == existing_namespace
                && existing.proxy_id.as_deref() == Some(existing_id.as_str())
        })
    });
    if !route_action_plugins.is_empty() {
        attach_route_plugins_to_proxy(
            &mut acc.config.proxies[existing_index],
            &route_action_plugins,
        );
        acc.config.plugin_configs.extend(route_action_plugins);
    }

    // The merge target came out of `acc.config.proxies`, which `upsert_proxy`
    // only ever admits with a non-empty namespace and id.
    namespaced_resource_key(&existing_namespace, &existing_id)
}

/// Only proxies from the same Gateway API route kind admitted on the **same
/// Gateway API listener** may collapse.
///
/// The numeric `listen_port` is deliberately not the merge key. Gateway API
/// permits several listeners — of one Gateway or of different Gateways — to
/// share a port, and a Route attached to listener A was never attached to
/// listener B. Merging by port would combine two unrelated listeners' dispatch
/// rules and default backends, serving one Gateway's traffic under another
/// Gateway's route contract. Same-kind, same-listener collapse still preserves
/// rule ordering and fall-through within one listener.
///
/// `None == None` is a legitimate match only for the deliberately parentless
/// legacy shape: those claims are port-agnostic and carry no listener identity
/// to distinguish. Declared Gateway parents that resolve no concrete listener
/// never materialize a proxy, so they are not merge candidates.
fn can_merge_http_route_proxy(
    acc: &K8sAccumulator,
    existing: &Proxy,
    proxy: &Proxy,
    route_kind: &str,
) -> bool {
    acc.proxy_source(&existing.namespace, &existing.id) == Some(SourceKind::GatewayApi)
        && occupies_same_route_slot(existing, proxy)
        && route_proxy_listener(acc, existing) == route_proxy_listener(acc, proxy)
        && namespaced_resource_key(&existing.namespace, &existing.id)
            .and_then(|key| acc.gateway_api_route_proxy_kinds.get(&key))
            .is_some_and(|kind| kind == route_kind)
}

/// Whether two materialized proxies occupy one physical route-table slot —
/// the tuple `GatewayConfig::validate_unique_listen_paths` treats as duplicate.
fn occupies_same_route_slot(existing: &Proxy, proxy: &Proxy) -> bool {
    existing.namespace == proxy.namespace
        && existing.listen_path == proxy.listen_path
        && existing.listen_port == proxy.listen_port
        && existing.hosts == proxy.hosts
}

/// An already-materialized Gateway API proxy that occupies the candidate's
/// physical route slot but was admitted on a **different** listener.
///
/// Returned as `(namespace, id)` so the caller can withdraw it without holding
/// a borrow of the accumulator across the mutation.
fn conflicting_slot_claim(acc: &K8sAccumulator, proxy: &Proxy) -> Option<(String, String)> {
    acc.config
        .proxies
        .iter()
        .find(|existing| {
            acc.proxy_source(&existing.namespace, &existing.id) == Some(SourceKind::GatewayApi)
                && occupies_same_route_slot(existing, proxy)
                && route_proxy_listener(acc, existing) != route_proxy_listener(acc, proxy)
        })
        .map(|existing| (existing.namespace.clone(), existing.id.clone()))
}

fn route_slot_of(proxy: &Proxy) -> GatewayApiRouteSlot {
    GatewayApiRouteSlot {
        namespace: proxy.namespace.clone(),
        hosts: proxy.hosts.clone(),
        listen_path: proxy.listen_path.clone(),
        listen_port: proxy.listen_port,
    }
}

/// The Gateway API listener a materialized route proxy was admitted on.
fn route_proxy_listener<'a>(
    acc: &'a K8sAccumulator,
    proxy: &Proxy,
) -> Option<&'a GatewayApiListenerKey> {
    namespaced_resource_key(&proxy.namespace, &proxy.id)
        .and_then(|key| acc.gateway_api_route_proxy_listeners.get(&key))
        .and_then(Option::as_ref)
}

fn dispatch_plugin_index(
    plugins: &[PluginConfig],
    namespace: &str,
    proxy_id: &str,
) -> Option<usize> {
    plugins.iter().position(|plugin| {
        plugin.plugin_name == "mesh_route_dispatch"
            && plugin.namespace == namespace
            && plugin.proxy_id.as_deref() == Some(proxy_id)
    })
}

fn dispatch_reject_unmatched(plugin: Option<&PluginConfig>) -> Option<bool> {
    plugin.and_then(|plugin| {
        plugin
            .config
            .get("reject_unmatched")
            .and_then(Value::as_bool)
    })
}

fn retarget_dispatch_plugin(mut plugin: PluginConfig, proxy_id: &str) -> PluginConfig {
    plugin.id = format!("istio-vs-mrd-{proxy_id}");
    plugin.proxy_id = Some(proxy_id.to_string());
    plugin
}

fn retarget_route_action_plugin(mut plugin: PluginConfig, proxy_id: &str) -> Option<PluginConfig> {
    plugin.id = match plugin.plugin_name.as_str() {
        "request_transformer" => format!("istio-vs-req-xform-{proxy_id}"),
        "response_transformer" => format!("istio-vs-resp-xform-{proxy_id}"),
        _ => return None,
    };
    plugin.proxy_id = Some(proxy_id.to_string());
    Some(plugin)
}

fn append_dispatch_rules(plugin: &mut PluginConfig, rules: Vec<Value>) {
    if rules.is_empty() {
        return;
    }
    if let Some(existing_rules) = plugin.config.get_mut("rules").and_then(Value::as_array_mut) {
        existing_rules.extend(rules);
        sort_dispatch_rule_values(existing_rules);
    }
}

pub(super) fn finalize_dispatch_plugin_precedence(plugins: &mut [PluginConfig]) {
    for plugin in plugins {
        if plugin.plugin_name != "mesh_route_dispatch" {
            continue;
        }
        sort_dispatch_rules(plugin);
        strip_dispatch_rule_precedence(plugin);
    }
}

pub(super) fn dispatch_rule_internal_metadata_present(plugins: &[PluginConfig]) -> bool {
    plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .filter_map(|plugin| plugin.config.get("rules").and_then(Value::as_array))
        .flatten()
        .any(|rule| {
            rule.as_object()
                .is_some_and(|object| object.keys().any(|key| key.starts_with("_ferrum_")))
        })
}

fn sort_dispatch_rules(plugin: &mut PluginConfig) {
    if let Some(rules) = plugin.config.get_mut("rules").and_then(Value::as_array_mut) {
        sort_dispatch_rule_values(rules);
    }
}

fn sort_dispatch_rule_values(rules: &mut [Value]) {
    if !rules
        .iter()
        .any(|rule| rule.get(GATEWAY_API_DISPATCH_PRECEDENCE_KEY).is_some())
    {
        return;
    }
    rules.sort_by(|left, right| {
        let left_precedence = dispatch_rule_precedence(left);
        let right_precedence = dispatch_rule_precedence(right);
        compare_dispatch_rule_precedence(&left_precedence, &right_precedence)
    });
}

fn strip_dispatch_rule_precedence(plugin: &mut PluginConfig) {
    let Some(rules) = plugin.config.get_mut("rules").and_then(Value::as_array_mut) else {
        return;
    };
    for rule in rules {
        if let Some(object) = rule.as_object_mut() {
            object.remove(GATEWAY_API_DISPATCH_PRECEDENCE_KEY);
        }
    }
}

fn dispatch_rule_precedence(rule: &Value) -> GatewayApiDispatchRulePrecedence {
    let metadata = rule
        .get(GATEWAY_API_DISPATCH_PRECEDENCE_KEY)
        .and_then(Value::as_object);
    GatewayApiDispatchRulePrecedence {
        has_precedence: metadata.is_some(),
        method_match: precedence_bool(metadata, "method_match"),
        header_count: precedence_usize(metadata, "header_count"),
        query_param_count: precedence_usize(metadata, "query_param_count"),
        creation_timestamp: metadata
            .and_then(|metadata| metadata.get("creation_timestamp"))
            .and_then(Value::as_str)
            .and_then(parse_k8s_timestamp),
        namespace: precedence_string(metadata, "namespace"),
        name: precedence_string(metadata, "name"),
        rule_index: precedence_usize(metadata, "rule_index"),
        match_index: precedence_usize(metadata, "match_index"),
    }
}

fn precedence_bool(metadata: Option<&serde_json::Map<String, Value>>, key: &str) -> bool {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn precedence_usize(metadata: Option<&serde_json::Map<String, Value>>, key: &str) -> usize {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0)
}

fn precedence_string(metadata: Option<&serde_json::Map<String, Value>>, key: &str) -> String {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn compare_dispatch_rule_precedence(
    left: &GatewayApiDispatchRulePrecedence,
    right: &GatewayApiDispatchRulePrecedence,
) -> Ordering {
    right
        .has_precedence
        .cmp(&left.has_precedence)
        .then_with(|| right.method_match.cmp(&left.method_match))
        .then_with(|| right.header_count.cmp(&left.header_count))
        .then_with(|| right.query_param_count.cmp(&left.query_param_count))
        .then_with(|| {
            compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp)
        })
        .then_with(|| (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name)))
        .then_with(|| left.rule_index.cmp(&right.rule_index))
        .then_with(|| left.match_index.cmp(&right.match_index))
}

fn set_dispatch_reject_unmatched(plugin: &mut PluginConfig, reject_unmatched: bool) {
    if let Some(config) = plugin.config.as_object_mut() {
        config.insert(
            "reject_unmatched".to_string(),
            Value::Bool(reject_unmatched),
        );
    }
}

/// Overlay the new proxy's "default route" fields onto an existing proxy that
/// is being preserved across a same-path collapse. The fields listed here are
/// the only ones the route-translation layer can supply — listener identity
/// (id, namespace, hosts, listen_path, listen_port, protocol family),
/// plugin-set state (resolved_tls, dispatch_kind), and frontend / pool /
/// admission policy come from elsewhere and must NOT be overwritten by a
/// dispatch-rule collapse. If a future field becomes route-derivable, it must
/// be added here AND a regression test added; otherwise traffic for the
/// collapsed default route silently retains stale per-proxy policy.
fn replace_proxy_default_route(existing: &mut Proxy, proxy: &Proxy) {
    existing.backend_host.clone_from(&proxy.backend_host);
    existing.backend_port = proxy.backend_port;
    existing.upstream_id.clone_from(&proxy.upstream_id);
    existing.preserve_host_header = proxy.preserve_host_header;
    existing.retry.clone_from(&proxy.retry);
    existing.backend_read_timeout_ms = proxy.backend_read_timeout_ms;
}

fn route_match_descriptors(object: &K8sObject, rule: &Value) -> Vec<RouteMatchDescriptor> {
    dedup_route_match_descriptors(
        route_match_entry_descriptors(object, rule)
            .into_iter()
            .map(|entry| entry.descriptor)
            .collect(),
    )
}

fn route_match_entry_descriptors(
    object: &K8sObject,
    rule: &Value,
) -> Vec<RouteMatchEntryDescriptor> {
    let Some(matches) = rule.get("matches").and_then(Value::as_array) else {
        // An omitted GRPCRoute `matches` field is the valid catch-all shape,
        // but a present non-array value is malformed. Do not reinterpret it as
        // omission: that would widen hostile input into "every gRPC call".
        if object.kind == "GRPCRoute" && rule.get("matches").is_some() {
            return Vec::new();
        }
        return vec![RouteMatchEntryDescriptor {
            match_index: 0,
            descriptor: default_route_match_descriptor(object),
        }];
    };
    if matches.is_empty() {
        return vec![RouteMatchEntryDescriptor {
            match_index: 0,
            descriptor: default_route_match_descriptor(object),
        }];
    }

    matches
        .iter()
        .enumerate()
        .filter_map(|(match_index, entry)| {
            route_match_descriptor_for_entry(object, entry).map(|descriptor| {
                RouteMatchEntryDescriptor {
                    match_index,
                    descriptor,
                }
            })
        })
        .collect()
}

fn dedup_route_match_descriptors(
    mut descriptors: Vec<RouteMatchDescriptor>,
) -> Vec<RouteMatchDescriptor> {
    descriptors.sort_by(|left, right| {
        (&left.listen_path, &left.match_signature)
            .cmp(&(&right.listen_path, &right.match_signature))
    });
    descriptors.dedup();
    descriptors
}

fn default_route_match_descriptor(object: &K8sObject) -> RouteMatchDescriptor {
    if object.kind == "GRPCRoute" {
        // A GRPCRoute rule with no `matches` matches every gRPC call on the
        // route's hostnames. It still must not swallow plain HTTP sharing the
        // same host, so it materializes on `/` behind the gRPC-shape
        // predicate rather than as an unguarded catch-all.
        return RouteMatchDescriptor {
            listen_path: "/".to_string(),
            match_signature: grpc_route_match_signature(&grpc_any_call_match()),
        };
    }
    RouteMatchDescriptor {
        listen_path: "/".to_string(),
        match_signature: "{}".to_string(),
    }
}

fn route_match_descriptor_for_entry(
    object: &K8sObject,
    entry: &Value,
) -> Option<RouteMatchDescriptor> {
    if object.kind == "GRPCRoute" {
        // gRPC predicates are represented independently from HTTP paths: a
        // fully-qualified `service`+`method` becomes an exact listen path, a
        // service-only match becomes a `/{service}/` prefix, and everything
        // else (method-only, header-only, empty) materializes on `/` behind a
        // `mesh_route_dispatch` URI predicate. Every shape additionally
        // carries the gRPC content-type gate. Nothing is dropped for being
        // pathless, and nothing widens into a catch-all or onto plain HTTP.
        let parsed = grpc_route_match(entry).ok()?;
        return Some(RouteMatchDescriptor {
            listen_path: match &parsed.plan {
                GrpcRouteMatchPlan::PathOnly { listen_path } => listen_path.clone(),
                GrpcRouteMatchPlan::UriRegex { .. } => "/".to_string(),
            },
            match_signature: grpc_route_match_signature(&parsed),
        });
    }

    if http_route_match_has_untranslated_non_path_predicate(entry) {
        return None;
    }

    let listen_path = if let Some(path) = entry.get("path").and_then(http_path_match) {
        path
    } else if entry.as_object().is_some_and(|object| object.is_empty())
        || http_route_match_has_supported_non_path_predicate(entry)
    {
        "/".to_string()
    } else {
        return None;
    };

    Some(RouteMatchDescriptor {
        listen_path,
        match_signature: http_route_match_signature(entry),
    })
}

fn http_route_match_signature(entry: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(method) = string_field(entry, "method") {
        parts.push(format!("method={}", json_string(method)));
    }

    let mut headers = Vec::new();
    if let Some(headers_array) = entry.get("headers").and_then(Value::as_array) {
        for header in headers_array {
            if !gateway_match_type_is_exact(header) {
                continue;
            }
            let Some(name) = string_field(header, "name") else {
                continue;
            };
            let Some(value) = string_field(header, "value") else {
                continue;
            };
            headers.push(format!(
                "{}={}",
                name.to_ascii_lowercase(),
                json_string(value)
            ));
        }
    }
    headers.sort();
    for header in headers {
        parts.push(format!("header:{header}"));
    }

    let mut query_params = Vec::new();
    if let Some(params_array) = entry.get("queryParams").and_then(Value::as_array) {
        for param in params_array {
            if !gateway_match_type_is_exact(param) {
                continue;
            }
            let Some(name) = string_field(param, "name") else {
                continue;
            };
            let Some(value) = string_field(param, "value") else {
                continue;
            };
            query_params.push(format!("{}={}", json_string(name), json_string(value)));
        }
    }
    query_params.sort();
    for param in query_params {
        parts.push(format!("query:{param}"));
    }

    if parts.is_empty() {
        "{}".to_string()
    } else {
        parts.join("|")
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

/// Regex fragment matching exactly one gRPC path segment (a service or a
/// method name). A gRPC `:path` is always `/{service}/{method}`, and neither
/// component may contain `/`, so a wildcard segment never crosses a separator.
const GRPC_PATH_SEGMENT_PATTERN: &str = "[^/]+";

/// Full-match `content-type` predicate gating every emitted GRPCRoute match on
/// the gRPC protocol.
///
/// This is the regex transcription of Ferrum's canonical native-gRPC
/// content-type contract,
/// [`crate::proxy::backend_dispatch::is_native_grpc_content_type`]: the
/// `application/grpc` essence followed by end-of-value, a `+` suffix, a `;`
/// parameter list, or an OWS run leading to end-of-value or `;`. Anything else
/// after the essence — notably a `-` (`application/grpc-web`) or another
/// alphanumeric (`application/grpcfoo`) — is a *different* media type and is
/// refused, so the GRPCRoute gate cannot bless a raw lookalike that the proxy's
/// own dispatcher would not treat as gRPC. A trusted, explicitly configured
/// `grpc_web` plugin is what rewrites a verified gRPC-Web request to native
/// `application/grpc`; the route gate must not independently widen that
/// boundary.
///
/// HTTP media types are case-insensitive, but `mesh_route_dispatch` header
/// `exact` / `prefix` operands are case-sensitive byte compares, so the gate is
/// expressed as a case-insensitive regex operand instead. `(?s)` only affects
/// `.`; header values never carry newlines, and the operand is anchored
/// `\A(?:…)\z` by the plugin at compile time. It is one compiled matcher shared
/// by every emitted rule, so the gate adds no per-request allocation.
const GRPC_CONTENT_TYPE_GATE_REGEX: &str = r"(?is)application/grpc(?:[+;].*|[ \t]+(?:;.*)?)?";

/// Diagnostic for a refused `method.type: RegularExpression` predicate.
const GRPC_REGEX_METHOD_UNSUPPORTED: &str = "matches[].method.type 'RegularExpression' is not supported; Ferrum cannot constrain a regex \
     operand to a single gRPC path segment, so the match is dropped fail-closed (use Exact \
     service / method matches)";

/// Diagnostic for a route-authored `content-type` predicate that is not itself
/// a native gRPC media type. The operator-supplied value is deliberately not
/// echoed — it is unbounded, attacker-influenceable input.
const GRPC_CONTENT_TYPE_MUST_NARROW: &str = "matches[].headers[] 'content-type' must be a native gRPC media type (application/grpc, \
     application/grpc+proto, or either with media-type parameters); a GRPCRoute header predicate \
     may only narrow the gRPC protocol gate, never widen it. application/grpc-web and \
     application/grpc-web-text are not native gRPC — configure the grpc_web plugin, which \
     rewrites a verified gRPC-Web request to application/grpc before backend dispatch";

/// Diagnostic for an explicit `matches[].method: null`. An explicit null is a
/// malformed predicate, not an omitted field: silently reading it as absent
/// would widen the match to every gRPC call on the route's hostnames.
const GRPC_EXPLICIT_NULL_METHOD: &str = "matches[].method must not be null; omit the field to match any gRPC call, or supply an \
     Exact service / method predicate";

/// Diagnostic for an explicit `matches[].headers: null`, which would otherwise
/// widen the predicate to the headerless match.
const GRPC_EXPLICIT_NULL_HEADERS: &str = "matches[].headers must not be null; omit the field to match without header predicates, or \
     supply an array of Exact header matches";

/// Diagnostic for a match entry carrying both the CRD `method` predicate and
/// Ferrum's hand-authored `path` extension. The two describe different
/// predicates and Ferrum cannot represent their conjunction, so honoring
/// either one alone would silently drop the other half and widen the match.
const GRPC_METHOD_AND_PATH_CONFLICT: &str = "matches[] must not carry both 'method' and the Ferrum 'path' extension; Ferrum cannot \
     represent their conjunction, and honoring either alone would widen the predicate. Use an \
     Exact service / method match (the CRD shape) or the path extension, not both";

/// Upper bound on an `Exact` GRPCRoute `method.service` / `method.method`
/// literal, matching the Gateway API v1.5.1 `GRPCMethodMatch` CRD, where both
/// fields carry `MaxLength=1024`. Anything longer cannot have been admitted by
/// the API server, so it is a malformed or hand-authored hostile predicate and
/// is refused rather than compiled into a request-path matcher.
const MAX_GRPC_METHOD_OPERAND_LENGTH: usize = 1024;

/// How one GRPCRoute `matches[]` entry projects onto Ferrum routing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GrpcRouteMatchPlan {
    /// The gRPC method predicate is expressed losslessly by the proxy's
    /// `listen_path` — an exact `={service}/{method}` path for a fully
    /// qualified method, or a `/{service}/` prefix for a service-only match.
    /// No request-time URI evaluation is needed; the gRPC content-type gate
    /// still applies so the listener cannot capture plain HTTP.
    PathOnly { listen_path: String },
    /// The predicate cannot be expressed as a listen path (method-only,
    /// header-only, or an empty match). The route materializes on the `/`
    /// listener and the predicate rides a `mesh_route_dispatch` URI regex plus
    /// the gRPC content-type gate, with `reject_unmatched` keeping unrelated
    /// traffic off the backend.
    UriRegex { pattern: String },
}

/// A single GRPCRoute `matches[]` entry after fail-closed parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GrpcRouteMatch {
    plan: GrpcRouteMatchPlan,
    /// Translated exact header predicates as `(lowercased name, value)` in
    /// first-occurrence order, mirroring the HTTPRoute translator's
    /// first-duplicate-wins rule.
    headers: Vec<(String, String)>,
}

fn grpc_any_call_pattern() -> String {
    format!("/{GRPC_PATH_SEGMENT_PATTERN}/{GRPC_PATH_SEGMENT_PATTERN}")
}

/// The predicate for "any gRPC call" — used for a GRPCRoute rule with no
/// `matches` (or an empty match entry), which the Gateway API defines as
/// matching every gRPC request on the route's hostnames.
fn grpc_any_call_match() -> GrpcRouteMatch {
    GrpcRouteMatch {
        plan: GrpcRouteMatchPlan::UriRegex {
            pattern: grpc_any_call_pattern(),
        },
        headers: Vec::new(),
    }
}

/// Parse one GRPCRoute `matches[]` entry. `Err` means Ferrum cannot represent
/// the predicate exactly; the caller drops that match fail-closed (with a
/// field-specific warning) rather than widening it into something broader.
fn grpc_route_match(entry: &Value) -> Result<GrpcRouteMatch, String> {
    if entry.as_object().is_none() {
        return Err("matches[] entry must be an object".to_string());
    }

    // An *explicit* null is malformed operator input, not an omission: treating
    // `method: null` as absent would widen the predicate to the any-gRPC-call
    // match, exactly the fail-open this parser exists to prevent. Omission stays
    // valid and keeps its documented meaning.
    //
    // `path` is not a GRPCRoute CRD field; it is retained as a Ferrum extension
    // for hand-authored specs that pin an HTTP listen path directly. It is
    // mutually exclusive with `method`: the plan is a single listen path *or* a
    // single URI predicate, so honoring one of the two would silently discard
    // the other half of the operator's conjunction and widen the match.
    let method_value = entry.get("method");
    if method_value.is_some_and(Value::is_null) {
        return Err(GRPC_EXPLICIT_NULL_METHOD.to_string());
    }
    let plan = match (method_value, entry.get("path")) {
        (Some(_), Some(_)) => return Err(GRPC_METHOD_AND_PATH_CONFLICT.to_string()),
        (Some(method), None) => grpc_route_method_plan(method)?,
        (None, Some(path)) => grpc_route_extension_path_plan(path)?,
        (None, None) => GrpcRouteMatchPlan::UriRegex {
            pattern: grpc_any_call_pattern(),
        },
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    // Same fail-closed rule as `method`: an explicit `headers: null` must not
    // silently become the headerless match.
    if let Some(headers_value) = entry.get("headers") {
        if headers_value.is_null() {
            return Err(GRPC_EXPLICIT_NULL_HEADERS.to_string());
        }
        let headers_array = headers_value
            .as_array()
            .ok_or_else(|| "matches[].headers must be an array".to_string())?;
        for header in headers_array {
            if !gateway_match_type_is_exact(header) {
                return Err(
                    "matches[].headers[].type is not supported; only Exact header matches are \
                     translated"
                        .to_string(),
                );
            }
            let name = string_field(header, "name")
                .ok_or_else(|| "matches[].headers[].name is required".to_string())?;
            let value = string_field(header, "value")
                .ok_or_else(|| "matches[].headers[].value is required".to_string())?;
            let name = name.to_ascii_lowercase();
            if !headers.iter().any(|(existing, _)| existing == &name) {
                // A route-authored `content-type` predicate replaces the
                // canonical gRPC gate (see `grpc_dispatch_match_criteria_for`),
                // so it must itself be a gRPC media type. Otherwise a
                // `text/plain` header match would widen the GRPCRoute onto
                // plain HTTP. The value is not echoed into the warning — it is
                // unbounded operator input.
                if name == "content-type" && !is_grpc_media_type(value) {
                    return Err(GRPC_CONTENT_TYPE_MUST_NARROW.to_string());
                }
                headers.push((name, value.to_string()));
            }
        }
    }

    Ok(GrpcRouteMatch { plan, headers })
}

/// Parse Ferrum's hand-authored `matches[].path` GRPCRoute extension without
/// allowing a malformed explicit value to become the broader pathless match.
fn grpc_route_extension_path_plan(path: &Value) -> Result<GrpcRouteMatchPlan, String> {
    if path.as_object().is_none() {
        return Err("matches[].path must be an object".to_string());
    }
    let value = string_field(path, "value")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "matches[].path.value is required and must not be empty".to_string())?;
    match string_field(path, "type").unwrap_or("PathPrefix") {
        "Exact" => Ok(GrpcRouteMatchPlan::PathOnly {
            listen_path: exact_path_listen_path(value),
        }),
        "PathPrefix" => Ok(GrpcRouteMatchPlan::PathOnly {
            listen_path: value.to_string(),
        }),
        "RegularExpression" => Ok(GrpcRouteMatchPlan::PathOnly {
            listen_path: format!("~{value}"),
        }),
        _ => Err(
            "matches[].path.type is not supported; expected Exact, PathPrefix, or \
             RegularExpression"
                .to_string(),
        ),
    }
}

/// Read an optional `method.service` / `method.method` operand.
///
/// A *present* non-string — including an explicit null — is malformed operator
/// input, not an omission. Silently reading it as absent is a fail-open:
/// `{"service": 1, "method": "SayHello"}` would degrade from the exact
/// `=/{service}/{method}` listener to the far broader method-only
/// `/[^/]+/SayHello` predicate, and `{"service": "pkg.Svc", "method": null}`
/// would degrade to the whole-service `/pkg.Svc/` prefix. Both widen the match
/// the operator wrote, which is exactly what this parser exists to prevent.
/// Omission keeps its documented meaning.
fn grpc_method_operand<'a>(method: &'a Value, field: &str) -> Result<Option<&'a str>, String> {
    match method.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(format!(
            "matches[].method.{field} must be a string; omit the field instead of supplying null \
             or a non-string value, which would widen the predicate"
        )),
    }
}

fn grpc_route_method_plan(method: &Value) -> Result<GrpcRouteMatchPlan, String> {
    if method.as_object().is_none() {
        return Err("matches[].method must be an object".to_string());
    }
    let service = grpc_method_operand(method, "service")?;
    let name = grpc_method_operand(method, "method")?;
    if service.is_none() && name.is_none() {
        return Err("matches[].method requires at least one of service / method".to_string());
    }

    match string_field(method, "type").unwrap_or("Exact") {
        "Exact" => {
            let service = service.map(validate_grpc_service_literal).transpose()?;
            let name = name.map(validate_grpc_method_literal).transpose()?;
            match (service, name) {
                (Some(service), Some(name)) => Ok(GrpcRouteMatchPlan::PathOnly {
                    listen_path: exact_path_listen_path(&format!("/{service}/{name}")),
                }),
                // gRPC paths always carry a trailing method segment, so the
                // `/{service}/` prefix selects exactly this service and can
                // never reach a longer service name (`/pkg.SvcExtra/…` does
                // not start with `/pkg.Svc/`).
                (Some(service), None) => Ok(GrpcRouteMatchPlan::PathOnly {
                    listen_path: format!("/{service}/"),
                }),
                // A method-only match has no path prefix: the service segment
                // is a wildcard, so it can only be a URI predicate. The
                // literal is regex-escaped and the service segment is the
                // single-segment wildcard, so the pattern cannot cross a `/`.
                (None, Some(name)) => {
                    let pattern = format!("/{GRPC_PATH_SEGMENT_PATTERN}/{}", regex::escape(name));
                    // Compile exactly the way `mesh_route_dispatch` will, so an
                    // unusable pattern is refused during translation rather
                    // than failing the plugin build on the data plane.
                    compile_grpc_uri_regex(&pattern).map_err(|error| {
                        format!("matches[].method.method is not usable as a URI predicate: {error}")
                    })?;
                    Ok(GrpcRouteMatchPlan::UriRegex { pattern })
                }
                // Already rejected above; re-checked rather than panicking so
                // the production path has no unreachable assertion.
                (None, None) => {
                    Err("matches[].method requires at least one of service / method".to_string())
                }
            }
        }
        // `RegularExpression` is an implementation-specific Gateway API
        // extension, and Ferrum cannot honor it soundly: a gRPC `:path` is
        // `/{service}/{method}`, but an operator-supplied pattern can consume
        // the `/` delimiter through `.*`, a character class, or an encoded
        // escape (`\x2F`, `\u{2F}`), and wrapping the operand in a
        // non-capturing group does not constrain it to one path segment. A
        // regex predicate could therefore widen a route across service and
        // method boundaries, so it is refused instead of compiled into a
        // request-path matcher.
        "RegularExpression" => Err(GRPC_REGEX_METHOD_UNSUPPORTED.to_string()),
        _ => Err("matches[].method.type is not supported; expected Exact".to_string()),
    }
}

/// Shared bounds check for an `Exact` gRPC `method.service` / `method.method`
/// literal. Runs before any grammar walk so a hostile operand can never drive
/// unbounded work, and the operator-supplied value is never echoed back into
/// the warning.
fn validate_grpc_operand_bounds(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("matches[].method.{field} must not be empty"));
    }
    // Byte length, not `chars().count()`: this is the O(1) DoS guard that runs
    // before any grammar walk. Both CRD grammars are ASCII-only, so for an
    // operand the API server could have admitted the two are identical, and a
    // multi-byte operand is rejected by the grammar regardless.
    if value.len() > MAX_GRPC_METHOD_OPERAND_LENGTH {
        return Err(format!(
            "matches[].method.{field} must not exceed {MAX_GRPC_METHOD_OPERAND_LENGTH} bytes"
        ));
    }
    Ok(())
}

/// One protobuf identifier: `[A-Za-z_][A-Za-z_0-9]*`. Both CRD grammars below
/// are built out of this, and both are ASCII-only, so a `bytes()` walk is
/// exact.
fn is_grpc_identifier(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() || first == b'_' => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Validate an `Exact` `method.service` literal against the Gateway API v1.5.1
/// `GRPCMethodMatch.service` CEL grammar
/// `^\.?[a-z_][a-z_0-9]*(\.[a-z_][a-z_0-9]*)*$`, which the CRD applies
/// case-insensitively — a dot-separated run of protobuf identifiers with an
/// optional leading `.` (the fully-qualified-name spelling).
///
/// Returns the literal in the form that appears on the wire: a gRPC `:path` is
/// `/{package}.{Service}/{Method}` and never carries the leading dot, so the
/// optional `.` is normalized away before it becomes a listen path. `.pkg.Svc`
/// and `pkg.Svc` therefore denote the same service and collapse onto the same
/// route (and, when two routes claim it, the same conflict key).
fn validate_grpc_service_literal(value: &str) -> Result<&str, String> {
    validate_grpc_operand_bounds("service", value)?;
    let normalized = value.strip_prefix('.').unwrap_or(value);
    if normalized.is_empty() || !normalized.split('.').all(is_grpc_identifier) {
        return Err(
            "matches[].method.service must be a dot-separated gRPC service name matching \
             '^\\.?[a-z_][a-z_0-9]*(\\.[a-z_][a-z_0-9]*)*$' (case-insensitive)"
                .to_string(),
        );
    }
    Ok(normalized)
}

/// Validate an `Exact` `method.method` literal against the Gateway API v1.5.1
/// `GRPCMethodMatch.method` grammar `^[A-Za-z_][A-Za-z_0-9]*$` — a single
/// protobuf identifier, so no dot, hyphen, path separator, query/fragment
/// delimiter, percent escape, whitespace, or control byte can be smuggled into
/// routing state.
fn validate_grpc_method_literal(value: &str) -> Result<&str, String> {
    validate_grpc_operand_bounds("method", value)?;
    if !is_grpc_identifier(value) {
        return Err(
            "matches[].method.method must be a gRPC method name matching \
             '^[A-Za-z_][A-Za-z_0-9]*$'"
                .to_string(),
        );
    }
    Ok(value)
}

/// Compile a candidate URI regex exactly the way `mesh_route_dispatch` will at
/// plugin-construction time (`\A(?:…)\z`), so an unusable pattern is refused
/// during translation instead of failing the plugin build on the data plane.
fn compile_grpc_uri_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::Regex::new(&format!(r"\A(?:{pattern})\z"))
}

/// Stable identity for a parsed gRPC match, used both for descriptor dedup and
/// as the route-conflict signature so two distinct gRPC predicates sharing the
/// `/` listener are not treated as the same route.
fn grpc_route_match_signature(parsed: &GrpcRouteMatch) -> String {
    let mut parts = Vec::new();
    if let GrpcRouteMatchPlan::UriRegex { pattern } = &parsed.plan {
        parts.push(format!("grpc_uri={}", json_string(pattern)));
    }
    let mut headers: Vec<String> = parsed
        .headers
        .iter()
        .map(|(name, value)| format!("header:{name}={}", json_string(value)))
        .collect();
    headers.sort();
    parts.extend(headers);

    if parts.is_empty() {
        "{}".to_string()
    } else {
        parts.join("|")
    }
}

/// Build the `mesh_route_dispatch` match criteria for one GRPCRoute entry.
/// Returns `None` for a match Ferrum cannot represent (same fail-closed
/// decision `route_match_descriptor_for_entry` made, so the two never diverge).
fn grpc_dispatch_match_criteria(entry: &Value) -> Option<serde_json::Map<String, Value>> {
    let parsed = grpc_route_match(entry).ok()?;
    Some(grpc_dispatch_match_criteria_for(&parsed))
}

fn grpc_dispatch_match_criteria_for(parsed: &GrpcRouteMatch) -> serde_json::Map<String, Value> {
    let mut criteria = serde_json::Map::new();
    let mut headers = serde_json::Map::new();

    if let GrpcRouteMatchPlan::UriRegex { pattern } = &parsed.plan {
        criteria.insert("uri".to_string(), serde_json::json!({ "regex": pattern }));
    }
    // Every GRPCRoute match is gated on the gRPC content type, including one
    // whose predicate is carried entirely by the proxy's `listen_path`. A
    // GRPCRoute selects gRPC calls, so neither an exact `=/{service}/{method}`
    // listener nor a `/{service}/` prefix may capture a plain HTTP request
    // that happens to use the same path, and a URI shape alone would still
    // admit any two-segment HTTP path.
    headers.insert(
        "content-type".to_string(),
        serde_json::json!({ "regex": GRPC_CONTENT_TYPE_GATE_REGEX }),
    );
    // A route-authored `content-type` predicate is more specific than the
    // gate, so it deliberately replaces it. `grpc_route_match` has already
    // validated it is itself a gRPC media type, so the replacement can only
    // narrow the protocol boundary.
    for (name, value) in &parsed.headers {
        headers.insert(name.clone(), Value::String(value.clone()));
    }
    criteria.insert("headers".to_string(), Value::Object(headers));

    criteria
}

/// Is `value` a native gRPC media type?
///
/// Delegates to the canonical dispatcher predicate so a route-authored
/// `content-type` predicate — which *replaces* [`GRPC_CONTENT_TYPE_GATE_REGEX`]
/// in the emitted criteria — can only ever narrow the same protocol boundary
/// the proxy itself enforces. `application/grpc`, `application/grpc+proto`, and
/// parameterized/OWS forms are native; `application/grpc-web`,
/// `application/grpc-web-text`, `application/grpcfoo`, `text/plain`, and
/// `application/json` are not.
fn is_grpc_media_type(value: &str) -> bool {
    crate::proxy::backend_dispatch::is_native_grpc_content_type(value.as_bytes())
}

fn route_hostnames(object: &K8sObject) -> Vec<String> {
    let mut hostnames: Vec<String> = string_array(&object.spec, "hostnames")
        .into_iter()
        .map(|hostname| hostname.to_ascii_lowercase())
        .collect();
    if hostnames.is_empty() {
        hostnames.push("*".to_string());
    }
    hostnames.sort();
    hostnames.dedup();
    hostnames
}

fn route_parent_ref_keys(object: &K8sObject) -> Vec<String> {
    route_parent_ref_keys_for_namespace(object, None)
}

fn route_parent_ref_keys_for_namespace(
    object: &K8sObject,
    namespace_filter: Option<&str>,
) -> Vec<String> {
    let mut refs: Vec<String> = object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|parent| {
            let namespace = string_field(parent, "namespace").unwrap_or(&object.metadata.namespace);
            if namespace_filter.is_some_and(|filter| namespace != filter) {
                return None;
            }
            Some(route_parent_ref_key_for_parent(object, parent))
        })
        .collect();
    if refs.is_empty()
        && namespace_filter.is_none_or(|namespace| namespace == object.metadata.namespace)
    {
        refs.push(format!(
            "gateway.networking.k8s.io/Gateway/{}/{}/*/*",
            object.metadata.namespace, "*"
        ));
    }
    refs.sort();
    refs.dedup();
    refs
}

fn route_allowed_parent_ref_keys_for_namespace(
    object: &K8sObject,
    acc: &K8sAccumulator,
    namespace_filter: Option<&str>,
) -> Vec<String> {
    let Some(parent_refs) = object.spec.get("parentRefs").and_then(Value::as_array) else {
        return route_parent_ref_keys_for_namespace(object, namespace_filter);
    };
    if parent_refs.is_empty() {
        return route_parent_ref_keys_for_namespace(object, namespace_filter);
    }

    let mut refs: Vec<String> = parent_refs
        .iter()
        .filter_map(|parent| {
            if !parent_ref_is_attachable_parent(parent) {
                return None;
            }
            let namespace = string_field(parent, "namespace").unwrap_or(&object.metadata.namespace);
            if namespace_filter.is_some_and(|filter| namespace != filter) {
                return None;
            }
            route_parent_ref_disallow_error(acc, object, parent)
                .is_none()
                .then(|| route_parent_ref_key_for_parent(object, parent))
        })
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

fn route_allowed_parent_ref_keys_for_hostname(
    object: &K8sObject,
    acc: &K8sAccumulator,
    requested_hostnames: &[String],
    namespace_filter: Option<&str>,
    conflict_hostname: &str,
) -> Vec<String> {
    route_allowed_parent_listeners_for_hostname(
        object,
        acc,
        requested_hostnames,
        namespace_filter,
        conflict_hostname,
    )
    .into_keys()
    .collect()
}

/// The concrete Gateway listeners a route attaches to for one conflict
/// hostname, grouped by the literal `parentRefs[]` entry that selected them.
///
/// A reference contributes only when it survives every attachment gate:
/// `parent_ref_matches_listener_policy` (section / port selection), the
/// listener's route-kind and namespace allowance plus its materializability
/// (`route_listener_policy_materializes_route`), and an intersection of the
/// route's hostnames with the listener hostname that lands exactly on
/// `conflict_hostname`.
///
/// An empty listener set means the reference is known-good but no listener
/// policy resolved it — typically the parentless legacy shape, which carries a
/// synthetic parentRef identity with no concrete listener. Callers that see a
/// *declared* Gateway parent with no attached listeners must fail closed
/// rather than materializing a listener-less claim.
fn route_allowed_parent_listeners_for_hostname(
    object: &K8sObject,
    acc: &K8sAccumulator,
    requested_hostnames: &[String],
    namespace_filter: Option<&str>,
    conflict_hostname: &str,
) -> BTreeMap<String, BTreeSet<GatewayApiListenerKey>> {
    let route_hostnames = hostnames_for_listener_intersection(requested_hostnames);
    let unresolved = |keys: Vec<String>| -> BTreeMap<String, BTreeSet<GatewayApiListenerKey>> {
        keys.into_iter().map(|key| (key, BTreeSet::new())).collect()
    };
    let Some(parent_refs) = object.spec.get("parentRefs").and_then(Value::as_array) else {
        return unresolved(route_parent_ref_keys_for_namespace(
            object,
            namespace_filter,
        ));
    };
    if parent_refs.is_empty() {
        return unresolved(route_parent_ref_keys_for_namespace(
            object,
            namespace_filter,
        ));
    }

    let mut refs: BTreeMap<String, BTreeSet<GatewayApiListenerKey>> = BTreeMap::new();
    for parent_ref in parent_refs {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        let Some(_parent_name) = string_field(parent_ref, "name") else {
            continue;
        };
        let gateway_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        if namespace_filter.is_some_and(|namespace| namespace != gateway_namespace)
            || route_parent_ref_disallow_error(acc, object, parent_ref).is_some()
        {
            continue;
        }

        let attached: BTreeSet<GatewayApiListenerKey> = acc
            .gateway_api_listener_policies
            .iter()
            .filter_map(|(key, policy)| {
                let attaches = listener_key_matches_parent_ref(key, gateway_namespace, parent_ref)
                    && parent_ref_matches_listener_policy(parent_ref, key, policy)
                    && route_listener_policy_materializes_route(
                        acc,
                        object,
                        gateway_namespace,
                        policy,
                    )
                    && route_hostnames.iter().any(|route_hostname| {
                        intersect_hostnames(
                            route_hostname.as_str(),
                            policy.hostname.as_deref().unwrap_or("*"),
                        )
                        .as_deref()
                            == Some(conflict_hostname)
                    });
                attaches.then(|| key.clone())
            })
            .collect();
        if attached.is_empty() {
            continue;
        }
        refs.entry(route_parent_ref_key_for_parent(object, parent_ref))
            .or_default()
            .extend(attached);
    }
    refs
}

fn route_parent_ref_key_for_parent(object: &K8sObject, parent_ref: &Value) -> String {
    let group = string_field(parent_ref, "group").unwrap_or("gateway.networking.k8s.io");
    let kind = string_field(parent_ref, "kind").unwrap_or("Gateway");
    let namespace = string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
    let name = string_field(parent_ref, "name").unwrap_or("*");
    let section = string_field(parent_ref, "sectionName").unwrap_or("*");
    let port = parent_ref
        .get("port")
        .and_then(Value::as_u64)
        .map_or_else(|| "*".to_string(), |port| port.to_string());
    format!("{group}/{kind}/{namespace}/{name}/{section}/{port}")
}

fn route_materialized_parent_ref_keys_for_namespace(
    object: &K8sObject,
    acc: &K8sAccumulator,
    namespace_filter: Option<&str>,
) -> Vec<String> {
    let mut refs = Vec::new();
    for parent_ref in object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        let parent_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        if namespace_filter.is_some_and(|filter| parent_namespace != filter) {
            continue;
        }
        if acc
            .gateway_api_listener_policies
            .iter()
            .any(|(key, policy)| {
                listener_key_matches_parent_ref(key, parent_namespace, parent_ref)
                    && parent_ref_matches_listener_policy(parent_ref, key, policy)
                    && route_listener_policy_materializes_route(
                        acc,
                        object,
                        parent_namespace,
                        policy,
                    )
            })
        {
            refs.push(route_parent_ref_key_for_parent(object, parent_ref));
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

fn l4_route_listener_bindings_for_namespace(
    object: &K8sObject,
    acc: &K8sAccumulator,
    namespace_filter: Option<&str>,
) -> Vec<(u16, Vec<String>)> {
    let requested_hostnames: Vec<String> = string_array(&object.spec, "hostnames")
        .into_iter()
        .map(|hostname| normalize_gateway_hostname(&hostname))
        .collect();
    let route_hostnames = hostnames_for_listener_intersection(&requested_hostnames);
    let mut bindings: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    for parent_ref in object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        let parent_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        if namespace_filter.is_some_and(|filter| parent_namespace != filter) {
            continue;
        }
        for (key, policy) in &acc.gateway_api_listener_policies {
            if listener_key_matches_parent_ref(key, parent_namespace, parent_ref)
                && parent_ref_matches_listener_policy(parent_ref, key, policy)
                && route_listener_policy_materializes_route(acc, object, parent_namespace, policy)
                && let Some(port) = policy.port.and_then(|port| u16::try_from(port).ok())
            {
                let hosts = bindings.entry(port).or_default();
                if object.kind == "TLSRoute" {
                    let listener_hostname = policy.hostname.as_deref().unwrap_or("*");
                    hosts.extend(route_hostnames.iter().filter_map(|route_hostname| {
                        intersect_hostnames(route_hostname, listener_hostname)
                    }));
                }
            }
        }
    }
    bindings
        .into_iter()
        .filter_map(|(port, mut hosts)| {
            hosts.sort();
            hosts.dedup();
            (object.kind != "TLSRoute" || !hosts.is_empty()).then_some((port, hosts))
        })
        .collect()
}

pub(crate) fn parse_k8s_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn compare_creation_timestamps(
    left: &Option<DateTime<Utc>>,
    right: &Option<DateTime<Utc>>,
) -> Ordering {
    match (left, right) {
        (Some(left_ts), Some(right_ts)) => left_ts.cmp(right_ts),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn compare_conflict_candidates(
    left: &GatewayApiRouteConflictCandidate,
    right: &GatewayApiRouteConflictCandidate,
) -> Ordering {
    compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp).then_with(
        || {
            (&left.resource.namespace, &left.resource.name)
                .cmp(&(&right.resource.namespace, &right.resource.name))
        },
    )
}

fn mesh_services_from_gateway(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<Vec<MeshService>, K8sTranslateError> {
    let mut services = Vec::new();
    object
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .try_for_each(|listener| {
            let listener_name = string_field(listener, "name").unwrap_or("listener");
            let listener_key = GatewayApiListenerKey {
                namespace: object.metadata.namespace.clone(),
                parent_kind: GatewayApiListenerParentKind::Gateway,
                gateway: object.metadata.name.clone(),
                listener: listener_name.to_string(),
            };
            // Snapshot the post-admission policy flags before we may push
            // warnings (which needs `&mut acc`).
            let Some((
                has_validation_error,
                materializable,
                requires_frontend_tls,
                routes_materializable,
            )) = acc
                .gateway_api_listener_policies
                .get(&listener_key)
                .map(|policy| {
                    (
                        policy.validation_error.is_some(),
                        policy.materializable,
                        policy.requires_frontend_tls,
                        policy.routes_materializable,
                    )
                })
            else {
                return Ok(());
            };
            if has_validation_error {
                return Ok(());
            }
            if !listener_protocol_mode_is_supported(listener) {
                acc.warnings.push(format!(
                    "Gateway API Gateway {}/{} listener {} uses unsupported protocol TLS with a non-Passthrough mode and will not be exposed",
                    object.metadata.namespace,
                    object.metadata.name,
                    listener_name
                ));
                return Ok(());
            }
            // Fail closed on the stored post-admission policy: same-port
            // physical refusal clears `materializable`, while hostname or
            // source-cap refusal clears `routes_materializable`. Re-checking
            // raw certificate resolution would re-admit a withdrawn listener.
            if !materializable {
                acc.warnings.push(format!(
                    "Gateway API Gateway {}/{} listener {} is not materializable and will not be exposed",
                    object.metadata.namespace,
                    object.metadata.name,
                    listener_name
                ));
                return Ok(());
            }
            if requires_frontend_tls && !routes_materializable {
                acc.warnings.push(format!(
                    "Gateway API Gateway {}/{} listener {} has no admitted frontend TLS source and will not be exposed",
                    object.metadata.namespace,
                    object.metadata.name,
                    listener_name
                ));
                return Ok(());
            }
            let Some(raw_port) = listener.get("port").and_then(Value::as_u64) else {
                return Ok(());
            };
            let port = port_from_u64(object, raw_port, "listeners[].port")?;
            let name = listener_name;
            services.push(MeshService {
                // Kind-scoped, length-prefixed identity — see
                // `gateway_api_listener_mesh_service_name`.
                name: super::gateway_api_listener_mesh_service_name(
                    GatewayApiListenerParentKind::Gateway,
                    &object.metadata.name,
                    name,
                ),
                namespace: object.metadata.namespace.clone(),
                ports: vec![ServicePort {
                    port,
                    protocol: app_protocol(string_field(listener, "protocol")),
                    name: Some(name.to_string()),
                    target_port: None,
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
                // Gateway listeners are not ClusterIP services; raw-TCP
                // egress VIP mapping does not apply to them.
                cluster_ips: Vec::new(),
            });
            acc.gateway_api_materialized_gateway_listeners
                .insert(listener_key);
            Ok::<(), K8sTranslateError>(())
        })?;
    Ok(services)
}

fn ensure_route_parent_refs_allowed(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<(), K8sTranslateError> {
    let Some(parent_refs) = object.spec.get("parentRefs").and_then(Value::as_array) else {
        return Ok(());
    };
    if parent_refs.is_empty() {
        return Ok(());
    }

    let mut saw_attachable_parent = false;
    let mut saw_allowed_parent = false;
    let mut first_error = None;
    for parent_ref in parent_refs {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        saw_attachable_parent = true;
        if let Some(error) = route_parent_ref_disallow_error(acc, object, parent_ref) {
            first_error.get_or_insert(error);
        } else {
            saw_allowed_parent = true;
        }
    }

    if saw_attachable_parent && !saw_allowed_parent {
        return Err(first_error.unwrap_or_else(|| {
            invalid_resource(
                object,
                format!(
                    "{} has no permitted Gateway or ListenerSet parentRefs",
                    object.kind
                ),
            )
        }));
    }

    Ok(())
}

#[allow(dead_code)] // Kept for callers that need the narrower ListenerSet predicate.
fn parent_ref_is_listenerset(parent_ref: &Value) -> bool {
    parent_ref_listener_parent_kind(parent_ref) == Some(GatewayApiListenerParentKind::ListenerSet)
}

fn parent_ref_is_attachable_parent(parent_ref: &Value) -> bool {
    parent_ref_listener_parent_kind(parent_ref).is_some()
}

fn parent_ref_listener_parent_kind(parent_ref: &Value) -> Option<GatewayApiListenerParentKind> {
    let parent_group = string_field(parent_ref, "group").unwrap_or("gateway.networking.k8s.io");
    if parent_group != "gateway.networking.k8s.io" {
        return None;
    }
    match string_field(parent_ref, "kind").unwrap_or("Gateway") {
        "Gateway" => Some(GatewayApiListenerParentKind::Gateway),
        "ListenerSet" => Some(GatewayApiListenerParentKind::ListenerSet),
        _ => None,
    }
}

fn listener_key_matches_parent_ref(
    key: &GatewayApiListenerKey,
    parent_namespace: &str,
    parent_ref: &Value,
) -> bool {
    let Some(parent_kind) = parent_ref_listener_parent_kind(parent_ref) else {
        return false;
    };
    let parent_name = string_field(parent_ref, "name").unwrap_or("*");
    key.parent_kind == parent_kind
        && key.namespace == parent_namespace
        && key.gateway == parent_name
}

fn route_parent_ref_disallow_error(
    acc: &K8sAccumulator,
    object: &K8sObject,
    parent_ref: &Value,
) -> Option<K8sTranslateError> {
    let parent_namespace =
        string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
    let parent_kind = parent_ref_listener_parent_kind(parent_ref)
        .map(|kind| kind.as_str())
        .unwrap_or("Gateway");
    let listener_match = gateway_parent_ref_listener_match(acc, parent_namespace, parent_ref);
    if parent_ref.get("sectionName").is_some() && listener_match != Some(true) {
        return Some(invalid_resource(
            object,
            format!(
                "{} parentRef does not match any known {parent_kind} listener in namespace '{}'",
                object.kind, parent_namespace
            ),
        ));
    }
    if parent_ref.get("port").is_some() && listener_match == Some(false) {
        return Some(invalid_resource(
            object,
            format!(
                "{} parentRef does not match any known {parent_kind} listener in namespace '{}'",
                object.kind, parent_namespace
            ),
        ));
    }
    if !route_namespace_allowed_by_listener(acc, object, parent_namespace, parent_ref) {
        return Some(invalid_resource(
            object,
            format!(
                "{} parentRef.namespace '{}' is not permitted by the target {parent_kind} listener",
                object.kind, parent_namespace
            ),
        ));
    }
    None
}

fn gateway_parent_ref_listener_match(
    acc: &K8sAccumulator,
    parent_namespace: &str,
    parent_ref: &Value,
) -> Option<bool> {
    let mut saw_parent = false;
    for (key, policy) in &acc.gateway_api_listener_policies {
        if !listener_key_matches_parent_ref(key, parent_namespace, parent_ref) {
            continue;
        }
        saw_parent = true;
        if parent_ref_matches_listener_policy(parent_ref, key, policy) {
            return Some(true);
        }
    }
    saw_parent.then_some(false)
}

fn route_namespace_allowed_by_listener(
    acc: &K8sAccumulator,
    route: &K8sObject,
    parent_namespace: &str,
    parent_ref: &Value,
) -> bool {
    let Some(parent_kind) = parent_ref_listener_parent_kind(parent_ref) else {
        return false;
    };
    if let Some(listener_name) = string_field(parent_ref, "sectionName") {
        let Some(policy) = acc
            .gateway_api_listener_policies
            .get(&GatewayApiListenerKey {
                namespace: parent_namespace.to_string(),
                parent_kind,
                gateway: string_field(parent_ref, "name").unwrap_or("*").to_string(),
                listener: listener_name.to_string(),
            })
        else {
            return false;
        };
        return route_listener_policy_allows_route(acc, route, parent_namespace, policy);
    }
    let mut saw_listener = false;
    for (key, policy) in &acc.gateway_api_listener_policies {
        if listener_key_matches_parent_ref(key, parent_namespace, parent_ref) {
            saw_listener = true;
            if route_listener_policy_allows_route(acc, route, parent_namespace, policy) {
                return true;
            }
        }
    }
    // A ListenerSet whose attachment was rejected (for example by the parent
    // Gateway's allowedListeners policy) deliberately publishes no listener
    // policies. Do not let the legacy same-namespace fallback turn that absence
    // into permission for a Route parentRef.
    if !saw_listener && parent_kind == GatewayApiListenerParentKind::ListenerSet {
        return false;
    }
    !saw_listener && route.metadata.namespace == parent_namespace
}

fn route_listener_policy_allows_route(
    acc: &K8sAccumulator,
    route: &K8sObject,
    parent_namespace: &str,
    policy: &GatewayApiListenerPolicy,
) -> bool {
    policy.route_kinds.contains(route.kind.as_str())
        && route_namespace_matches_policy(acc, route, parent_namespace, policy)
}

fn route_listener_policy_materializes_route(
    acc: &K8sAccumulator,
    route: &K8sObject,
    parent_namespace: &str,
    policy: &GatewayApiListenerPolicy,
) -> bool {
    policy.routes_materializable
        && route_listener_policy_allows_route(acc, route, parent_namespace, policy)
}

fn route_namespace_matches_policy(
    acc: &K8sAccumulator,
    route: &K8sObject,
    parent_namespace: &str,
    policy: &GatewayApiListenerPolicy,
) -> bool {
    match &policy.namespaces {
        GatewayApiAllowedRoutesNamespaces::Same => route.metadata.namespace == parent_namespace,
        GatewayApiAllowedRoutesNamespaces::All => true,
        GatewayApiAllowedRoutesNamespaces::Selector(selector) => acc
            .namespace_labels
            .get(&route.metadata.namespace)
            .is_some_and(|labels| namespace_selector_matches(labels, selector)),
        GatewayApiAllowedRoutesNamespaces::Invalid => false,
    }
}

pub(crate) fn namespace_selector_matches(
    labels: &HashMap<String, String>,
    selector: &GatewayApiNamespaceSelector,
) -> bool {
    selector
        .match_labels
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
        && selector
            .match_expressions
            .iter()
            .all(|expression| namespace_selector_expression_matches(labels, expression))
}

fn namespace_selector_expression_matches(
    labels: &HashMap<String, String>,
    expression: &GatewayApiNamespaceSelectorExpression,
) -> bool {
    match expression.operator {
        GatewayApiNamespaceSelectorOperator::In => labels
            .get(&expression.key)
            .is_some_and(|value| expression.values.iter().any(|allowed| allowed == value)),
        GatewayApiNamespaceSelectorOperator::NotIn => labels
            .get(&expression.key)
            .is_none_or(|value| expression.values.iter().all(|blocked| blocked != value)),
        GatewayApiNamespaceSelectorOperator::Exists => labels.contains_key(&expression.key),
        GatewayApiNamespaceSelectorOperator::DoesNotExist => !labels.contains_key(&expression.key),
    }
}

fn route_materialization_namespaces(object: &K8sObject, acc: &K8sAccumulator) -> Vec<String> {
    let mut saw_attachable_parent = false;
    let mut saw_known_parent_listener = false;
    let mut saw_section_name_parent = false;
    let mut namespaces = Vec::new();
    for parent_ref in object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        saw_attachable_parent = true;
        saw_section_name_parent |= parent_ref.get("sectionName").is_some();
        let parent_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        for (key, policy) in &acc.gateway_api_listener_policies {
            if listener_key_matches_parent_ref(key, parent_namespace, parent_ref)
                && parent_ref_matches_listener_policy(parent_ref, key, policy)
            {
                saw_known_parent_listener = true;
                if route_listener_policy_materializes_route(acc, object, parent_namespace, policy) {
                    namespaces.push(parent_namespace.to_string());
                }
            }
        }
    }
    namespaces.sort();
    namespaces.dedup();
    if namespaces.is_empty()
        && (!saw_attachable_parent || (!saw_known_parent_listener && !saw_section_name_parent))
    {
        namespaces.push(object.metadata.namespace.clone());
    }
    namespaces
}

fn route_effective_hostnames(
    object: &K8sObject,
    acc: &K8sAccumulator,
    requested_hostnames: &[String],
    parent_namespace_filter: Option<&str>,
) -> Option<Vec<String>> {
    let route_hostnames = hostnames_for_listener_intersection(requested_hostnames);
    let mut saw_matching_listener = false;
    let mut effective = Vec::new();

    for parent_ref in object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        let Some(_parent_name) = string_field(parent_ref, "name") else {
            continue;
        };
        let gateway_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        if parent_namespace_filter.is_some_and(|namespace| namespace != gateway_namespace) {
            continue;
        }

        for (key, policy) in &acc.gateway_api_listener_policies {
            if !listener_key_matches_parent_ref(key, gateway_namespace, parent_ref)
                || !parent_ref_matches_listener_policy(parent_ref, key, policy)
                || !route_listener_policy_materializes_route(acc, object, gateway_namespace, policy)
            {
                continue;
            }
            saw_matching_listener = true;
            let listener_hostname = policy.hostname.as_deref().unwrap_or("*");
            for route_hostname in &route_hostnames {
                if let Some(hostname) =
                    intersect_hostnames(route_hostname.as_str(), listener_hostname)
                {
                    effective.push(hostname);
                }
            }
        }
    }

    if !saw_matching_listener {
        return Some(requested_hostnames.to_vec());
    }
    if effective.iter().any(|hostname| hostname == "*") {
        return Some(Vec::new());
    }
    effective.sort();
    effective.dedup();
    if effective.is_empty() {
        None
    } else {
        Some(effective)
    }
}

fn route_redirect_default_listener_port(
    object: &K8sObject,
    acc: &K8sAccumulator,
    requested_hostnames: &[String],
    parent_namespace_filter: Option<&str>,
) -> Option<u16> {
    let route_hostnames = hostnames_for_listener_intersection(requested_hostnames);
    let mut ports = HashSet::new();

    for parent_ref in object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !parent_ref_is_attachable_parent(parent_ref) {
            continue;
        }
        let Some(_gateway_name) = string_field(parent_ref, "name") else {
            continue;
        };
        let gateway_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        if parent_namespace_filter.is_some_and(|namespace| namespace != gateway_namespace) {
            continue;
        }

        for (key, policy) in &acc.gateway_api_listener_policies {
            if !listener_key_matches_parent_ref(key, gateway_namespace, parent_ref)
                || !parent_ref_matches_listener_policy(parent_ref, key, policy)
                || !route_listener_policy_materializes_route(acc, object, gateway_namespace, policy)
            {
                continue;
            }
            let listener_hostname = policy.hostname.as_deref().unwrap_or("*");
            if !route_hostnames.iter().any(|route_hostname| {
                intersect_hostnames(route_hostname.as_str(), listener_hostname).is_some()
            }) {
                continue;
            }
            if let Some(port) = policy.port.and_then(|port| u16::try_from(port).ok()) {
                ports.insert(port);
            }
        }
    }

    let mut iter = ports.into_iter();
    let port = iter.next()?;
    iter.next().is_none().then_some(port)
}

fn parent_ref_matches_listener_policy(
    parent_ref: &Value,
    key: &GatewayApiListenerKey,
    policy: &GatewayApiListenerPolicy,
) -> bool {
    if let Some(section_name) = string_field(parent_ref, "sectionName")
        && section_name != key.listener
    {
        return false;
    }
    if let Some(parent_port) = parent_ref.get("port").and_then(Value::as_u64)
        && policy.port != Some(parent_port)
    {
        return false;
    }
    true
}

fn hostnames_for_listener_intersection(requested_hostnames: &[String]) -> Vec<String> {
    if requested_hostnames.is_empty() {
        vec!["*".to_string()]
    } else {
        requested_hostnames.to_vec()
    }
}

fn conflict_hostnames_for_proxy_hosts(proxy_hosts: &[String]) -> Vec<String> {
    if proxy_hosts.is_empty() {
        vec!["*".to_string()]
    } else {
        proxy_hosts.to_vec()
    }
}

pub(crate) fn normalize_gateway_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Gateway API `SectionName` grammar (pinned v1.5.1 shared_types.go).
pub(crate) fn gateway_api_section_name_is_valid(name: &str) -> bool {
    valid_kubernetes_dns_subdomain(name)
}

/// Gateway API `Hostname` grammar (pinned v1.5.1 shared_types.go).
///
/// Allows an optional single leading `*.` wildcard label, then a DNS1123
/// subdomain. IP literals are never valid Hostnames.
pub(crate) fn gateway_api_hostname_is_valid(hostname: &str) -> bool {
    let hostname = normalize_gateway_hostname(hostname);
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let rest = match hostname.strip_prefix("*.") {
        Some(rest) => rest,
        None if hostname.contains('*') => return false,
        None => hostname.as_str(),
    };
    valid_kubernetes_dns_subdomain(rest)
}

/// Whether `protocol` is a pinned Gateway API `ProtocolType` value.
pub(crate) fn gateway_api_protocol_type_is_known(protocol: &str) -> bool {
    matches!(
        protocol.to_ascii_uppercase().as_str(),
        "HTTP" | "HTTPS" | "TLS" | "TCP" | "UDP"
    )
}

/// Bounded ListenerSet listener core-shape validation (pinned v1.5.1
/// `apis/v1/listenerset_types.go` ListenerEntry + XValidation).
///
/// Field paths are static so diagnostics never echo hostile input. Callers must
/// not silently default missing `name` / `protocol` / `port`.
pub(crate) fn validate_listenerset_listener_entry(
    listener: &Value,
) -> Result<(), GatewayApiListenerValidationError> {
    let Some(name) = string_field(listener, "name") else {
        return Err(listener_validation_error(
            "spec.listeners[].name",
            "is required",
        ));
    };
    if name.is_empty() || !gateway_api_section_name_is_valid(name) {
        return Err(listener_validation_error(
            "spec.listeners[].name",
            "must be a nonempty valid SectionName",
        ));
    }

    let Some(port) = listener.get("port") else {
        return Err(listener_validation_error(
            "spec.listeners[].port",
            "is required",
        ));
    };
    let Some(port) = port.as_u64() else {
        return Err(listener_validation_error(
            "spec.listeners[].port",
            "must be an integer between 1 and 65535",
        ));
    };
    if port == 0 || port > u16::MAX as u64 {
        return Err(listener_validation_error(
            "spec.listeners[].port",
            "must be an integer between 1 and 65535",
        ));
    }

    let Some(protocol) = string_field(listener, "protocol") else {
        return Err(listener_validation_error(
            "spec.listeners[].protocol",
            "is required",
        ));
    };
    if !gateway_api_protocol_type_is_known(protocol) {
        return Err(listener_validation_error(
            "spec.listeners[].protocol",
            "must be one of HTTP, HTTPS, TLS, TCP, or UDP",
        ));
    }
    let protocol = protocol.to_ascii_uppercase();

    if let Some(hostname) = listener.get("hostname") {
        let Some(hostname) = hostname.as_str() else {
            return Err(listener_validation_error(
                "spec.listeners[].hostname",
                "must be a string Hostname",
            ));
        };
        if protocol == "TCP" || protocol == "UDP" {
            if !hostname.is_empty() {
                return Err(listener_validation_error(
                    "spec.listeners[].hostname",
                    "must not be specified for protocols TCP or UDP",
                ));
            }
        } else if !hostname.is_empty() && !gateway_api_hostname_is_valid(hostname) {
            return Err(listener_validation_error(
                "spec.listeners[].hostname",
                "must be a valid Gateway API Hostname",
            ));
        }
    }

    let tls = listener.get("tls");
    match protocol.as_str() {
        "HTTP" | "TCP" | "UDP" => {
            if tls.is_some() {
                return Err(listener_validation_error(
                    "spec.listeners[].tls",
                    "must not be specified for protocols HTTP, TCP, or UDP",
                ));
            }
        }
        "HTTPS" => {
            let Some(tls) = tls else {
                return Err(listener_validation_error(
                    "spec.listeners[].tls",
                    "is required for protocol HTTPS",
                ));
            };
            if let Some(mode) = string_field(tls, "mode")
                && !mode.is_empty()
                && !mode.eq_ignore_ascii_case("Terminate")
            {
                return Err(listener_validation_error(
                    "spec.listeners[].tls.mode",
                    "must be Terminate for protocol HTTPS",
                ));
            }
        }
        "TLS" => {
            let Some(tls) = tls else {
                return Err(listener_validation_error(
                    "spec.listeners[].tls",
                    "is required for protocol TLS",
                ));
            };
            match string_field(tls, "mode") {
                None | Some("") => {
                    return Err(listener_validation_error(
                        "spec.listeners[].tls.mode",
                        "must be set for protocol TLS",
                    ));
                }
                Some(_) => {}
            }
        }
        _ => {}
    }

    allowed_route_namespaces(listener).map(|_| ())
}

fn intersect_hostnames(route_hostname: &str, listener_hostname: &str) -> Option<String> {
    if route_hostname == "*" {
        return Some(listener_hostname.to_string());
    }
    if listener_hostname == "*" {
        return Some(route_hostname.to_string());
    }
    match (
        wildcard_hostname_suffix(route_hostname),
        wildcard_hostname_suffix(listener_hostname),
    ) {
        (None, None) => (route_hostname == listener_hostname).then(|| route_hostname.to_string()),
        (Some(route_suffix), None) => hostname_matches_wildcard(listener_hostname, route_suffix)
            .then(|| listener_hostname.to_string()),
        (None, Some(listener_suffix)) => hostname_matches_wildcard(route_hostname, listener_suffix)
            .then(|| route_hostname.to_string()),
        (Some(route_suffix), Some(listener_suffix)) => {
            if route_suffix == listener_suffix || suffix_is_within(route_suffix, listener_suffix) {
                Some(route_hostname.to_string())
            } else if suffix_is_within(listener_suffix, route_suffix) {
                Some(listener_hostname.to_string())
            } else {
                None
            }
        }
    }
}

fn wildcard_hostname_suffix(hostname: &str) -> Option<&str> {
    hostname.strip_prefix("*.")
}

fn hostname_matches_wildcard(hostname: &str, suffix: &str) -> bool {
    hostname != suffix && suffix_is_within(hostname, suffix)
}

fn suffix_is_within(hostname: &str, suffix: &str) -> bool {
    hostname
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn resource_suffix_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn route_scoped_suffix(
    route_kind: &str,
    rule_index: usize,
    match_index: Option<usize>,
    namespace_suffix: Option<&str>,
) -> String {
    match (match_index, namespace_suffix) {
        (Some(match_index), Some(namespace_suffix)) => {
            format!("{route_kind}-{rule_index}-{match_index}-{namespace_suffix}")
        }
        (Some(match_index), None) => format!("{route_kind}-{rule_index}-{match_index}"),
        (None, Some(namespace_suffix)) => format!("{route_kind}-{rule_index}-{namespace_suffix}"),
        (None, None) => format!("{route_kind}-{rule_index}"),
    }
}

/// Emit one field-specific warning per GRPCRoute match Ferrum refuses to
/// represent. The match itself is dropped fail-closed by
/// `route_match_descriptor_for_entry`; this makes the drop visible to
/// operators instead of leaving a rule silently inert.
fn warn_unrepresentable_grpc_route_matches(object: &K8sObject, acc: &mut K8sAccumulator) {
    if object.kind != "GRPCRoute" {
        return;
    }
    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(matches_value) = rule.get("matches") else {
            continue;
        };
        let Some(matches) = matches_value.as_array() else {
            acc.warnings.push(format!(
                "GRPCRoute {}/{} rules[{rule_index}].matches dropped fail-closed: matches must \
                 be an array",
                object.metadata.namespace, object.metadata.name
            ));
            continue;
        };
        for (match_index, entry) in matches.iter().enumerate() {
            if let Err(reason) = grpc_route_match(entry) {
                acc.warnings.push(format!(
                    "GRPCRoute {}/{} rules[{rule_index}].matches[{match_index}] dropped \
                     fail-closed: {reason}",
                    object.metadata.namespace, object.metadata.name
                ));
            }
        }
    }
}

type HttpRouteResources = (Vec<Proxy>, Vec<PluginConfig>);

fn http_route_resources(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<HttpRouteResources, K8sTranslateError> {
    ensure_route_parent_refs_allowed(object, acc)?;
    let requested_hostnames: Vec<String> = string_array(&object.spec, "hostnames")
        .into_iter()
        .map(|hostname| normalize_gateway_hostname(&hostname))
        .collect();
    let route_family = object.kind.to_ascii_lowercase();
    let config_namespaces = route_materialization_namespaces(object, acc);
    let losing_conflict_keys: HashSet<GatewayApiRouteConflictKey> = acc
        .gateway_api_conflict_losers
        .get(&K8sResourceKey::from_object(object))
        .into_iter()
        .flat_map(|conflicts| conflicts.iter().map(|conflict| conflict.key.clone()))
        .collect();
    let route_kind = object.kind.to_ascii_lowercase();
    warn_unrepresentable_grpc_route_matches(object, acc);
    let mut proxies = Vec::new();
    let mut plugins = Vec::new();

    for config_namespace in &config_namespaces {
        let parent_refs =
            route_allowed_parent_ref_keys_for_namespace(object, acc, Some(config_namespace));
        if parent_refs.is_empty() {
            continue;
        }
        let materialized_parent_refs =
            route_materialized_parent_ref_keys_for_namespace(object, acc, Some(config_namespace));
        let proxies_before_namespace = proxies.len();
        let Some(hostnames) = route_effective_hostnames(
            object,
            acc,
            &requested_hostnames,
            Some(config_namespace.as_str()),
        ) else {
            continue;
        };
        let conflict_hostnames = conflict_hostnames_for_proxy_hosts(&hostnames);
        let route_namespace_suffix = (config_namespaces.len() > 1)
            .then(|| format!("ns-{}", resource_suffix_component(config_namespace)));
        let default_redirect_port = route_redirect_default_listener_port(
            object,
            acc,
            &requested_hostnames,
            Some(config_namespace.as_str()),
        );

        for (rule_index, rule) in object
            .spec
            .get("rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let entry_descriptors = route_match_entry_descriptors(object, rule);
            let descriptors = dedup_route_match_descriptors(
                entry_descriptors
                    .iter()
                    .map(|entry| entry.descriptor.clone())
                    .collect(),
            );
            if descriptors.is_empty() {
                continue;
            }
            let mut match_paths: Vec<String> = descriptors
                .iter()
                .map(|descriptor| descriptor.listen_path.clone())
                .collect();
            match_paths.sort();
            match_paths.dedup();

            let request_transform = gateway_request_header_modifier_rules(rule);
            let redirect = gateway_request_redirect_value(object, rule, default_redirect_port)?;
            let mut backend_resolution = route_backends(object, rule, acc)?;
            let backend_tls_policy = super::backend_tls_policy::resolve_backends_tls_policy(
                acc,
                &backend_resolution.backends,
            );
            let backend_tls_overlay = match backend_tls_policy {
                super::backend_tls_policy::BackendTlsPolicyLookup::None => None,
                super::backend_tls_policy::BackendTlsPolicyLookup::Apply(overlay) => Some(overlay),
                super::backend_tls_policy::BackendTlsPolicyLookup::Fault { .. } => {
                    // Fail closed: drop backends and force an HTTP 500 fault so
                    // traffic never reaches a Service under a broken TLS policy.
                    let fault_weight = backend_resolution
                        .backends
                        .iter()
                        .fold(0u32, |sum, backend| sum.saturating_add(backend.weight));
                    backend_resolution.invalid_weight = backend_resolution
                        .invalid_weight
                        .saturating_add(fault_weight);
                    backend_resolution.valid_weight = 0;
                    backend_resolution.backends.clear();
                    backend_resolution
                        .fault_reason
                        .get_or_insert(BackendRefFaultReason::InvalidBackendTlsPolicy);
                    None
                }
            };
            let session_persistence = resolve_rule_session_persistence(
                object,
                rule,
                rule_index,
                &backend_resolution.backends,
                acc,
            )?;
            let backend_ref_fault = backend_resolution.fault_reason.map(|reason| {
                backend_ref_fault_value_with_percentage(
                    reason,
                    backend_ref_fault_percentage(
                        backend_resolution.valid_weight,
                        backend_resolution.invalid_weight,
                    ),
                )
            });
            let has_route_actions =
                !request_transform.is_empty() || redirect.is_some() || backend_ref_fault.is_some();

            let (
                backend_host,
                backend_port,
                upstream_id,
                mut pending_upstream,
                requires_node_waypoint_authz,
                backend_scheme,
            ) = if backend_resolution.backends.is_empty() {
                if !has_only_zero_weight_backend_refs(rule) && !has_route_actions {
                    continue;
                }
                (
                    ZERO_WEIGHT_BACKEND_HOST.to_string(),
                    ZERO_WEIGHT_BACKEND_PORT,
                    None,
                    None,
                    false,
                    BackendScheme::Http,
                )
            } else if backend_resolution.backends.len() == 1
                && backend_tls_overlay.is_none()
                && session_persistence.is_none()
            {
                let Some(backend) = backend_resolution.backends.into_iter().next() else {
                    continue;
                };
                let requires_node_waypoint_authz =
                    route_backends_require_node_waypoint_authz(std::slice::from_ref(&backend));
                (
                    backend.host,
                    backend.port,
                    None,
                    None,
                    requires_node_waypoint_authz,
                    BackendScheme::Http,
                )
            } else {
                // Multi-backend rules, BackendTLSPolicy overlays, and session
                // persistence use an Upstream so SNI/SAN/CA and sticky cookies
                // can be projected (direct proxies have no serialized
                // backend_tls_sni field).
                let requires_node_waypoint_authz =
                    route_backends_require_node_waypoint_authz(&backend_resolution.backends);
                let route_suffix = route_scoped_suffix(
                    &route_kind,
                    rule_index,
                    None,
                    route_namespace_suffix.as_deref(),
                );
                let upstream_id = resource_id(
                    "gwapi-route-upstream",
                    &object.metadata.namespace,
                    &object.metadata.name,
                    &route_suffix,
                );
                let mut upstream = upstream_for_route_with_session(
                    upstream_id.clone(),
                    config_namespace.clone(),
                    backend_resolution.backends,
                    session_persistence.as_ref(),
                );
                let backend_scheme = if let Some(overlay) = backend_tls_overlay.as_ref() {
                    super::backend_tls_policy::apply_to_upstream(&mut upstream, overlay);
                    BackendScheme::Https
                } else {
                    BackendScheme::Http
                };
                (
                    String::new(),
                    0,
                    Some(upstream_id),
                    Some(upstream),
                    requires_node_waypoint_authz,
                    backend_scheme,
                )
            };

            let match_count = match_paths.len();
            for (match_index, listen_path) in match_paths.into_iter().enumerate() {
                let entry_descriptors_for_path: Vec<_> = entry_descriptors
                    .iter()
                    .filter(|entry| entry.descriptor.listen_path == listen_path)
                    .cloned()
                    .collect();
                let descriptors_for_path = dedup_route_match_descriptors(
                    entry_descriptors_for_path
                        .iter()
                        .map(|entry| entry.descriptor.clone())
                        .collect(),
                );
                let host_scopes = route_host_scopes_for_path(RouteHostScopeInputs {
                    object,
                    acc,
                    spec_hostnames: &hostnames,
                    conflict_hostnames: &conflict_hostnames,
                    requested_hostnames: &requested_hostnames,
                    config_namespace,
                    route_family: &route_family,
                    descriptors_for_path: &descriptors_for_path,
                    losing_conflict_keys: &losing_conflict_keys,
                });
                if host_scopes.is_empty() {
                    continue;
                }
                if let Some(upstream) = pending_upstream.take() {
                    acc.upsert_upstream(upstream);
                }
                let suffix = route_scoped_suffix(
                    &route_kind,
                    rule_index,
                    (match_count > 1).then_some(match_index),
                    route_namespace_suffix.as_deref(),
                );

                for host_scope in host_scopes {
                    let scoped_suffix = host_scope.suffix.as_ref().map_or_else(
                        || suffix.clone(),
                        |host_suffix| format!("{suffix}-{host_suffix}"),
                    );
                    let proxy_id = resource_id(
                        "gwapi-route",
                        &object.metadata.namespace,
                        &object.metadata.name,
                        &scoped_suffix,
                    );
                    // TLS class comes from *this* scope's own listener policy.
                    // Scanning every policy for a matching port would let an
                    // unrelated HTTPS listener on the same number mark a
                    // plaintext claim TLS-scoped.
                    if let Some(port) = host_scope.listen_port
                        && host_scope.requires_tls
                    {
                        acc.config
                            .http_tls_listen_ports
                            .insert((config_namespace.clone(), port));
                    }
                    // Record the exact admitting listener for this proxy id
                    // BEFORE it reaches `upsert_http_route_resources`, so the
                    // same-kind merge decision can compare listener identity
                    // for both the candidate and any existing sibling instead
                    // of collapsing them by numeric port.
                    if let Some(key) = namespaced_resource_key(config_namespace, proxy_id.as_str())
                    {
                        acc.gateway_api_route_proxy_listeners
                            .insert(key.clone(), host_scope.listener.clone());
                        // Recorded from the same scope, so a refused slot can
                        // withdraw exactly the `(route, parentRef, listener)`
                        // claims it takes down — and no sibling claim.
                        acc.record_gateway_api_route_proxy_attachments(
                            key,
                            object,
                            &host_scope.parent_refs,
                            host_scope.listener.as_ref(),
                        );
                    }
                    let mut proxy = proxy_for_route(RouteProxySpec {
                        id: proxy_id.clone(),
                        namespace: config_namespace.clone(),
                        hosts: host_scope.proxy_hosts,
                        listen_path: Some(listen_path.clone()),
                        strip_listen_path: false,
                        preserve_host_header: true,
                        backend_host: backend_host.clone(),
                        backend_port,
                        upstream_id: upstream_id.clone(),
                        backend_scheme,
                        listen_port: host_scope.listen_port,
                        retry: None,
                        backend_read_timeout_ms: None,
                    });

                    if matches!(object.kind.as_str(), "HTTPRoute" | "GRPCRoute") {
                        let skipped_descriptors = skipped_descriptors_for_host(
                            &host_scope.parent_refs,
                            &route_family,
                            &host_scope.conflict_hostname,
                            host_scope.listener.as_ref(),
                            &descriptors_for_path,
                            &losing_conflict_keys,
                        );
                        let (rules, has_path_only_match) = http_route_dispatch_rules_for_proxy(
                            object,
                            rule,
                            rule_index,
                            Some(listen_path.as_str()),
                            MeshRouteDispatchDestination {
                                backend_host: backend_host.as_str(),
                                backend_port,
                                upstream_id: upstream_id.as_deref(),
                                requires_node_waypoint_authz,
                            },
                            &skipped_descriptors,
                            &entry_descriptors_for_path,
                            &request_transform,
                            redirect.as_ref(),
                            backend_ref_fault.as_ref(),
                        );
                        let rules_have_request_transform =
                            dispatch_rules_carry_field(&rules, "request_transform");
                        if let Some(mut plugin) = mesh_route_dispatch_plugin_from_rules(
                            &proxy_id,
                            config_namespace,
                            rules,
                            !has_path_only_match,
                        ) {
                            sort_dispatch_rules(&mut plugin);
                            let mut route_plugins = Vec::new();
                            if rules_have_request_transform {
                                route_plugins.push(route_request_transformer_plugin_for_proxy(
                                    &proxy_id,
                                    config_namespace,
                                ));
                            }
                            route_plugins.push(plugin);
                            attach_route_plugins_to_proxy(&mut proxy, &route_plugins);
                            plugins.extend(route_plugins);
                        }
                    }

                    proxies.push(proxy);
                }
            }
        }
        if proxies.len() > proxies_before_namespace {
            for parent_ref in materialized_parent_refs {
                acc.record_gateway_api_materialized_route_parent(object, parent_ref);
            }
        }
    }

    Ok((proxies, plugins))
}

struct RouteHostScopeInputs<'a> {
    object: &'a K8sObject,
    acc: &'a K8sAccumulator,
    spec_hostnames: &'a [String],
    conflict_hostnames: &'a [String],
    requested_hostnames: &'a [String],
    config_namespace: &'a str,
    route_family: &'a str,
    descriptors_for_path: &'a [RouteMatchDescriptor],
    losing_conflict_keys: &'a HashSet<GatewayApiRouteConflictKey>,
}

fn route_host_scopes_for_path(inputs: RouteHostScopeInputs<'_>) -> Vec<RouteHostScope> {
    let RouteHostScopeInputs {
        object,
        acc,
        spec_hostnames,
        conflict_hostnames,
        requested_hostnames,
        config_namespace,
        route_family,
        descriptors_for_path,
        losing_conflict_keys,
    } = inputs;
    let mut scopes = Vec::new();
    for (host_index, hostname) in conflict_hostnames.iter().enumerate() {
        // Keep only references that actually resolved a concrete listener.
        // An entry with an EMPTY listener set is not a materializable claim:
        // iterating it below would emit no scope. Declared Gateway parents in
        // that state fail closed below; only the parentless legacy shape keeps
        // a listener-less, port-agnostic claim.
        let resolved: Vec<(String, BTreeSet<GatewayApiListenerKey>)> =
            route_allowed_parent_listeners_for_hostname(
                object,
                acc,
                requested_hostnames,
                Some(config_namespace),
                hostname,
            )
            .into_iter()
            .filter(|(_, listener_keys)| !listener_keys.is_empty())
            .collect();
        if resolved.is_empty() {
            // A declared Gateway parentRef that resolves no concrete,
            // materializable listener must emit nothing — no proxy, upstream,
            // plugin, or materialized-parent record for that parent. Falling
            // back to a listener-less claim would expose the backend on
            // unrelated frontends while status correctly reports
            // NoMatchingParent / NotAllowedByListeners. Same rule for an
            // absent Gateway and for sectionName/port/policy gates that clear
            // no listener.
            if route_declares_gateway_parent_ref(object) {
                continue;
            }
            // Parentless legacy shape only: keep a listener-less, port-agnostic
            // claim. Do not broaden this into removal of that compatibility
            // surface.
            let parent_refs = route_allowed_parent_ref_keys_for_hostname(
                object,
                acc,
                requested_hostnames,
                Some(config_namespace),
                hostname,
            );
            if parent_refs.is_empty() {
                continue;
            }
            let has_surviving_match = descriptors_for_path.iter().any(|descriptor| {
                !descriptor_conflicts_for_host(
                    &parent_refs,
                    route_family,
                    hostname,
                    descriptor,
                    None,
                    losing_conflict_keys,
                )
            });
            if !has_surviving_match {
                continue;
            }
            scopes.push(RouteHostScope {
                proxy_hosts: proxy_hosts_for_conflict_hostname(spec_hostnames, hostname),
                conflict_hostname: hostname.clone(),
                parent_refs,
                listener: None,
                listen_port: None,
                requires_tls: false,
                suffix: Some(format!("host{host_index}")),
            });
            continue;
        }

        // Group by the RESOLVED LISTENER, not by parentRef. The materialized
        // proxy id is keyed by `(hostname, listener)`, so two parentRef
        // selectors that name the *same* listener — `{name: edge}` beside
        // `{name: edge, sectionName: http}`, or a `sectionName` and a `port`
        // reference to one listener — would otherwise emit two scopes carrying
        // an identical id. The duplicate re-enters `merge_http_route_proxy`
        // with no plugins of its own (the first copy already claimed them),
        // which clears `reject_unmatched` on the surviving dispatch plugin and
        // serves every non-matching request on that host+path to the default
        // backend — a fail-open on header/method/query match predicates.
        //
        // One scope per listener carrying every parentRef that resolved it is
        // both the correct claim and the correct attachment record. Cross-kind
        // arbitration decides losses per `(route, listener)`, so every parentRef
        // in one group always agrees about a loss on that listener.
        let mut by_listener: BTreeMap<GatewayApiListenerKey, Vec<String>> = BTreeMap::new();
        for (parent_ref, listener_keys) in resolved {
            for listener_key in listener_keys {
                by_listener
                    .entry(listener_key)
                    .or_default()
                    .push(parent_ref.clone());
            }
        }
        for (listener_key, parent_refs) in by_listener {
            let has_surviving_match = descriptors_for_path.iter().any(|descriptor| {
                !descriptor_conflicts_for_host(
                    &parent_refs,
                    route_family,
                    hostname,
                    descriptor,
                    Some(&listener_key),
                    losing_conflict_keys,
                )
            });
            if !has_surviving_match {
                continue;
            }
            // The suffix carries the listener identity, not just its port:
            // two Gateways can expose same-named hostnames on one port, and
            // a port-only suffix would collide their proxy IDs.
            let listener_suffix = listener_id_suffix(&listener_key);
            scopes.push(RouteHostScope {
                proxy_hosts: proxy_hosts_for_conflict_hostname(spec_hostnames, hostname),
                conflict_hostname: hostname.clone(),
                parent_refs,
                listen_port: listener_policy_port(acc, &listener_key),
                requires_tls: listener_policy_requires_tls(acc, &listener_key),
                listener: Some(listener_key),
                suffix: Some(format!("host{host_index}-{listener_suffix}")),
            });
        }
    }

    // Collapse scopes that resolved to the same listener claim; keep stable order.
    scopes.sort_by(|left, right| {
        (
            &left.conflict_hostname,
            &left.listener,
            &left.parent_refs,
            &left.suffix,
        )
            .cmp(&(
                &right.conflict_hostname,
                &right.listener,
                &right.parent_refs,
                &right.suffix,
            ))
    });
    scopes.dedup_by(|left, right| {
        left.proxy_hosts == right.proxy_hosts
            && left.listener == right.listener
            && left.parent_refs == right.parent_refs
            && left.conflict_hostname == right.conflict_hostname
    });

    // Single-scope routes omit the host/listener suffix for stable proxy IDs.
    if scopes.len() == 1 {
        scopes[0].suffix = None;
    }
    scopes
}

/// A stable, ID-safe, collision-resistant token for one listener, used to keep
/// generated proxy IDs distinct across listeners that share a numeric port.
///
/// A sanitized name is not sufficient: valid Gateway names `edge.a` and
/// `edge-a` both become `edge-a` when projected into Ferrum resource IDs. Bind
/// the token to the full namespace/Gateway/listener identity instead.
fn listener_id_suffix(key: &GatewayApiListenerKey) -> String {
    let identity = format!("{}|{}|{}", key.namespace, key.gateway, key.listener);
    let digest = hex::encode(crate::fips::approved::Sha256::digest(identity.as_bytes()));
    const LISTENER_SUFFIX_LEN: usize = 16;
    format!("listener-{}", &digest[..LISTENER_SUFFIX_LEN])
}

fn proxy_hosts_for_conflict_hostname(spec_hostnames: &[String], hostname: &str) -> Vec<String> {
    if spec_hostnames.is_empty() && hostname == "*" {
        Vec::new()
    } else {
        vec![hostname.to_string()]
    }
}

fn skipped_descriptors_for_host(
    parent_refs: &[String],
    route_family: &str,
    hostname: &str,
    listener: Option<&GatewayApiListenerKey>,
    descriptors_for_path: &[RouteMatchDescriptor],
    losing_conflict_keys: &HashSet<GatewayApiRouteConflictKey>,
) -> HashSet<RouteMatchDescriptor> {
    descriptors_for_path
        .iter()
        .filter(|descriptor| {
            descriptor_conflicts_for_host(
                parent_refs,
                route_family,
                hostname,
                descriptor,
                listener,
                losing_conflict_keys,
            )
        })
        .cloned()
        .collect()
}

/// Losing-key membership is looked up on the exact `(parentRef, listener)`
/// claim. `listen_port` is deliberately excluded from the probe key: it is a
/// derived field of `listener`, and including a separately-computed copy would
/// let a stale/absent port silently miss a real loss.
fn descriptor_conflicts_for_host(
    parent_refs: &[String],
    route_family: &str,
    hostname: &str,
    descriptor: &RouteMatchDescriptor,
    listener: Option<&GatewayApiListenerKey>,
    losing_conflict_keys: &HashSet<GatewayApiRouteConflictKey>,
) -> bool {
    if parent_refs.is_empty() || losing_conflict_keys.is_empty() {
        return false;
    }
    let match_signature = route_conflict_match_signature(descriptor);
    parent_refs.iter().all(|parent_ref| {
        losing_conflict_keys.iter().any(|key| {
            key.listener.as_ref() == listener
                && key.route_family == route_family
                && key.parent_ref == *parent_ref
                && key.hostname == hostname
                && key.listen_path == descriptor.listen_path
                && key.match_signature == match_signature
        })
    })
}

fn has_only_zero_weight_backend_refs(rule: &Value) -> bool {
    let Some(backend_refs) = rule.get("backendRefs").and_then(Value::as_array) else {
        return false;
    };
    if backend_refs.is_empty() {
        return false;
    }

    backend_refs
        .iter()
        .all(|backend_ref| backend_ref.get("weight").and_then(Value::as_u64) == Some(0))
}

#[allow(clippy::too_many_arguments)]
fn http_route_dispatch_rules_for_proxy(
    object: &K8sObject,
    rule: &Value,
    rule_index: usize,
    listen_path: Option<&str>,
    route_destination: MeshRouteDispatchDestination<'_>,
    skipped_descriptors: &HashSet<RouteMatchDescriptor>,
    entry_descriptors: &[RouteMatchEntryDescriptor],
    request_transform: &[Value],
    redirect: Option<&Value>,
    fault: Option<&Value>,
) -> (Vec<Value>, bool) {
    let has_route_actions = !request_transform.is_empty() || redirect.is_some() || fault.is_some();
    let matches = rule
        .get("matches")
        .and_then(Value::as_array)
        .filter(|matches| !matches.is_empty());
    let Some(matches) = matches else {
        return route_default_match_dispatch_rules(
            object,
            rule_index,
            route_destination,
            request_transform,
            redirect,
            fault,
            has_route_actions,
        );
    };

    let mut rules = Vec::new();
    let mut has_path_only_match = false;
    for entry_descriptor in entry_descriptors {
        let match_index = entry_descriptor.match_index;
        let Some(entry) = matches.get(match_index) else {
            continue;
        };
        let descriptor = &entry_descriptor.descriptor;
        let entry_path = descriptor.listen_path.as_str();
        if let Some(listen_path) = listen_path
            && entry_path != listen_path
        {
            continue;
        }
        if skipped_descriptors.contains(descriptor) {
            continue;
        }

        let match_criteria = if object.kind == "GRPCRoute" {
            // Fail closed on a gRPC predicate Ferrum cannot represent — the
            // descriptor pass already dropped it, so emitting an unguarded
            // rule here would resurrect it as a widened match.
            let Some(criteria) = grpc_dispatch_match_criteria(entry) else {
                continue;
            };
            criteria
        } else {
            http_route_dispatch_match_criteria(entry)
        };

        if match_criteria.is_empty() {
            has_path_only_match = true;
            if has_route_actions {
                rules.push(gateway_api_dispatch_route_rule(
                    object,
                    Value::Object(match_criteria),
                    rule_index,
                    match_index,
                    route_destination,
                    request_transform,
                    redirect,
                    fault,
                    entry,
                ));
            }
            continue;
        }

        rules.push(gateway_api_dispatch_route_rule(
            object,
            Value::Object(match_criteria),
            rule_index,
            match_index,
            route_destination,
            request_transform,
            redirect,
            fault,
            entry,
        ));
    }

    (rules, has_path_only_match)
}

fn http_route_dispatch_match_criteria(entry: &Value) -> serde_json::Map<String, Value> {
    let mut match_criteria = serde_json::Map::new();
    if let Some(method) = string_field(entry, "method") {
        match_criteria.insert("methods".to_string(), serde_json::json!([method]));
    }

    if let Some(headers_array) = entry.get("headers").and_then(Value::as_array) {
        let mut headers = serde_json::Map::new();
        for header in headers_array {
            if !gateway_match_type_is_exact(header) {
                continue;
            }
            let Some(name) = string_field(header, "name") else {
                continue;
            };
            let Some(value) = string_field(header, "value") else {
                continue;
            };
            let name = name.to_ascii_lowercase();
            if !headers.contains_key(&name) {
                headers.insert(name, Value::String(value.to_string()));
            }
        }
        if !headers.is_empty() {
            match_criteria.insert("headers".to_string(), Value::Object(headers));
        }
    }

    if let Some(params_array) = entry.get("queryParams").and_then(Value::as_array) {
        let mut params = serde_json::Map::new();
        for param in params_array {
            if !gateway_match_type_is_exact(param) {
                continue;
            }
            let Some(name) = string_field(param, "name") else {
                continue;
            };
            let Some(value) = string_field(param, "value") else {
                continue;
            };
            let name = name.to_string();
            if !params.contains_key(&name) {
                params.insert(name, Value::String(value.to_string()));
            }
        }
        if !params.is_empty() {
            match_criteria.insert("query_params".to_string(), Value::Object(params));
        }
    }

    match_criteria
}

/// Dispatch rules for a rule whose `matches` is omitted or empty.
///
/// For an HTTPRoute that is an unconditional `/` catch-all, so a rule is only
/// emitted when it carries route-local actions and the caller keeps
/// `has_path_only_match = true` (unmatched requests fall through to the
/// proxy's default backend).
///
/// For a GRPCRoute the Gateway API defines it as "every gRPC call on the
/// route's hostnames" — which is NOT the same as every HTTP request. It
/// therefore always emits a rule carrying the gRPC-shape URI predicate plus
/// the content-type gate, and reports `has_path_only_match = false` so
/// `reject_unmatched` keeps non-gRPC traffic off the backend.
#[allow(clippy::too_many_arguments)]
fn route_default_match_dispatch_rules(
    object: &K8sObject,
    rule_index: usize,
    route_destination: MeshRouteDispatchDestination<'_>,
    request_transform: &[Value],
    redirect: Option<&Value>,
    fault: Option<&Value>,
    has_route_actions: bool,
) -> (Vec<Value>, bool) {
    if object.kind == "GRPCRoute" {
        let entry = Value::Object(serde_json::Map::new());
        let criteria = grpc_dispatch_match_criteria_for(&grpc_any_call_match());
        return (
            vec![gateway_api_dispatch_route_rule(
                object,
                Value::Object(criteria),
                rule_index,
                0,
                route_destination,
                request_transform,
                redirect,
                fault,
                &entry,
            )],
            false,
        );
    }

    if has_route_actions {
        let default_match = gateway_api_default_path_prefix_match();
        return (
            vec![gateway_api_dispatch_route_rule(
                object,
                default_match.clone(),
                rule_index,
                0,
                route_destination,
                request_transform,
                redirect,
                fault,
                &default_match,
            )],
            true,
        );
    }

    (Vec::new(), true)
}

fn gateway_api_default_path_prefix_match() -> Value {
    serde_json::json!({"path": {"type": "PathPrefix", "value": "/"}})
}

#[allow(clippy::too_many_arguments)]
fn gateway_api_dispatch_route_rule(
    object: &K8sObject,
    match_criteria: Value,
    rule_index: usize,
    match_index: usize,
    route_destination: MeshRouteDispatchDestination<'_>,
    request_transform: &[Value],
    redirect: Option<&Value>,
    fault: Option<&Value>,
    precedence_entry: &Value,
) -> Value {
    let mut destination = serde_json::Map::new();
    if let Some(uid) = route_destination.upstream_id {
        destination.insert("upstream_id".to_string(), Value::String(uid.to_string()));
    } else {
        destination.insert(
            "backend_host".to_string(),
            Value::String(route_destination.backend_host.to_string()),
        );
        destination.insert(
            "backend_port".to_string(),
            serde_json::json!(route_destination.backend_port),
        );
    }
    if route_destination.requires_node_waypoint_authz {
        destination.insert(
            "requires_node_waypoint_authz".to_string(),
            Value::Bool(true),
        );
    }

    let mut route_rule = serde_json::Map::new();
    route_rule.insert("match".to_string(), match_criteria);
    route_rule.insert("destination".to_string(), Value::Object(destination));
    if !request_transform.is_empty() {
        route_rule.insert(
            "request_transform".to_string(),
            Value::Array(request_transform.to_vec()),
        );
    }
    if let Some(redirect) = redirect {
        route_rule.insert(
            "redirect".to_string(),
            gateway_redirect_value_for_match(redirect, precedence_entry),
        );
    }
    if let Some(fault) = fault {
        route_rule.insert("fault".to_string(), fault.clone());
    }
    route_rule.insert(
        GATEWAY_API_DISPATCH_PRECEDENCE_KEY.to_string(),
        gateway_api_dispatch_rule_precedence(object, precedence_entry, rule_index, match_index),
    );
    Value::Object(route_rule)
}

fn dispatch_rules_carry_field(rules: &[Value], field: &str) -> bool {
    rules.iter().any(|rule| {
        rule.as_object()
            .and_then(|object| object.get(field))
            .is_some_and(|value| value.as_array().is_none_or(|array| !array.is_empty()))
    })
}

fn gateway_request_header_modifier_rules(rule: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(filters) = rule.get("filters").and_then(Value::as_array) else {
        return out;
    };

    for filter in filters {
        if string_field(filter, "type") != Some("RequestHeaderModifier") {
            continue;
        }
        let Some(modifier) = filter
            .get("requestHeaderModifier")
            .and_then(Value::as_object)
        else {
            continue;
        };

        let set = gateway_header_name_value_entries(modifier.get("set"));
        let add = gateway_header_name_value_entries(modifier.get("add"));
        let remove = gateway_header_remove_entries(modifier.get("remove"));
        out.extend(route_header_transform_rules_to_json(
            (!set.is_empty()).then_some(&set),
            (!add.is_empty()).then_some(&add),
            (!remove.is_empty()).then_some(remove.as_slice()),
        ));
    }

    out
}

fn gateway_header_name_value_entries(value: Option<&Value>) -> serde_json::Map<String, Value> {
    let mut entries = serde_json::Map::new();
    let Some(items) = value.and_then(Value::as_array) else {
        return entries;
    };
    for item in items {
        let Some(name) = string_field(item, "name") else {
            continue;
        };
        let Some(value) = string_field(item, "value") else {
            continue;
        };
        entries.insert(name.to_string(), Value::String(value.to_string()));
    }
    entries
}

fn gateway_header_remove_entries(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn gateway_request_redirect_value(
    object: &K8sObject,
    rule: &Value,
    default_listener_port: Option<u16>,
) -> Result<Option<Value>, K8sTranslateError> {
    let Some(filters) = rule.get("filters").and_then(Value::as_array) else {
        return Ok(None);
    };

    for filter in filters {
        if string_field(filter, "type") != Some("RequestRedirect") {
            continue;
        }
        let Some(redirect) = filter.get("requestRedirect").and_then(Value::as_object) else {
            continue;
        };
        let mut out = serde_json::Map::new();

        let redirect_scheme = redirect.get("scheme").and_then(Value::as_str);
        if let Some(scheme) = redirect_scheme
            && !scheme.is_empty()
        {
            out.insert("scheme".to_string(), Value::String(scheme.to_string()));
        }

        let redirect_port =
            gateway_redirect_port(object, redirect, redirect_scheme, default_listener_port)?;
        let authority = redirect
            .get("hostname")
            .and_then(Value::as_str)
            .filter(|host| !host.is_empty())
            .map(ToOwned::to_owned);
        if let Some(authority) = authority {
            out.insert("authority".to_string(), Value::String(authority));
        }
        if let Some(port) = redirect_port {
            out.insert("port".to_string(), serde_json::json!(port));
        }

        if let Some((path, replace_prefix_match)) = gateway_redirect_path(redirect) {
            out.insert("uri".to_string(), Value::String(path.to_string()));
            if replace_prefix_match {
                out.insert(
                    GATEWAY_API_REDIRECT_REPLACE_PREFIX_MATCH_KEY.to_string(),
                    Value::Bool(true),
                );
            }
        }

        let status_code = match redirect.get("statusCode") {
            Some(value) => {
                let Some(code) = value.as_u64() else {
                    return Err(invalid_resource(
                        object,
                        "HTTPRoute RequestRedirect statusCode must be an integer in the 300-399 range",
                    ));
                };
                if !(300..=399).contains(&code) {
                    return Err(invalid_resource(
                        object,
                        "HTTPRoute RequestRedirect statusCode must be in the 300-399 range",
                    ));
                }
                code
            }
            None => 302,
        };
        out.insert("redirect_code".to_string(), serde_json::json!(status_code));

        return Ok(Some(Value::Object(out)));
    }

    Ok(None)
}

fn gateway_redirect_port(
    object: &K8sObject,
    redirect: &serde_json::Map<String, Value>,
    redirect_scheme: Option<&str>,
    default_listener_port: Option<u16>,
) -> Result<Option<u16>, K8sTranslateError> {
    let Some(port) = redirect.get("port") else {
        return Ok(default_port_for_scheme(redirect_scheme).or(default_listener_port));
    };
    let Some(port) = port.as_u64() else {
        return Err(invalid_resource(
            object,
            "HTTPRoute RequestRedirect port must be an integer in the 1-65535 range",
        ));
    };
    if port == 0 || port > u64::from(u16::MAX) {
        return Err(invalid_resource(
            object,
            "HTTPRoute RequestRedirect port must be in the 1-65535 range",
        ));
    }
    Ok(Some(port as u16))
}

fn default_port_for_scheme(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => Some(80),
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => Some(443),
        _ => None,
    }
}

fn gateway_redirect_path(redirect: &serde_json::Map<String, Value>) -> Option<(&str, bool)> {
    let path = redirect.get("path")?.as_object()?;
    let path_type = path.get("type").and_then(Value::as_str).unwrap_or_default();
    match path_type {
        "ReplaceFullPath" => path
            .get("replaceFullPath")
            .and_then(Value::as_str)
            .map(|path| (path, false)),
        "ReplacePrefixMatch" => path
            .get("replacePrefixMatch")
            .and_then(Value::as_str)
            .map(|path| (path, true)),
        _ => None,
    }
}

fn gateway_redirect_value_for_match(redirect: &Value, match_entry: &Value) -> Value {
    let mut value = redirect.clone();
    let Some(obj) = value.as_object_mut() else {
        return value;
    };
    let replace_prefix = obj
        .remove(GATEWAY_API_REDIRECT_REPLACE_PREFIX_MATCH_KEY)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if replace_prefix && let Some(prefix) = gateway_match_path_prefix(match_entry) {
        obj.insert(
            "match_prefix".to_string(),
            Value::String(prefix.to_string()),
        );
    }
    value
}

fn gateway_match_path_prefix(match_entry: &Value) -> Option<&str> {
    let Some(path) = match_entry.get("path") else {
        return Some("/");
    };
    let path = path.as_object()?;
    if path
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("PathPrefix")
        != "PathPrefix"
    {
        return None;
    }
    path.get("value").and_then(Value::as_str)
}

fn backend_ref_fault_value_with_percentage(
    reason: BackendRefFaultReason,
    percentage: f64,
) -> Value {
    let body = match reason {
        BackendRefFaultReason::InvalidKind => "Gateway API backendRef kind is unsupported",
        BackendRefFaultReason::BackendNotFound => "Gateway API backendRef target was not found",
        BackendRefFaultReason::UnsupportedProtocol => {
            "Gateway API backendRef target uses an unsupported protocol"
        }
        BackendRefFaultReason::RefNotPermitted => {
            "Gateway API backendRef is not permitted by ReferenceGrant"
        }
        BackendRefFaultReason::NoServiceableBackend => {
            "Gateway API rule has no serviceable backendRefs"
        }
        BackendRefFaultReason::InvalidBackendTlsPolicy => {
            "Gateway API BackendTLSPolicy for backend Service is invalid or conflicting"
        }
    };
    serde_json::json!({
        "abort": {
            "status_code": 500,
            "percentage": percentage,
            "body": serde_json::json!({"error": body}).to_string(),
        }
    })
}

fn backend_ref_fault_percentage(valid_weight: u32, invalid_weight: u32) -> f64 {
    let total = valid_weight.saturating_add(invalid_weight);
    // An all-zero-weight HTTPRoute has no weighted traffic denominator, but
    // every request matching the retained rule must still fail closed.
    if total == 0 || invalid_weight >= total {
        return 100.0;
    }
    (f64::from(invalid_weight) / f64::from(total)) * 100.0
}

fn gateway_api_dispatch_rule_precedence(
    object: &K8sObject,
    entry: &Value,
    rule_index: usize,
    match_index: usize,
) -> Value {
    let mut precedence = serde_json::Map::new();
    // HTTPRoute `matches[].method` is a string; GRPCRoute's is an object
    // carrying `service`/`method`. Both count as a method predicate for
    // dispatch-order specificity.
    let method_match = if object.kind == "GRPCRoute" {
        entry
            .get("method")
            .is_some_and(|method| !method.is_null() && method.as_object().is_some())
    } else {
        string_field(entry, "method").is_some()
    };
    precedence.insert("method_match".to_string(), Value::Bool(method_match));
    precedence.insert(
        "header_count".to_string(),
        serde_json::json!(translated_header_match_count(entry)),
    );
    precedence.insert(
        "query_param_count".to_string(),
        serde_json::json!(translated_query_param_match_count(entry)),
    );
    if let Some(creation_timestamp) = object.metadata.creation_timestamp.as_deref() {
        precedence.insert(
            "creation_timestamp".to_string(),
            Value::String(creation_timestamp.to_string()),
        );
    }
    precedence.insert(
        "namespace".to_string(),
        Value::String(object.metadata.namespace.clone()),
    );
    precedence.insert(
        "name".to_string(),
        Value::String(object.metadata.name.clone()),
    );
    precedence.insert("rule_index".to_string(), serde_json::json!(rule_index));
    precedence.insert("match_index".to_string(), serde_json::json!(match_index));
    Value::Object(precedence)
}

fn translated_header_match_count(entry: &Value) -> usize {
    let mut names = HashSet::new();
    if let Some(headers) = entry.get("headers").and_then(Value::as_array) {
        for header in headers {
            if !gateway_match_type_is_exact(header) {
                continue;
            }
            let Some(name) = string_field(header, "name") else {
                continue;
            };
            if string_field(header, "value").is_some() {
                names.insert(name.to_ascii_lowercase());
            }
        }
    }
    names.len()
}

fn translated_query_param_match_count(entry: &Value) -> usize {
    let mut names = HashSet::new();
    if let Some(params) = entry.get("queryParams").and_then(Value::as_array) {
        for param in params {
            if !gateway_match_type_is_exact(param) {
                continue;
            }
            let Some(name) = string_field(param, "name") else {
                continue;
            };
            if string_field(param, "value").is_some() {
                names.insert(name.to_string());
            }
        }
    }
    names.len()
}

fn http_route_match_has_supported_non_path_predicate(entry: &Value) -> bool {
    string_field(entry, "method").is_some()
        || entry
            .get("headers")
            .and_then(Value::as_array)
            .is_some_and(|headers| {
                headers.iter().any(|header| {
                    gateway_match_type_is_exact(header)
                        && string_field(header, "name").is_some()
                        && string_field(header, "value").is_some()
                })
            })
        || entry
            .get("queryParams")
            .and_then(Value::as_array)
            .is_some_and(|params| {
                params.iter().any(|param| {
                    gateway_match_type_is_exact(param)
                        && string_field(param, "name").is_some()
                        && string_field(param, "value").is_some()
                })
            })
}

fn http_route_match_has_untranslated_non_path_predicate(entry: &Value) -> bool {
    entry
        .get("headers")
        .and_then(Value::as_array)
        .is_some_and(|headers| {
            headers
                .iter()
                .any(gateway_header_query_match_is_untranslated)
        })
        || entry
            .get("queryParams")
            .and_then(Value::as_array)
            .is_some_and(|params| {
                params
                    .iter()
                    .any(gateway_header_query_match_is_untranslated)
            })
}

fn gateway_header_query_match_is_untranslated(value: &Value) -> bool {
    !gateway_match_type_is_exact(value)
        || string_field(value, "name").is_none()
        || string_field(value, "value").is_none()
}

fn gateway_match_type_is_exact(value: &Value) -> bool {
    matches!(string_field(value, "type"), None | Some("Exact"))
}

fn route_backends(
    object: &K8sObject,
    rule: &Value,
    acc: &mut K8sAccumulator,
) -> Result<RouteBackendResolution, K8sTranslateError> {
    let mut backend_groups = Vec::new();
    let mut fault_reason = None;
    let mut invalid_weight = 0u32;
    let mut valid_weight = 0u32;
    let mut skipped_zero = 0usize;
    for backend_ref in rule
        .get("backendRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let weight = backend_weight(object, backend_ref)?;
        if weight == 0 {
            skipped_zero += 1;
            continue;
        }
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        let (backend_kind, backend_namespace) =
            match checked_backend_namespace(object, backend_ref, acc, object.kind.as_str()) {
                Ok(resolved) => resolved,
                Err(error) if error_is_backend_ref_resolution(&error) => {
                    fault_reason.get_or_insert(backend_ref_resolution_reason(&error));
                    invalid_weight = invalid_weight.saturating_add(weight);
                    continue;
                }
                Err(error) => return Err(error),
            };
        let requested_port =
            optional_port_field(object, backend_ref.get("port"), "backendRefs[].port")?;
        let backend_port = match backend_kind {
            super::backend_ref::BackendKind::Service => {
                requested_port.unwrap_or(if object.kind == "GRPCRoute" {
                    50051
                } else {
                    80
                })
            }
            super::backend_ref::BackendKind::ServiceImport => {
                match super::backend_ref::resolve_service_import_port(
                    acc,
                    &backend_namespace,
                    backend_name,
                    requested_port,
                ) {
                    Ok(port) => port,
                    Err(super::backend_ref::ServiceImportPortError::BackendNotFound) => {
                        fault_reason.get_or_insert(BackendRefFaultReason::BackendNotFound);
                        invalid_weight = invalid_weight.saturating_add(weight);
                        continue;
                    }
                    Err(super::backend_ref::ServiceImportPortError::UnsupportedProtocol) => {
                        fault_reason.get_or_insert(BackendRefFaultReason::UnsupportedProtocol);
                        invalid_weight = invalid_weight.saturating_add(weight);
                        continue;
                    }
                }
            }
        };
        if super::backend_ref::backend_target_missing(
            acc,
            backend_kind,
            &backend_namespace,
            backend_name,
            backend_port,
        ) {
            fault_reason.get_or_insert(BackendRefFaultReason::BackendNotFound);
            invalid_weight = invalid_weight.saturating_add(weight);
            continue;
        }
        valid_weight = valid_weight.saturating_add(weight);
        let endpoint_backends = super::backend_ref::materialize_backend(
            acc,
            backend_kind,
            &backend_namespace,
            backend_name,
            backend_port,
            weight,
        );
        // Match historical Service semantics: only multi-address EndpointSlice
        // expansion triggers weight redistribution across targets.
        let expanded_endpoints = endpoint_backends.len() > 1;
        backend_groups.push(RouteBackendGroup {
            total_weight: weight,
            expanded_endpoints,
            backends: endpoint_backends,
        });
    }
    let backends = flatten_route_backend_groups(backend_groups);
    if skipped_zero > 0 {
        if has_only_zero_weight_backend_refs(rule) {
            if object.kind == "HTTPRoute" {
                fault_reason.get_or_insert(BackendRefFaultReason::NoServiceableBackend);
                acc.warnings.push(
                    "HTTPRoute rule has only zero-weight backendRefs; materializing HTTP 500 fail-closed route action"
                        .to_string(),
                );
            } else {
                acc.warnings.push(format!(
                    "{} rule has only zero-weight backendRefs; emitted blackhole backend",
                    object.kind
                ));
            }
        } else {
            acc.warnings.push(format!(
                "{} skipped {} zero-weight backendRef(s)",
                object.kind, skipped_zero
            ));
        }
    }
    if fault_reason.is_some_and(|reason| reason != BackendRefFaultReason::NoServiceableBackend) {
        acc.warnings.push(format!(
            "{} {}/{} has unresolved backendRef(s); materializing fail-closed route action",
            object.kind, object.metadata.namespace, object.metadata.name
        ));
    }
    Ok(RouteBackendResolution {
        backends,
        fault_reason,
        invalid_weight,
        valid_weight,
    })
}

fn flatten_route_backend_groups(groups: Vec<RouteBackendGroup>) -> Vec<RouteBackend> {
    let has_expanded_endpoint_group = groups.iter().any(|group| group.expanded_endpoints);
    if !has_expanded_endpoint_group {
        return groups
            .into_iter()
            .flat_map(|group| group.backends)
            .collect();
    }

    let max_group_targets = groups
        .iter()
        .map(|group| group.backends.len())
        .max()
        .unwrap_or(1);
    let scale = GATEWAY_API_BACKEND_WEIGHT_SCALE
        .max(u32::try_from(max_group_targets).unwrap_or(u32::MAX).max(1));
    let mut flattened = Vec::new();
    for group in groups {
        let total_weight = scaled_backend_weight(group.total_weight, scale);
        if group.expanded_endpoints {
            let len = group.backends.len();
            for (index, mut backend) in group.backends.into_iter().enumerate() {
                backend.weight = distributed_backend_weight(total_weight, len, index);
                flattened.push(backend);
            }
        } else {
            for mut backend in group.backends {
                backend.weight = total_weight;
                flattened.push(backend);
            }
        }
    }
    normalize_backend_weights_to_target_limit(&mut flattened);
    flattened
}

fn scaled_backend_weight(weight: u32, scale: u32) -> u32 {
    u32::try_from(u64::from(weight).saturating_mul(u64::from(scale))).unwrap_or(u32::MAX)
}

fn distributed_backend_weight(total_weight: u32, count: usize, index: usize) -> u32 {
    let Ok(count) = u32::try_from(count) else {
        return 1;
    };
    if count == 0 {
        return total_weight;
    }
    let base = total_weight / count;
    let remainder = total_weight % count;
    base + u32::from(u32::try_from(index).is_ok_and(|idx| idx < remainder))
}

fn normalize_backend_weights_to_target_limit(backends: &mut [RouteBackend]) {
    let max_weight = backends
        .iter()
        .map(|backend| backend.weight)
        .max()
        .unwrap_or(0);
    if max_weight <= MAX_TARGET_WEIGHT {
        return;
    }
    for backend in backends {
        if backend.weight == 0 {
            continue;
        }
        let normalized = (u64::from(backend.weight) * u64::from(MAX_TARGET_WEIGHT)
            / u64::from(max_weight))
        .max(1);
        backend.weight = u32::try_from(normalized).unwrap_or(MAX_TARGET_WEIGHT);
    }
}

fn error_is_backend_ref_resolution(error: &K8sTranslateError) -> bool {
    match error {
        K8sTranslateError::InvalidResource { message, .. } => {
            message.contains("ReferenceGrant")
                || super::backend_ref::message_is_unsupported_backend_kind(message)
        }
        K8sTranslateError::Unsupported(_) => false,
    }
}

fn backend_ref_resolution_reason(error: &K8sTranslateError) -> BackendRefFaultReason {
    match error {
        K8sTranslateError::InvalidResource { message, .. }
            if super::backend_ref::message_is_unsupported_backend_kind(message) =>
        {
            BackendRefFaultReason::InvalidKind
        }
        _ => BackendRefFaultReason::RefNotPermitted,
    }
}

fn backend_weight(object: &K8sObject, backend_ref: &Value) -> Result<u32, K8sTranslateError> {
    optional_target_weight_field(object, backend_ref, "backendRefs[].weight", 1)
}

fn l4_route_proxies(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
    scheme: BackendScheme,
) -> Result<Vec<crate::config::types::Proxy>, K8sTranslateError> {
    // Cross-namespace TCPRoute/TLSRoute parentRefs use the same listener
    // AllowedRoutes gates as HTTPRoute/GRPCRoute. ReferenceGrant authorizes
    // backendRefs only, not parentRefs. UDPRoute keeps its stricter
    // same-namespace parent contract.
    ensure_route_parent_refs_allowed(object, acc)?;
    if scheme.is_udp() {
        ensure_l4_parent_refs_are_same_namespace(object)?;
    }

    let config_namespaces = if scheme.is_udp() {
        vec![object.metadata.namespace.clone()]
    } else {
        route_materialization_namespaces(object, acc)
    };
    let mut proxies = Vec::new();
    for config_namespace in &config_namespaces {
        if !scheme.is_udp()
            && route_declares_gateway_parent_ref(object)
            && route_allowed_parent_ref_keys_for_namespace(object, acc, Some(config_namespace))
                .is_empty()
        {
            continue;
        }
        let namespace_suffix = (config_namespaces.len() > 1)
            .then(|| format!("ns-{}", resource_suffix_component(config_namespace)));
        proxies.extend(l4_route_proxies_for_namespace(
            object,
            acc,
            scheme,
            config_namespace,
            namespace_suffix.as_deref(),
        )?);
    }
    Ok(proxies)
}

fn l4_route_proxies_for_namespace(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
    scheme: BackendScheme,
    config_namespace: &str,
    route_namespace_suffix: Option<&str>,
) -> Result<Vec<crate::config::types::Proxy>, K8sTranslateError> {
    let fallback_hosts = l4_route_hosts(object, scheme)?;
    ensure_udp_route_rule_shape(object, scheme)?;
    // A `UDPRoute` never carries hostnames (`l4_route_hosts` rejects the field
    // fail closed), so its surviving listeners bind with an empty host set.
    // `TCPRoute`/`TLSRoute` keep the shared binding resolver, which is where
    // TLS SNI is bounded by the listener hostname.
    let (materialized_listener_bindings, materialized_parent_refs) = if scheme.is_udp() {
        let (ports, parent_refs) = udp_route_surviving_materialization(object, acc);
        (
            ports
                .into_iter()
                .map(|port| (port, Vec::new()))
                .collect::<Vec<(u16, Vec<String>)>>(),
            parent_refs,
        )
    } else {
        (
            l4_route_listener_bindings_for_namespace(object, acc, Some(config_namespace)),
            route_materialized_parent_ref_keys_for_namespace(object, acc, Some(config_namespace)),
        )
    };

    // Suppress listener materialization when there is no attached Gateway
    // listener. UDPRoute is a Gateway API-only resource and Ferrum implements
    // no non-Gateway L4 parents, so a declared but unattached parent must never
    // turn a backend port into an implicit public listener.
    //
    // `materialized_listener_bindings` is the set of concrete listener ports
    // that survived every gate: Gateway identity, `sectionName`/`port`
    // selection, listener protocol and `allowedRoutes` kind, `allowedRoutes`
    // namespace, listener materializability, and — for `TLSRoute` — a
    // non-empty route/listener hostname intersection. A route that *declares*
    // a parent and clears none of those gates has no listener to
    // attach to, so it must open nothing — falling through to the backend port
    // would bind an unintended OS listener while status correctly reports
    // `NoMatchingParent` / `NotAllowedByListeners`. The backend-port fallback
    // below is retained only for the parentless legacy TCPRoute/TLSRoute shape
    // supplied by a non-Kubernetes config source.
    //
    // For UDPRoute this set is additionally filtered by same-listener conflict
    // losers: a route that lost ownership of every declared listener opens
    // nothing and creates no upstream, so duplicate OS binds cannot race.
    //
    // Suppression must not bypass hostile-input validation, ReferenceGrant
    // enforcement, backend-kind/port checks, or rule-level warnings: still run
    // `l4_rule_backends` for every rule, then skip proxy/upstream creation.
    let suppress_listener_materialization = materialized_listener_bindings.is_empty()
        && (scheme.is_udp() || l4_route_declares_parent_ref(object));
    if suppress_listener_materialization {
        if scheme.is_udp()
            && acc
                .gateway_api_conflict_losers
                .contains_key(&K8sResourceKey::from_object(object))
        {
            acc.warnings.push(format!(
                "{} {}/{} lost every claimed UDP listener to an older competing UDPRoute; \
                 no listener was opened",
                object.kind, object.metadata.namespace, object.metadata.name
            ));
        } else if scheme.is_udp() && !route_declares_gateway_parent_ref(object) {
            acc.warnings.push(format!(
                "{} {}/{} has no valid attached Gateway listener; no listener was opened",
                object.kind, object.metadata.namespace, object.metadata.name
            ));
        } else {
            acc.warnings.push(format!(
                "{} {}/{} declares parentRefs but none resolved to a materializable Gateway listener; \
                 no listener was opened",
                object.kind, object.metadata.namespace, object.metadata.name
            ));
        }
    }

    let mut proxies = Vec::new();
    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(resolved) = l4_rule_backends(object, rule, acc, scheme)? else {
            continue;
        };

        if suppress_listener_materialization {
            continue;
        }

        let listen_bindings = if materialized_listener_bindings.is_empty() {
            vec![(resolved.fallback_listen_port, fallback_hosts.clone())]
        } else {
            materialized_listener_bindings.clone()
        };
        let rule_suffix = l4_rule_suffix(scheme, rule_index);

        // One leg dispatches directly; a set of legs becomes one namespaced
        // upstream whose weighted targets preserve the declared relative
        // weights. The upstream is listener-independent, so every listen port
        // for this rule shares it. Create it only when at least one listen
        // port survives — a UDPRoute conflict loser must not leave an orphan
        // upstream behind.
        let (backend_host, backend_port, upstream_id) = if resolved.backends.len() == 1 {
            let Some(backend) = resolved.backends.into_iter().next() else {
                continue;
            };
            (backend.host, backend.port, None)
        } else {
            let upstream_id = resource_id(
                "gwapi-l4-upstream",
                &object.metadata.namespace,
                &object.metadata.name,
                &rule_suffix,
            );
            acc.upsert_upstream(upstream_for_route(
                upstream_id.clone(),
                object.metadata.namespace.clone(),
                resolved.backends,
            ));
            (String::new(), 0, Some(upstream_id))
        };

        for (listen_port_index, (listen_port, hosts)) in listen_bindings.iter().enumerate() {
            let base_suffix = if listen_bindings.len() == 1 {
                rule_suffix.clone()
            } else {
                format!("{rule_suffix}-{listen_port_index}")
            };
            let suffix = route_namespace_suffix.map_or_else(
                || base_suffix.clone(),
                |namespace_suffix| format!("{base_suffix}-{namespace_suffix}"),
            );
            let id = if scheme.is_udp() || config_namespace == object.metadata.namespace {
                resource_id(
                    "gwapi-l4",
                    &object.metadata.namespace,
                    &object.metadata.name,
                    &suffix,
                )
            } else {
                gateway_api_l4_proxy_id(
                    &object.kind,
                    &object.metadata.namespace,
                    &object.metadata.name,
                    &suffix,
                )
            };
            proxies.push(proxy_for_route(RouteProxySpec {
                id,
                // The parent Gateway namespace owns the stream listener.
                namespace: config_namespace.to_string(),
                hosts: hosts.clone(),
                listen_path: None,
                strip_listen_path: false,
                preserve_host_header: false,
                backend_host: backend_host.clone(),
                backend_port,
                upstream_id: upstream_id.clone(),
                backend_scheme: scheme,
                listen_port: Some(*listen_port),
                retry: None,
                backend_read_timeout_ms: None,
            }));
        }
    }
    if !proxies.is_empty() {
        for parent_ref in materialized_parent_refs {
            acc.record_gateway_api_materialized_route_parent(object, parent_ref);
        }
    }
    Ok(proxies)
}

const GATEWAY_API_L4_PROXY_ID_DIGEST_HEX_LEN: usize = 16;
const GATEWAY_API_L4_PROXY_ID_DIGEST_SUFFIX_LEN: usize = 2 + GATEWAY_API_L4_PROXY_ID_DIGEST_HEX_LEN;

fn gateway_api_l4_proxy_id(
    route_kind: &str,
    namespace: &str,
    route_name: &str,
    suffix: &str,
) -> String {
    // Cross-namespace routes are materialized in their parent Gateway's
    // namespace, so distinct route owners can share the proxy keyspace. Keep
    // the readable legacy id, but bind it to the unambiguous, unsanitized
    // source identity so dash-join and sanitization collisions cannot replace
    // another tenant's proxy.
    let identity = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        route_kind.len(),
        route_kind,
        namespace.len(),
        namespace,
        route_name.len(),
        route_name,
        suffix.len(),
        suffix
    );
    let digest = hex::encode(crate::fips::approved::Sha256::digest(identity.as_bytes()));
    let mut readable = resource_id("gwapi-l4", namespace, route_name, suffix);
    let readable_budget = MAX_ID_LENGTH - GATEWAY_API_L4_PROXY_ID_DIGEST_SUFFIX_LEN;
    if readable.len() > readable_budget {
        let mut end = readable_budget;
        while end > 0 && !readable.is_char_boundary(end) {
            end -= 1;
        }
        readable.truncate(end);
    }
    format!(
        "{readable}__{}",
        &digest[..GATEWAY_API_L4_PROXY_ID_DIGEST_HEX_LEN]
    )
}

/// UDP listener ports and parentRefs that survive same-listener conflict loss.
///
/// Arbitration is per concrete listener: a route that loses on one listener may
/// still keep another. ParentRefs that retain at least one surviving listener
/// are recorded as materialized so status `Programmed` tracks live ownership.
fn udp_route_surviving_materialization(
    object: &K8sObject,
    acc: &K8sAccumulator,
) -> (Vec<u16>, Vec<String>) {
    let losing_conflict_keys: HashSet<GatewayApiRouteConflictKey> = acc
        .gateway_api_conflict_losers
        .get(&K8sResourceKey::from_object(object))
        .into_iter()
        .flat_map(|conflicts| conflicts.iter().map(|conflict| conflict.key.clone()))
        .collect();

    let mut ports = Vec::new();
    let mut parent_refs = Vec::new();
    for claim in udp_route_listener_claims(object, acc) {
        let key = udp_route_conflict_key(&claim.parent_ref, &claim.listener, Some(claim.port));
        if losing_conflict_keys.contains(&key) {
            continue;
        }
        ports.push(claim.port);
        parent_refs.push(claim.parent_ref);
    }
    ports.sort();
    ports.dedup();
    parent_refs.sort();
    parent_refs.dedup();
    (ports, parent_refs)
}

/// True when the route names at least one Gateway or ListenerSet `parentRefs[]`
/// entry.
///
/// A non-Gateway/ListenerSet parent (a GAMMA `Service` parent, say) is not a
/// listener declaration and must not arm the fail-closed listener gate.
fn route_declares_gateway_parent_ref(object: &K8sObject) -> bool {
    object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .is_some_and(|parent_refs| parent_refs.iter().any(parent_ref_is_attachable_parent))
}

/// True when the route declares a `parentRefs[]` entry that arms the
/// fail-closed listener gate.
///
/// Ferrum implements no non-Gateway L4 parent. Any present declaration that
/// resolves to no materializable listener
/// — a `Service` parent, a mistyped `kind`, an unrecognized `group`, or a
/// malformed/empty value that bypassed CRD admission — must open nothing rather
/// than quietly bind a north-south listener on the backend port. Such a route
/// also names no managed Gateway, so it is not a status candidate and the
/// fallback listener would be completely unannounced. The fallback survives
/// only for a genuinely parentless route (the `parentRefs` field is absent),
/// which is the non-Kubernetes config-source shape.
fn l4_route_declares_parent_ref(object: &K8sObject) -> bool {
    object.spec.get("parentRefs").is_some()
}

/// Proxy/upstream id suffix for one L4 rule.
///
/// `UDPRoute` ids are kind-scoped. The historical L4 id encodes only
/// `(namespace, route name, rule index)`, so a `UDPRoute` and a same-named
/// `TCPRoute` in one namespace would upsert over each other's proxy. Existing
/// `TCPRoute`/`TLSRoute` ids stay byte-identical.
fn l4_rule_suffix(scheme: BackendScheme, rule_index: usize) -> String {
    if scheme.is_udp() {
        format!("udproute-{rule_index}")
    } else {
        rule_index.to_string()
    }
}

/// Gateway API v1.5.1 bounds `UDPRouteSpec.rules` and `UDPRouteRule.backendRefs`
/// at 16 entries each. A non-Kubernetes config source is not CRD-validated, so
/// the cold path enforces the same ceiling rather than expanding an unbounded
/// hostile fan-out.
const MAX_UDP_ROUTE_RULES: usize = 16;
const MAX_UDP_ROUTE_BACKEND_REFS: usize = 16;
/// Gateway API v1.5.1 `BackendRef.weight` upper bound. Ferrum stores target
/// weights under [`MAX_TARGET_WEIGHT`], so accepted UDPRoute weights are
/// normalized proportionally after the whole backend set is resolved.
const GATEWAY_API_MAX_BACKEND_WEIGHT: u64 = 1_000_000;

/// Ferrum's supported `UDPRouteSpec.rules` cardinality.
///
/// The pinned Gateway API v1.5.1 CRD accepts `1..=16` rules
/// (`apis/v1alpha2/udproute_types.go`: `MinItems=1`, `MaxItems=16`,
/// `listType=atomic`), so a 2..=16-rule object is **valid upstream** — Ferrum
/// declines to serve it rather than calling it malformed, and says so in
/// status with the upstream `UnsupportedValue` reason.
const MAX_SUPPORTED_UDP_ROUTE_RULES: usize = 1;

/// Reject a `UDPRoute` whose `spec.rules` shape is hostile or unrepresentable.
///
/// The CRD requires `rules` to be an array with `MinItems=1` / `MaxItems=16`.
/// Missing, non-array, empty, and over-long shapes are rejected fail closed as
/// `Invalid`. A CRD-valid `2..=16`-rule object remains
/// [`UNSUPPORTED_SHAPE_MARKER`] / `UnsupportedValue` because Ferrum still
/// cannot represent matchless competing rules on one listener.
///
/// `TCPRoute`/`TLSRoute` keep their historical behavior.
fn ensure_udp_route_rule_shape(
    object: &K8sObject,
    scheme: BackendScheme,
) -> Result<(), K8sTranslateError> {
    if !scheme.is_udp() {
        return Ok(());
    }
    let Some(rules_value) = object.spec.get("rules") else {
        return Err(invalid_resource(
            object,
            format!(
                "{} spec.rules is required and must be an array with 1..={MAX_UDP_ROUTE_RULES} entries",
                object.kind
            ),
        ));
    };
    let Some(rules) = rules_value.as_array() else {
        return Err(invalid_resource(
            object,
            format!(
                "{} spec.rules must be an array with 1..={MAX_UDP_ROUTE_RULES} entries",
                object.kind
            ),
        ));
    };
    if rules.is_empty() {
        return Err(invalid_resource(
            object,
            format!(
                "{} spec.rules must contain at least 1 entry (Gateway API MinItems=1)",
                object.kind
            ),
        ));
    }
    if rules.len() > MAX_UDP_ROUTE_RULES {
        return Err(invalid_resource(
            object,
            format!(
                "{} spec.rules supports at most {MAX_UDP_ROUTE_RULES} entries (got {})",
                object.kind,
                rules.len()
            ),
        ));
    }
    if rules.len() > MAX_SUPPORTED_UDP_ROUTE_RULES {
        return Err(invalid_resource(
            object,
            format!(
                "{} spec.rules holds {} rules, which {UNSUPPORTED_SHAPE_MARKER}: \
                 Gateway API v1.5.1 permits 1..={MAX_UDP_ROUTE_RULES} rules, but a UDPRouteRule carries only \
                 `name` and `backendRefs` and so has no match predicate, leaving \
                 {} indistinguishable rules on one listener port with no \
                 standards-defined precedence and no cross-rule weight comparison; Ferrum \
                 serves exactly {MAX_SUPPORTED_UDP_ROUTE_RULES} rule per UDPRoute",
                object.kind,
                rules.len(),
                rules.len()
            ),
        ));
    }
    Ok(())
}

/// One L4 rule's resolved backend set.
struct L4RuleBackends {
    /// Listen port used only by the parentless legacy shape. This is the
    /// *declared* `backendRefs[].port`, never a resolved blackhole port.
    fallback_listen_port: u16,
    /// Weighted target set. Exactly one entry dispatches directly; more than
    /// one becomes an upstream.
    backends: Vec<RouteBackend>,
}

fn l4_rule_backends(
    object: &K8sObject,
    rule: &Value,
    acc: &mut K8sAccumulator,
    scheme: BackendScheme,
) -> Result<Option<L4RuleBackends>, K8sTranslateError> {
    if scheme.is_udp() {
        return udp_rule_backends(object, rule, acc);
    }

    // TCPRoute / TLSRoute: unchanged first-non-zero-weight selection.
    let Some(backend_ref) = first_backend_ref(object, rule, acc)? else {
        return Ok(None);
    };
    let backend_name = string_field(backend_ref, "name")
        .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
    let (backend_kind, backend_namespace) =
        checked_backend_namespace(object, backend_ref, acc, object.kind.as_str())?;
    // Field-specific diagnostics name the route's own kind: an operator
    // reading a UDPRoute condition must not be told about TCPRoute/TLSRoute.
    let backend_port_field = format!("{} backendRefs[].port", object.kind);
    let requested_port = optional_port_field(object, backend_ref.get("port"), &backend_port_field)?;
    let backend_port = match backend_kind {
        super::backend_ref::BackendKind::Service => requested_port
            .ok_or_else(|| invalid_resource(object, format!("{backend_port_field} is required")))?,
        super::backend_ref::BackendKind::ServiceImport => {
            // Stream routes keep a stable ClusterSet DNS target and never
            // expand MCS EndpointSlice addresses (that would discard all but
            // one address). Omitted ports derive only for a single TCP port.
            super::backend_ref::resolve_service_import_port(
                acc,
                &backend_namespace,
                backend_name,
                requested_port,
            )
            .map_err(|error| {
                invalid_resource(
                    object,
                    super::backend_ref::service_import_port_error_message(
                        &backend_namespace,
                        backend_name,
                        requested_port,
                        error,
                    ),
                )
            })?
        }
    };
    Ok(Some(L4RuleBackends {
        fallback_listen_port: backend_port,
        backends: vec![RouteBackend {
            host: super::backend_ref::backend_dns_name(
                backend_kind,
                backend_name,
                &backend_namespace,
                &acc.options.cluster_domain,
            ),
            port: backend_port,
            weight: 1,
            service_namespace: None,
            service_name: None,
            service_port: None,
        }],
    }))
}

/// Resolve one `UDPRouteRule`'s `backendRefs` **set**.
///
/// Pinned Gateway API v1.5.1 (`apis/v1alpha2/udproute_types.go`) makes
/// `backendRefs` a set of up to 16 backends with Extended weight support, and
/// requires that an invalid backend's share of traffic be dropped rather than
/// handed to the valid backends: "if an invalid backend is requested to have
/// 80% of the packets, then 80% of packets must be dropped instead."
///
/// Ferrum honors that by never renormalizing: an unserviceable leg keeps its
/// declared weight and is pointed at the unresolvable blackhole host, so the
/// sessions that select it fail closed instead of shifting onto a valid leg.
/// Selection granularity is the UDP *session* (client 5-tuple), not the
/// individual datagram — Ferrum's UDP data path selects a target once per
/// session and reuses it for that session's lifetime.
///
/// Unsupported backend kinds and denied cross-namespace `ReferenceGrant`s stay
/// whole-route hard errors (the strongest fail-closed outcome) rather than
/// per-leg blackholes, matching `TCPRoute`/`TLSRoute`.
fn udp_rule_backends(
    object: &K8sObject,
    rule: &Value,
    acc: &mut K8sAccumulator,
) -> Result<Option<L4RuleBackends>, K8sTranslateError> {
    let Some(backend_refs_value) = rule.get("backendRefs") else {
        return Err(invalid_resource(
            object,
            format!(
                "{} backendRefs is required and must be an array with 1..={MAX_UDP_ROUTE_BACKEND_REFS} entries",
                object.kind
            ),
        ));
    };
    let Some(backend_refs) = backend_refs_value.as_array() else {
        return Err(invalid_resource(
            object,
            format!(
                "{} backendRefs must be an array with 1..={MAX_UDP_ROUTE_BACKEND_REFS} entries",
                object.kind
            ),
        ));
    };
    if backend_refs.is_empty() {
        return Err(invalid_resource(
            object,
            format!(
                "{} backendRefs must contain at least 1 entry (Gateway API MinItems=1)",
                object.kind
            ),
        ));
    }
    if backend_refs.len() > MAX_UDP_ROUTE_BACKEND_REFS {
        return Err(invalid_resource(
            object,
            format!(
                "{} backendRefs supports at most {MAX_UDP_ROUTE_BACKEND_REFS} entries (got {})",
                object.kind,
                backend_refs.len()
            ),
        ));
    }

    let backend_port_field = format!("{} backendRefs[].port", object.kind);
    let mut backends = Vec::new();
    let mut fallback_listen_port = None;
    let mut skipped_zero = 0usize;
    let mut unserviceable = 0usize;
    for backend_ref in backend_refs {
        // Every entry's port is validated, including a zero-weight one: a
        // malformed port is a spec error regardless of whether traffic would
        // have selected that leg.
        let Some(raw_backend_port) = backend_ref.get("port").and_then(Value::as_u64) else {
            return Err(invalid_resource(
                object,
                format!("{backend_port_field} is required"),
            ));
        };
        let backend_port = port_from_u64(object, raw_backend_port, &backend_port_field)?;
        // Gateway API permits 0..=1,000,000. Parse that public boundary here;
        // the complete set is normalized below to Ferrum's smaller target
        // weight representation without changing relative proportions.
        let weight = udp_backend_weight(object, backend_ref)?;
        // Zero weight disables selection; it does not waive the BackendRef
        // boundary. Validate the target identity, supported kind, namespace,
        // and ReferenceGrant before filtering so an ignored leg cannot hide
        // an unauthorized cross-namespace reference or unsupported target.
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        // Route-kind capability lives in `checked_backend_namespace` /
        // `classify_backend_kind_for_route`: UDPRoute rejects ServiceImport
        // (and every other non-Service kind) as InvalidKind before any
        // ReferenceGrant can authorize it, matching `ResolvedRefs` status.
        let (_, backend_namespace) =
            checked_backend_namespace(object, backend_ref, acc, object.kind.as_str())?;
        if weight == 0 {
            skipped_zero += 1;
            continue;
        }
        fallback_listen_port.get_or_insert(backend_port);

        // A missing Service, or a Service without the referenced port, is an
        // unserviceable leg. It keeps its weight and becomes an explicit
        // blackhole target so its share of sessions is dropped, never
        // redistributed. The check is skipped entirely when no Service has
        // been observed at all (a non-Kubernetes or not-yet-synced source),
        // so a cold cache cannot blackhole a healthy route.
        let serviceable = !acc.has_observed_services()
            || (acc.service_exists(&backend_namespace, backend_name)
                && acc.service_port_exists(&backend_namespace, backend_name, backend_port));
        if serviceable {
            backends.push(RouteBackend {
                host: service_dns_name(
                    backend_name,
                    &backend_namespace,
                    &acc.options.cluster_domain,
                ),
                port: backend_port,
                weight,
                service_namespace: Some(backend_namespace.clone()),
                service_name: Some(backend_name.to_string()),
                service_port: Some(backend_port),
            });
        } else {
            unserviceable += 1;
            backends.push(RouteBackend {
                host: ZERO_WEIGHT_BACKEND_HOST.to_string(),
                port: ZERO_WEIGHT_BACKEND_PORT,
                weight,
                service_namespace: None,
                service_name: None,
                service_port: None,
            });
        }
    }

    if backends.is_empty() {
        if skipped_zero > 0 {
            acc.warnings.push(format!(
                "{} rule has only zero-weight backendRefs; no proxy was materialized",
                object.kind
            ));
        }
        return Ok(None);
    }
    normalize_backend_weights_to_target_limit(&mut backends);
    if skipped_zero > 0 {
        acc.warnings.push(format!(
            "{} skipped {} zero-weight backendRef(s)",
            object.kind, skipped_zero
        ));
    }
    if unserviceable > 0 {
        acc.warnings.push(format!(
            "{} {}/{} has {} unresolved backendRef(s); their declared weight is dropped fail \
             closed and is not redistributed to the resolvable backends",
            object.kind, object.metadata.namespace, object.metadata.name, unserviceable
        ));
    }

    let Some(fallback_listen_port) = fallback_listen_port else {
        return Ok(None);
    };
    Ok(Some(L4RuleBackends {
        fallback_listen_port,
        backends,
    }))
}

/// Parse the Gateway API `BackendRef.weight` contract for UDPRoute.
///
/// The shared Ferrum target parser intentionally caps weights at 65,535, but
/// Gateway API's public schema accepts values through 1,000,000. Rejecting the
/// upper part of that range would make a CRD-valid UDPRoute inert. The caller
/// normalizes the resolved set proportionally before it reaches an Upstream.
fn udp_backend_weight(object: &K8sObject, backend_ref: &Value) -> Result<u32, K8sTranslateError> {
    let Some(value) = backend_ref.get("weight") else {
        return Ok(1);
    };
    let Some(weight) = value.as_u64() else {
        return Err(invalid_resource(
            object,
            format!("backendRefs[].weight must be between 0 and {GATEWAY_API_MAX_BACKEND_WEIGHT}"),
        ));
    };
    if weight > GATEWAY_API_MAX_BACKEND_WEIGHT {
        return Err(invalid_resource(
            object,
            format!("backendRefs[].weight must be between 0 and {GATEWAY_API_MAX_BACKEND_WEIGHT}"),
        ));
    }
    Ok(weight as u32)
}

/// Route-level hostnames an L4 route may carry.
///
/// `TLSRoute.spec.hostnames` selects by SNI, so it materializes onto the
/// stream proxy. Gateway API defines **no** `hostnames` field on `UDPRoute`:
/// a datagram carries no name to match on, so a hostname would be silently
/// inert on the data path. Reject it fail closed with a field-specific
/// diagnostic rather than accepting a selector Ferrum can never honor.
/// `TCPRoute` keeps its historical behavior untouched.
fn l4_route_hosts(
    object: &K8sObject,
    scheme: BackendScheme,
) -> Result<Vec<String>, K8sTranslateError> {
    if scheme.is_udp() && object.spec.get("hostnames").is_some() {
        return Err(invalid_resource(
            object,
            format!(
                "{} spec.hostnames is not a Gateway API UDPRoute field and cannot be matched on a datagram listener",
                object.kind
            ),
        ));
    }
    Ok(string_array(&object.spec, "hostnames"))
}

fn ensure_l4_parent_refs_are_same_namespace(object: &K8sObject) -> Result<(), K8sTranslateError> {
    let Some(parent_refs) = object.spec.get("parentRefs").and_then(Value::as_array) else {
        return Ok(());
    };
    for parent_ref in parent_refs {
        let group = string_field(parent_ref, "group").unwrap_or("gateway.networking.k8s.io");
        let kind = string_field(parent_ref, "kind").unwrap_or("Gateway");
        if group == "gateway.networking.k8s.io" && matches!(kind, "Gateway" | "ListenerSet") {
            let parent_namespace =
                string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
            if parent_namespace != object.metadata.namespace {
                return Err(invalid_resource(
                    object,
                    format!(
                        "{} cross-namespace parentRefs are not supported by Ferrum yet",
                        object.kind
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn checked_backend_namespace(
    object: &K8sObject,
    backend_ref: &Value,
    acc: &K8sAccumulator,
    from_kind: &str,
) -> Result<(super::backend_ref::BackendKind, String), K8sTranslateError> {
    super::backend_ref::checked_backend_namespace(object, backend_ref, acc, from_kind)
}

fn first_backend_ref<'a>(
    object: &K8sObject,
    rule: &'a Value,
    acc: &mut K8sAccumulator,
) -> Result<Option<&'a Value>, K8sTranslateError> {
    let Some(backend_refs) = rule.get("backendRefs").and_then(Value::as_array) else {
        return Ok(None);
    };

    let mut selected_backend = None;
    let mut skipped_zero = 0usize;
    for backend_ref in backend_refs {
        let weight = backend_weight(object, backend_ref)?;
        if weight > 0 {
            selected_backend.get_or_insert(backend_ref);
        } else {
            skipped_zero += 1;
        }
    }

    if let Some(backend_ref) = selected_backend {
        if skipped_zero > 0 {
            acc.warnings.push(format!(
                "{} skipped {} zero-weight backendRef(s)",
                object.kind, skipped_zero
            ));
        }
        return Ok(Some(backend_ref));
    }

    if skipped_zero > 0 {
        acc.warnings.push(format!(
            "{} rule has only zero-weight backendRefs; no proxy was materialized",
            object.kind
        ));
    }
    Ok(None)
}

fn http_path_match(path: &Value) -> Option<String> {
    let value = string_field(path, "value")?;
    match string_field(path, "type").unwrap_or("PathPrefix") {
        "Exact" => Some(exact_path_listen_path(value)),
        "RegularExpression" => Some(format!("~{value}")),
        _ => Some(value.to_string()),
    }
}

fn app_protocol(value: Option<&str>) -> AppProtocol {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "http" => AppProtocol::Http,
        "https" | "tls" => AppProtocol::Tls,
        "grpc" => AppProtocol::Grpc,
        "tcp" => AppProtocol::Tcp,
        _ => AppProtocol::Unknown,
    }
}

pub(crate) fn listener_app_protocol(value: Option<&str>) -> AppProtocol {
    app_protocol(value)
}

fn listener_route_kinds_for_protocol(protocol: Option<&str>) -> Vec<&'static str> {
    match protocol.unwrap_or_default().to_ascii_uppercase().as_str() {
        "HTTP" | "HTTPS" => vec!["HTTPRoute", "GRPCRoute"],
        "GRPC" | "GRPCS" => vec!["GRPCRoute"],
        "TCP" => vec!["TCPRoute"],
        "TLS" => vec!["TLSRoute"],
        "UDP" => vec!["UDPRoute"],
        _ => Vec::new(),
    }
}

pub(crate) fn listener_allowed_route_kinds(listener: &Value) -> HashSet<String> {
    if !listener_protocol_mode_is_supported(listener) {
        return HashSet::new();
    }
    let protocol_kinds = listener_route_kinds_for_protocol(string_field(listener, "protocol"));
    if protocol_kinds.is_empty() {
        return HashSet::new();
    }
    let Some(kinds) = listener
        .get("allowedRoutes")
        .and_then(|allowed_routes| allowed_routes.get("kinds"))
        .and_then(Value::as_array)
    else {
        return protocol_kinds.into_iter().map(ToOwned::to_owned).collect();
    };
    kinds
        .iter()
        .filter_map(|kind| listener_allowed_route_kind(kind, &protocol_kinds))
        .map(ToOwned::to_owned)
        .collect()
}

fn listener_allowed_route_kind<'a>(kind: &Value, protocol_kinds: &'a [&str]) -> Option<&'a str> {
    let group = string_field(kind, "group").unwrap_or("gateway.networking.k8s.io");
    let kind = string_field(kind, "kind")?;
    if group != "gateway.networking.k8s.io" {
        return None;
    }
    protocol_kinds
        .iter()
        .copied()
        .find(|allowed| *allowed == kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{
        K8sMetadata, K8sTranslationOptions, gateway_api_status_conflict_context,
        translate_k8s_objects,
    };
    use crate::identity::spiffe::TrustDomain;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn object(kind: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: "sample".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
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

    fn object_in_namespace(kind: &str, namespace: &str, spec: Value) -> K8sObject {
        K8sObject {
            metadata: K8sMetadata {
                namespace: namespace.to_string(),
                generation: None,
                ..object(kind, Value::Null).metadata
            },
            spec,
            ..object(kind, Value::Null)
        }
    }

    fn tls_secret(name: &str, namespace: &str, valid: bool) -> K8sObject {
        use base64::Engine as _;

        let (cert, key) = if valid {
            (
                include_str!("../../../tests/certs/server.crt"),
                include_str!("../../../tests/certs/server.key"),
            )
        } else {
            ("Hello world", "Hello world")
        };
        let mut secret = object_in_namespace(
            "Secret",
            namespace,
            serde_json::json!({
                "type": "kubernetes.io/tls",
                "data": {
                    "tls.crt": base64::engine::general_purpose::STANDARD.encode(cert),
                    "tls.key": base64::engine::general_purpose::STANDARD.encode(key),
                }
            }),
        );
        secret.api_version = "v1".to_string();
        secret.metadata.name = name.to_string();
        secret
    }

    fn tls_secret_with_mismatched_key(name: &str, namespace: &str) -> K8sObject {
        use base64::Engine as _;

        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let mut secret = tls_secret(name, namespace, true);
        secret.spec["data"]["tls.key"] = serde_json::json!(
            base64::engine::general_purpose::STANDARD.encode(key_pair.serialize_pem())
        );
        secret
    }

    #[test]
    fn gateway_https_listener_certificate_ref_sets_frontend_tls_sources() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {
                        "certificateRefs": [{
                            "name": "gateway-cert"
                        }]
                    }
                }]
            }),
        );

        let secret = tls_secret("gateway-cert", "default", true);
        let result =
            translate_k8s_objects(&[gateway, secret], options()).expect("translation succeeds");
        assert!(
            result
                .config
                .frontend_tls_cert_path
                .as_deref()
                .is_some_and(|path| path.starts_with("k8s://default/gateway-cert#tls.crt?sha256="))
        );
        assert!(
            result
                .config
                .frontend_tls_key_path
                .as_deref()
                .is_some_and(|path| path.starts_with("k8s://default/gateway-cert#tls.key?sha256="))
        );
        assert_eq!(
            result.config.frontend_tls_source_namespace.as_deref(),
            Some("default")
        );
        assert_eq!(result.config.frontend_tls_certificate_sources.len(), 1);
        assert_eq!(
            result.config.frontend_tls_certificate_sources[0].namespace,
            "default"
        );
    }

    #[test]
    fn gateway_frontend_tls_sources_are_partitioned_by_gateway_namespace() {
        let mut gateway_a = object_in_namespace(
            "Gateway",
            "ns-a",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "cert-a"}]}
                }]
            }),
        );
        gateway_a.metadata.name = "gateway-a".to_string();
        let mut gateway_b = object_in_namespace(
            "Gateway",
            "ns-b",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "cert-b"}]}
                }]
            }),
        );
        gateway_b.metadata.name = "gateway-b".to_string();
        let secret_a = tls_secret("cert-a", "ns-a", true);
        let secret_b = tls_secret("cert-b", "ns-b", true);

        let result = translate_k8s_objects(
            &[gateway_a, gateway_b, secret_a, secret_b],
            options().with_source_namespaces(vec!["ns-a".to_string(), "ns-b".to_string()]),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
        let source_a = result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .find(|source| source.namespace == "ns-a")
            .expect("ns-a TLS source should be retained");
        let source_b = result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .find(|source| source.namespace == "ns-b")
            .expect("ns-b TLS source should be retained");
        assert!(
            source_a
                .cert_path
                .starts_with("k8s://ns-a/cert-a#tls.crt?sha256=")
        );
        assert!(
            source_b
                .cert_path
                .starts_with("k8s://ns-b/cert-b#tls.crt?sha256=")
        );
    }

    #[test]
    fn gateway_frontend_tls_ignores_gateway_owned_by_other_controller() {
        let mut other_class = object(
            "GatewayClass",
            serde_json::json!({"controllerName": "example.com/other-controller"}),
        );
        other_class.metadata.name = "other".to_string();
        other_class.metadata.namespace.clear();

        let other_gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "other",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "other-cert"}]}
                }]
            }),
        );
        let ferrum_gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "ferrum-cert"}]}
                }]
            }),
        );
        let other_cert = tls_secret("other-cert", "default", true);
        let ferrum_cert = tls_secret("ferrum-cert", "default", true);

        let result = translate_k8s_objects(
            &[
                other_class,
                other_gateway,
                other_cert,
                ferrum_gateway,
                ferrum_cert,
            ],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            result
                .config
                .frontend_tls_cert_path
                .as_deref()
                .is_some_and(|path| path.starts_with("k8s://default/ferrum-cert#tls.crt?sha256=")),
            "only Ferrum-owned Gateways should materialize frontend TLS"
        );
    }

    #[test]
    fn gateway_https_listener_certificate_ref_requires_observed_valid_secret() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {
                        "certificateRefs": [{
                            "name": "gateway-cert"
                        }]
                    }
                }]
            }),
        );
        let malformed = tls_secret("gateway-cert", "default", false);

        let missing_secret = translate_k8s_objects(std::slice::from_ref(&gateway), options())
            .expect("translation succeeds");
        assert_eq!(missing_secret.config.frontend_tls_cert_path, None);
        assert_eq!(missing_secret.config.frontend_tls_key_path, None);

        let malformed_secret = translate_k8s_objects(&[gateway.clone(), malformed], options())
            .expect("translation succeeds");
        assert_eq!(malformed_secret.config.frontend_tls_cert_path, None);
        assert_eq!(malformed_secret.config.frontend_tls_key_path, None);

        let mismatched = tls_secret_with_mismatched_key("gateway-cert", "default");
        let mismatched_secret =
            translate_k8s_objects(&[gateway, mismatched], options()).expect("translation succeeds");
        assert_eq!(mismatched_secret.config.frontend_tls_cert_path, None);
        assert_eq!(mismatched_secret.config.frontend_tls_key_path, None);
    }

    #[test]
    fn gateway_https_listener_certificate_refs_fail_closed_when_any_ref_is_unresolved() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {
                        "certificateRefs": [
                            {"name": "gateway-cert"},
                            {"name": "missing-cert"}
                        ]
                    }
                }]
            }),
        );
        let valid = tls_secret("gateway-cert", "default", true);

        let result = translate_k8s_objects(&[gateway, valid], options())
            .expect("translation should leave unresolved TLS unmaterialized");

        assert_eq!(result.config.frontend_tls_cert_path, None);
        assert_eq!(result.config.frontend_tls_key_path, None);
        assert!(result.config.frontend_tls_certificate_sources.is_empty());
        // Multi-ref path uses a field-scoped diagnostic (no Secret bytes / digests);
        // one unresolved ref still fails the whole listener closed.
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains(
                    "certificateRefs has at least one reference that is not an authorized, valid kubernetes.io/tls Secret",
                )
            }),
            "expected authorized-Secret diagnostic, got: {:?}",
            result.warnings
        );
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains("listener https is not materializable and will not be exposed")
            }),
            "expected exposure-skip diagnostic, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn gateway_https_listener_without_certificate_refs_fails_closed() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {}
                }]
            }),
        );

        let result = translate_k8s_objects(&[gateway], options())
            .expect("translation should leave listener TLS unmaterialized");

        assert_eq!(result.config.frontend_tls_cert_path, None);
        assert_eq!(result.config.frontend_tls_key_path, None);
        assert!(result.config.frontend_tls_certificate_sources.is_empty());
        assert!(
            result
                .config
                .mesh
                .as_ref()
                .is_none_or(|mesh| mesh.services.is_empty()),
            "invalid terminating TLS listener must not be exposed as a data-plane service"
        );
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains(
                    "certificateRefs is empty on a Terminate-mode listener; leaving this listener's frontend TLS unmaterialized",
                )
            }),
            "expected empty-certificateRefs diagnostic, got: {:?}",
            result.warnings
        );
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains("listener https is not materializable and will not be exposed")
            }),
            "expected exposure-skip diagnostic, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn gateway_https_listener_without_tls_block_fails_closed() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS"
                }]
            }),
        );

        let result = translate_k8s_objects(&[gateway], options())
            .expect("translation should leave listener TLS unmaterialized");

        assert_eq!(result.config.frontend_tls_cert_path, None);
        assert_eq!(result.config.frontend_tls_key_path, None);
        assert!(result.config.frontend_tls_certificate_sources.is_empty());
        assert!(
            result
                .config
                .mesh
                .as_ref()
                .is_none_or(|mesh| mesh.services.is_empty()),
            "HTTPS listeners without TLS material must not be exposed as plaintext services"
        );
        // Missing `tls` is treated as an empty certificateRefs set for Terminate.
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains(
                    "certificateRefs is empty on a Terminate-mode listener; leaving this listener's frontend TLS unmaterialized",
                )
            }),
            "expected empty-certificateRefs diagnostic, got: {:?}",
            result.warnings
        );
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains("listener https is not materializable and will not be exposed")
            }),
            "expected exposure-skip diagnostic, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn http_route_attaches_but_does_not_materialize_for_invalid_tls_listener() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {}
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "sectionName": "https"
                }],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(&[gateway, route], options())
            .expect("invalid TLS listener should not reject route attachment");

        assert!(result.config.proxies.is_empty());
        assert!(
            result
                .config
                .mesh
                .as_ref()
                .is_none_or(|mesh| mesh.services.is_empty())
        );
    }

    #[test]
    fn gateway_valid_tls_listener_materializes_when_sibling_tls_listener_is_invalid() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https-valid",
                        "port": 443,
                        "protocol": "HTTPS",
                        "tls": {"certificateRefs": [{"name": "valid-cert"}]}
                    },
                    {
                        "name": "https-invalid",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "tls": {"certificateRefs": [{"name": "missing-cert"}]}
                    }
                ]
            }),
        );
        let cert = tls_secret("valid-cert", "default", true);

        let result = translate_k8s_objects(&[gateway, cert], options())
            .expect("valid sibling TLS listener should materialize");

        assert!(
            result
                .config
                .frontend_tls_cert_path
                .as_deref()
                .is_some_and(|path| path.starts_with("k8s://default/valid-cert#tls.crt?sha256="))
        );
        let mesh = result.config.mesh.as_ref().expect("mesh emitted");
        assert!(
            mesh.services
                .iter()
                .any(|service| service.name == "gateway-6-sample-https-valid")
        );
        assert!(
            mesh.services
                .iter()
                .all(|service| service.name != "gateway-6-sample-https-invalid")
        );
    }

    #[test]
    fn same_namespace_gateways_each_serve_their_own_certificate() {
        let mut gateway_a = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https-a",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "cert-a"}]}
                }]
            }),
        );
        gateway_a.metadata.name = "edge-a".to_string();
        let mut gateway_b = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https-b",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "cert-b"}]}
                }]
            }),
        );
        gateway_b.metadata.name = "edge-b".to_string();
        let cert_a = tls_secret("cert-a", "default", true);
        let cert_b = tls_secret("cert-b", "default", true);
        let route_b = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge-b", "sectionName": "https-b"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/b"}}],
                    "backendRefs": [{"name": "backend", "port": 8080}]
                }]
            }),
        );

        let result =
            translate_k8s_objects(&[gateway_a, cert_a, gateway_b, cert_b, route_b], options())
                .expect("translation should keep valid same-namespace TLS listener status");

        // Issue #3268: a namespace is not a one-certificate slot. Both
        // Gateways keep their own certificate and both serve route traffic.
        assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
        assert!(
            result
                .config
                .frontend_tls_certificate_sources
                .iter()
                .any(|source| source.gateway == "edge-a"
                    && source
                        .cert_path
                        .starts_with("k8s://default/cert-a#tls.crt?sha256="))
        );
        assert!(
            result
                .config
                .frontend_tls_certificate_sources
                .iter()
                .any(|source| source.gateway == "edge-b"
                    && source
                        .cert_path
                        .starts_with("k8s://default/cert-b#tls.crt?sha256="))
        );
        assert_eq!(
            result
                .config
                .frontend_tls_certificate_sources
                .iter()
                .filter(|source| source.default_certificate)
                .count(),
            1,
            "exactly one fallback certificate per namespace"
        );
        assert!(result.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "gateway-6-edge-a-https-a")
        }));
        assert!(result.config.mesh.as_ref().is_some_and(|mesh| {
            mesh.services
                .iter()
                .any(|service| service.name == "gateway-6-edge-b-https-b")
        }));
        assert!(
            !result.config.proxies.is_empty(),
            "the second Gateway's routes must materialize now that it owns its own certificate"
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|warning| warning.contains("route traffic on this listener unmaterialized")),
            "no listener is withdrawn when the hostnames do not collide"
        );
    }

    #[test]
    fn gateway_cross_namespace_certificate_ref_requires_reference_grant() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {
                        "certificateRefs": [{
                            "name": "gateway-cert",
                            "namespace": "certs"
                        }]
                    }
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "certs",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Secret",
                    "name": "gateway-cert"
                }]
            }),
        );
        let secret = tls_secret("gateway-cert", "certs", true);

        let without_grant = translate_k8s_objects(std::slice::from_ref(&gateway), options())
            .expect("translation succeeds");
        assert_eq!(without_grant.config.frontend_tls_cert_path, None);

        let with_grant = translate_k8s_objects(
            &[gateway, grant, secret],
            options().with_source_namespaces(vec!["default".to_string(), "certs".to_string()]),
        )
        .expect("translation succeeds");
        assert!(
            with_grant
                .config
                .frontend_tls_cert_path
                .as_deref()
                .is_some_and(|path| path.starts_with("k8s://certs/gateway-cert#tls.crt?sha256="))
        );
        assert!(
            with_grant
                .config
                .frontend_tls_key_path
                .as_deref()
                .is_some_and(|path| path.starts_with("k8s://certs/gateway-cert#tls.key?sha256="))
        );
        assert_eq!(
            with_grant.config.frontend_tls_source_namespace.as_deref(),
            Some("default")
        );
    }

    #[test]
    fn gateway_tls_secret_data_changes_frontend_tls_source_digest() {
        use base64::Engine as _;

        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": {"certificateRefs": [{"name": "gateway-cert"}]}
                }]
            }),
        );
        let original = tls_secret("gateway-cert", "default", true);
        let mut rotated = tls_secret("gateway-cert", "default", true);
        rotated.spec["data"]["tls.crt"] = serde_json::json!(
            base64::engine::general_purpose::STANDARD
                .encode("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n")
        );

        let original_result =
            translate_k8s_objects(&[gateway.clone(), original], options()).expect("original");
        let rotated_result =
            translate_k8s_objects(&[gateway, rotated], options()).expect("rotated");

        assert_ne!(
            original_result.config.frontend_tls_cert_path,
            rotated_result.config.frontend_tls_cert_path,
            "Secret data changes must alter the stable source string so CP broadcasts a snapshot"
        );
    }

    #[test]
    fn gateway_multiple_distinct_certificate_refs_all_serve() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https-a",
                        "port": 443,
                        "protocol": "HTTPS",
                        "tls": {"certificateRefs": [{"name": "gateway-cert-a"}]}
                    },
                    {
                        "name": "https-b",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "tls": {"certificateRefs": [{"name": "gateway-cert-b"}]}
                    }
                ]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample", "sectionName": "https-a"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        let cert_a = tls_secret("gateway-cert-a", "default", true);
        let cert_b = tls_secret("gateway-cert-b", "default", true);

        let result = translate_k8s_objects(&[gateway, cert_a, cert_b, route], options())
            .expect("translation");

        // Issue #3267: two listeners with distinct certificateRefs both
        // materialize and both are offered for SNI selection.
        assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
        let listeners: Vec<&str> = result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .map(|source| source.listener.as_str())
            .collect();
        assert!(listeners.contains(&"https-a") && listeners.contains(&"https-b"));
        assert!(
            result
                .config
                .frontend_tls_cert_path
                .as_deref()
                .is_some_and(|path| path.starts_with("k8s://default/gateway-cert-")),
            "the fallback certificate is still projected for a ClientHello with no usable SNI"
        );
        assert!(
            !result.config.proxies.is_empty(),
            "routes attached to a listener with its own certificate must materialize"
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|warning| warning.contains("multiple distinct TLS certificateRefs"))
        );
    }

    fn core_service(name: &str, spec: Value) -> K8sObject {
        let mut service = object("Service", spec);
        service.api_version = "v1".to_string();
        service.metadata.name = name.to_string();
        service
    }

    fn endpoint_slice_for_service(service_name: &str, endpoints: Vec<Value>) -> K8sObject {
        let mut slice = object(
            "EndpointSlice",
            serde_json::json!({
                "addressType": "IPv4",
                "ports": [{"name": "first-port", "port": 3000}],
                "endpoints": endpoints
            }),
        );
        slice.api_version = "discovery.k8s.io/v1".to_string();
        slice.metadata.name = format!("{service_name}-manual");
        slice.metadata.labels.insert(
            "kubernetes.io/service-name".to_string(),
            service_name.to_string(),
        );
        slice
    }

    fn namespace(name: &str, labels: &[(&str, &str)]) -> K8sObject {
        let mut ns = object("Namespace", Value::Object(serde_json::Map::new()));
        ns.api_version = "v1".to_string();
        ns.metadata.name = name.to_string();
        ns.metadata.namespace = String::new();
        ns.metadata.labels = labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        ns
    }

    fn route_with_name_and_created_at(name: &str, created_at: &str) -> K8sObject {
        let mut route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        route.metadata.name = name.to_string();
        route.metadata.creation_timestamp = Some(created_at.to_string());
        route
    }

    /// Resolvable Gateway for conflict/dispatch fixtures that declare
    /// `parentRefs: [{"name": "edge"}]`. Declared parents with no concrete
    /// listener correctly emit zero routes; these tests exercise resolved
    /// listener arbitration and need an explicit attachment target.
    fn edge_http_gateway() -> K8sObject {
        edge_http_gateway_ports(&[80])
    }

    fn edge_http_gateway_ports(ports: &[u16]) -> K8sObject {
        let listeners: Vec<Value> = ports
            .iter()
            .map(|port| {
                serde_json::json!({
                    "name": format!("http-{port}"),
                    "port": port,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {"from": "All"},
                        "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
                    }
                })
            })
            .collect();
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": listeners
            }),
        );
        gateway.metadata.name = "edge".to_string();
        gateway
    }

    fn assert_invalid_backend_fault_route(
        result: &crate::config_sources::k8s::K8sTranslation,
        expected_body: &str,
    ) {
        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            ZERO_WEIGHT_BACKEND_HOST
        );
        assert_eq!(
            result.config.proxies[0].backend_port,
            ZERO_WEIGHT_BACKEND_PORT
        );
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("invalid backend route should carry mesh_route_dispatch");
        let abort = &plugin.config["rules"][0]["fault"]["abort"];
        assert_eq!(abort["status_code"], 500);
        assert_eq!(abort["percentage"], 100.0);
        let body = abort["body"]
            .as_str()
            .expect("fault body should be a string");
        let body: Value = serde_json::from_str(body).expect("fault body should be valid JSON");
        assert_eq!(body["error"].as_str(), Some(expected_body));
    }

    #[test]
    fn translates_http_route_to_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].hosts, vec!["api.example.com"]);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/api")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn http_route_proxy_hosts_are_limited_to_gateway_listener_hostname_intersections() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "specific",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "very.specific.com"
                    },
                    {
                        "name": "wildcard",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "*.wildcard.io"
                    }
                ]
            }),
        );
        let exact_route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample", "sectionName": "specific"}],
                "hostnames": [
                    "non.matching.com",
                    "*.nonmatchingwildcard.io",
                    "very.specific.com"
                ],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/s1"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        let wildcard_listener_route = {
            let mut route = object(
                "HTTPRoute",
                serde_json::json!({
                    "parentRefs": [{"name": "sample", "sectionName": "wildcard"}],
                    "hostnames": ["wildcard.io", "foo.wildcard.io"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s2"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            );
            route.metadata.name = "wildcard-listener".to_string();
            route
        };
        let wildcard_route_specific_listener = {
            let mut route = object(
                "HTTPRoute",
                serde_json::json!({
                    "parentRefs": [{"name": "sample", "sectionName": "specific"}],
                    "hostnames": ["*.specific.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s3"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            );
            route.metadata.name = "wildcard-route".to_string();
            route
        };
        let omitted_route_hostname = {
            let mut route = object(
                "HTTPRoute",
                serde_json::json!({
                    "parentRefs": [{"name": "sample", "sectionName": "specific"}],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/s4"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            );
            route.metadata.name = "omitted-hostname".to_string();
            route
        };

        let result = translate_k8s_objects(
            &[
                gateway,
                exact_route,
                wildcard_listener_route,
                wildcard_route_specific_listener,
                omitted_route_hostname,
            ],
            options(),
        )
        .expect("translation succeeds");

        assert_proxy_hosts(&result.config.proxies, "/s1", &["very.specific.com"]);
        assert_proxy_hosts(&result.config.proxies, "/s2", &["foo.wildcard.io"]);
        assert_proxy_hosts(&result.config.proxies, "/s3", &["very.specific.com"]);
        assert_proxy_hosts(&result.config.proxies, "/s4", &["very.specific.com"]);
    }

    #[test]
    fn http_route_without_gateway_listener_hostname_intersection_materializes_no_proxy() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "specific",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "very.specific.com"
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample", "sectionName": "specific"}],
                "hostnames": ["specific.but.wrong.com", "wildcard.io"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/s5"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(&[gateway, route], options())
            .expect("translation should skip the non-intersecting route");

        assert!(
            result.config.proxies.is_empty(),
            "route with no listener hostname intersection must fail closed"
        );
    }

    #[test]
    fn conflicting_http_routes_use_oldest_creation_timestamp_winner() {
        let newer = route_with_name_and_created_at("api-b", "2026-01-02T00:00:00Z");
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");

        let result = translate_k8s_objects(&[edge_http_gateway(), newer, older], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-a"),
            "oldest route must win the conflicting host/path"
        );
        assert!(result.warnings.iter().any(
            |warning| warning.contains("api-b") && warning.contains("winner is default/api-a")
        ));
    }

    #[test]
    fn translation_surfaces_conflict_list_to_status_writer() {
        // The status writer reuses `K8sTranslation.route_conflicts` so it
        // doesn't recompute conflicts (and so invalid, translator-skipped
        // routes don't leak into a valid sibling's `Conflicted` condition).
        // Guard the wiring: the same conflict that drove the warning must
        // also appear on the translation's exposed conflict list.
        let newer = route_with_name_and_created_at("api-b", "2026-01-02T00:00:00Z");
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");

        let result = translate_k8s_objects(&[edge_http_gateway(), newer, older], options())
            .expect("translation succeeds");

        assert!(
            result
                .route_conflicts
                .iter()
                .any(|conflict| conflict.loser.name == "api-b" && conflict.winner.name == "api-a"),
            "translator must surface conflict for the losing route on K8sTranslation: {:?}",
            result.route_conflicts
        );
    }

    #[test]
    fn conflicting_http_route_timestamp_tie_uses_name_winner() {
        let right = route_with_name_and_created_at("api-b", "2026-01-01T00:00:00Z");
        let left = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");

        let result = translate_k8s_objects(&[edge_http_gateway(), right, left], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-a"),
            "lexicographically earlier route name must win timestamp ties"
        );
    }

    #[test]
    fn conflicting_http_routes_normalize_hostname_case() {
        let mut upper = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        upper.spec["hostnames"] = serde_json::json!(["Api.Example.Com"]);
        let lower = route_with_name_and_created_at("api-b", "2026-01-02T00:00:00Z");

        let result = translate_k8s_objects(&[edge_http_gateway(), lower, upper], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-a"),
            "case-equivalent hostnames must share one conflict bucket"
        );
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("host=api.example.com") && warning.contains("winner is default/api-a")
        }));
    }

    #[test]
    fn conflicting_http_route_keeps_surviving_parent_ref() {
        let mut gateway_a = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "api.example.com"
                }]
            }),
        );
        gateway_a.metadata.name = "edge-a".to_string();

        let mut gateway_b = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "other.example.com"
                }]
            }),
        );
        gateway_b.metadata.name = "edge-b".to_string();

        let mut winner = route_with_name_and_created_at("api-old", "2026-01-01T00:00:00Z");
        winner.spec["hostnames"] = serde_json::json!(["api.example.com"]);
        winner.spec["parentRefs"] = serde_json::json!([{"name": "edge-a"}]);

        let mut loser = route_with_name_and_created_at("api-new", "2026-01-02T00:00:00Z");
        loser.spec["hostnames"] = serde_json::json!(["api.example.com", "other.example.com"]);
        loser.spec["parentRefs"] = serde_json::json!([{"name": "edge-a"}, {"name": "edge-b"}]);

        let result = translate_k8s_objects(&[gateway_a, gateway_b, loser, winner], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert!(
            result.config.proxies.iter().any(|proxy| {
                proxy.id.contains("api-old")
                    && proxy.hosts == vec!["api.example.com".to_string()]
                    && proxy.listen_path.as_deref() == Some("/api")
            }),
            "winner should keep the conflicted edge-a hostname"
        );
        assert!(
            result.config.proxies.iter().any(|proxy| {
                proxy.id.contains("api-new")
                    && proxy.hosts == vec!["other.example.com".to_string()]
                    && proxy.listen_path.as_deref() == Some("/api")
            }),
            "loser should still materialize the surviving edge-b hostname"
        );
        assert!(result.config.validate_unique_listen_paths().is_ok());
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("api-new")
                && warning.contains("parent=gateway.networking.k8s.io/Gateway/default/edge-a/*/*")
                && warning.contains("winner is default/api-old")
        }));
    }

    /// Same hostname+path on distinct HTTP and HTTPS listeners must validate
    /// and stamp each admitting listener port onto the materialized proxies.
    #[test]
    fn http_and_https_listeners_share_host_path_without_collision() {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "http",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "app.example.com",
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    },
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "hostname": "app.example.com",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        );
        gateway.metadata.name = "edge".to_string();
        let secret = tls_secret("app-cert", "default", true);
        let http_route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "http"}],
                "hostnames": ["app.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-plain", "port": 8080}]
                }]
            }),
        );
        let mut https_route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "https"}],
                "hostnames": ["app.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-tls", "port": 8443}]
                }]
            }),
        );
        https_route.metadata.name = "https-api".to_string();

        let result = translate_k8s_objects(&[gateway, secret, http_route, https_route], options())
            .expect("translation succeeds");

        assert!(
            result.config.validate_unique_listen_paths().is_ok(),
            "distinct listeners must not collide: {:?}",
            result.config.validate_unique_listen_paths()
        );
        let mut listen_ports: Vec<Option<u16>> = result
            .config
            .proxies
            .iter()
            .filter(|proxy| proxy.listen_path.as_deref() == Some("/api"))
            .map(|proxy| proxy.listen_port)
            .collect();
        listen_ports.sort();
        assert_eq!(listen_ports, vec![Some(80), Some(443)]);
        assert!(
            result
                .config
                .http_tls_listen_ports
                .contains(&("default".to_string(), 443)),
            "HTTPS listener ports must be recorded for TLS frontend matching: {:?}",
            result.config.http_tls_listen_ports
        );
        assert!(
            !result
                .config
                .http_tls_listen_ports
                .contains(&("default".to_string(), 80)),
            "the plaintext listener must not be TLS-classified: {:?}",
            result.config.http_tls_listen_ports
        );
    }

    /// Two sibling listeners of ONE Gateway sharing a numeric port (the
    /// standard multi-hostname HTTPS pattern) are independent claims: neither
    /// suppresses the other, and both materialize.
    #[test]
    fn sibling_listeners_sharing_a_port_do_not_suppress_each_other() {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https-a",
                        "port": 443,
                        "protocol": "HTTPS",
                        "hostname": "a.example.com",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    },
                    {
                        "name": "https-b",
                        "port": 443,
                        "protocol": "HTTPS",
                        "hostname": "b.example.com",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        );
        gateway.metadata.name = "edge".to_string();
        let secret = tls_secret("app-cert", "default", true);
        let route_a = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "https-a"}],
                "hostnames": ["a.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-a", "port": 8080}]
                }]
            }),
        );
        let mut route_b = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "https-b"}],
                "hostnames": ["b.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-b", "port": 8081}]
                }]
            }),
        );
        route_b.metadata.name = "route-b".to_string();

        let result = translate_k8s_objects(&[gateway, secret, route_a, route_b], options())
            .expect("translation succeeds");

        let mut backends: Vec<u16> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.backend_port)
            .collect();
        backends.sort_unstable();
        assert_eq!(
            backends,
            vec![8080, 8081],
            "both same-port sibling listeners must materialize: {:?}",
            result.config.proxies
        );
        assert!(
            result
                .config
                .proxies
                .iter()
                .all(|proxy| proxy.listen_port == Some(443)),
            "both claims live on the shared numeric port"
        );
        assert!(
            result.config.validate_unique_listen_paths().is_ok(),
            "distinct hostnames keep the shared port valid: {:?}",
            result.config.validate_unique_listen_paths()
        );
    }

    /// A numeric port claimed by one plaintext and one TLS-terminating
    /// listener is physically unservable — one socket cannot be both. Both
    /// claims are refused at admission with an explicit diagnostic rather than
    /// one silently winning the socket.
    #[test]
    fn incompatible_same_port_listeners_are_refused_at_admission() {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "plain",
                        "port": 8443,
                        "protocol": "HTTP",
                        "hostname": "a.example.com",
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    },
                    {
                        "name": "secure",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "hostname": "b.example.com",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        );
        gateway.metadata.name = "edge".to_string();
        let secret = tls_secret("app-cert", "default", true);
        let plain_route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "plain"}],
                "hostnames": ["a.example.com"],
                "rules": [{"backendRefs": [{"name": "web-a", "port": 8080}]}]
            }),
        );
        let mut secure_route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "secure"}],
                "hostnames": ["b.example.com"],
                "rules": [{"backendRefs": [{"name": "web-b", "port": 8081}]}]
            }),
        );
        secure_route.metadata.name = "secure-route".to_string();

        let result =
            translate_k8s_objects(&[gateway, secret, plain_route, secure_route], options())
                .expect("translation succeeds");

        assert!(
            result.config.proxies.is_empty(),
            "neither incompatible same-port claim may program traffic: {:?}",
            result.config.proxies
        );
        assert!(
            result.config.http_tls_listen_ports.is_empty(),
            "a refused listener must not leave a TLS classification behind: {:?}",
            result.config.http_tls_listen_ports
        );
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains(
                    "Port 8443 is claimed by both plaintext and an effective TLS-serving \
                     frontend shape",
                )
            }),
            "the refusal must be reported: {:?}",
            result.warnings
        );
        for (key, conflict) in &result.listener_conflicts {
            assert_eq!(conflict.reason, "ProtocolConflict");
            assert_eq!(
                conflict.message,
                "Port 8443 is claimed by both plaintext and an effective TLS-serving \
                 frontend shape, so every conflicting claim on this port is refused \
                 (Conflicted)."
            );
            assert!(
                !conflict.message.contains(&key.to_string())
                    && !conflict.message.contains("a.example.com")
                    && !conflict.message.contains("b.example.com")
                    && !conflict.message.contains("app-cert")
                    && !conflict.message.contains("Gateway API listeners ["),
                "physical conflict message must not disclose listener identities: {} => {}",
                key,
                conflict.message
            );
        }
    }

    /// GRPCS terminates frontend TLS just like HTTPS. Treating it as plaintext
    /// would make an otherwise compatible GRPCS sibling withdraw HTTPS routes.
    #[test]
    fn grpcs_same_port_listener_does_not_withdraw_https_routes() {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "hostname": "web.example.com",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]}
                    },
                    {
                        "name": "grpcs",
                        "port": 443,
                        "protocol": "GRPCS",
                        "hostname": "grpc.example.com",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]}
                    }
                ]
            }),
        );
        gateway.metadata.name = "edge".to_string();
        let secret = tls_secret("app-cert", "default", true);
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "https"}],
                "hostnames": ["web.example.com"],
                "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
            }),
        );

        let result = translate_k8s_objects(&[gateway, secret, route], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_port, Some(443));
        assert!(
            result
                .config
                .http_tls_listen_ports
                .contains(&("default".to_string(), 443))
        );
        assert!(
            result
                .warnings
                .iter()
                .all(|warning| !warning.contains("incompatible frontend shapes")),
            "compatible HTTPS/GRPCS listeners must not conflict: {:?}",
            result.warnings
        );
    }

    /// Adversarial: two DIFFERENT Gateways share a numeric port with a
    /// compatible plaintext shape, and each admits a Route claiming the same
    /// host + path. Gateway API attached neither Route to the other's
    /// listener, so their dispatch rules and default backends must never be
    /// combined — and the two claims cannot both own one physical route-table
    /// slot either, so both are refused rather than one silently absorbing
    /// the other's routing policy.
    #[test]
    fn routes_on_different_same_port_listeners_never_combine_routing_policy() {
        let mut gateway_a = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 8080,
                    "protocol": "HTTP",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }]
            }),
        );
        gateway_a.metadata.name = "edge-a".to_string();
        let mut gateway_b = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 8080,
                    "protocol": "HTTP",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }]
            }),
        );
        gateway_b.metadata.name = "edge-b".to_string();

        let mut route_a = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge-a", "sectionName": "http"}],
                "hostnames": ["app.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-a", "port": 8080}]
                }]
            }),
        );
        route_a.metadata.name = "route-a".to_string();
        let mut route_b = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge-b", "sectionName": "http"}],
                "hostnames": ["app.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-b", "port": 9090}]
                }]
            }),
        );
        route_b.metadata.name = "route-b".to_string();

        for objects in [
            vec![
                gateway_a.clone(),
                gateway_b.clone(),
                route_a.clone(),
                route_b.clone(),
            ],
            // Order must not decide the outcome.
            vec![gateway_b, gateway_a, route_b, route_a],
        ] {
            let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

            assert!(
                result.config.proxies.is_empty(),
                "an ambiguous same-slot claim from two listeners must materialize nothing: {:?}",
                result.config.proxies
            );
            assert!(
                !result
                    .config
                    .plugin_configs
                    .iter()
                    .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
                "no combined dispatch plugin may survive: {:?}",
                result.config.plugin_configs
            );
            assert!(
                result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("physically ambiguous")),
                "the refusal must be reported: {:?}",
                result.warnings
            );
            // The refusal has to reach status too: a Route may not advertise a
            // materialized Ferrum parent for a slot the data plane withdrew.
            assert!(
                result.materialized_route_parents.is_empty(),
                "a refused claim must leave no materialized parent: {:?}",
                result.materialized_route_parents
            );
            assert_eq!(
                result.refused_route_attachments.len(),
                2,
                "both sides of the ambiguity must be reported to status"
            );
            assert!(
                result.config.validate_unique_listen_paths().is_ok(),
                "the refusal must leave a valid config: {:?}",
                result.config.validate_unique_listen_paths()
            );
        }
    }

    /// The compatible case must keep working: two listeners sharing a port
    /// with DISJOINT hostnames each keep their own proxy, their own dispatch
    /// plugin, and their own backend — nothing is merged across listeners.
    #[test]
    fn same_port_listeners_with_disjoint_hostnames_keep_independent_routing() {
        let mut gateway_a = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "a.example.com",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }]
            }),
        );
        gateway_a.metadata.name = "edge-a".to_string();
        let mut gateway_b = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "b.example.com",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }]
            }),
        );
        gateway_b.metadata.name = "edge-b".to_string();

        let mut route_a = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge-a", "sectionName": "http"}],
                "hostnames": ["a.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-a", "port": 8080}]
                }]
            }),
        );
        route_a.metadata.name = "route-a".to_string();
        let mut route_b = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge-b", "sectionName": "http"}],
                "hostnames": ["b.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web-b", "port": 9090}]
                }]
            }),
        );
        route_b.metadata.name = "route-b".to_string();

        let result = translate_k8s_objects(&[gateway_a, gateway_b, route_a, route_b], options())
            .expect("translation succeeds");

        let mut backends: Vec<u16> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.backend_port)
            .collect();
        backends.sort_unstable();
        assert_eq!(
            backends,
            vec![8080, 9090],
            "both same-port listeners must keep their own route: {:?}",
            result.config.proxies
        );
        assert!(
            result
                .config
                .proxies
                .iter()
                .all(|proxy| proxy.listen_port == Some(8080)),
            "both claims live on the shared numeric port"
        );
        assert!(
            result.config.validate_unique_listen_paths().is_ok(),
            "disjoint hostnames keep the shared port valid: {:?}",
            result.config.validate_unique_listen_paths()
        );
    }

    /// An unknown sectionName fails closed with no materialization for that claim.
    #[test]
    fn missing_section_name_listener_does_not_materialize() {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "app.example.com",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }]
            }),
        );
        gateway.metadata.name = "edge".to_string();
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "edge", "sectionName": "does-not-exist"}],
                "hostnames": ["app.example.com"],
                "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
            }),
        );

        // An explicit `sectionName` that names no listener is operator error,
        // not an unknown-Gateway selector: the route is refused fail-closed at
        // admission, which is strictly stronger than materializing nothing.
        let error = translate_k8s_objects(&[gateway, route], options())
            .expect_err("an unknown sectionName must be refused fail-closed");
        assert!(
            format!("{error:?}").contains("does not match any known Gateway listener"),
            "unknown sectionName must not program traffic: {error:?}"
        );
    }

    #[test]
    fn conflicting_http_route_materializes_surviving_parent_namespace() {
        let mut gateway_a = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );
        gateway_a.metadata.name = "edge-a".to_string();

        let mut gateway_b = gateway_a.clone();
        gateway_b.metadata.name = "edge-b".to_string();
        gateway_b.metadata.namespace = "other".to_string();
        gateway_b.spec["listeners"][0]["allowedRoutes"] =
            serde_json::json!({"namespaces": {"from": "All"}});

        let mut winner = route_with_name_and_created_at("api-old", "2026-01-01T00:00:00Z");
        winner.spec["parentRefs"] = serde_json::json!([{"name": "edge-a"}]);

        let mut loser = route_with_name_and_created_at("api-new", "2026-01-02T00:00:00Z");
        loser.spec["parentRefs"] = serde_json::json!([
            {"name": "edge-a"},
            {"name": "edge-b", "namespace": "other"}
        ]);

        let result = translate_k8s_objects(
            &[gateway_a, gateway_b, loser, winner],
            options().with_source_namespaces(vec!["default".to_string(), "other".to_string()]),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.namespace == "default"
                && proxy.id.contains("api-old")
                && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.namespace == "other"
                && proxy.id.contains("api-new")
                && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(result.config.validate_unique_listen_paths().is_ok());
    }

    #[test]
    fn http_route_conflicts_use_listener_hostname_intersection() {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "api",
                    "port": 80,
                    "protocol": "HTTP",
                    "hostname": "api.example.com"
                }]
            }),
        );
        gateway.metadata.name = "edge".to_string();
        let mut wildcard = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        wildcard.spec["hostnames"] = serde_json::json!(["*.example.com"]);
        wildcard.spec["parentRefs"] = serde_json::json!([{"name": "edge", "sectionName": "api"}]);

        let mut exact = route_with_name_and_created_at("api-b", "2026-01-02T00:00:00Z");
        exact.spec["hostnames"] = serde_json::json!(["api.example.com"]);
        exact.spec["parentRefs"] = serde_json::json!([{"name": "edge", "sectionName": "api"}]);

        let result =
            translate_k8s_objects(&[gateway, exact, wildcard], options()).expect("translation");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-a"),
            "older route should win after both routes intersect the same listener hostname"
        );
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("api-b")
                && warning.contains("host=api.example.com")
                && warning.contains("winner is default/api-a")
        }));
    }

    #[test]
    fn http_route_listener_exact_and_wildcard_hosts_validate_together() {
        let mut exact = route_with_name_and_created_at("backend-v2", "2026-01-01T00:00:00Z");
        exact.spec["hostnames"] = serde_json::json!(["foo.bar.com"]);

        let mut wildcard = route_with_name_and_created_at("backend-v3", "2026-01-01T00:00:01Z");
        wildcard.spec["hostnames"] = serde_json::json!(["*.bar.com"]);

        let result = translate_k8s_objects(&[edge_http_gateway(), exact, wildcard], options())
            .expect("translation");

        assert_eq!(result.config.proxies.len(), 2);
        assert!(
            result.config.validate_unique_listen_paths().is_ok(),
            "exact host and wildcard host routes on one path are resolved by router host precedence"
        );
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.listen_path.as_deref() == Some("/api")
                && proxy.hosts == vec!["foo.bar.com".to_string()]
        }));
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.listen_path.as_deref() == Some("/api")
                && proxy.hosts == vec!["*.bar.com".to_string()]
        }));
    }

    #[test]
    fn http_route_conflicts_preserve_match_predicates_per_path() {
        let mut get_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET"
                    }],
                    "backendRefs": [{"name": "api-get", "port": 8080}]
                }]
            }),
        );
        get_route.metadata.name = "api-get".to_string();
        get_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let mut post_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "POST"
                    }],
                    "backendRefs": [{"name": "api-post", "port": 8081}]
                }]
            }),
        );
        post_route.metadata.name = "api-post".to_string();
        post_route.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[edge_http_gateway(), get_route, post_route], options())
                .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.validate_unique_listen_paths().is_ok(),
            "merged predicate routes must not produce duplicate host/path proxies"
        );
        assert!(
            result
                .warnings
                .iter()
                .all(|warning| !warning.contains("api-post")),
            "distinct match predicates must not conflict: {:?}",
            result.warnings
        );
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("merged predicate routes need dispatch rules");
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(8080));
        assert_eq!(rules[1]["match"]["methods"][0].as_str(), Some("POST"));
        assert!(
            rules[1]["destination"]["backend_port"].as_u64() == Some(8081),
            "POST route must keep its own backend destination"
        );
    }

    #[test]
    fn http_route_matching_across_routes_splits_host_subsets_before_merging() {
        let mut part1 = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["example.com", "example.net"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                    "backendRefs": [{"name": "backend-v1", "port": 8080}]
                }]
            }),
        );
        part1.metadata.name = "matching-part1".to_string();
        part1.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let mut part2 = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/v2"}},
                        {"headers": [{"name": "Version", "value": "two"}]}
                    ],
                    "backendRefs": [{"name": "backend-v2", "port": 8081}]
                }]
            }),
        );
        part2.metadata.name = "matching-part2".to_string();
        part2.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[edge_http_gateway(), part1, part2], options())
            .expect("translation");

        assert!(
            result.config.validate_unique_listen_paths().is_ok(),
            "Gateway API routes with overlapping host subsets must not produce duplicate host/path proxies"
        );
        let example_com_root = result
            .config
            .proxies
            .iter()
            .find(|proxy| {
                proxy.listen_path.as_deref() == Some("/")
                    && proxy.hosts == vec!["example.com".to_string()]
            })
            .expect("example.com root proxy");
        let example_net_root = result
            .config
            .proxies
            .iter()
            .find(|proxy| {
                proxy.listen_path.as_deref() == Some("/")
                    && proxy.hosts == vec!["example.net".to_string()]
            })
            .expect("example.net root proxy");
        assert_eq!(example_com_root.backend_port, 8080);
        assert_eq!(example_net_root.backend_port, 8080);
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| {
                plugin.plugin_name == "mesh_route_dispatch"
                    && plugin.proxy_id.as_deref() == Some(example_com_root.id.as_str())
            })
            .expect("example.com root proxy should carry the Version=two override");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["version"].as_str(),
            Some("two")
        );
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(8081));
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .all(|plugin| { plugin.proxy_id.as_deref() != Some(example_net_root.id.as_str()) }),
            "example.net fallback must not inherit the example.com-only header override"
        );
    }

    #[test]
    fn http_route_dispatch_prefers_more_specific_gateway_api_match() {
        let mut header_only = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "headers": [{"name": "x-env", "value": "prod"}]
                    }],
                    "backendRefs": [{"name": "api-header", "port": 8080}]
                }]
            }),
        );
        header_only.metadata.name = "api-header".to_string();
        header_only.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let mut method_and_header = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET",
                        "headers": [{"name": "x-env", "value": "prod"}]
                    }],
                    "backendRefs": [{"name": "api-get-header", "port": 8081}]
                }]
            }),
        );
        method_and_header.metadata.name = "api-get-header".to_string();
        method_and_header.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(
            &[edge_http_gateway(), header_only, method_and_header],
            options(),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("merged predicate routes need dispatch rules");
        let rules = plugin.config["rules"].as_array().expect("rules array");

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(8081));
        assert_eq!(rules[1]["destination"]["backend_port"].as_u64(), Some(8080));
        assert!(
            rules
                .iter()
                .all(|rule| rule.get(GATEWAY_API_DISPATCH_PRECEDENCE_KEY).is_none()),
            "internal sort metadata must not leak into the translated config"
        );
    }

    #[test]
    fn http_route_dispatch_specificity_ties_use_route_creation_order() {
        let mut newer = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "headers": [{"name": "x-newer", "value": "yes"}]
                    }],
                    "backendRefs": [{"name": "api-newer", "port": 8081}]
                }]
            }),
        );
        newer.metadata.name = "api-newer".to_string();
        newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let mut older = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "headers": [{"name": "x-older", "value": "yes"}]
                    }],
                    "backendRefs": [{"name": "api-older", "port": 8080}]
                }]
            }),
        );
        older.metadata.name = "api-older".to_string();
        older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[edge_http_gateway(), newer, older], options())
            .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("merged predicate routes need dispatch rules");
        let rules = plugin.config["rules"].as_array().expect("rules array");

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(8080));
        assert_eq!(rules[1]["destination"]["backend_port"].as_u64(), Some(8081));
    }

    #[test]
    fn http_route_conflicts_include_parent_ref_port() {
        let mut port_80_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge", "port": 80}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api-http", "port": 8080}]
                }]
            }),
        );
        port_80_route.metadata.name = "api-http".to_string();
        port_80_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let mut port_8080_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge", "port": 8080}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api-alt", "port": 8081}]
                }]
            }),
        );
        port_8080_route.metadata.name = "api-alt".to_string();
        port_8080_route.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(
            &[
                edge_http_gateway_ports(&[80, 8080]),
                port_80_route,
                port_8080_route,
            ],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert!(
            result.warnings.is_empty(),
            "port-distinct parentRefs must not conflict: {:?}",
            result.warnings
        );
    }

    #[test]
    fn conflicting_http_route_skips_only_conflicting_rule() {
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        let mut mixed = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [
                    {
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [{"name": "api-b", "port": 8080}]
                    },
                    {
                        "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                        "backendRefs": [{"name": "admin", "port": 9090}]
                    }
                ]
            }),
        );
        mixed.metadata.name = "api-b".to_string();
        mixed.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[edge_http_gateway(), older, mixed], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-a") && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-b") && proxy.listen_path.as_deref() == Some("/admin")
        }));
        assert!(!result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-b") && proxy.listen_path.as_deref() == Some("/api")
        }));
    }

    #[test]
    fn conflicting_weighted_http_route_does_not_emit_orphan_upstream() {
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        let mut weighted_loser = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [
                        {"name": "api-v1", "port": 8080, "weight": 90},
                        {"name": "api-v2", "port": 8081, "weight": 10}
                    ]
                }]
            }),
        );
        weighted_loser.metadata.name = "api-b".to_string();
        weighted_loser.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[edge_http_gateway(), older, weighted_loser], options())
                .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.upstreams.is_empty(),
            "fully conflicted weighted route must not leave an unreferenced upstream"
        );
    }

    #[test]
    fn conflicting_http_route_keeps_surviving_listener_parent_ref() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "http-a",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "api.example.com"
                    },
                    {
                        "name": "http-b",
                        "port": 8080,
                        "protocol": "HTTP",
                        "hostname": "other.example.com"
                    }
                ]
            }),
        );
        let mut older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        older.spec["hostnames"] = serde_json::json!(["api.example.com"]);
        older.spec["parentRefs"] = serde_json::json!([{"name": "sample", "sectionName": "http-a"}]);

        let mut mixed_parent_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com", "other.example.com"],
                "parentRefs": [
                    {"name": "sample", "sectionName": "http-a"},
                    {"name": "sample", "sectionName": "http-b"}
                ],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api-b", "port": 8080}]
                }]
            }),
        );
        mixed_parent_route.metadata.name = "api-b".to_string();
        mixed_parent_route.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[gateway, older, mixed_parent_route], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-a")
                && proxy.hosts == vec!["api.example.com".to_string()]
                && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-b")
                && proxy.hosts == vec!["other.example.com".to_string()]
                && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(result.config.validate_unique_listen_paths().is_ok());
    }

    #[test]
    fn conflicting_grpc_route_warning_explains_shared_path_limit() {
        let mut greeter = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["grpc.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/grpc"}}],
                    "backendRefs": [{"name": "greeter", "port": 50051}]
                }]
            }),
        );
        greeter.metadata.name = "greeter".to_string();
        greeter.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut goodbye = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["grpc.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/grpc"}}],
                    "backendRefs": [{"name": "goodbye", "port": 50052}]
                }]
            }),
        );
        goodbye.metadata.name = "goodbye".to_string();
        goodbye.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[edge_http_gateway(), greeter, goodbye], options())
            .expect("translation succeeds");

        // Two GRPCRoutes with the same path on the same host conflict — only one wins
        assert_eq!(result.config.proxies.len(), 1);
    }

    #[test]
    fn translates_http_route_exact_path_to_exact_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "Exact", "value": "/api.v1"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("=/api.v1")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn translates_http_route_regular_expression_path_to_regex_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "RegularExpression", "value": "/v[0-9]+/items"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("~/v[0-9]+/items")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn http_route_preserves_weighted_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [
                            {"name": "api-v1", "port": 8080, "weight": 90},
                            {"name": "api-v2", "port": 8081, "weight": 10}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.upstreams.len(), 1);
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(result.config.upstreams[0].id.as_str())
        );
        assert!(
            result.config.proxies[0].preserve_host_header,
            "Gateway API HTTPRoute backends must see the original request Host"
        );
        assert_eq!(result.config.upstreams[0].targets.len(), 2);
        assert_eq!(result.config.upstreams[0].targets[0].weight, 90);
        assert_eq!(result.config.upstreams[0].targets[1].port, 8081);
    }

    #[test]
    fn http_route_selectorless_service_uses_ready_endpoint_slice_target_port() {
        let service = core_service(
            "manual",
            serde_json::json!({
                "clusterIP": "10.96.0.10",
                "ports": [{
                    "name": "first-port",
                    "port": 8080,
                    "targetPort": 3000
                }]
            }),
        );
        let endpoint_slice = endpoint_slice_for_service(
            "manual",
            vec![serde_json::json!({
                "addresses": ["10.1.0.10"],
                "conditions": {"ready": true}
            })],
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/manual"}}],
                    "backendRefs": [{"name": "manual", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[service, endpoint_slice, route],
            options().with_pod_discovery_enabled(true),
        )
        .expect("manual EndpointSlice service should translate");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].backend_host, "10.1.0.10");
        assert_eq!(result.config.proxies[0].backend_port, 3000);
        assert!(
            result.config.upstreams.is_empty(),
            "single ready endpoint can be dialed directly"
        );
    }

    #[test]
    fn http_route_selectorless_service_resolves_named_target_port() {
        let service = core_service(
            "named-target",
            serde_json::json!({
                "clusterIP": "10.96.0.11",
                "ports": [{
                    "name": "http",
                    "port": 8080,
                    "targetPort": "app-http"
                }]
            }),
        );
        let endpoint_slice = {
            let mut slice = endpoint_slice_for_service(
                "named-target",
                vec![serde_json::json!({
                    "addresses": ["10.1.0.11"],
                    "conditions": {"ready": true}
                })],
            );
            slice.spec["ports"] = serde_json::json!([{
                "name": "app-http",
                "port": 3001
            }]);
            slice
        };
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/named"}}],
                    "backendRefs": [{"name": "named-target", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[service, endpoint_slice, route],
            options().with_pod_discovery_enabled(true),
        )
        .expect("named Service targetPort should resolve through EndpointSlice port names");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].backend_host, "10.1.0.11");
        assert_eq!(result.config.proxies[0].backend_port, 3001);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn http_route_headless_service_uses_ready_endpoint_slice_targets() {
        let service = core_service(
            "headless",
            serde_json::json!({
                "clusterIP": "None",
                "selector": {"app": "headless"},
                "ports": [{
                    "name": "first-port",
                    "port": 8080,
                    "targetPort": 3000
                }]
            }),
        );
        let endpoint_slice = endpoint_slice_for_service(
            "headless",
            vec![
                serde_json::json!({
                    "addresses": ["10.1.0.11"],
                    "conditions": {"ready": true}
                }),
                serde_json::json!({
                    "addresses": ["10.1.0.12"],
                    "conditions": {"ready": true}
                }),
            ],
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/headless"}}],
                    "backendRefs": [{"name": "headless", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[service, endpoint_slice, route],
            options().with_pod_discovery_enabled(true),
        )
        .expect("headless EndpointSlice service should translate");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.upstreams.len(), 1);
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(result.config.upstreams[0].id.as_str())
        );
        assert_eq!(result.config.upstreams[0].targets.len(), 2);
        assert_eq!(result.config.upstreams[0].targets[0].host, "10.1.0.11");
        assert_eq!(result.config.upstreams[0].targets[0].port, 3000);
        assert_eq!(result.config.upstreams[0].targets[1].host, "10.1.0.12");
        assert_eq!(result.config.upstreams[0].targets[1].port, 3000);
    }

    #[test]
    fn http_route_endpoint_expansion_preserves_backend_ref_weight_totals() {
        let manual = core_service(
            "manual",
            serde_json::json!({
                "ports": [{
                    "name": "first-port",
                    "port": 8080,
                    "targetPort": 3000
                }]
            }),
        );
        let manual_slice = endpoint_slice_for_service(
            "manual",
            vec![
                serde_json::json!({
                    "addresses": ["10.1.0.21"],
                    "conditions": {"ready": true}
                }),
                serde_json::json!({
                    "addresses": ["10.1.0.22"],
                    "conditions": {"ready": true}
                }),
            ],
        );
        let direct = core_service(
            "direct",
            serde_json::json!({
                "clusterIP": "10.96.0.20",
                "selector": {"app": "direct"},
                "ports": [{"port": 8080}]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/weighted"}}],
                    "backendRefs": [
                        {"name": "manual", "port": 8080, "weight": 1},
                        {"name": "direct", "port": 8080, "weight": 1}
                    ]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[manual, manual_slice, direct, route],
            options().with_pod_discovery_enabled(true),
        )
        .expect("mixed endpoint and service backends should translate");

        let upstream = result.config.upstreams.first().expect("weighted upstream");
        assert_eq!(upstream.targets.len(), 3);
        let expanded_total: u32 = upstream
            .targets
            .iter()
            .filter(|target| target.host.starts_with("10.1.0."))
            .map(|target| target.weight)
            .sum();
        let direct_weight = upstream
            .targets
            .iter()
            .find(|target| target.host == "direct.default.svc.cluster.local")
            .map(|target| target.weight)
            .expect("direct service target");
        assert_eq!(expanded_total, direct_weight);
        assert!(
            upstream
                .targets
                .iter()
                .filter(|target| target.host.starts_with("10.1.0."))
                .all(|target| target.weight > 0)
        );
    }

    #[test]
    fn http_route_endpoint_expansion_normalizes_scaled_weights_under_target_limit() {
        let manual = core_service(
            "manual",
            serde_json::json!({
                "ports": [{
                    "name": "first-port",
                    "port": 8080,
                    "targetPort": 3000
                }]
            }),
        );
        let manual_slice = endpoint_slice_for_service(
            "manual",
            vec![
                serde_json::json!({
                    "addresses": ["10.1.0.31"],
                    "conditions": {"ready": true}
                }),
                serde_json::json!({
                    "addresses": ["10.1.0.32"],
                    "conditions": {"ready": true}
                }),
            ],
        );
        let direct = core_service(
            "direct",
            serde_json::json!({
                "clusterIP": "10.96.0.30",
                "selector": {"app": "direct"},
                "ports": [{"port": 8080}]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/weighted"}}],
                    "backendRefs": [
                        {"name": "direct", "port": 8080, "weight": 90},
                        {"name": "manual", "port": 8080, "weight": 10}
                    ]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[manual, manual_slice, direct, route],
            options().with_pod_discovery_enabled(true),
        )
        .expect("mixed endpoint and service backends should translate");

        let upstream = result.config.upstreams.first().expect("weighted upstream");
        assert!(
            upstream
                .targets
                .iter()
                .all(|target| target.weight <= MAX_TARGET_WEIGHT),
            "scaled Gateway API weights must remain within Ferrum's upstream target limit"
        );
        let expanded_total: u32 = upstream
            .targets
            .iter()
            .filter(|target| target.host.starts_with("10.1.0."))
            .map(|target| target.weight)
            .sum();
        let direct_weight = upstream
            .targets
            .iter()
            .find(|target| target.host == "direct.default.svc.cluster.local")
            .map(|target| target.weight)
            .expect("direct service target");
        let ratio = f64::from(direct_weight) / f64::from(expanded_total);
        assert!(
            (ratio - 9.0).abs() < 0.02,
            "normalized weights should preserve the 90:10 backendRef ratio, got {ratio}"
        );
    }

    #[test]
    fn http_route_creates_proxy_per_match() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/v1"}},
                            {"path": {"type": "PathPrefix", "value": "/v2"}}
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let paths: Vec<_> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.listen_path.as_deref())
            .collect();
        assert_eq!(paths, vec![Some("/v1"), Some("/v2")]);
        assert!(
            result
                .config
                .proxies
                .iter()
                .all(|proxy| proxy.backend_port == 8080)
        );
    }

    #[test]
    fn http_route_emits_dispatch_for_predicate_only_pathless_matches() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"headers": [{"name": "x-tenant", "value": "a"}]},
                            {"method": "GET"}
                        ],
                        "backendRefs": [
                            {"name": "api-a", "port": 8080},
                            {"name": "api-b", "port": 8081}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
        assert_eq!(result.config.upstreams.len(), 1);
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("predicate-only HTTPRoute emits mesh_route_dispatch");
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(rules[1]["match"]["headers"]["x-tenant"].as_str(), Some("a"));
        assert_eq!(
            rules[0]["destination"]["upstream_id"].as_str(),
            result.config.proxies[0].upstream_id.as_deref()
        );
    }

    #[test]
    fn http_route_dispatch_matchers_keep_first_duplicate_header_and_query_name() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{
                            "headers": [
                                {"name": "X-Tenant", "value": "first"},
                                {"name": "x-tenant", "value": "second"}
                            ],
                            "queryParams": [
                                {"name": "version", "value": "v1"},
                                {"name": "version", "value": "v2"}
                            ]
                        }],
                        "backendRefs": [
                            {"name": "api-a", "port": 8080},
                            {"name": "api-b", "port": 8081}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("predicate-only HTTPRoute emits mesh_route_dispatch");
        let rule_match = &plugin.config["rules"][0]["match"];
        assert_eq!(rule_match["headers"]["x-tenant"].as_str(), Some("first"));
        assert_eq!(rule_match["query_params"]["version"].as_str(), Some("v1"));
    }

    #[test]
    fn http_route_request_header_modifier_emits_dispatch_transform_and_consumer() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/set"}}],
                        "filters": [{
                            "type": "RequestHeaderModifier",
                            "requestHeaderModifier": {
                                "set": [{"name": "X-Set", "value": "set"}],
                                "add": [{"name": "X-Add", "value": "add"}],
                                "remove": ["X-Remove"]
                            }
                        }],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "request_transformer"),
            "route-level transforms need a request_transformer consumer"
        );
        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for route actions");
        let request_transform = dispatch.config["rules"][0]["request_transform"]
            .as_array()
            .expect("request transform rules");
        assert_eq!(request_transform.len(), 3);
        assert_eq!(request_transform[0]["operation"], "update");
        assert_eq!(request_transform[1]["operation"], "add");
        assert_eq!(request_transform[2]["operation"], "remove");
    }

    #[test]
    fn merged_http_route_preserves_request_header_transformer_consumer() {
        let mut plain = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/merge"},
                        "method": "GET"
                    }],
                    "backendRefs": [{"name": "plain", "port": 8080}]
                }]
            }),
        );
        plain.metadata.name = "plain".to_string();
        plain.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut transformed = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/merge"},
                        "method": "POST"
                    }],
                    "filters": [{
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": {
                            "set": [{"name": "X-Merged", "value": "yes"}]
                        }
                    }],
                    "backendRefs": [{"name": "transformed", "port": 8081}]
                }]
            }),
        );
        transformed.metadata.name = "transformed".to_string();
        transformed.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[plain, transformed], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        let proxy_id = result.config.proxies[0].id.as_str();
        let request_transformer = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "request_transformer")
            .expect("merged route-level transform must keep a consumer");
        assert_eq!(request_transformer.proxy_id.as_deref(), Some(proxy_id));
        assert_eq!(
            request_transformer.id,
            format!("istio-vs-req-xform-{proxy_id}")
        );
        assert!(
            result.config.proxies[0]
                .plugins
                .iter()
                .any(|association| { association.plugin_config_id == request_transformer.id })
        );
    }

    #[test]
    fn http_route_request_redirect_without_backend_materializes_dispatch_redirect() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/redirect"}}],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {"hostname": "example.org"}
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("redirect-only route should materialize");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/redirect")
        );
        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["authority"], "example.org");
        assert_eq!(redirect["redirect_code"], 302);
    }

    #[test]
    fn http_route_request_redirect_port_without_hostname_preserves_request_host() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/redirect"}}],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {
                                "scheme": "https",
                                "port": 8443,
                                "statusCode": 301
                            }
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("redirect-only route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["scheme"], "https");
        assert_eq!(redirect["port"], 8443);
        assert_eq!(redirect["redirect_code"], 301);
        assert!(
            redirect.get("authority").is_none(),
            "port-only redirect must preserve the request host at the DP"
        );
    }

    #[test]
    fn http_route_request_redirect_scheme_derives_default_port() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/secure"}}],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {
                                "scheme": "https",
                                "statusCode": 301
                            }
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("redirect-only route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["scheme"], "https");
        assert_eq!(redirect["port"], 443);
        assert!(
            redirect.get("authority").is_none(),
            "scheme-derived port must still preserve the request host at the DP"
        );
    }

    #[test]
    fn http_route_request_redirect_hostname_keeps_default_port_structured() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/secure"}}],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {
                                "hostname": "example.org",
                                "scheme": "https",
                                "statusCode": 301
                            }
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("redirect-only route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["authority"], "example.org");
        assert_eq!(redirect["scheme"], "https");
        assert_eq!(redirect["port"], 443);
    }

    #[test]
    fn http_route_status_only_request_redirect_materializes_dispatch_redirect() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/redirect"}}],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {"statusCode": 301}
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("status-only redirect route should materialize");

        assert_eq!(result.config.proxies.len(), 1);
        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["redirect_code"], 301);
        assert!(
            redirect
                .as_object()
                .is_some_and(|object| object.keys().all(|key| key == "redirect_code")),
            "status-only redirect must preserve request URL at the DP"
        );
    }

    #[test]
    fn http_route_request_redirect_without_port_uses_attached_listener_port() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 8080,
                    "protocol": "HTTP"
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "sectionName": "web"
                }],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/redirect"}}],
                    "filters": [{
                        "type": "RequestRedirect",
                        "requestRedirect": {"statusCode": 301}
                    }]
                }]
            }),
        );

        let result = translate_k8s_objects(&[gateway, route], options())
            .expect("redirect route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["redirect_code"], 301);
        assert_eq!(redirect["port"], 8080);
        assert!(
            redirect.get("authority").is_none(),
            "listener-derived port must still preserve the request host at the DP"
        );
    }

    #[test]
    fn http_route_replace_prefix_redirect_preserves_match_prefix() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/old"}}],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {
                                "path": {
                                    "type": "ReplacePrefixMatch",
                                    "replacePrefixMatch": "/new"
                                },
                                "statusCode": 302
                            }
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("prefix redirect route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["uri"], "/new");
        assert_eq!(redirect["match_prefix"], "/old");
        assert!(
            redirect.as_object().is_some_and(
                |object| !object.contains_key(GATEWAY_API_REDIRECT_REPLACE_PREFIX_MATCH_KEY)
            ),
            "private translator marker must not reach DP config"
        );
    }

    #[test]
    fn http_route_replace_prefix_redirect_defaults_match_path_type_to_prefix() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"value": "/old"}}],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {
                                "path": {
                                    "type": "ReplacePrefixMatch",
                                    "replacePrefixMatch": "/new"
                                }
                            }
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("prefix redirect route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["uri"], "/new");
        assert_eq!(redirect["match_prefix"], "/old");
    }

    #[test]
    fn http_route_replace_prefix_redirect_defaults_missing_match_to_root_prefix() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {
                                "path": {
                                    "type": "ReplacePrefixMatch",
                                    "replacePrefixMatch": "/new"
                                }
                            }
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("default-match prefix redirect route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let redirect = &dispatch.config["rules"][0]["redirect"];
        assert_eq!(redirect["uri"], "/new");
        assert_eq!(redirect["match_prefix"], "/");
    }

    #[test]
    fn http_route_replace_prefix_redirect_defaults_predicate_only_match_to_root_prefix() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{
                            "headers": [{"name": "x-mode", "value": "preview"}]
                        }],
                        "filters": [{
                            "type": "RequestRedirect",
                            "requestRedirect": {
                                "path": {
                                    "type": "ReplacePrefixMatch",
                                    "replacePrefixMatch": "/new"
                                }
                            }
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("predicate-only prefix redirect route should materialize");

        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("dispatch plugin should be emitted for redirect");
        let rule = &dispatch.config["rules"][0];
        assert_eq!(rule["match"]["headers"]["x-mode"], "preview");
        let redirect = &rule["redirect"];
        assert_eq!(redirect["uri"], "/new");
        assert_eq!(redirect["match_prefix"], "/");
    }

    #[test]
    fn http_route_dispatch_skips_partially_supported_predicate_matches() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {
                                "path": {"type": "PathPrefix", "value": "/api"},
                                "headers": [
                                    {"name": "x-tenant", "value": "a"},
                                    {"type": "RegularExpression", "name": "x-scope", "value": "prod|dev"}
                                ]
                            },
                            {
                                "path": {"type": "PathPrefix", "value": "/api"},
                                "headers": [{"name": "x-tenant", "value": "b"}],
                                "queryParams": [
                                    {"name": "version", "value": "v2"},
                                    {"type": "RegularExpression", "name": "debug", "value": "true|false"}
                                ]
                            },
                            {
                                "path": {"type": "PathPrefix", "value": "/api"},
                                "headers": [{"name": "x-tenant", "value": "c"}],
                                "queryParams": [{"name": "version", "value": "v3"}]
                            }
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("supported HTTPRoute match emits mesh_route_dispatch");
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 1);
        let rule_match = &rules[0]["match"];
        assert_eq!(rule_match["headers"]["x-tenant"].as_str(), Some("c"));
        assert_eq!(rule_match["query_params"]["version"].as_str(), Some("v3"));
    }

    #[test]
    fn http_route_rejects_cross_namespace_gateway_parent_ref_when_listener_does_not_allow_route_namespace()
     {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "parentRefs": [{
                        "name": "shared-gw",
                        "namespace": "platform"
                    }],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                        "backendRefs": [{"name": "admin", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("cross-namespace parentRef should fail closed");

        assert!(
            err.to_string()
                .contains("not permitted by the target Gateway listener")
        );
    }

    #[test]
    fn http_route_accepts_cross_namespace_gateway_parent_ref_when_listener_allows_route_namespace()
    {
        let gateway = object_in_namespace(
            "Gateway",
            "platform",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {"from": "All"}
                    }
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "namespace": "platform",
                    "sectionName": "web"
                }],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                    "backendRefs": [{"name": "admin", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[gateway, route],
            options().with_source_namespaces(vec!["default".to_string(), "platform".to_string()]),
        )
        .expect("listener allowed cross-namespace parentRef");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some("/admin"))
            .expect("route proxy materialized");
        assert_eq!(proxy.namespace, "platform");
        assert_eq!(proxy.backend_host, "admin.default.svc.cluster.local");
    }

    #[test]
    fn http_route_materializes_for_each_valid_parent_gateway_namespace() {
        let gateway_a = object_in_namespace(
            "Gateway",
            "platform-a",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {"from": "All"}
                    }
                }]
            }),
        );
        let gateway_b = object_in_namespace(
            "Gateway",
            "platform-b",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {"from": "All"}
                    }
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [
                    {"name": "sample", "namespace": "platform-a", "sectionName": "web"},
                    {"name": "sample", "namespace": "platform-b", "sectionName": "web"}
                ],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/multi"}}],
                    "backendRefs": [{"name": "multi", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[gateway_a, gateway_b, route],
            options().with_source_namespaces(vec![
                "default".to_string(),
                "platform-a".to_string(),
                "platform-b".to_string(),
            ]),
        )
        .expect("route should materialize for each valid parent namespace");

        let mut namespaces: Vec<_> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.namespace.as_str())
            .collect();
        namespaces.sort();
        assert_eq!(namespaces, vec!["platform-a", "platform-b"]);
        assert_ne!(result.config.proxies[0].id, result.config.proxies[1].id);
    }

    #[test]
    fn http_route_allowed_routes_selector_honors_match_expressions_without_pod_discovery() {
        let gateway = object_in_namespace(
            "Gateway",
            "platform",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {
                            "from": "Selector",
                            "selector": {
                                "matchExpressions": [
                                    {"key": "env", "operator": "In", "values": ["prod"]},
                                    {"key": "team", "operator": "Exists"}
                                ]
                            }
                        }
                    }
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "namespace": "platform",
                    "sectionName": "web"
                }],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/selected"}}],
                    "backendRefs": [{"name": "selected", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[
                namespace("default", &[("env", "prod"), ("team", "payments")]),
                namespace("platform", &[("env", "platform")]),
                gateway,
                route,
            ],
            options().with_source_namespaces(vec!["default".to_string(), "platform".to_string()]),
        )
        .expect("selector expression route should translate without pod discovery");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/selected")
        );
        assert_eq!(result.config.proxies[0].namespace, "platform");
    }

    #[test]
    fn http_route_rejects_parent_ref_when_listener_allowed_kinds_exclude_http_route() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {"from": "All"},
                        "kinds": [{"kind": "GRPCRoute"}]
                    }
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "sectionName": "web"
                }],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                    "backendRefs": [{"name": "admin", "port": 8080}]
                }]
            }),
        );

        let err = translate_k8s_objects(&[gateway, route], options())
            .expect_err("listener allowedRoutes.kinds should exclude HTTPRoute");

        assert!(
            err.to_string()
                .contains("not permitted by the target Gateway listener")
        );
    }

    #[test]
    fn http_route_materializes_allowed_parent_when_sibling_parent_ref_is_not_allowed() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "web",
                        "port": 80,
                        "protocol": "HTTP",
                        "hostname": "ok.example.com",
                        "allowedRoutes": {
                            "namespaces": {"from": "All"},
                            "kinds": [{"kind": "HTTPRoute"}]
                        }
                    },
                    {
                        "name": "grpc",
                        "port": 8080,
                        "protocol": "HTTP",
                        "hostname": "blocked.example.com",
                        "allowedRoutes": {
                            "namespaces": {"from": "All"},
                            "kinds": [{"kind": "GRPCRoute"}]
                        }
                    }
                ]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["ok.example.com", "blocked.example.com"],
                "parentRefs": [
                    {"name": "sample", "sectionName": "web"},
                    {"name": "sample", "sectionName": "grpc"}
                ],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/ok"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );

        let result = translate_k8s_objects(&[gateway, route], options())
            .expect("allowed parentRef should materialize");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].hosts,
            vec!["ok.example.com".to_string()]
        );
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/ok"));
        assert!(result.materialized_route_parents.iter().any(|parent| {
            parent.route.kind == "HTTPRoute"
                && parent.route.name == "sample"
                && parent.parent_ref == "gateway.networking.k8s.io/Gateway/default/sample/web/*"
        }));
        assert!(!result.materialized_route_parents.iter().any(|parent| {
            parent.route.kind == "HTTPRoute"
                && parent.route.name == "sample"
                && parent.parent_ref == "gateway.networking.k8s.io/Gateway/default/sample/grpc/*"
        }));
    }

    #[test]
    fn grpc_route_can_attach_to_http_listener_when_allowed() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": {
                        "namespaces": {"from": "All"},
                        "kinds": [{"kind": "GRPCRoute"}]
                    }
                }]
            }),
        );
        let route = object(
            "GRPCRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "sectionName": "web"
                }],
                "rules": [{
                    "matches": [{
                        "method": {
                            "service": "ferrum.echo.v1.Echo",
                            "method": "Ping"
                        }
                    }],
                    "backendRefs": [{"name": "grpc", "port": 50051}]
                }]
            }),
        );

        let result = translate_k8s_objects(&[gateway, route], options())
            .expect("HTTP listeners should allow GRPCRoute when requested");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("=/ferrum.echo.v1.Echo/Ping")
        );
    }

    #[test]
    fn http_route_rejects_parent_ref_when_section_name_listener_is_absent() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "sectionName": "missing"
                }],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                    "backendRefs": [{"name": "admin", "port": 8080}]
                }]
            }),
        );

        let err = translate_k8s_objects(&[route], options())
            .expect_err("explicit missing listener selector should fail closed");

        assert!(
            err.to_string()
                .contains("does not match any known Gateway listener")
        );
    }

    #[test]
    fn http_route_rejects_parent_ref_when_port_does_not_match_listener() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "web",
                    "port": 80,
                    "protocol": "HTTP"
                }]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "port": 81
                }],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                    "backendRefs": [{"name": "admin", "port": 8080}]
                }]
            }),
        );

        let err = translate_k8s_objects(&[gateway, route], options())
            .expect_err("parentRef port should match a Gateway listener");

        assert!(
            err.to_string()
                .contains("does not match any known Gateway listener")
        );
    }

    #[test]
    fn http_route_keeps_empty_match_as_default_catch_all() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn http_route_keeps_pathless_predicate_in_mixed_rule() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/v1"}},
                            {"headers": [{"name": "x-tenant", "value": "a"}]}
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let paths: HashSet<_> = result
            .config
            .proxies
            .iter()
            .filter_map(|proxy| proxy.listen_path.as_deref())
            .collect();
        assert_eq!(paths, HashSet::from(["/v1", "/"]));
        let catch_all = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some("/"))
            .expect("pathless predicate catch-all proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(catch_all.id.as_str())
            })
            .expect("catch-all proxy has dispatch rule");
        assert_eq!(
            plugin.config["rules"][0]["match"]["headers"]["x-tenant"].as_str(),
            Some("a")
        );
    }

    fn grpc_dispatch_plugin<'a>(
        result: &'a crate::config_sources::k8s::K8sTranslation,
        proxy: &Proxy,
    ) -> &'a PluginConfig {
        result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| {
                plugin.plugin_name == "mesh_route_dispatch"
                    && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("gRPC predicate proxy carries a mesh_route_dispatch plugin")
    }

    fn grpc_catch_all_proxy(result: &crate::config_sources::k8s::K8sTranslation) -> &Proxy {
        result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some("/"))
            .expect("pathless gRPC predicate materializes a `/` listener")
    }

    #[test]
    fn grpc_route_service_and_method_match_becomes_exact_path() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [
                            {"method": {"service": "helloworld.Greeter", "method": "SayHello"}},
                            {"method": {"service": "helloworld.Greeter", "method": "SayGoodbye"}}
                        ],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mut paths: Vec<_> = result
            .config
            .proxies
            .iter()
            .filter_map(|proxy| proxy.listen_path.clone())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "=/helloworld.Greeter/SayGoodbye".to_string(),
                "=/helloworld.Greeter/SayHello".to_string(),
            ],
            "fully-qualified gRPC methods must become exact listen paths, not a catch-all"
        );
        // The path predicate is exact, but a GRPCRoute still selects gRPC
        // calls only: each exact listener carries the content-type gate and
        // rejects unmatched (i.e. non-gRPC) traffic.
        for proxy in &result.config.proxies {
            let plugin = grpc_dispatch_plugin(&result, proxy);
            assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
            let matcher = &plugin.config["rules"][0]["match"];
            assert!(
                matcher.get("uri").is_none(),
                "an exact gRPC path needs no request-time URI predicate"
            );
            assert_eq!(
                matcher["headers"]["content-type"]["regex"].as_str(),
                Some(GRPC_CONTENT_TYPE_GATE_REGEX),
                "an exact gRPC listener must not capture plain HTTP on the same path"
            );
        }
    }

    #[test]
    fn grpc_content_type_gate_matches_the_canonical_native_grpc_contract() {
        // `mesh_route_dispatch` anchors every regex header operand with
        // `\A(?:…)\z` at plugin-construction time; mirror that exactly so the
        // gate is evaluated the way the data plane will evaluate it.
        let gate = regex::Regex::new(&format!(r"\A(?:{GRPC_CONTENT_TYPE_GATE_REGEX})\z"))
            .expect("the emitted content-type gate compiles");
        for admitted in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json",
            "application/grpc+",
            "application/grpc; charset=utf-8",
            "application/grpc ; charset=utf-8",
            "application/grpc\t",
            "application/grpc ",
            "Application/GRPC",
            "APPLICATION/GRPC+PROTO",
        ] {
            assert!(gate.is_match(admitted), "gate must admit {admitted}");
            assert!(
                is_grpc_media_type(admitted),
                "an authored {admitted} predicate must be accepted"
            );
        }
        // gRPC-Web and lookalikes are NOT native gRPC. Ferrum's canonical
        // dispatcher rejects them, and a trusted `grpc_web` plugin is what
        // rewrites a verified gRPC-Web request to `application/grpc` before
        // backend dispatch — the route gate must not bless the raw form.
        for refused in [
            "application/grpcfoo",
            "application/grpc-web",
            "application/grpc-website",
            "application/grpc-web-text",
            "text/plain",
            "application/json",
            "application/x-www-form-urlencoded",
            "text/html; charset=utf-8",
            "",
        ] {
            assert!(!gate.is_match(refused), "gate must refuse {refused}");
            assert!(
                !is_grpc_media_type(refused),
                "an authored {refused} predicate must be refused"
            );
        }
        // Non-ASCII input must not panic on a byte-slice boundary.
        assert!(!is_grpc_media_type("applicati\u{00f3}n/grpc"));

        // The emitted gate and Ferrum's canonical dispatcher must agree on
        // every one of these, or a GRPCRoute could select a request the proxy
        // would not treat as gRPC (or vice versa).
        for value in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+",
            "application/grpc; charset=utf-8",
            "application/grpc ; charset=utf-8",
            "application/grpc\t",
            "Application/GRPC",
            "application/grpcfoo",
            "application/grpc-web",
            "application/grpc-website",
            "application/grpc-web-text",
            "application/grpc  +proto",
            "text/plain",
            "",
        ] {
            assert_eq!(
                gate.is_match(value),
                crate::proxy::backend_dispatch::is_native_grpc_content_type(value.as_bytes()),
                "the emitted gate must agree with the canonical dispatcher on {value:?}"
            );
        }
    }

    #[test]
    fn grpc_exact_operands_follow_the_v1_5_1_crd_grammars() {
        // `service`: `^\.?[a-z_][a-z_0-9]*(\.[a-z_][a-z_0-9]*)*$`, applied
        // case-insensitively, MaxLength 1024.
        for accepted in [
            "helloworld.Greeter",
            ".helloworld.Greeter",
            "Greeter",
            "_private.Svc_1",
            "PKG.SVC",
            "a.b.c.d",
        ] {
            assert_eq!(
                validate_grpc_service_literal(accepted).map(str::to_string),
                Ok(accepted.trim_start_matches('.').to_string()),
                "{accepted} is a valid CRD service literal (leading dot normalized away)"
            );
        }
        for refused in [
            "",
            "1pkg.Svc",
            "-pkg.Svc",
            "pkg-name.Svc",
            "pkg..Svc",
            "pkg.",
            ".",
            "..pkg",
            "pkg/Svc",
            "pkg.Svc%2f",
            "pkg Svc",
        ] {
            assert!(
                validate_grpc_service_literal(refused).is_err(),
                "{refused:?} must be refused as a service literal"
            );
        }

        // `method`: `^[A-Za-z_][A-Za-z_0-9]*$`, MaxLength 1024. No dot.
        for accepted in ["SayHello", "_hidden", "Say2", "s"] {
            assert_eq!(validate_grpc_method_literal(accepted), Ok(accepted));
        }
        for refused in [
            "",
            "1Say",
            "-Say",
            "Say.Hello",
            "Say-Hello",
            "Say/Hello",
            ".SayHello",
            "Say Hello",
        ] {
            assert!(
                validate_grpc_method_literal(refused).is_err(),
                "{refused:?} must be refused as a method literal"
            );
        }

        // MaxLength boundary: 1024 accepted, 1025 refused, on both fields.
        let at_limit = "a".repeat(MAX_GRPC_METHOD_OPERAND_LENGTH);
        let over_limit = "a".repeat(MAX_GRPC_METHOD_OPERAND_LENGTH + 1);
        assert_eq!(MAX_GRPC_METHOD_OPERAND_LENGTH, 1024);
        assert!(validate_grpc_service_literal(&at_limit).is_ok());
        assert!(validate_grpc_method_literal(&at_limit).is_ok());
        assert!(validate_grpc_service_literal(&over_limit).is_err());
        assert!(validate_grpc_method_literal(&over_limit).is_err());
        // The refusal must not echo the hostile operand back into the warning.
        for error in [
            validate_grpc_service_literal(&over_limit).unwrap_err(),
            validate_grpc_method_literal(&over_limit).unwrap_err(),
            validate_grpc_service_literal("pkg/Svc").unwrap_err(),
            validate_grpc_method_literal("Say/Hello").unwrap_err(),
        ] {
            assert!(
                !error.contains(&at_limit) && !error.contains('/'),
                "operand values must never be echoed into a warning: {error}"
            );
        }
    }

    #[test]
    fn grpc_leading_dot_service_normalizes_onto_the_undotted_listen_path() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [{
                            "method": {"service": ".helloworld.Greeter", "method": "SayHello"}
                        }],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("=/helloworld.Greeter/SayHello"),
            "a gRPC :path never carries the fully-qualified-name leading dot"
        );
    }

    #[test]
    fn grpc_route_service_only_match_becomes_service_prefix() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [{"method": {"service": "helloworld.Greeter"}}],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/helloworld.Greeter/"),
            "a service-only match is a single-service prefix, never `/`"
        );
        let plugin = grpc_dispatch_plugin(&result, &result.config.proxies[0]);
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        assert_eq!(
            plugin.config["rules"][0]["match"]["headers"]["content-type"]["regex"].as_str(),
            Some(GRPC_CONTENT_TYPE_GATE_REGEX),
            "a service-prefix listener must not capture plain HTTP under the same prefix"
        );
    }

    #[test]
    fn grpc_route_authored_content_type_must_narrow_the_grpc_gate() {
        // A valid gRPC media type replaces the canonical gate (more specific
        // operator intent) and the route still materializes.
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [{
                            "method": {"method": "SayHello"},
                            "headers": [{"name": "Content-Type", "value": "application/grpc+proto"}]
                        }],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let proxy = grpc_catch_all_proxy(&result);
        let plugin = grpc_dispatch_plugin(&result, proxy);
        assert_eq!(
            plugin.config["rules"][0]["match"]["headers"]["content-type"].as_str(),
            Some("application/grpc+proto"),
            "an authored gRPC media type narrows the gate"
        );

        // A non-gRPC media type would widen the route onto plain HTTP, so the
        // whole match is refused and no route materializes.
        // `application/grpc-web` is deliberately covered by the diagnostics
        // test instead: it is a literal substring of the diagnostic itself, so
        // the "never echo the operand" assertion below cannot be expressed for
        // it here.
        for widening in [
            "text/plain",
            "application/json",
            "application/grpcfoo",
            "application/grpc-website",
        ] {
            let entry = serde_json::json!({
                "method": {"service": "helloworld.Greeter", "method": "SayHello"},
                "headers": [{"name": "content-type", "value": widening}]
            });
            let reason = grpc_route_match(&entry)
                .expect_err("a non-gRPC content-type predicate must fail closed")
                .to_string();
            assert!(
                reason.contains("must be a native gRPC media type"),
                "expected a content-type diagnostic, got `{reason}`"
            );
            assert!(
                !reason.contains(widening),
                "the operator-supplied value must not be echoed into the warning: {reason}"
            );

            let result = translate_k8s_objects(
                &[object(
                    "GRPCRoute",
                    serde_json::json!({
                        "hostnames": ["grpc.example.com"],
                        "rules": [{
                            "matches": [entry],
                            "backendRefs": [{"name": "grpc-api"}]
                        }]
                    }),
                )],
                options(),
            )
            .expect("translation succeeds");
            assert!(
                result.config.proxies.is_empty(),
                "a widening content-type predicate must not materialize a route"
            );
            assert!(
                result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("dropped fail-closed")
                        && warning.contains("must be a native gRPC media type")),
                "expected a field-specific drop warning in {:?}",
                result.warnings
            );
        }
    }

    #[test]
    fn grpc_route_method_only_match_uses_grpc_uri_predicate() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [{"method": {"method": "SayHello"}}],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = grpc_catch_all_proxy(&result);
        let plugin = grpc_dispatch_plugin(&result, proxy);
        assert_eq!(
            plugin.config["reject_unmatched"].as_bool(),
            Some(true),
            "a predicate-only gRPC route must not serve unmatched traffic from the `/` listener"
        );
        let matcher = &plugin.config["rules"][0]["match"];
        let pattern = matcher["uri"]["regex"]
            .as_str()
            .expect("method-only match carries a URI regex");
        assert_eq!(pattern, "/[^/]+/SayHello");
        assert_eq!(
            matcher["headers"]["content-type"]["regex"].as_str(),
            Some(GRPC_CONTENT_TYPE_GATE_REGEX),
            "a pathless gRPC predicate must be gated on the gRPC content type"
        );

        let compiled = compile_grpc_uri_regex(pattern).expect("emitted pattern compiles");
        assert!(compiled.is_match("/helloworld.Greeter/SayHello"));
        assert!(compiled.is_match("/other.Svc/SayHello"));
        assert!(!compiled.is_match("/helloworld.Greeter/SayHelloAgain"));
        assert!(!compiled.is_match("/SayHello"));
        assert!(!compiled.is_match("/a/b/SayHello"));
    }

    #[test]
    fn grpc_route_header_only_match_gates_on_grpc_shape_and_content_type() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [{"headers": [{"name": "X-Tenant", "value": "a"}]}],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = grpc_catch_all_proxy(&result);
        let plugin = grpc_dispatch_plugin(&result, proxy);
        let matcher = &plugin.config["rules"][0]["match"];
        assert_eq!(matcher["uri"]["regex"].as_str(), Some("/[^/]+/[^/]+"));
        assert_eq!(matcher["headers"]["x-tenant"].as_str(), Some("a"));
        assert_eq!(
            matcher["headers"]["content-type"]["regex"].as_str(),
            Some(GRPC_CONTENT_TYPE_GATE_REGEX)
        );
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
    }

    #[test]
    fn grpc_route_regular_expression_matches_are_refused_fail_closed() {
        // Ferrum cannot constrain an operator regex to one gRPC path segment:
        // every operand below can consume the `/` delimiter and widen the
        // route across service/method boundaries, and wrapping it in a
        // non-capturing group does not change that. The predicate is refused
        // rather than compiled into a request-path matcher.
        for operand in [
            ".*",
            "[\\s\\S]*",
            "a\\x2Fb",
            "a\\u{2F}b",
            "a[/]b",
            "a|.*",
            "helloworld\\..*",
            "[^x]+",
        ] {
            for method in [
                serde_json::json!({"type": "RegularExpression", "service": operand}),
                serde_json::json!({"type": "RegularExpression", "method": operand}),
                serde_json::json!({
                    "type": "RegularExpression",
                    "service": "helloworld.Greeter",
                    "method": operand
                }),
            ] {
                let reason = grpc_route_method_plan(&method)
                    .expect_err("a RegularExpression gRPC predicate must fail closed")
                    .to_string();
                assert!(
                    reason.contains("'RegularExpression' is not supported"),
                    "expected a RegularExpression diagnostic, got `{reason}`"
                );
            }
        }

        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [{"method": {
                            "type": "RegularExpression",
                            "service": "helloworld\\..*",
                            "method": "Say.*"
                        }}],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            result.config.proxies.is_empty(),
            "a RegularExpression GRPCRoute match must not materialize a route"
        );
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
            "a refused predicate must not leave a dispatch rule behind"
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("dropped fail-closed")
                    && warning.contains("'RegularExpression' is not supported")),
            "expected a field-specific drop warning in {:?}",
            result.warnings
        );
    }

    #[test]
    fn grpc_route_unrepresentable_matches_are_dropped_with_field_diagnostics() {
        for (entry, expected_fragment) in [
            (
                serde_json::json!({"method": {"type": "Prefix", "service": "a.B"}}),
                "matches[].method.type is not supported",
            ),
            (
                serde_json::json!({"method": {}}),
                "matches[].method requires at least one of service / method",
            ),
            (
                serde_json::json!({"method": {"service": "a/B"}}),
                "matches[].method.service must be a dot-separated gRPC service name",
            ),
            (
                serde_json::json!({"method": {"service": "1pkg.Svc"}}),
                "matches[].method.service must be a dot-separated gRPC service name",
            ),
            (
                serde_json::json!({"method": {"service": "pkg..Svc"}}),
                "matches[].method.service must be a dot-separated gRPC service name",
            ),
            (
                serde_json::json!({"method": {"method": "Say.Hello"}}),
                "matches[].method.method must be a gRPC method name",
            ),
            (
                serde_json::json!({"method": {"method": "-Say"}}),
                "matches[].method.method must be a gRPC method name",
            ),
            (
                serde_json::json!({"method": {"service": ""}}),
                "matches[].method.service must not be empty",
            ),
            (
                serde_json::json!({
                    "method": {"type": "RegularExpression", "service": "a.*"}
                }),
                "matches[].method.type 'RegularExpression' is not supported",
            ),
            (
                serde_json::json!({
                    "method": {"service": "a.B", "method": "C"},
                    "headers": [{"name": "content-type", "value": "text/plain"}]
                }),
                "matches[].headers[] 'content-type' must be a native gRPC media type",
            ),
            (
                serde_json::json!({
                    "method": {"service": "a.B", "method": "C"},
                    "headers": [{"name": "content-type", "value": "application/grpc-web"}]
                }),
                "matches[].headers[] 'content-type' must be a native gRPC media type",
            ),
            (
                serde_json::json!({
                    "method": {"service": "a.B", "method": "C"},
                    "headers": [{"type": "RegularExpression", "name": "x", "value": ".*"}]
                }),
                "matches[].headers[].type is not supported",
            ),
            (
                serde_json::json!({"headers": [{"name": "x"}]}),
                "matches[].headers[].value is required",
            ),
            // A present non-string operand must not read as an omission: that
            // would silently degrade an exact `=/pkg.Svc/SayHello` listener
            // into the far broader method-only or service-only shape.
            (
                serde_json::json!({"method": {"service": 1, "method": "SayHello"}}),
                "matches[].method.service must be a string",
            ),
            (
                serde_json::json!({"method": {"service": "pkg.Svc", "method": null}}),
                "matches[].method.method must be a string",
            ),
            (
                serde_json::json!({"method": {"service": ["pkg.Svc"], "method": "SayHello"}}),
                "matches[].method.service must be a string",
            ),
            // The CRD `method` predicate and Ferrum's hand-authored `path`
            // extension are mutually exclusive: honoring either alone would
            // discard the other half of the conjunction and widen the match.
            (
                serde_json::json!({
                    "method": {"service": "pkg.Svc", "method": "SayHello"},
                    "path": {"type": "PathPrefix", "value": "/pkg.Svc"}
                }),
                "must not carry both 'method' and the Ferrum 'path' extension",
            ),
        ] {
            let reason = grpc_route_match(&entry)
                .expect_err("unrepresentable gRPC match must fail closed")
                .to_string();
            assert!(
                reason.contains(expected_fragment),
                "expected `{expected_fragment}` in `{reason}`"
            );

            let result = translate_k8s_objects(
                &[object(
                    "GRPCRoute",
                    serde_json::json!({
                        "hostnames": ["grpc.example.com"],
                        "rules": [{
                            "matches": [entry],
                            "backendRefs": [{"name": "grpc-api"}]
                        }]
                    }),
                )],
                options(),
            )
            .expect("translation succeeds");

            assert!(
                result.config.proxies.is_empty(),
                "unrepresentable gRPC match must not materialize a route: {reason}"
            );
            assert!(
                result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("dropped fail-closed")
                        && warning.contains(expected_fragment)),
                "expected a field-specific drop warning for `{expected_fragment}` in {:?}",
                result.warnings
            );
        }
    }

    #[test]
    fn grpc_route_unknown_match_types_are_not_echoed_into_diagnostics() {
        let hostile_type = "operator-controlled-type-that-must-not-be-logged";
        for entry in [
            serde_json::json!({
                "method": {"type": hostile_type, "service": "a.B"}
            }),
            serde_json::json!({
                "headers": [{"type": hostile_type, "name": "x", "value": "y"}]
            }),
        ] {
            let reason =
                grpc_route_match(&entry).expect_err("unknown match types must fail closed");
            assert!(
                !reason.contains(hostile_type),
                "operator-controlled match type leaked into diagnostic: {reason}"
            );
        }
    }

    #[test]
    fn grpc_route_malformed_matches_and_extension_paths_fail_closed() {
        for (rules, expected_fragment) in [
            (
                serde_json::json!([{
                    "matches": {"method": {"method": "SayHello"}},
                    "backendRefs": [{"name": "grpc", "port": 50051}]
                }]),
                "matches must be an array",
            ),
            (
                serde_json::json!([{
                    "matches": [{"path": {"type": "Unknown", "value": "/"}}],
                    "backendRefs": [{"name": "grpc", "port": 50051}]
                }]),
                "matches[].path.type is not supported",
            ),
            (
                serde_json::json!([{
                    "matches": [{"path": {"type": "PathPrefix"}}],
                    "backendRefs": [{"name": "grpc", "port": 50051}]
                }]),
                "matches[].path.value is required",
            ),
        ] {
            let result = translate_k8s_objects(
                &[object(
                    "GRPCRoute",
                    serde_json::json!({
                        "hostnames": ["grpc.example.com"],
                        "rules": rules
                    }),
                )],
                options(),
            )
            .expect("malformed predicates are dropped rather than aborting translation");
            assert!(
                result.config.proxies.is_empty(),
                "malformed explicit input must not widen into a catch-all route"
            );
            assert!(
                result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains(expected_fragment)),
                "expected `{expected_fragment}` in {:?}",
                result.warnings
            );
        }
    }

    #[test]
    fn grpc_route_without_matches_still_gates_on_grpc_shape() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{"backendRefs": [{"name": "grpc-api"}]}]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = grpc_catch_all_proxy(&result);
        let plugin = grpc_dispatch_plugin(&result, proxy);
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        assert_eq!(
            plugin.config["rules"][0]["match"]["uri"]["regex"].as_str(),
            Some("/[^/]+/[^/]+"),
            "a match-less GRPCRoute matches every gRPC call, not every HTTP request"
        );
        assert_eq!(
            plugin.config["rules"][0]["match"]["headers"]["content-type"]["regex"].as_str(),
            Some(GRPC_CONTENT_TYPE_GATE_REGEX)
        );
    }

    #[test]
    fn grpc_route_preserves_rule_order_and_fallthrough_on_shared_listener() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [
                        {
                            "matches": [{
                                "method": {"method": "SayHello"},
                                "headers": [{"name": "x-tenant", "value": "a"}]
                            }],
                            "backendRefs": [{"name": "tenant-a", "port": 50051}]
                        },
                        {
                            "matches": [{"method": {"method": "SayHello"}}],
                            "backendRefs": [{"name": "shared", "port": 50052}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = grpc_catch_all_proxy(&result);
        assert_eq!(
            result.config.proxies.len(),
            1,
            "both pathless rules collapse onto one `/` listener"
        );
        let plugin = grpc_dispatch_plugin(&result, proxy);
        let rules = plugin.config["rules"]
            .as_array()
            .expect("ordered dispatch rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0]["match"]["headers"]["x-tenant"].as_str(),
            Some("a"),
            "the more specific header-bearing rule must be evaluated first"
        );
        assert_eq!(
            rules[0]["destination"]["backend_port"].as_u64(),
            Some(50051)
        );
        assert!(rules[1]["match"]["headers"].get("x-tenant").is_none());
        assert_eq!(
            rules[1]["destination"]["backend_port"].as_u64(),
            Some(50052)
        );
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
    }

    /// Gateway API v1.5.1 `GRPCRouteRule`: "Merging MUST not be done between
    /// GRPCRoutes and HTTPRoutes", and `GRPCRouteSpec` requires that an
    /// HTTPRoute and a GRPCRoute overlapping on one listener resolve to exactly
    /// one accepted Route by oldest `creationTimestamp`, then
    /// `{namespace}/{name}`. The losing Route must materialize nothing.
    fn cross_kind_routes_on_one_listener_reject_the_whole_losing_route(
        http_created: &str,
        grpc_created: &str,
    ) -> crate::config_sources::k8s::K8sTranslation {
        let mut http_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["edge.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
            }),
        );
        http_route.metadata.name = "web".to_string();
        http_route.metadata.creation_timestamp = Some(http_created.to_string());
        let mut grpc_route = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["edge.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"method": {"method": "SayHello"}}],
                    "backendRefs": [{"name": "grpc-api", "port": 50051}]
                }]
            }),
        );
        grpc_route.metadata.name = "grpc".to_string();
        grpc_route.metadata.creation_timestamp = Some(grpc_created.to_string());

        // Order-independence is the whole point of the timestamp rule: both
        // input orders must produce identical routing config. `updated_at`
        // stamps differ per construction, so compare the routing fingerprint.
        fn fingerprint(result: &crate::config_sources::k8s::K8sTranslation) -> Vec<String> {
            let mut entries: Vec<String> =
                result
                    .config
                    .proxies
                    .iter()
                    .map(|proxy| {
                        format!(
                            "proxy {} {} {:?} {:?} {}:{}",
                            proxy.namespace,
                            proxy.id,
                            proxy.hosts,
                            proxy.listen_path,
                            proxy.backend_host,
                            proxy.backend_port
                        )
                    })
                    .chain(result.config.plugin_configs.iter().map(|plugin| {
                        format!(
                            "plugin {} {} {} {:?} {}",
                            plugin.namespace,
                            plugin.id,
                            plugin.plugin_name,
                            plugin.proxy_id,
                            plugin.config
                        )
                    }))
                    .chain(
                        result.config.upstreams.iter().map(|upstream| {
                            format!("upstream {} {}", upstream.namespace, upstream.id)
                        }),
                    )
                    .collect();
            entries.sort();
            entries
        }

        let forward = translate_k8s_objects(
            &[edge_http_gateway(), http_route.clone(), grpc_route.clone()],
            options(),
        )
        .expect("translation succeeds");
        let reverse =
            translate_k8s_objects(&[edge_http_gateway(), grpc_route, http_route], options())
                .expect("translation succeeds");
        assert_eq!(
            fingerprint(&forward),
            fingerprint(&reverse),
            "the accepted route must not depend on input order"
        );
        forward
    }

    #[test]
    fn older_http_route_beats_a_newer_grpc_route_on_the_same_listener() {
        let result = cross_kind_routes_on_one_listener_reject_the_whole_losing_route(
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
        );

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_port, 8080,
            "the older HTTPRoute is the single accepted route"
        );
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
            "the rejected GRPCRoute must contribute no dispatch rules"
        );
        assert!(
            result.config.upstreams.is_empty(),
            "the rejected GRPCRoute must contribute no upstream"
        );
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains("GRPCRoute default/grpc")
                    && warning.contains("Gateway API forbids merging")
            }),
            "the whole-route rejection must be reported: {:?}",
            result.warnings
        );
        assert!(result.config.validate_unique_listen_paths().is_ok());
    }

    #[test]
    fn older_grpc_route_beats_a_newer_http_route_on_the_same_listener() {
        let result = cross_kind_routes_on_one_listener_reject_the_whole_losing_route(
            "2026-02-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        );

        let proxy = grpc_catch_all_proxy(&result);
        assert_eq!(
            proxy.backend_port, 50051,
            "the older GRPCRoute is the single accepted route"
        );
        let plugin = grpc_dispatch_plugin(&result, proxy);
        assert_eq!(
            plugin.config["reject_unmatched"].as_bool(),
            Some(true),
            "with no accepted HTTPRoute there is nothing for plain HTTP to fall through to"
        );
        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|proxy| proxy.backend_port == 8080),
            "the rejected HTTPRoute must contribute no proxy"
        );
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("HTTPRoute default/web")
                && warning.contains("Gateway API forbids merging")
        }));
    }

    #[test]
    fn cross_kind_routes_on_disjoint_hostnames_both_materialize() {
        // The rejection is scoped to intersecting hostnames on one listener,
        // so two kinds that never share a host are not in conflict.
        let mut http_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["web.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
            }),
        );
        http_route.metadata.name = "web".to_string();
        http_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut grpc_route = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["grpc.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"method": {"method": "SayHello"}}],
                    "backendRefs": [{"name": "grpc-api", "port": 50051}]
                }]
            }),
        );
        grpc_route.metadata.name = "grpc".to_string();
        grpc_route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[edge_http_gateway(), http_route, grpc_route], options())
                .expect("translation succeeds");

        let mut ports: Vec<u16> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.backend_port)
            .collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![8080, 50051]);
        assert!(
            !result
                .warnings
                .iter()
                .any(|warning| warning.contains("Gateway API forbids merging")),
            "unexpected cross-kind conflict: {:?}",
            result.warnings
        );
    }

    /// A Gateway whose listeners are named, so cross-kind arbitration has
    /// concrete listener identities to resolve parentRefs against.
    fn cross_kind_gateway(listeners: Value) -> K8sObject {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": listeners
            }),
        );
        gateway.metadata.name = "edge".to_string();
        gateway
    }

    fn cross_kind_http_route(parent_ref: Value, matches: Option<Value>) -> K8sObject {
        let rule = match matches {
            Some(matches) => serde_json::json!({
                "matches": matches,
                "backendRefs": [{"name": "web", "port": 8080}]
            }),
            None => serde_json::json!({"backendRefs": [{"name": "web", "port": 8080}]}),
        };
        let mut route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["edge.example.com"],
                "parentRefs": [parent_ref],
                "rules": [rule]
            }),
        );
        route.metadata.name = "web".to_string();
        route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        route
    }

    fn cross_kind_grpc_route(parent_ref: Value, method_match: Value) -> K8sObject {
        let mut route = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["edge.example.com"],
                "parentRefs": [parent_ref],
                "rules": [{
                    "matches": [{"method": method_match}],
                    "backendRefs": [{"name": "grpc-api", "port": 50051}]
                }]
            }),
        );
        route.metadata.name = "grpc".to_string();
        route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());
        route
    }

    fn cross_kind_route_conflicts_only(
        conflicts: &[GatewayApiRouteConflict],
    ) -> Vec<&GatewayApiRouteConflict> {
        conflicts
            .iter()
            .filter(|conflict| conflict.winner.kind != conflict.loser.kind)
            .collect()
    }

    /// Cross-kind arbitration is impossible when only one Route kind is present.
    /// Regression for the O(n²) same-kind scan that hung the 10k-route status
    /// planning fixture (#2397).
    #[test]
    fn same_kind_only_snapshots_emit_no_cross_kind_conflicts() {
        let gateway = cross_kind_gateway(serde_json::json!([{
            "name": "web",
            "port": 80,
            "protocol": "HTTP",
            "allowedRoutes": {
                "namespaces": {"from": "All"},
                "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
            }
        }]));

        let mut http_routes = Vec::new();
        for index in 0..8 {
            let mut route = cross_kind_http_route(serde_json::json!({"name": "edge"}), None);
            route.metadata.name = format!("http-{index}");
            route.metadata.creation_timestamp = Some(format!("2026-01-{:02}T00:00:00Z", index + 1));
            http_routes.push(route);
        }
        let http_objects: Vec<K8sObject> = std::iter::once(gateway.clone())
            .chain(http_routes)
            .collect();
        let http_acc = gateway_api_status_conflict_context(&http_objects, options());
        let http_conflicts = route_conflicts(&http_objects, &options(), Some(&http_acc));
        assert!(
            cross_kind_route_conflicts_only(&http_conflicts).is_empty(),
            "all-HTTP snapshots must not yield cross-kind conflicts: {:?}",
            http_conflicts
        );
        assert!(
            http_conflicts
                .iter()
                .any(|conflict| conflict.winner.kind == conflict.loser.kind),
            "same-kind overlap must still be collected: {:?}",
            http_conflicts
        );

        let mut grpc_routes = Vec::new();
        for index in 0..8 {
            // Identical method predicate so these claim the same conflict key;
            // distinct methods intentionally do not conflict (see
            // `distinct_grpc_predicates_on_one_listener_do_not_conflict`).
            let mut route = cross_kind_grpc_route(
                serde_json::json!({"name": "edge"}),
                serde_json::json!({"method": "SayHello"}),
            );
            route.metadata.name = format!("grpc-{index}");
            route.metadata.creation_timestamp = Some(format!("2026-01-{:02}T00:00:00Z", index + 1));
            grpc_routes.push(route);
        }
        let grpc_objects: Vec<K8sObject> = std::iter::once(gateway.clone())
            .chain(grpc_routes)
            .collect();
        let grpc_acc = gateway_api_status_conflict_context(&grpc_objects, options());
        let grpc_conflicts = route_conflicts(&grpc_objects, &options(), Some(&grpc_acc));
        assert!(
            cross_kind_route_conflicts_only(&grpc_conflicts).is_empty(),
            "all-gRPC snapshots must not yield cross-kind conflicts: {:?}",
            grpc_conflicts
        );
        assert!(
            grpc_conflicts
                .iter()
                .any(|conflict| conflict.winner.kind == conflict.loser.kind),
            "same-kind overlap must still be collected: {:?}",
            grpc_conflicts
        );

        let http_route = cross_kind_http_route(serde_json::json!({"name": "edge"}), None);
        let grpc_route = cross_kind_grpc_route(
            serde_json::json!({"name": "edge"}),
            serde_json::json!({"method": "SayHello"}),
        );
        let mixed_objects = vec![gateway, http_route, grpc_route];
        let mixed_acc = gateway_api_status_conflict_context(&mixed_objects, options());
        let mixed_conflicts = route_conflicts(&mixed_objects, &options(), Some(&mixed_acc));
        let cross_kind = cross_kind_route_conflicts_only(&mixed_conflicts);
        assert!(
            cross_kind
                .iter()
                .all(|conflict| conflict.winner.kind == "HTTPRoute"
                    && conflict.loser.kind == "GRPCRoute"),
            "mixed overlapping snapshot must arbitrate cross-kind: {:?}",
            cross_kind
        );
        assert!(
            cross_kind
                .iter()
                .any(|conflict| conflict.winner.name == "web" && conflict.loser.name == "grpc"),
            "older HTTPRoute must beat newer GRPCRoute: {:?}",
            cross_kind
        );
    }

    /// A parentRef is a *selector*, not a listener identity. A wildcard
    /// reference (no `sectionName`, no `port`) and a reference pinning that same
    /// listener by `sectionName` or `port` attach to the very same listener, so
    /// Gateway API v1.5.1's HTTPRoute/GRPCRoute merge prohibition applies and the
    /// newer Route must be rejected whole — even though the two literal
    /// parentRef keys differ.
    #[test]
    fn cross_kind_wildcard_and_pinned_parent_refs_contend_on_one_listener() {
        for grpc_parent_ref in [
            serde_json::json!({"name": "edge", "sectionName": "web"}),
            serde_json::json!({"name": "edge", "port": 80}),
        ] {
            let gateway = cross_kind_gateway(serde_json::json!([{
                "name": "web",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
                }
            }]));
            let http_route = cross_kind_http_route(serde_json::json!({"name": "edge"}), None);
            let grpc_route = cross_kind_grpc_route(
                grpc_parent_ref.clone(),
                serde_json::json!({"method": "SayHello"}),
            );

            for objects in [
                vec![gateway.clone(), http_route.clone(), grpc_route.clone()],
                vec![grpc_route.clone(), http_route.clone(), gateway.clone()],
            ] {
                let result =
                    translate_k8s_objects(&objects, options()).expect("translation succeeds");

                assert_eq!(
                    result.config.proxies.len(),
                    1,
                    "the older HTTPRoute is the single accepted route for {grpc_parent_ref}"
                );
                assert_eq!(result.config.proxies[0].backend_port, 8080);
                assert!(
                    !result
                        .config
                        .plugin_configs
                        .iter()
                        .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
                    "the rejected GRPCRoute must contribute no dispatch rules"
                );
                assert!(
                    result.warnings.iter().any(|warning| {
                        warning.contains("GRPCRoute default/grpc")
                            && warning.contains("Gateway API forbids merging")
                    }),
                    "expected a whole-route rejection for {grpc_parent_ref}: {:?}",
                    result.warnings
                );
                assert!(result.config.validate_unique_listen_paths().is_ok());
            }
        }
    }

    /// The mirror of the case above: two wildcard parentRefs share the literal
    /// `*/*` key, but `allowedRoutes.kinds` sends each kind to a *different*
    /// listener, so the two Routes never share one and neither may be rejected.
    #[test]
    fn cross_kind_wildcard_parent_refs_on_kind_disjoint_listeners_both_materialize() {
        let gateway = cross_kind_gateway(serde_json::json!([
            {
                "name": "web",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}]
                }
            },
            {
                "name": "grpc",
                "port": 8080,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "GRPCRoute"}]
                }
            }
        ]));
        // Distinct listen paths keep the same-kind dispatch lists separate; with
        // port-aware representation the kind-disjoint listeners also stamp
        // distinct `listen_port` values.
        let http_route = cross_kind_http_route(
            serde_json::json!({"name": "edge"}),
            Some(serde_json::json!([{"path": {"type": "PathPrefix", "value": "/admin"}}])),
        );
        let grpc_route = cross_kind_grpc_route(
            serde_json::json!({"name": "edge"}),
            serde_json::json!({"service": "pkg.Svc", "method": "SayHello"}),
        );

        for objects in [
            vec![gateway.clone(), http_route.clone(), grpc_route.clone()],
            vec![grpc_route.clone(), http_route.clone(), gateway.clone()],
        ] {
            let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

            let mut ports: Vec<u16> = result
                .config
                .proxies
                .iter()
                .map(|proxy| proxy.backend_port)
                .collect();
            ports.sort_unstable();
            assert_eq!(
                ports,
                vec![8080, 50051],
                "kind-disjoint listeners are not a shared listener"
            );
            assert!(
                !result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("Gateway API forbids merging")),
                "unexpected cross-kind conflict: {:?}",
                result.warnings
            );
            assert!(result.config.validate_unique_listen_paths().is_ok());
        }
    }

    /// The same kind-disjoint topology as above, but with both Routes on the
    /// listen path they most commonly occupy: a pathless GRPCRoute predicate
    /// *always* materializes on `/`, and an HTTPRoute with no `matches` (or a
    /// `PathPrefix: /` rule) does too. Gateway API requires both Routes to be
    /// accepted here — they never share a listener — and port-aware
    /// representation gives each a distinct `listen_port` so they validate.
    #[test]
    fn cross_kind_routes_on_kind_disjoint_listeners_do_not_merge() {
        let gateway = cross_kind_gateway(serde_json::json!([
            {
                "name": "web",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}]
                }
            },
            {
                "name": "grpc",
                "port": 8080,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "GRPCRoute"}]
                }
            }
        ]));
        let http_route = cross_kind_http_route(serde_json::json!({"name": "edge"}), None);
        let grpc_route = cross_kind_grpc_route(
            serde_json::json!({"name": "edge"}),
            serde_json::json!({"method": "SayHello"}),
        );

        for objects in [
            vec![gateway.clone(), http_route.clone(), grpc_route.clone()],
            vec![grpc_route.clone(), http_route.clone(), gateway.clone()],
        ] {
            let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

            assert!(
                !result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("Gateway API forbids merging")),
                "kind-disjoint listeners are not a shared listener: {:?}",
                result.warnings
            );
            assert_eq!(
                result.config.proxies.len(),
                2,
                "cross-kind routes must remain separate to preserve listener isolation"
            );
            let mut listen_ports: Vec<Option<u16>> = result
                .config
                .proxies
                .iter()
                .map(|proxy| proxy.listen_port)
                .collect();
            listen_ports.sort();
            assert_eq!(
                listen_ports,
                vec![Some(80), Some(8080)],
                "each kind-disjoint listener must stamp its port onto the proxy"
            );
            assert!(
                result.config.validate_unique_listen_paths().is_ok(),
                "port-scoped siblings must not collide: {:?}",
                result.config.validate_unique_listen_paths()
            );
        }
    }

    /// A wildcard parentRef can reach several listeners while emitting one
    /// parentRef selector. With port-aware representation, a loss on the shared
    /// listener withdraws only that listener's claim — the GRPCRoute keeps the
    /// grpc-only listener and continues to program traffic there.
    #[test]
    fn a_wildcard_parent_ref_losing_on_one_listener_retains_sibling_claims() {
        let gateway = cross_kind_gateway(serde_json::json!([
            {
                "name": "shared",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
                }
            },
            {
                "name": "grpc-only",
                "port": 8080,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "GRPCRoute"}]
                }
            }
        ]));
        // The HTTPRoute pins the shared listener and is older, so it wins
        // there. The GRPCRoute must keep the grpc-only listener.
        let http_route = cross_kind_http_route(
            serde_json::json!({"name": "edge", "sectionName": "shared"}),
            Some(serde_json::json!([{"path": {"type": "PathPrefix", "value": "/admin"}}])),
        );
        let grpc_route = cross_kind_grpc_route(
            serde_json::json!({"name": "edge"}),
            serde_json::json!({"method": "SayHello"}),
        );

        for objects in [
            vec![gateway.clone(), http_route.clone(), grpc_route.clone()],
            vec![grpc_route.clone(), http_route.clone(), gateway.clone()],
        ] {
            let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

            let mut ports: Vec<u16> = result
                .config
                .proxies
                .iter()
                .map(|proxy| proxy.backend_port)
                .collect();
            ports.sort_unstable();
            assert_eq!(
                ports,
                vec![8080, 50051],
                "the GRPCRoute loses on the shared listener but retains the grpc-only claim"
            );
            assert!(
                result
                    .config
                    .proxies
                    .iter()
                    .any(|proxy| proxy.backend_port == 50051 && proxy.listen_port == Some(8080)),
                "retained GRPCRoute claim must be scoped to the grpc-only listener port"
            );
            assert!(
                result
                    .materialized_route_parents
                    .iter()
                    .any(|entry| entry.route.kind == "GRPCRoute"),
                "the retained GRPCRoute must claim a materialized parent"
            );
            assert!(
                result.warnings.iter().any(|warning| {
                    warning.contains("GRPCRoute default/grpc")
                        && warning.contains("Gateway API forbids merging")
                }),
                "the shared-listener loss must still be reported: {:?}",
                result.warnings
            );
            assert!(result.config.validate_unique_listen_paths().is_ok());
        }
    }

    /// A multi-parent GRPCRoute that loses on the shared listener keeps the
    /// grpc-only parentRef claim once port-aware representation applies.
    #[test]
    fn a_multi_parent_route_losing_on_one_listener_retains_sibling_claims() {
        let gateway = cross_kind_gateway(serde_json::json!([
            {
                "name": "shared",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
                }
            },
            {
                "name": "grpc-only",
                "port": 8080,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "GRPCRoute"}]
                }
            }
        ]));
        let http_route = cross_kind_http_route(
            serde_json::json!({"name": "edge", "sectionName": "shared"}),
            None,
        );
        let mut grpc_route = cross_kind_grpc_route(
            serde_json::json!({"name": "edge", "sectionName": "shared"}),
            serde_json::json!({"method": "SayHello"}),
        );
        grpc_route.spec["parentRefs"] = serde_json::json!([
            {"name": "edge", "sectionName": "shared"},
            {"name": "edge", "sectionName": "grpc-only"}
        ]);

        let result = translate_k8s_objects(&[gateway, http_route, grpc_route], options())
            .expect("translation succeeds");

        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|proxy| { proxy.backend_port == 50051 && proxy.listen_port == Some(8080) }),
            "the GRPCRoute must retain the grpc-only claim: {:?}",
            result.config.proxies
        );
        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|proxy| { proxy.backend_port == 50051 && proxy.listen_port == Some(80) }),
            "the shared-listener GRPCRoute claim must still be withdrawn"
        );
        // A single unweighted backendRef resolves to a direct backend, not an
        // Upstream, so the retained claim's destination lives on the proxy.
        assert!(
            result.config.proxies.iter().any(|proxy| {
                proxy.listen_port == Some(8080)
                    && proxy.backend_port == 50051
                    && !proxy.backend_host.is_empty()
            }),
            "the retained GRPCRoute claim must keep its backend destination: {:?}",
            result.config.proxies
        );
    }

    /// A Route that loses on one listener retains sibling claims, and its
    /// withdrawn claim must not go on occupying the listener it lost on: a
    /// later Route of the *winning* kind still materializes there.
    ///
    /// Cross-kind arbitration is scoped to `(listener, hostname)`, so the later
    /// Route has to share the losing listener and the winner's kind for this to
    /// exercise the withdrawal — a newer HTTPRoute on the listener the GRPCRoute
    /// still holds would legitimately lose to it.
    #[test]
    fn a_partial_loss_does_not_displace_a_later_route_elsewhere() {
        let gateway = cross_kind_gateway(serde_json::json!([
            {
                "name": "first",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
                }
            },
            {
                "name": "second",
                "port": 8080,
                "protocol": "HTTP",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
                }
            }
        ]));

        let first_http = cross_kind_http_route(
            serde_json::json!({"name": "edge", "sectionName": "first"}),
            None,
        );

        let mut middle_grpc = cross_kind_grpc_route(
            serde_json::json!({"name": "edge", "sectionName": "first"}),
            serde_json::json!({"method": "SayHello"}),
        );
        middle_grpc.spec["parentRefs"] = serde_json::json!([
            {"name": "edge", "sectionName": "first"},
            {"name": "edge", "sectionName": "second"}
        ]);

        let mut later_http = cross_kind_http_route(
            serde_json::json!({"name": "edge", "sectionName": "first"}),
            Some(serde_json::json!([{
                "path": {"type": "PathPrefix", "value": "/survivor"}
            }])),
        );
        later_http.metadata.name = "survivor".to_string();
        later_http.metadata.creation_timestamp = Some("2026-03-01T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[gateway, first_http, middle_grpc, later_http], options())
                .expect("translation succeeds");

        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|proxy| proxy.backend_port == 50051 && proxy.listen_port == Some(8080)),
            "the middle GRPCRoute retains the second-listener claim after losing on the first"
        );
        assert!(
            result
                .materialized_route_parents
                .iter()
                .any(|entry| { entry.route.kind == "HTTPRoute" && entry.route.name == "survivor" }),
            "the later HTTPRoute on the listener the GRPCRoute lost must still materialize"
        );
        assert!(
            !result.warnings.iter().any(|warning| {
                warning.contains("HTTPRoute default/survivor")
                    && warning.contains("Gateway API forbids merging")
            }),
            "the later Route must not be reported as losing to a Route that only lost elsewhere: {:?}",
            result.warnings
        );
    }

    /// An explicit `null` is malformed operator input, not an omitted field.
    /// Reading it as absent would widen `method` into the any-gRPC-call match
    /// and `headers` into the headerless match, so both fail closed with a
    /// generic, field-specific diagnostic.
    #[test]
    fn grpc_route_explicit_null_predicates_fail_closed() {
        for (entry, expected_fragment) in [
            (
                serde_json::json!({"method": null}),
                "matches[].method must not be null",
            ),
            (
                serde_json::json!({
                    "method": null,
                    "headers": [{"name": "x-tenant", "value": "a"}]
                }),
                "matches[].method must not be null",
            ),
            (
                serde_json::json!({"method": null, "path": {"value": "/api"}}),
                "matches[].method must not be null",
            ),
            (
                serde_json::json!({"headers": null}),
                "matches[].headers must not be null",
            ),
            (
                serde_json::json!({
                    "method": {"service": "pkg.Svc", "method": "SayHello"},
                    "headers": null
                }),
                "matches[].headers must not be null",
            ),
        ] {
            let reason = grpc_route_match(&entry)
                .expect_err("an explicit null predicate must fail closed")
                .to_string();
            assert!(
                reason.contains(expected_fragment),
                "expected `{expected_fragment}` in `{reason}`"
            );
            assert!(
                grpc_dispatch_match_criteria(&entry).is_none(),
                "a refused predicate must not reach dispatch state: {entry}"
            );

            let result = translate_k8s_objects(
                &[object(
                    "GRPCRoute",
                    serde_json::json!({
                        "hostnames": ["grpc.example.com"],
                        "rules": [{
                            "matches": [entry],
                            "backendRefs": [{"name": "grpc-api"}]
                        }]
                    }),
                )],
                options(),
            )
            .expect("translation succeeds");

            assert!(
                result.config.proxies.is_empty(),
                "an explicit null predicate must not materialize a route: {reason}"
            );
            assert!(
                !result
                    .config
                    .plugin_configs
                    .iter()
                    .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
                "an explicit null predicate must not emit dispatch rules: {reason}"
            );
            assert!(
                result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("dropped fail-closed")
                        && warning.contains(expected_fragment)),
                "expected a field-specific drop warning for `{expected_fragment}` in {:?}",
                result.warnings
            );
        }
    }

    /// The other half of the split above: an *omitted* `method` / `headers`
    /// keeps its documented meaning and still materializes.
    #[test]
    fn grpc_route_omitted_predicates_remain_valid() {
        let any_call = grpc_route_match(&serde_json::json!({}))
            .expect("an empty match entry is the any-gRPC-call predicate");
        assert_eq!(any_call, grpc_any_call_match());

        let header_only = grpc_route_match(&serde_json::json!({
            "headers": [{"name": "x-tenant", "value": "a"}]
        }))
        .expect("a header-only match omits `method`");
        assert_eq!(
            header_only.plan,
            GrpcRouteMatchPlan::UriRegex {
                pattern: grpc_any_call_pattern()
            }
        );
        assert_eq!(
            header_only.headers,
            vec![("x-tenant".to_string(), "a".to_string())]
        );

        let method_only = grpc_route_match(&serde_json::json!({
            "method": {"service": "pkg.Svc", "method": "SayHello"}
        }))
        .expect("a method-only match omits `headers`");
        assert!(method_only.headers.is_empty());
    }

    #[test]
    fn a_rejected_cross_kind_route_does_not_reject_its_same_kind_sibling() {
        // web (HTTPRoute, oldest) beats grpc (GRPCRoute); the *second*
        // HTTPRoute is the same kind as the winner, so it merges normally
        // instead of being dragged down by the rejected GRPCRoute.
        let mut web = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["edge.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "web", "port": 8080}]
                }]
            }),
        );
        web.metadata.name = "web".to_string();
        web.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut grpc_route = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["edge.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"method": {"method": "SayHello"}}],
                    "backendRefs": [{"name": "grpc-api", "port": 50051}]
                }]
            }),
        );
        grpc_route.metadata.name = "grpc".to_string();
        grpc_route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());
        let mut late_web = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["edge.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                    "backendRefs": [{"name": "admin", "port": 9090}]
                }]
            }),
        );
        late_web.metadata.name = "late-web".to_string();
        late_web.metadata.creation_timestamp = Some("2026-03-01T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[edge_http_gateway(), web, grpc_route, late_web], options())
                .expect("translation succeeds");

        let mut ports: Vec<u16> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.backend_port)
            .collect();
        ports.sort_unstable();
        assert_eq!(
            ports,
            vec![8080, 9090],
            "both HTTPRoutes materialize; only the GRPCRoute is rejected"
        );
    }

    #[test]
    fn distinct_grpc_predicates_on_one_listener_do_not_conflict() {
        let mut hello = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["grpc.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"method": {"method": "SayHello"}}],
                    "backendRefs": [{"name": "hello", "port": 50051}]
                }]
            }),
        );
        hello.metadata.name = "hello".to_string();
        hello.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut goodbye = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["grpc.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"method": {"method": "SayGoodbye"}}],
                    "backendRefs": [{"name": "goodbye", "port": 50052}]
                }]
            }),
        );
        goodbye.metadata.name = "goodbye".to_string();
        goodbye.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[edge_http_gateway(), hello, goodbye], options())
            .expect("translation succeeds");

        let proxy = grpc_catch_all_proxy(&result);
        let plugin = grpc_dispatch_plugin(&result, proxy);
        let rules = plugin.config["rules"]
            .as_array()
            .expect("ordered dispatch rules");
        assert_eq!(
            rules.len(),
            2,
            "different gRPC methods are different predicates, not a route conflict"
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|warning| warning.contains("conflicted on parent")),
            "unexpected conflict warning: {:?}",
            result.warnings
        );
    }

    #[test]
    fn grpc_route_preserves_weighted_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/helloworld.Greeter"}}
                        ],
                        "backendRefs": [
                            {"name": "grpc-v1", "port": 50051, "weight": 90},
                            {"name": "grpc-v2", "port": 50052, "weight": 10}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/helloworld.Greeter")
        );
        assert_eq!(result.config.upstreams.len(), 1);
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(result.config.upstreams[0].id.as_str())
        );
        assert_eq!(result.config.upstreams[0].targets.len(), 2);
        assert_eq!(result.config.upstreams[0].targets[0].weight, 90);
        assert_eq!(result.config.upstreams[0].targets[1].port, 50052);
    }

    #[test]
    fn gateway_api_weighted_upstream_ids_include_route_kind() {
        let result = translate_k8s_objects(
            &[
                object(
                    "HTTPRoute",
                    serde_json::json!({
                        "hostnames": ["api.example.com"],
                        "rules": [{
                            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                            "backendRefs": [
                                {"name": "api-v1", "port": 8080, "weight": 90},
                                {"name": "api-v2", "port": 8081, "weight": 10}
                            ]
                        }]
                    }),
                ),
                object(
                    "GRPCRoute",
                    serde_json::json!({
                        "hostnames": ["grpc.example.com"],
                        "rules": [{
                            "matches": [
                                {"path": {"type": "PathPrefix", "value": "/helloworld.Greeter"}}
                            ],
                            "backendRefs": [
                                {"name": "grpc-v1", "port": 50051, "weight": 90},
                                {"name": "grpc-v2", "port": 50052, "weight": 10}
                            ]
                        }]
                    }),
                ),
            ],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert_eq!(result.config.upstreams.len(), 2);
        assert_ne!(result.config.upstreams[0].id, result.config.upstreams[1].id);
        assert!(
            result
                .config
                .upstreams
                .iter()
                .any(|upstream| upstream.id.contains("httproute"))
        );
        assert!(
            result
                .config
                .upstreams
                .iter()
                .any(|upstream| upstream.id.contains("grpcroute"))
        );
        assert_eq!(
            result
                .config
                .proxies
                .iter()
                .filter_map(|proxy| proxy.upstream_id.as_deref())
                .collect::<HashSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn http_route_keeps_all_zero_weight_rule_as_500_fault() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [
                        {
                            "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                            "backendRefs": [{"name": "admin", "port": 8080, "weight": 0}]
                        },
                        {
                            "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                            "backendRefs": [{"name": "api", "port": 8080}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        let admin_proxy = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some("/admin"))
            .expect("admin route proxy exists");
        assert_eq!(admin_proxy.backend_host, ZERO_WEIGHT_BACKEND_HOST);
        assert_eq!(admin_proxy.backend_port, ZERO_WEIGHT_BACKEND_PORT);
        assert!(admin_proxy.upstream_id.is_none());
        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| {
                plugin.plugin_name == "mesh_route_dispatch"
                    && plugin.proxy_id.as_deref() == Some(admin_proxy.id.as_str())
            })
            .expect("zero-weight-only route should carry mesh_route_dispatch");
        let abort = &dispatch.config["rules"][0]["fault"]["abort"];
        assert_eq!(abort["status_code"], 500);
        assert_eq!(abort["percentage"], 100.0);
        let body = abort["body"]
            .as_str()
            .expect("fault body should be a string");
        let body: Value = serde_json::from_str(body).expect("fault body should be valid JSON");
        assert_eq!(
            body["error"].as_str(),
            Some("Gateway API rule has no serviceable backendRefs")
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight backendRefs"))
        );
    }

    #[test]
    fn http_route_skips_zero_weight_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 8080, "weight": 0},
                            {"name": "stable", "port": 9090, "weight": 100}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 9090);
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight backendRef"))
        );
    }

    #[test]
    fn http_route_omitted_weight_defaults_to_one_and_skips_zero_sibling() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 8080, "weight": 0},
                            {"name": "stable", "port": 9090}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 9090);
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight backendRef"))
        );
    }

    #[test]
    fn http_route_rejects_backend_weight_above_ferrum_limit() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "api", "port": 8080, "weight": 65536}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("oversized backend weight should fail translation");

        assert!(
            err.to_string()
                .contains("weight must be between 0 and 65535")
        );
    }

    #[test]
    fn http_route_rejects_malformed_backend_weights() {
        for weight in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("high"),
        ] {
            let err = translate_k8s_objects(
                &[object(
                    "HTTPRoute",
                    serde_json::json!({
                        "rules": [{
                            "backendRefs": [{"name": "api", "port": 8080, "weight": weight}]
                        }]
                    }),
                )],
                options(),
            )
            .expect_err("malformed backend weight should fail translation");

            assert!(
                err.to_string()
                    .contains("weight must be between 0 and 65535")
            );
        }
    }

    #[test]
    fn translates_tcp_route_to_stream_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "db", "port": 5432}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].listen_port, Some(5432));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn tcp_route_uses_materialized_gateway_listener_port() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tcp",
                    "port": 15432,
                    "protocol": "TCP",
                    "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
                }]
            }),
        );
        let route = object(
            "TCPRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample"}],
                "rules": [{
                    "backendRefs": [{"name": "db", "port": 5432}]
                }]
            }),
        );

        let result =
            translate_k8s_objects(&[gateway, route], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].backend_port, 5432);
        assert_eq!(result.config.proxies[0].listen_port, Some(15432));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn tcp_route_materializes_cross_namespace_parent_ref_when_listener_allows_it() {
        let mut gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tcp",
                    "port": 5432,
                    "protocol": "TCP",
                    "allowedRoutes": {
                        "namespaces": {"from": "All"},
                        "kinds": [{"kind": "TCPRoute"}]
                    }
                }]
            }),
        );
        gateway.metadata.namespace = "infra".to_string();
        let route = object(
            "TCPRoute",
            serde_json::json!({
                "parentRefs": [{
                    "name": "sample",
                    "namespace": "infra"
                }],
                "rules": [{
                    "backendRefs": [{"name": "db", "port": 5432}]
                }]
            }),
        );

        let result = translate_k8s_objects(
            &[gateway, route],
            options().with_source_namespaces(vec!["default".to_string(), "infra".to_string()]),
        )
        .expect("an allowed cross-namespace L4 parentRef should materialize");

        assert_eq!(result.config.proxies.len(), 1);
        let proxy = &result.config.proxies[0];
        assert_eq!(proxy.namespace, "infra");
        assert_eq!(proxy.listen_port, Some(5432));
        assert_eq!(proxy.backend_host, "db.default.svc.cluster.local");
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
    }

    #[test]
    fn tcp_route_skips_zero_weight_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 5432, "weight": 0},
                            {"name": "stable", "port": 5433, "weight": 1}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 5433);
        assert_eq!(result.config.proxies[0].listen_port, Some(5433));
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight backendRef"))
        );
    }

    #[test]
    fn tls_route_with_only_zero_weight_backend_refs_is_not_materialized() {
        let result = translate_k8s_objects(
            &[object(
                "TLSRoute",
                serde_json::json!({
                    "hostnames": ["db.example.com"],
                    "rules": [{
                        "backendRefs": [{"name": "dark", "port": 15443, "weight": 0}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight backendRefs"))
        );
    }

    #[test]
    fn tls_route_materializes_sni_passthrough_on_gateway_tls_listener_port() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tls",
                    "port": 15443,
                    "protocol": "TLS",
                    "tls": {"mode": "Passthrough"},
                    "allowedRoutes": {"kinds": [{"kind": "TLSRoute"}]}
                }]
            }),
        );
        let route = object(
            "TLSRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample", "sectionName": "tls"}],
                "hostnames": ["db.example.com"],
                "rules": [{
                    "backendRefs": [{"name": "db", "port": 5432}]
                }]
            }),
        );

        let result =
            translate_k8s_objects(&[gateway, route], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        let proxy = &result.config.proxies[0];
        assert_eq!(proxy.listen_port, Some(15443));
        assert_eq!(proxy.backend_port, 5432);
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
        assert!(
            proxy.passthrough,
            "TLSRoute must be SNI passthrough (encrypted bytes, no termination)"
        );
        assert_eq!(proxy.hosts, vec!["db.example.com".to_string()]);
        assert!(
            !proxy.frontend_tls,
            "passthrough and frontend_tls are mutually exclusive"
        );
    }

    #[test]
    fn tls_route_is_bounded_by_gateway_listener_hostname() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tls",
                    "hostname": "allowed.example.com",
                    "port": 15443,
                    "protocol": "TLS",
                    "tls": {"mode": "Passthrough"},
                    "allowedRoutes": {"kinds": [{"kind": "TLSRoute"}]}
                }]
            }),
        );
        let route = object(
            "TLSRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample", "sectionName": "tls"}],
                "hostnames": ["evil.example.com"],
                "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
            }),
        );

        let result =
            translate_k8s_objects(&[gateway, route], options()).expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
    }

    #[test]
    fn tls_route_without_hostnames_inherits_gateway_listener_hostname() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tls",
                    "hostname": "allowed.example.com",
                    "port": 15443,
                    "protocol": "TLS",
                    "tls": {"mode": "Passthrough"},
                    "allowedRoutes": {"kinds": [{"kind": "TLSRoute"}]}
                }]
            }),
        );
        let route = object(
            "TLSRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample", "sectionName": "tls"}],
                "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
            }),
        );

        let result =
            translate_k8s_objects(&[gateway, route], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].hosts,
            vec!["allowed.example.com".to_string()]
        );
    }

    #[test]
    fn tls_route_rejects_terminate_listener_without_backend_port_fallback() {
        let gateway = object(
            "Gateway",
            serde_json::json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "tls-terminate",
                    "port": 15443,
                    "protocol": "TLS",
                    "tls": {"mode": "Terminate"},
                    "allowedRoutes": {"kinds": [{"kind": "TLSRoute"}]}
                }]
            }),
        );
        let route = object(
            "TLSRoute",
            serde_json::json!({
                "parentRefs": [{"name": "sample", "sectionName": "tls-terminate"}],
                "hostnames": ["db.example.com"],
                "rules": [{
                    "backendRefs": [{"name": "db", "port": 5432}]
                }]
            }),
        );

        let error = translate_k8s_objects(&[gateway, route], options())
            .expect_err("TLSRouteModeTerminate must fail closed until implemented");

        assert!(error.to_string().contains("not permitted"));
        assert!(error.to_string().contains("Gateway listener"));
    }

    #[test]
    fn parented_l4_route_without_materialized_listener_never_uses_backend_port() {
        let result = translate_k8s_objects(
            &[object(
                "TLSRoute",
                serde_json::json!({
                    "parentRefs": [{"name": "missing-gateway"}],
                    "hostnames": ["db.example.com"],
                    "rules": [{
                        "backendRefs": [{"name": "db", "port": 5432}]
                    }]
                }),
            )],
            options(),
        )
        .expect("unknown parent is represented as an unmaterialized route");

        assert!(
            result.config.proxies.is_empty(),
            "a parented route must not expose the backend port as a listener"
        );
    }

    #[test]
    fn rejects_gateway_api_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "api", "port": 70000}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid port must fail closed");

        assert!(err.to_string().contains("backendRefs[].port"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_gateway_listener_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "Gateway",
                serde_json::json!({
                    "gatewayClassName": "ferrum",
                    "listeners": [{"name": "http", "port": 70000, "protocol": "HTTP"}]
                }),
            )],
            options(),
        )
        .expect_err("invalid listener port must fail closed");

        assert!(err.to_string().contains("listeners[].port"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_l4_route_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "db", "port": 70000}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid L4 backend port must fail closed");

        assert!(err.to_string().contains("TCPRoute backendRefs[].port"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn unresolved_cross_namespace_backend_ref_materializes_fail_closed_route() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{
                            "name": "api",
                            "namespace": "backend",
                            "port": 8080
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("cross-namespace backendRef should translate to a fail-closed route");

        assert_invalid_backend_fault_route(
            &result,
            "Gateway API backendRef is not permitted by ReferenceGrant",
        );
    }

    #[test]
    fn existing_service_with_missing_backend_ref_port_materializes_fail_closed_route() {
        let service = core_service(
            "api",
            serde_json::json!({
                "ports": [{"name": "http", "port": 8080}]
            }),
        );
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 9090}]
                }]
            }),
        );

        let result = translate_k8s_objects(&[service, route], options())
            .expect("missing Service port should translate to invalid backend behavior");

        assert_invalid_backend_fault_route(&result, "Gateway API backendRef target was not found");
    }

    #[test]
    fn mixed_valid_and_invalid_backend_refs_preserve_invalid_weight_as_fault_percentage() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/mixed"}}],
                        "backendRefs": [
                            {"name": "valid", "port": 8080, "weight": 3},
                            {"name": "blocked", "namespace": "other", "port": 8080, "weight": 1}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("mixed backendRefs should translate with weighted fault");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "valid.default.svc.cluster.local"
        );
        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("mixed invalid backendRefs need dispatch fault");
        let abort = &dispatch.config["rules"][0]["fault"]["abort"];
        assert_eq!(abort["status_code"], 500);
        assert_eq!(abort["percentage"], 25.0);
        let body: Value = serde_json::from_str(abort["body"].as_str().unwrap()).unwrap();
        assert_eq!(
            body["error"].as_str(),
            Some("Gateway API backendRef is not permitted by ReferenceGrant")
        );
    }

    #[test]
    fn skips_zero_weight_cross_namespace_backend_ref_without_reference_grant() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "api", "port": 8080},
                            {
                                "name": "staged-api",
                                "namespace": "backend",
                                "port": 8081,
                                "weight": 0
                            }
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("zero-weight cross-namespace backendRef should not require a ReferenceGrant");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "api.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn mismatched_reference_grant_from_group_materializes_fail_closed_route() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let result = translate_k8s_objects(&[route, grant], options())
            .expect("ReferenceGrant group mismatch should translate to a fail-closed route");

        assert_invalid_backend_fault_route(
            &result,
            "Gateway API backendRef is not permitted by ReferenceGrant",
        );
    }

    #[test]
    fn mismatched_reference_grant_to_group_materializes_fail_closed_route() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "example.com",
                    "kind": "Service"
                }]
            }),
        );

        let result = translate_k8s_objects(&[route, grant], options())
            .expect("ReferenceGrant target group mismatch should translate fail-closed");

        assert_invalid_backend_fault_route(
            &result,
            "Gateway API backendRef is not permitted by ReferenceGrant",
        );
    }

    #[test]
    fn unsupported_backend_ref_kind_materializes_fail_closed_route() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{
                            "group": "example.com",
                            "kind": "Backend",
                            "name": "api",
                            "namespace": "default",
                            "port": 8080
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("non-Service backendRefs should translate to a fail-closed route");

        assert_invalid_backend_fault_route(&result, "Gateway API backendRef kind is unsupported");
    }

    #[test]
    fn accepts_cross_namespace_backend_ref_with_reference_grant() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let options =
            options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]);

        let result = translate_k8s_objects(&[route, grant], options)
            .expect("ReferenceGrant should authorize backendRef");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "api.backend.svc.cluster.local"
        );
    }

    #[test]
    fn excluded_namespace_reference_grant_does_not_authorize_included_route() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );
        let options = options().with_source_namespaces(vec!["default".to_string()]);

        let result = translate_k8s_objects(&[route, grant], options)
            .expect("excluded ReferenceGrant should translate to a fail-closed route");

        assert_invalid_backend_fault_route(
            &result,
            "Gateway API backendRef is not permitted by ReferenceGrant",
        );
    }

    #[test]
    fn accepts_tcp_route_cross_namespace_backend_ref_with_reference_grant() {
        let route = object(
            "TCPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "db",
                        "namespace": "backend",
                        "port": 5432
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "TCPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let options =
            options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]);

        let result = translate_k8s_objects(&[route, grant], options)
            .expect("ReferenceGrant should authorize TCPRoute backendRef");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "db.backend.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].listen_port, Some(5432));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn rejects_tls_route_cross_namespace_backend_ref_when_reference_grant_from_group_mismatches() {
        let route = object(
            "TLSRoute",
            serde_json::json!({
                "hostnames": ["db.example.com"],
                "rules": [{
                    "backendRefs": [{
                        "name": "db",
                        "namespace": "backend",
                        "port": 15443
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "",
                    "kind": "TLSRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let err = translate_k8s_objects(&[route, grant], options())
            .expect_err("ReferenceGrant group must match TLSRoute API group");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn http_route_uses_custom_cluster_domain() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["app.example.com"],
                "rules": [{
                    "backendRefs": [{ "name": "stable", "port": 8080 }]
                }]
            }),
        );

        let opts = options().with_cluster_domain("corp.example".to_string());
        let result =
            translate_k8s_objects(&[route], opts).expect("custom cluster domain should work");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.corp.example"
        );
    }

    #[test]
    fn tcp_route_uses_custom_cluster_domain() {
        let route = object(
            "TCPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{ "name": "db", "port": 5432 }]
                }]
            }),
        );

        let opts = options().with_cluster_domain("corp.example".to_string());
        let result =
            translate_k8s_objects(&[route], opts).expect("custom cluster domain should work");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "db.default.svc.corp.example"
        );
    }

    #[test]
    fn lossy_http_route_ids_in_two_namespaces_both_survive_with_scoped_plugins() {
        // resource_id joins with dashes, so ns `a` / name `b-c` collides with
        // ns `a-b` / name `c` on the bare proxy/plugin id string.
        let mut route_a = object_in_namespace(
            "HTTPRoute",
            "a",
            serde_json::json!({
                "hostnames": ["a.example.com"],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET"
                    }],
                    "filters": [{
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": {
                            "set": [{"name": "X-Tenant", "value": "a"}]
                        }
                    }],
                    "backendRefs": [{"name": "api-a", "port": 8080}]
                }, {
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "POST"
                    }],
                    "backendRefs": [{"name": "api-a-post", "port": 8081}]
                }]
            }),
        );
        route_a.metadata.name = "b-c".to_string();

        let mut route_b = object_in_namespace(
            "HTTPRoute",
            "a-b",
            serde_json::json!({
                "hostnames": ["b.example.com"],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET"
                    }],
                    "filters": [{
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": {
                            "set": [{"name": "X-Tenant", "value": "a-b"}]
                        }
                    }],
                    "backendRefs": [{"name": "api-b", "port": 9080}]
                }, {
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "POST"
                    }],
                    "backendRefs": [{"name": "api-b-post", "port": 9081}]
                }]
            }),
        );
        route_b.metadata.name = "c".to_string();

        let result = translate_k8s_objects(
            &[route_a, route_b],
            options().with_source_namespaces(vec!["a".to_string(), "a-b".to_string()]),
        )
        .expect("lossy cross-namespace HTTPRoutes must both translate");

        let expected_id = resource_id("gwapi-route", "a", "b-c", "httproute-0");
        assert_eq!(
            expected_id,
            resource_id("gwapi-route", "a-b", "c", "httproute-0"),
            "fixture must exercise the lossy dash-join collision"
        );

        let proxy_a = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == "a" && proxy.id == expected_id)
            .expect("namespace a proxy must survive");
        let proxy_b = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == "a-b" && proxy.id == expected_id)
            .expect("namespace a-b proxy must survive");
        assert_eq!(proxy_a.hosts, vec!["a.example.com".to_string()]);
        assert_eq!(proxy_b.hosts, vec!["b.example.com".to_string()]);

        let dispatch_a = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| {
                plugin.plugin_name == "mesh_route_dispatch"
                    && plugin.namespace == "a"
                    && plugin.proxy_id.as_deref() == Some(expected_id.as_str())
            })
            .expect("namespace a must keep its own dispatch plugin");
        let dispatch_b = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| {
                plugin.plugin_name == "mesh_route_dispatch"
                    && plugin.namespace == "a-b"
                    && plugin.proxy_id.as_deref() == Some(expected_id.as_str())
            })
            .expect("namespace a-b must keep its own dispatch plugin");
        assert_eq!(
            dispatch_a.config["rules"]
                .as_array()
                .map(|rules| rules.len()),
            Some(2),
            "Gateway API merge within namespace a must still combine GET+POST rules"
        );
        assert_eq!(
            dispatch_b.config["rules"]
                .as_array()
                .map(|rules| rules.len()),
            Some(2),
            "Gateway API merge within namespace a-b must still combine GET+POST rules"
        );
        assert!(
            result.config.plugin_configs.iter().any(|plugin| {
                plugin.plugin_name == "request_transformer"
                    && plugin.namespace == "a"
                    && plugin.proxy_id.as_deref() == Some(expected_id.as_str())
            }),
            "tenant a request_transformer must not be suppressed by tenant a-b"
        );
        assert!(
            result.config.plugin_configs.iter().any(|plugin| {
                plugin.plugin_name == "request_transformer"
                    && plugin.namespace == "a-b"
                    && plugin.proxy_id.as_deref() == Some(expected_id.as_str())
            }),
            "tenant a-b request_transformer must not be suppressed by tenant a"
        );
    }

    fn assert_proxy_hosts(proxies: &[Proxy], listen_path: &str, expected_hosts: &[&str]) {
        let proxy = proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some(listen_path))
            .unwrap_or_else(|| panic!("missing proxy for {listen_path}"));
        assert_eq!(
            proxy.hosts,
            expected_hosts
                .iter()
                .map(|host| host.to_string())
                .collect::<Vec<_>>()
        );
    }

    fn backend_lb_policy(name: &str, spec: Value) -> K8sObject {
        let mut policy = object("BackendLBPolicy", spec);
        policy.api_version = "gateway.networking.k8s.io/v1alpha2".to_string();
        policy.metadata.name = name.to_string();
        policy
    }

    fn x_backend_traffic_policy(name: &str, spec: Value) -> K8sObject {
        let mut policy = object("XBackendTrafficPolicy", spec);
        policy.api_version = "gateway.networking.x-k8s.io/v1alpha1".to_string();
        policy.metadata.name = name.to_string();
        policy
    }

    fn http_route_to_service(service: &str) -> K8sObject {
        object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": service, "port": 8080}]
                }]
            }),
        )
    }

    #[test]
    fn backend_lb_policy_cookie_session_forces_consistent_hash_upstream() {
        let policy = backend_lb_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "lb-affinity",
                    "type": "Cookie",
                    "cookieConfig": {"lifetimeType": "Session"}
                }
            }),
        );
        let route = http_route_to_service("api");
        let result = translate_k8s_objects(&[policy, route], options())
            .expect("BackendLBPolicy cookie session should translate");

        assert_eq!(result.config.upstreams.len(), 1);
        let upstream = &result.config.upstreams[0];
        assert_eq!(
            upstream.algorithm,
            crate::config::types::LoadBalancerAlgorithm::ConsistentHashing
        );
        assert!(
            upstream
                .hash_on
                .as_deref()
                .is_some_and(|value| value.starts_with("cookie:lb-affinity-fe-")),
            "cookie name must be scoped to the route rule: {:?}",
            upstream.hash_on
        );
        let cookie = upstream
            .hash_on_cookie_config
            .as_ref()
            .expect("cookie config");
        assert!(
            cookie.session_cookie,
            "Session lifetimeType must omit Max-Age"
        );
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(upstream.id.as_str()),
            "single-backend sticky routes must materialize an Upstream so \
             Set-Cookie injection runs on the live LB path"
        );
    }

    #[test]
    fn x_backend_traffic_policy_permanent_cookie_sets_max_age() {
        let policy = x_backend_traffic_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "perm",
                    "type": "Cookie",
                    "absoluteTimeout": "2h",
                    "cookieConfig": {"lifetimeType": "Permanent"}
                }
            }),
        );
        let result = translate_k8s_objects(&[policy, http_route_to_service("api")], options())
            .expect("XBackendTrafficPolicy permanent cookie should translate");
        let cookie = result.config.upstreams[0]
            .hash_on_cookie_config
            .as_ref()
            .expect("cookie config");
        assert!(!cookie.session_cookie);
        assert_eq!(cookie.ttl_seconds, 7200);
    }

    #[test]
    fn session_cookie_absolute_timeout_fails_closed() {
        let policy = x_backend_traffic_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "bounded-session",
                    "type": "Cookie",
                    "absoluteTimeout": "2h",
                    "cookieConfig": {"lifetimeType": "Session"}
                }
            }),
        );
        let err = translate_k8s_objects(&[policy.clone(), http_route_to_service("api")], options())
            .expect_err("an unenforced absolute session lifetime must fail closed");
        assert!(
            err.to_string()
                .contains("cannot enforce an absolute lifetime"),
            "got: {err}"
        );

        let status = super::backend_lb_policy_status(&policy, false);
        assert_eq!(status["ancestors"][0]["conditions"][0]["status"], "False");
    }

    #[test]
    fn gateway_api_duration_parser_rejects_wider_istio_grammar() {
        assert!(is_gateway_api_duration("1h2m3s4ms"));
        assert!(is_gateway_api_duration("0s"));
        assert!(!is_gateway_api_duration("1.5s"));
        assert!(!is_gateway_api_duration("123456s"));
        assert!(!is_gateway_api_duration("1s2s3s4s5s"));
        assert!(!is_gateway_api_duration(""));
    }

    #[test]
    fn malformed_session_persistence_shape_fails_closed() {
        let policy = x_backend_traffic_policy(
            "malformed",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": "Cookie"
            }),
        );
        let err = translate_k8s_objects(std::slice::from_ref(&policy), options())
            .expect_err("a non-object sessionPersistence must fail closed");
        assert!(err.to_string().contains("must be an object"), "got: {err}");
        let status = super::backend_lb_policy_status(&policy, false);
        assert_eq!(status["ancestors"][0]["conditions"][0]["status"], "False");
    }

    #[test]
    fn service_policy_cookie_is_scoped_independently_to_each_route_rule() {
        let policy = backend_lb_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "shared-policy-name",
                    "type": "Cookie"
                }
            }),
        );
        let mut route = http_route_to_service("api");
        route.spec["rules"] = serde_json::json!([
            {
                "matches": [{"path": {"type": "PathPrefix", "value": "/one"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            },
            {
                "matches": [{"path": {"type": "PathPrefix", "value": "/two"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }
        ]);
        let result = translate_k8s_objects(&[policy, route], options())
            .expect("both route rules should receive independent persistence");
        assert_eq!(result.config.upstreams.len(), 2);
        let names = result
            .config
            .upstreams
            .iter()
            .map(|upstream| upstream.hash_on.as_deref().expect("cookie hash key"))
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), 2, "route rules must not share a cookie name");
        assert!(
            names
                .iter()
                .all(|name| name.starts_with("cookie:shared-policy-name-fe-"))
        );
    }

    #[test]
    fn http_route_rule_session_persistence_overrides_backend_policy() {
        let policy = backend_lb_policy(
            "service-sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "from-policy",
                    "type": "Cookie"
                }
            }),
        );
        let mut route = http_route_to_service("api");
        route.spec["rules"][0]["sessionPersistence"] = serde_json::json!({
            "sessionName": "from-route",
            "type": "Cookie"
        });
        let result = translate_k8s_objects(&[policy, route], options())
            .expect("route-level sessionPersistence should win");
        assert!(
            result.config.upstreams[0]
                .hash_on
                .as_deref()
                .is_some_and(|value| value.starts_with("cookie:from-route-fe-"))
        );
        assert!(result.config.upstreams[0].hash_on_cookie_config.is_some());
    }

    #[test]
    fn backend_lb_policy_idle_timeout_fails_closed() {
        let policy = backend_lb_policy(
            "idle",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "type": "Cookie",
                    "idleTimeout": "30s"
                }
            }),
        );
        let err =
            translate_k8s_objects(&[policy], options()).expect_err("idleTimeout must fail closed");
        assert!(err.to_string().contains("idleTimeout"), "got: {err}");
    }

    #[test]
    fn backend_lb_policy_permanent_without_absolute_timeout_fails_closed() {
        let policy = backend_lb_policy(
            "perm",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "type": "Cookie",
                    "cookieConfig": {"lifetimeType": "Permanent"}
                }
            }),
        );
        let err = translate_k8s_objects(&[policy], options())
            .expect_err("Permanent without absoluteTimeout must fail");
        assert!(err.to_string().contains("absoluteTimeout"), "got: {err}");
    }

    #[test]
    fn backend_lb_policy_unsupported_target_kind_fails_closed() {
        let policy = backend_lb_policy(
            "bad-target",
            serde_json::json!({
                "targetRefs": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": "gw"
                }],
                "sessionPersistence": {"type": "Cookie"}
            }),
        );
        let err = translate_k8s_objects(&[policy], options())
            .expect_err("non-Service targetRef must fail closed");
        assert!(err.to_string().contains("Service"), "got: {err}");
    }

    #[test]
    fn backend_lb_policy_empty_target_name_fails_closed() {
        let policy = backend_lb_policy(
            "empty-target",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": ""}],
                "sessionPersistence": {"type": "Cookie"}
            }),
        );
        let err = translate_k8s_objects(std::slice::from_ref(&policy), options())
            .expect_err("an empty target name must fail closed");
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
        let status = super::backend_lb_policy_status(&policy, false);
        assert_eq!(status["ancestors"][0]["conditions"][0]["status"], "False");
    }

    #[test]
    fn backend_lb_policy_target_ref_bound_fails_closed() {
        let target_refs = (0..17)
            .map(|index| {
                serde_json::json!({
                    "group": "",
                    "kind": "Service",
                    "name": format!("api-{index}")
                })
            })
            .collect::<Vec<_>>();
        let policy = backend_lb_policy(
            "too-many-targets",
            serde_json::json!({
                "targetRefs": target_refs,
                "sessionPersistence": {"type": "Cookie"}
            }),
        );
        let err = translate_k8s_objects(std::slice::from_ref(&policy), options())
            .expect_err("more than 16 targetRefs must fail closed");
        assert!(err.to_string().contains("at most 16"), "got: {err}");
        let status = super::backend_lb_policy_status(&policy, false);
        assert_eq!(status["ancestors"][0]["conditions"][0]["status"], "False");
    }

    #[test]
    fn same_named_cross_kind_policy_tie_break_is_input_order_independent() {
        let legacy = backend_lb_policy(
            "same-name",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "legacy"}
            }),
        );
        let current = x_backend_traffic_policy(
            "same-name",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "current"}
            }),
        );
        let route = http_route_to_service("api");
        let forward =
            translate_k8s_objects(&[legacy.clone(), current.clone(), route.clone()], options())
                .expect("forward policy order");
        let reverse = translate_k8s_objects(&[current, legacy, route], options())
            .expect("reverse policy order");
        assert_eq!(
            forward.config.upstreams[0].hash_on, reverse.config.upstreams[0].hash_on,
            "cross-kind policy precedence must not depend on watch order"
        );
    }

    /// A multi-target policy that loses ONE Service is reported
    /// `Accepted=False` / `Conflicted` atomically, so translation must not keep
    /// applying it to the Services it happened to win — otherwise a policy the
    /// operator was told is rejected still steers live traffic.
    #[test]
    fn backend_lb_policy_losing_one_target_is_withdrawn_from_every_service() {
        let mut older = backend_lb_policy(
            "older",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "cart"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "older"}
            }),
        );
        older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut newer = backend_lb_policy(
            "newer",
            serde_json::json!({
                "targetRefs": [
                    {"group": "", "kind": "Service", "name": "api"},
                    {"group": "", "kind": "Service", "name": "cart"}
                ],
                "sessionPersistence": {"type": "Cookie", "sessionName": "newer"}
            }),
        );
        newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let losers = super::backend_lb_policy_conflict_losers([&older, &newer], &options());
        assert!(
            losers.contains(&K8sResourceKey::from_object(&newer)),
            "the challenger that lost `cart` must report Conflicted"
        );
        assert!(
            !losers.contains(&K8sResourceKey::from_object(&older)),
            "the oldest-wins policy stays Accepted"
        );

        // `api` was only targeted by the Conflicted challenger, so it must get
        // no persistence at all — status and data plane agree.
        let api_objects = [older.clone(), newer.clone(), http_route_to_service("api")];
        let api = translate_k8s_objects(&api_objects, options()).expect("translation");
        assert!(
            api.config.upstreams.is_empty(),
            "a Conflicted policy must not force a session Upstream on the Service it won"
        );
        assert!(api.config.proxies[0].upstream_id.is_none());

        // The accepted winner still applies to its own Service.
        let cart_objects = [older, newer, http_route_to_service("cart")];
        let cart = translate_k8s_objects(&cart_objects, options()).expect("translation");
        assert!(
            cart.config.upstreams[0]
                .hash_on
                .as_deref()
                .is_some_and(|value| value.starts_with("cookie:older-fe-")),
            "the oldest-wins policy must still apply to the Service it won"
        );
    }

    /// The status planner patches whenever the desired status differs from the
    /// live one, so a value-unchanged policy status must be byte-identical or
    /// every policy is re-patched on every reconcile and `lastTransitionTime`
    /// flaps against the Kubernetes condition contract.
    #[test]
    fn backend_lb_policy_status_preserves_unchanged_last_transition_time() {
        let mut policy = backend_lb_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "lb-affinity"}
            }),
        );
        let first = super::backend_lb_policy_status(&policy, false);
        policy.status = first.clone();
        let second = super::backend_lb_policy_status(&policy, false);
        assert_eq!(
            second, first,
            "an unchanged policy status must not be re-stamped every reconcile"
        );

        // A real transition still advances the timestamp.
        let mut stale = first.clone();
        stale["ancestors"][0]["conditions"][0]["status"] = serde_json::json!("False");
        stale["ancestors"][0]["conditions"][0]["reason"] = serde_json::json!("Conflicted");
        stale["ancestors"][0]["conditions"][0]["lastTransitionTime"] =
            serde_json::json!("2020-01-01T00:00:00Z");
        policy.status = stale;
        let transitioned = super::backend_lb_policy_status(&policy, false);
        let condition = &transitioned["ancestors"][0]["conditions"][0];
        assert_eq!(condition["reason"], "Accepted");
        assert_ne!(
            condition["lastTransitionTime"],
            serde_json::json!("2020-01-01T00:00:00Z"),
            "a real transition must advance lastTransitionTime"
        );
    }

    /// `status.ancestors` is shared across Gateway API implementations and is
    /// applied as one atomic array, so Ferrum's forced server-side apply must
    /// carry foreign ancestor entries through instead of erasing them.
    #[test]
    fn backend_lb_policy_status_preserves_foreign_controller_ancestors() {
        let mut policy = backend_lb_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "lb-affinity"}
            }),
        );
        policy.status = serde_json::json!({
            "ancestors": [{
                "ancestorRef": {
                    "group": "",
                    "kind": "Service",
                    "name": "api",
                    "namespace": "default"
                },
                "controllerName": "example.com/other-controller",
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "other implementation",
                    "observedGeneration": 1,
                    "lastTransitionTime": "2020-01-01T00:00:00Z"
                }]
            }]
        });

        let status = super::backend_lb_policy_status(&policy, false);
        let ancestors = status["ancestors"].as_array().expect("ancestors array");
        assert_eq!(ancestors.len(), 2, "got: {status}");
        let foreign = "example.com/other-controller";
        let ferrum = "ferrum.io/gateway-controller";
        assert!(
            ancestors
                .iter()
                .any(|entry| entry["controllerName"] == foreign),
            "a foreign controller's ancestor must survive Ferrum's apply document"
        );
        assert!(
            ancestors
                .iter()
                .any(|entry| entry["controllerName"] == ferrum),
            "Ferrum still reports its own ancestor"
        );

        // Idempotent: the planner merges against the snapshot and the apply path
        // merges again against the fresh live status.
        policy.status = status.clone();
        let again = super::backend_lb_policy_status(&policy, false);
        assert_eq!(again, status, "re-merging must not duplicate an ancestor");
    }

    /// Gateway API caps the shared ancestor map at 16 entries and requires an
    /// implementation not to add entries once it is full. Foreign controller
    /// ownership therefore wins the capacity budget over Ferrum's desired
    /// entry; forced SSA must never evict a foreign status just to report ours.
    ///
    /// Translation / Accepted semantics for a full foreign map are covered in
    /// `tests/unit/gateway_core/gateway_backend_lb_policy_tests.rs`.
    #[test]
    fn backend_lb_policy_status_does_not_evict_a_full_foreign_ancestor_map() {
        let mut policy = backend_lb_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "lb-affinity"}
            }),
        );
        let foreign = (0..super::POLICY_ANCESTOR_MAX_ITEMS)
            .map(|index| {
                serde_json::json!({
                    "ancestorRef": {
                        "group": "",
                        "kind": "Service",
                        "name": format!("foreign-{index}"),
                        "namespace": "default"
                    },
                    "controllerName": format!("example.com/controller-{index}"),
                    "conditions": []
                })
            })
            .collect::<Vec<_>>();
        policy.status = serde_json::json!({ "ancestors": foreign });

        let status = super::backend_lb_policy_status(&policy, false);
        let ancestors = status["ancestors"].as_array().expect("ancestors array");
        assert_eq!(
            ancestors.len(),
            super::POLICY_ANCESTOR_MAX_ITEMS,
            "Ferrum must never write a seventeenth status ancestor"
        );
        assert!(
            ancestors.iter().all(|entry| {
                entry["controllerName"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("example.com/controller-"))
            }),
            "a full foreign ancestor map must leave Ferrum with no status slot"
        );

        // Applying a planner-produced document without a fresh live snapshot
        // still preserves its already-carried foreign entries.
        let again = super::merge_backend_lb_policy_status(&status, None);
        assert_eq!(again, status);
    }

    #[test]
    fn backend_lb_policy_delete_withdraws_session_persistence() {
        let policy = backend_lb_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "lb-affinity",
                    "type": "Cookie"
                }
            }),
        );
        let route = http_route_to_service("api");
        let with_policy =
            translate_k8s_objects(&[policy, route.clone()], options()).expect("with policy");
        assert!(
            with_policy.config.upstreams[0]
                .hash_on
                .as_deref()
                .is_some_and(|value| value.starts_with("cookie:lb-affinity-fe-"))
        );

        let without_policy = translate_k8s_objects(&[route], options())
            .expect("policy deletion withdraws sticky config");
        assert!(
            without_policy.config.upstreams.is_empty(),
            "without session persistence a single backend stays direct"
        );
        assert!(without_policy.config.proxies[0].upstream_id.is_none());
    }

    #[test]
    fn backend_lb_policy_update_changes_session_name() {
        let mut policy = backend_lb_policy(
            "sticky",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "v1",
                    "type": "Cookie"
                }
            }),
        );
        let route = http_route_to_service("api");
        let v1 = translate_k8s_objects(&[policy.clone(), route.clone()], options()).expect("v1");
        assert!(
            v1.config.upstreams[0]
                .hash_on
                .as_deref()
                .is_some_and(|value| value.starts_with("cookie:v1-fe-"))
        );

        policy.spec["sessionPersistence"]["sessionName"] = serde_json::json!("v2");
        let v2 = translate_k8s_objects(&[policy, route], options()).expect("v2");
        assert!(
            v2.config.upstreams[0]
                .hash_on
                .as_deref()
                .is_some_and(|value| value.starts_with("cookie:v2-fe-"))
        );
    }

    #[test]
    fn backend_lb_policy_status_rejects_idle_timeout() {
        let policy = backend_lb_policy(
            "idle",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "type": "Cookie",
                    "idleTimeout": "10s"
                }
            }),
        );
        let status = super::backend_lb_policy_status(&policy, false);
        let condition = &status["ancestors"][0]["conditions"][0];
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "UnsupportedValue");
        assert!(
            condition["message"]
                .as_str()
                .unwrap_or("")
                .contains("idleTimeout")
        );
    }

    #[test]
    fn backend_lb_policy_rejects_cookie_session_name_with_newline_injection() {
        let policy = backend_lb_policy(
            "inject",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "lb-affinity\nevilmalicious=1",
                    "type": "Cookie"
                }
            }),
        );
        let err = translate_k8s_objects(&[policy.clone(), http_route_to_service("api")], options())
            .expect_err("newline in cookie sessionName must fail closed");
        assert!(
            err.to_string().contains("sessionPersistence.sessionName"),
            "got: {err}"
        );
        assert!(err.to_string().contains("cookie name"), "got: {err}");

        let status = super::backend_lb_policy_status(&policy, false);
        let condition = &status["ancestors"][0]["conditions"][0];
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "UnsupportedValue");
        assert!(
            condition["message"]
                .as_str()
                .unwrap_or("")
                .contains("sessionPersistence.sessionName")
        );
        assert!(
            condition["message"]
                .as_str()
                .unwrap_or("")
                .contains("cookie name")
        );
    }

    #[test]
    fn backend_lb_policy_rejects_header_session_name_with_invalid_characters() {
        let policy = backend_lb_policy(
            "bad-header",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "x-session name",
                    "type": "Header"
                }
            }),
        );
        let err = translate_k8s_objects(&[policy.clone(), http_route_to_service("api")], options())
            .expect_err("space in header sessionName must fail closed");
        assert!(
            err.to_string().contains("sessionPersistence.sessionName"),
            "got: {err}"
        );
        assert!(err.to_string().contains("header name"), "got: {err}");

        let status = super::backend_lb_policy_status(&policy, false);
        let condition = &status["ancestors"][0]["conditions"][0];
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "UnsupportedValue");
        assert!(
            condition["message"]
                .as_str()
                .unwrap_or("")
                .contains("sessionPersistence.sessionName")
        );
        assert!(
            condition["message"]
                .as_str()
                .unwrap_or("")
                .contains("header name")
        );
    }

    #[test]
    fn backend_lb_policy_accepts_valid_cookie_and_rejects_header_persistence() {
        let cookie_policy = backend_lb_policy(
            "cookie",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "lb-affinity",
                    "type": "Cookie"
                }
            }),
        );
        let header_policy = backend_lb_policy(
            "header",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "sessionName": "X-Session-Affinity",
                    "type": "Header"
                }
            }),
        );
        let cookie =
            translate_k8s_objects(&[cookie_policy, http_route_to_service("api")], options())
                .expect("valid cookie sessionName should translate");
        assert!(
            cookie.config.upstreams[0]
                .hash_on
                .as_deref()
                .is_some_and(|value| value.starts_with("cookie:lb-affinity-fe-"))
        );

        let err = translate_k8s_objects(
            &[header_policy.clone(), http_route_to_service("api")],
            options(),
        )
        .expect_err("Header persistence must fail closed until Ferrum emits response tokens");
        assert!(
            err.to_string().contains("type Header is not supported"),
            "got: {err}"
        );
        let status = super::backend_lb_policy_status(&header_policy, false);
        assert_eq!(status["ancestors"][0]["conditions"][0]["status"], "False");
    }

    #[test]
    fn x_backend_traffic_policy_retry_constraint_rejects_entire_policy() {
        let policy = x_backend_traffic_policy(
            "budget",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "retryConstraint": {
                    "budget": {"percent": 20, "interval": "10s"}
                },
                "sessionPersistence": {
                    "sessionName": "with-budget",
                    "type": "Cookie"
                }
            }),
        );
        let err = translate_k8s_objects(&[policy.clone(), http_route_to_service("api")], options())
            .expect_err("retryConstraint must reject the entire policy fail-closed");
        assert!(err.to_string().contains("retryConstraint"), "got: {err}");
        assert!(
            err.to_string()
                .contains("sessionPersistence is not applied"),
            "rejection must withhold sessionPersistence, got: {err}"
        );

        let status = super::backend_lb_policy_status(&policy, false);
        let condition = &status["ancestors"][0]["conditions"][0];
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "UnsupportedValue");
        let message = condition["message"].as_str().unwrap_or("");
        assert!(
            message.contains("retryConstraint"),
            "status message must name the field, got: {message}"
        );
        assert!(
            message.contains("sessionPersistence is not applied"),
            "status must document that sticky affinity is withheld, got: {message}"
        );
    }

    #[test]
    fn x_backend_traffic_policy_retry_constraint_only_still_rejects() {
        let policy = x_backend_traffic_policy(
            "budget-only",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "retryConstraint": {
                    "budget": {"percent": 10, "interval": "5s"}
                }
            }),
        );
        let err = translate_k8s_objects(std::slice::from_ref(&policy), options())
            .expect_err("retryConstraint-only policies must fail closed");
        assert!(err.to_string().contains("retryConstraint"), "got: {err}");

        let status = super::backend_lb_policy_status(&policy, false);
        let condition = &status["ancestors"][0]["conditions"][0];
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "UnsupportedValue");
    }

    fn accepted_condition(status: &Value) -> &Value {
        &status["ancestors"][0]["conditions"][0]
    }

    #[test]
    fn backend_lb_policy_status_older_wins_marks_challenger_conflicted() {
        let mut older = backend_lb_policy(
            "older",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "older"}
            }),
        );
        older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut newer = backend_lb_policy(
            "newer",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "newer"}
            }),
        );
        newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let losers =
            super::backend_lb_policy_conflict_losers(&[older.clone(), newer.clone()], &options());
        assert!(!losers.contains(&K8sResourceKey::from_object(&older)));
        assert!(losers.contains(&K8sResourceKey::from_object(&newer)));

        let winner_status = super::backend_lb_policy_status(&older, false);
        let winner = accepted_condition(&winner_status);
        assert_eq!(winner["status"], "True");
        assert_eq!(winner["reason"], "Accepted");

        let loser_status = super::backend_lb_policy_status(&newer, true);
        let loser = accepted_condition(&loser_status);
        assert_eq!(loser["status"], "False");
        assert_eq!(loser["reason"], "Conflicted");
        assert_eq!(
            loser["message"].as_str(),
            Some(super::BACKEND_LB_POLICY_CONFLICTED_MESSAGE)
        );
    }

    #[test]
    fn backend_lb_policy_status_same_timestamp_cross_kind_uses_full_identity() {
        let stamp = "2026-01-01T00:00:00Z";
        let mut legacy = backend_lb_policy(
            "same-name",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "legacy"}
            }),
        );
        legacy.metadata.creation_timestamp = Some(stamp.to_string());
        let mut current = x_backend_traffic_policy(
            "same-name",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "current"}
            }),
        );
        current.metadata.creation_timestamp = Some(stamp.to_string());

        let forward = super::backend_lb_policy_conflict_losers(
            &[legacy.clone(), current.clone()],
            &options(),
        );
        let reverse = super::backend_lb_policy_conflict_losers(
            &[current.clone(), legacy.clone()],
            &options(),
        );
        assert_eq!(
            forward, reverse,
            "same-timestamp cross-kind precedence must not depend on input order"
        );

        // Full resource identity: apiVersion/kind/namespace/name. The
        // gateway.networking.k8s.io BackendLBPolicy sorts before the
        // gateway.networking.x-k8s.io XBackendTrafficPolicy sibling.
        assert!(!forward.contains(&K8sResourceKey::from_object(&legacy)));
        assert!(forward.contains(&K8sResourceKey::from_object(&current)));
    }

    #[test]
    fn backend_lb_policy_status_conflict_is_input_order_independent() {
        let mut older = x_backend_traffic_policy(
            "alpha",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "alpha"}
            }),
        );
        older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut newer = backend_lb_policy(
            "beta",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "beta"}
            }),
        );
        newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let forward =
            super::backend_lb_policy_conflict_losers(&[older.clone(), newer.clone()], &options());
        let reverse =
            super::backend_lb_policy_conflict_losers(&[newer.clone(), older.clone()], &options());
        assert_eq!(forward, reverse);
        assert!(!forward.contains(&K8sResourceKey::from_object(&older)));
        assert!(forward.contains(&K8sResourceKey::from_object(&newer)));
    }

    #[test]
    fn backend_lb_policy_status_multi_target_partial_conflict_fails_closed() {
        let mut older = backend_lb_policy(
            "older-svc-a",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "svc-a"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "a"}
            }),
        );
        older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut multi = backend_lb_policy(
            "multi",
            serde_json::json!({
                "targetRefs": [
                    {"group": "", "kind": "Service", "name": "svc-a"},
                    {"group": "", "kind": "Service", "name": "svc-b"}
                ],
                "sessionPersistence": {"type": "Cookie", "sessionName": "multi"}
            }),
        );
        multi.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let losers =
            super::backend_lb_policy_conflict_losers(&[older.clone(), multi.clone()], &options());
        assert!(
            losers.contains(&K8sResourceKey::from_object(&multi)),
            "losing any Service target must Conflict the whole multi-target policy"
        );
        assert!(!losers.contains(&K8sResourceKey::from_object(&older)));

        let status = super::backend_lb_policy_status(&multi, true);
        // Atomic direct-policy behavior: every ancestor reports Conflicted.
        for ancestor in status["ancestors"].as_array().expect("ancestors") {
            let condition = &ancestor["conditions"][0];
            assert_eq!(condition["status"], "False");
            assert_eq!(condition["reason"], "Conflicted");
        }
    }

    #[test]
    fn backend_lb_policy_status_invalid_policy_stays_rejected_not_conflicted() {
        let mut older = backend_lb_policy(
            "older",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {"type": "Cookie", "sessionName": "older"}
            }),
        );
        older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut invalid = backend_lb_policy(
            "invalid",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
                "sessionPersistence": {
                    "type": "Cookie",
                    "idleTimeout": "10s"
                }
            }),
        );
        invalid.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let losers =
            super::backend_lb_policy_conflict_losers(&[older.clone(), invalid.clone()], &options());
        assert!(
            losers.is_empty(),
            "invalid policies must not participate in conflict: {losers:?}"
        );

        // Validation precedes conflict: even if a caller incorrectly marked
        // conflicted, the status reason stays UnsupportedValue.
        let status = super::backend_lb_policy_status(&invalid, true);
        let condition = accepted_condition(&status);
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "UnsupportedValue");
        assert!(
            condition["message"]
                .as_str()
                .unwrap_or("")
                .contains("idleTimeout")
        );
    }

    #[test]
    fn backend_lb_policy_diagnostics_omit_hostile_duration_and_service_name() {
        let hostile_duration = "1s\ninjected-hostile-duration-marker";
        let hostile_service = "svc-echo\ninjected-hostile-service-marker";
        let policy = backend_lb_policy(
            "hostile",
            serde_json::json!({
                "targetRefs": [
                    {"group": "", "kind": "Service", "name": "api"},
                    {"group": "", "kind": "Service", "name": hostile_service}
                ],
                "sessionPersistence": {
                    "type": "Cookie",
                    "absoluteTimeout": hostile_duration,
                    "cookieConfig": {"lifetimeType": "Permanent"}
                }
            }),
        );

        // Duplicate targetRef path uses a second policy with a repeated Service.
        let duplicate = backend_lb_policy(
            "dup",
            serde_json::json!({
                "targetRefs": [
                    {"group": "", "kind": "Service", "name": hostile_service},
                    {"group": "", "kind": "Service", "name": hostile_service}
                ],
                "sessionPersistence": {"type": "Cookie"}
            }),
        );

        let duration_err = translate_k8s_objects(std::slice::from_ref(&policy), options())
            .expect_err("hostile duration must fail closed");
        let duration_msg = duration_err.to_string();
        assert!(
            duration_msg.contains("sessionPersistence.absoluteTimeout"),
            "got: {duration_msg}"
        );
        assert!(
            duration_msg.contains("is not a valid Gateway API duration")
                || duration_msg.contains("exceeds the sticky-cookie"),
            "got: {duration_msg}"
        );
        assert!(
            !duration_msg.contains(hostile_duration),
            "duration diagnostic must not echo operator text: {duration_msg}"
        );
        assert!(
            !duration_msg.contains("injected-hostile-duration-marker"),
            "got: {duration_msg}"
        );

        let duration_status = super::backend_lb_policy_status(&policy, false);
        let duration_status_msg = duration_status["ancestors"][0]["conditions"][0]["message"]
            .as_str()
            .unwrap_or("");
        assert!(
            !duration_status_msg.contains(hostile_duration)
                && !duration_status_msg.contains("injected-hostile-duration-marker"),
            "status must not echo hostile duration: {duration_status_msg}"
        );

        let dup_err = translate_k8s_objects(std::slice::from_ref(&duplicate), options())
            .expect_err("duplicate Service targetRef must fail closed");
        let dup_msg = dup_err.to_string();
        assert!(
            dup_msg.contains("duplicates an earlier Service targetRef"),
            "got: {dup_msg}"
        );
        assert!(
            !dup_msg.contains(hostile_service)
                && !dup_msg.contains("injected-hostile-service-marker"),
            "duplicate diagnostic must not echo Service name: {dup_msg}"
        );

        let dup_status = super::backend_lb_policy_status(&duplicate, false);
        let dup_status_msg = dup_status["ancestors"][0]["conditions"][0]["message"]
            .as_str()
            .unwrap_or("");
        assert_eq!(
            dup_status_msg,
            "spec.targetRefs[1] duplicates an earlier Service targetRef"
        );
        assert!(
            !dup_status_msg.contains(hostile_service)
                && !dup_status_msg.contains("injected-hostile-service-marker"),
            "status must not echo Service name: {dup_status_msg}"
        );
    }
}
