//! Ferrum `UDPResponseAmplificationPolicy` Direct Policy Attachment.
//!
//! Ordinary Gateway API `UDPRoute` translation must never silently program an
//! unlimited amplification relay. This module collects the Ferrum-owned CRD,
//! resolves GEP-713 oldest-wins precedence, and projects a finite factor (or an
//! explicit dual-acknowledged unlimited override) onto every generated UDP
//! proxy before listener bind.
//!
//! Invalid, zero, negative, non-finite, or excessive factors never win. A
//! missing or unusable policy falls through to the next precedence level and
//! finally the controller default — never to unlimited.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use super::gateway_api::{self, parse_k8s_timestamp};
use super::{
    GatewayApiListenerParentKind, K8sAccumulator, K8sObject, K8sResourceKey, K8sTranslateError,
};
use crate::config::types::Proxy;
use crate::udp_amplification::{
    DEFAULT_UDP_AMPLIFICATION_FACTOR, MAX_UDP_AMPLIFICATION_FACTOR, UDP_AMPLIFICATION_POLICY_GROUP,
    UDP_AMPLIFICATION_POLICY_KIND, factor_is_valid, record_policy_invalid,
};

const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";
const MAX_TARGET_REFS: usize = 16;

const ACCEPTED_OK: &str = "Ferrum accepted this UDPResponseAmplificationPolicy";
const REFS_OK: &str = "All UDPResponseAmplificationPolicy references accepted by Ferrum";
const CONFLICTED_MESSAGE: &str =
    "An older UDPResponseAmplificationPolicy already governs one or more of the same targets";
const REF_NOT_PERMITTED_MESSAGE: &str =
    "Cross-namespace UDPResponseAmplificationPolicy attachment is not permitted by ReferenceGrant";
const TARGET_NOT_FOUND_MESSAGE: &str =
    "UDPResponseAmplificationPolicy targetRef does not resolve to an observed Gateway or UDPRoute";
const TARGET_SECTION_NOT_FOUND_MESSAGE: &str = "UDPResponseAmplificationPolicy targetRef sectionName does not name a listener on the observed Gateway";
const DUPLICATE_TARGET_MESSAGE: &str =
    "spec.targetRefs entries must be unique by kind, namespace, name, and sectionName";

/// Effective protection posture projected onto a generated UDPRoute proxy and
/// published on `UDPRoute.status.parents[].conditions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAmplificationPosture {
    /// Controller default (`8.0`), or a mixed finite-policy / default parent.
    /// Protection is on.
    FiniteDefault,
    /// Every matching listener won a valid finite policy. Protection is on.
    FinitePolicy,
    /// Dual-acknowledged `mode: Unlimited` on any matching listener.
    /// Protection is off.
    ExplicitUnlimited,
}

impl UdpAmplificationPosture {
    pub fn condition_status(self) -> bool {
        !matches!(self, Self::ExplicitUnlimited)
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::FiniteDefault => "FiniteDefault",
            Self::FinitePolicy => "FinitePolicy",
            Self::ExplicitUnlimited => "ExplicitUnlimited",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::FiniteDefault => "Ferrum applied a finite UDP response-amplification limit",
            Self::FinitePolicy => "Ferrum applied a finite UDPResponseAmplificationPolicy",
            Self::ExplicitUnlimited => {
                "Ferrum programmed this UDPRoute without a response-amplification limit because an attached policy acknowledged unsafe amplification"
            }
        }
    }
}

/// Translation outcome for one `UDPResponseAmplificationPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayApiUdpAmplificationPolicyStatus {
    pub policy: K8sResourceKey,
    pub accepted: bool,
    pub accepted_reason: String,
    pub accepted_message: String,
    pub resolved_refs: bool,
    pub resolved_refs_reason: String,
    pub resolved_refs_message: String,
    /// Named targets Ferrum will list as `status.ancestors` (Gateway / UDPRoute).
    pub ancestors: Vec<UdpAmplificationAncestorRef>,
}

/// One Direct Policy Attachment target for status `ancestorRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAmplificationAncestorRef {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub section_name: Option<String>,
}

/// Per-parent UDPRoute protection posture for status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayApiUdpAmplificationRoutePosture {
    pub route: K8sResourceKey,
    pub parent_ref: String,
    pub posture: UdpAmplificationPosture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMode {
    Finite,
    Unlimited,
}

#[derive(Debug, Clone)]
struct ValidPolicyBody {
    factor: Option<f32>,
}

#[derive(Debug, Clone)]
struct IndexedPolicy {
    resource: K8sResourceKey,
    creation_timestamp: Option<DateTime<Utc>>,
    body: ValidPolicyBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AttachmentKey {
    Route {
        namespace: String,
        name: String,
    },
    Gateway {
        namespace: String,
        name: String,
        section: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct TargetRef {
    kind: String,
    namespace: String,
    name: String,
    section_name: Option<String>,
    cross_namespace: bool,
}

#[derive(Debug, Clone)]
struct DirectPolicyCandidate {
    policy: IndexedPolicy,
    targets: Vec<AttachmentKey>,
}

#[derive(Debug, Default)]
pub(crate) struct UdpAmplificationPolicyIndex {
    by_attachment: HashMap<AttachmentKey, IndexedPolicy>,
    /// Valid policy bodies keyed by `(namespace, name)` for GatewayClass.parametersRef.
    /// A Direct policy that lost any named target is withdrawn here as well so
    /// a Conflicted resource cannot still win through `parametersRef`.
    by_name: HashMap<(String, String), IndexedPolicy>,
    /// Every valid Direct-attachment candidate. `finalize_conflicts` rebuilds
    /// `by_attachment` from this set in oldest-wins order so an atomic loser
    /// never consumes a target a later eligible policy can still govern.
    candidates: Vec<DirectPolicyCandidate>,
}

fn policy_is_preferred(candidate: &IndexedPolicy, existing: &IndexedPolicy) -> bool {
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

/// Collect every in-scope `UDPResponseAmplificationPolicy`. Invalid objects
/// record status and never occupy an attachment slot.
pub(crate) fn collect_all(
    acc: &mut K8sAccumulator,
    objects: &[&K8sObject],
) -> Result<(), K8sTranslateError> {
    let observed_udproutes: HashSet<(String, String)> = objects
        .iter()
        .filter(|object| object.kind == "UDPRoute")
        .map(|object| {
            (
                object.metadata.namespace.clone(),
                object.metadata.name.clone(),
            )
        })
        .collect();
    let observed_gateway_listeners = authored_gateway_listeners(objects);

    for object in objects {
        if object.kind != UDP_AMPLIFICATION_POLICY_KIND {
            continue;
        }
        collect_one(
            acc,
            object,
            &observed_udproutes,
            &observed_gateway_listeners,
        );
    }
    Ok(())
}

fn authored_gateway_listeners(
    objects: &[&K8sObject],
) -> HashMap<(String, String), HashSet<String>> {
    let mut listeners: HashMap<(String, String), HashSet<String>> = HashMap::new();
    for object in objects {
        if object.kind != "Gateway" {
            continue;
        }
        let key = (
            object.metadata.namespace.clone(),
            object.metadata.name.clone(),
        );
        let names = listeners.entry(key).or_default();
        let Some(entries) = object.spec.get("listeners").and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            if let Some(name) = entry
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
            {
                names.insert(name.to_string());
            }
        }
    }
    listeners
}

fn collect_one(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    observed_udproutes: &HashSet<(String, String)>,
    observed_gateway_listeners: &HashMap<(String, String), HashSet<String>>,
) {
    let parsed_targets = parse_target_refs(object);
    let parsed_body = parse_policy_body(object);

    let (body, targets, error) = match (parsed_body, parsed_targets) {
        (Err(error), targets) => (None, targets.unwrap_or_default(), Some(error)),
        (Ok(_), Err(error)) => (None, Vec::new(), Some(error)),
        (Ok(body), Ok(targets)) => (Some(body), targets, None),
    };

    let mut resolved_error = error;
    if resolved_error.is_none() {
        for target in &targets {
            if let Some(error) = authorize_and_resolve_target(
                acc,
                object,
                target,
                observed_udproutes,
                observed_gateway_listeners,
            ) {
                resolved_error = Some(error);
                break;
            }
        }
    }

    let ancestors: Vec<UdpAmplificationAncestorRef> = targets
        .iter()
        .map(|target| UdpAmplificationAncestorRef {
            kind: target.kind.clone(),
            namespace: target.namespace.clone(),
            name: target.name.clone(),
            section_name: target.section_name.clone(),
        })
        .collect();

    if let Some(error) = resolved_error {
        record_policy_invalid();
        acc.warnings.push(format!(
            "Gateway API UDPResponseAmplificationPolicy {:?}/{:?} is invalid: {}",
            object.metadata.namespace, object.metadata.name, error.message
        ));
        acc.record_udp_amplification_policy_status(GatewayApiUdpAmplificationPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: false,
            accepted_reason: error.accepted_reason.to_string(),
            accepted_message: error.message.clone(),
            resolved_refs: false,
            resolved_refs_reason: error.refs_reason.to_string(),
            resolved_refs_message: error.message,
            ancestors,
        });
        return;
    }

    let Some(body) = body else {
        return;
    };

    let indexed = IndexedPolicy {
        resource: K8sResourceKey::from_object(object),
        creation_timestamp: object
            .metadata
            .creation_timestamp
            .as_deref()
            .and_then(parse_k8s_timestamp),
        body: body.clone(),
    };
    acc.udp_amplification_policies.by_name.insert(
        (
            object.metadata.namespace.clone(),
            object.metadata.name.clone(),
        ),
        indexed.clone(),
    );

    let target_keys: Vec<AttachmentKey> = targets
        .iter()
        .filter_map(attachment_key_for_target)
        .collect();
    acc.udp_amplification_policies
        .candidates
        .push(DirectPolicyCandidate {
            policy: indexed,
            targets: target_keys,
        });

    // Conflicted losers are finalized after every valid candidate is stored so
    // status is stable under input reorder. Record a provisional Accepted here;
    // finalize_conflicts rebuilds Direct-attachment winners in oldest-wins
    // order, flips any policy that lost any named target, and withdraws it
    // from every live lookup, including GatewayClass.parametersRef.
    acc.record_udp_amplification_policy_status(GatewayApiUdpAmplificationPolicyStatus {
        policy: K8sResourceKey::from_object(object),
        accepted: true,
        accepted_reason: "Accepted".to_string(),
        accepted_message: ACCEPTED_OK.to_string(),
        resolved_refs: true,
        resolved_refs_reason: "ResolvedRefs".to_string(),
        resolved_refs_message: REFS_OK.to_string(),
        ancestors,
    });
}

struct PolicyError {
    accepted_reason: &'static str,
    refs_reason: &'static str,
    message: String,
}

impl PolicyError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            accepted_reason: "Invalid",
            refs_reason: "Invalid",
            message: message.into(),
        }
    }

    fn ref_not_permitted() -> Self {
        Self {
            accepted_reason: "RefNotPermitted",
            refs_reason: "RefNotPermitted",
            message: REF_NOT_PERMITTED_MESSAGE.to_string(),
        }
    }

    fn target_not_found() -> Self {
        Self {
            accepted_reason: "TargetNotFound",
            refs_reason: "InvalidKind",
            message: TARGET_NOT_FOUND_MESSAGE.to_string(),
        }
    }

    fn target_section_not_found() -> Self {
        Self {
            accepted_reason: "TargetNotFound",
            refs_reason: "InvalidKind",
            message: TARGET_SECTION_NOT_FOUND_MESSAGE.to_string(),
        }
    }
}

fn parse_target_refs(object: &K8sObject) -> Result<Vec<TargetRef>, PolicyError> {
    let Some(raw) = object.spec.get("targetRefs") else {
        return Ok(Vec::new());
    };
    let Some(entries) = raw.as_array() else {
        return Err(PolicyError::invalid("spec.targetRefs must be an array"));
    };
    if entries.len() > MAX_TARGET_REFS {
        return Err(PolicyError::invalid(format!(
            "spec.targetRefs must contain at most {MAX_TARGET_REFS} entries"
        )));
    }
    let mut targets = Vec::with_capacity(entries.len());
    let mut seen = HashSet::with_capacity(entries.len());
    for entry in entries {
        let target = parse_one_target(object, entry)?;
        let canonical = (
            target.kind.clone(),
            target.namespace.clone(),
            target.name.clone(),
            target.section_name.clone(),
        );
        if !seen.insert(canonical) {
            return Err(PolicyError::invalid(DUPLICATE_TARGET_MESSAGE));
        }
        targets.push(target);
    }
    Ok(targets)
}

fn optional_string_field<'a>(
    value: &'a Value,
    field: &str,
    path: &str,
) -> Result<Option<&'a str>, PolicyError> {
    match value.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(PolicyError::invalid(format!("{path} must be a string"))),
    }
}

fn optional_bool_field(
    value: &Value,
    field: &str,
    path: &str,
) -> Result<Option<bool>, PolicyError> {
    match value.get(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(PolicyError::invalid(format!("{path} must be a bool"))),
    }
}

fn parse_one_target(object: &K8sObject, entry: &Value) -> Result<TargetRef, PolicyError> {
    if !entry.is_object() {
        return Err(PolicyError::invalid(
            "spec.targetRefs entries must be objects",
        ));
    }
    let group = optional_string_field(entry, "group", "spec.targetRefs.group")?
        .unwrap_or(GATEWAY_API_GROUP);
    if group != GATEWAY_API_GROUP {
        return Err(PolicyError::invalid(
            "spec.targetRefs.group must be gateway.networking.k8s.io",
        ));
    }
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyError::invalid("spec.targetRefs.kind is required"))?;
    if kind != "Gateway" && kind != "UDPRoute" {
        return Err(PolicyError::invalid(
            "spec.targetRefs.kind must be Gateway or UDPRoute",
        ));
    }
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyError::invalid("spec.targetRefs.name is required"))?;
    if name.is_empty() {
        return Err(PolicyError::invalid(
            "spec.targetRefs.name must not be empty",
        ));
    }
    let target_namespace = optional_string_field(entry, "namespace", "spec.targetRefs.namespace")?
        .unwrap_or(object.metadata.namespace.as_str());
    if target_namespace.is_empty() {
        return Err(PolicyError::invalid(
            "spec.targetRefs.namespace must not be empty",
        ));
    }
    let section_name =
        match optional_string_field(entry, "sectionName", "spec.targetRefs.sectionName")? {
            None => None,
            Some("") => {
                return Err(PolicyError::invalid(
                    "spec.targetRefs.sectionName must not be empty when set",
                ));
            }
            Some(name) => Some(name.to_string()),
        };
    if kind == "UDPRoute" && section_name.is_some() {
        return Err(PolicyError::invalid(
            "spec.targetRefs.sectionName is not valid on a UDPRoute target",
        ));
    }
    let cross_namespace = target_namespace != object.metadata.namespace;
    Ok(TargetRef {
        kind: kind.to_string(),
        namespace: target_namespace.to_string(),
        name: name.to_string(),
        section_name,
        cross_namespace,
    })
}

fn parse_policy_body(object: &K8sObject) -> Result<ValidPolicyBody, PolicyError> {
    let mode = match optional_string_field(&object.spec, "mode", "spec.mode")? {
        None | Some("Finite") => PolicyMode::Finite,
        Some("Unlimited") => PolicyMode::Unlimited,
        Some(_) => {
            return Err(PolicyError::invalid(
                "spec.mode must be Finite or Unlimited",
            ));
        }
    };
    let ack = optional_bool_field(
        &object.spec,
        "acknowledgeUnsafeAmplification",
        "spec.acknowledgeUnsafeAmplification",
    )?
    .unwrap_or(false);

    match mode {
        PolicyMode::Unlimited => {
            if !ack {
                return Err(PolicyError::invalid(
                    "spec.acknowledgeUnsafeAmplification must be true when spec.mode is Unlimited",
                ));
            }
            Ok(ValidPolicyBody { factor: None })
        }
        PolicyMode::Finite => {
            if ack {
                return Err(PolicyError::invalid(
                    "spec.acknowledgeUnsafeAmplification must not be set when spec.mode is Finite",
                ));
            }
            let Some(raw) = object.spec.get("maxResponseAmplificationFactor") else {
                return Err(PolicyError::invalid(
                    "spec.maxResponseAmplificationFactor is required when spec.mode is Finite",
                ));
            };
            let factor = match raw {
                Value::Number(number) => number.as_f64(),
                _ => None,
            };
            let Some(factor) = factor else {
                return Err(PolicyError::invalid(
                    "spec.maxResponseAmplificationFactor must be a finite number",
                ));
            };
            if !factor.is_finite()
                || factor <= 0.0
                || factor > f64::from(MAX_UDP_AMPLIFICATION_FACTOR)
            {
                return Err(PolicyError::invalid(format!(
                    "spec.maxResponseAmplificationFactor must be a finite number greater than 0 and at most {MAX_UDP_AMPLIFICATION_FACTOR}"
                )));
            }
            let factor = factor as f32;
            if !factor_is_valid(factor) {
                return Err(PolicyError::invalid(
                    "spec.maxResponseAmplificationFactor must be a finite number greater than 0 and at most 1024",
                ));
            }
            Ok(ValidPolicyBody {
                factor: Some(factor),
            })
        }
    }
}

fn authorize_and_resolve_target(
    acc: &K8sAccumulator,
    object: &K8sObject,
    target: &TargetRef,
    observed_udproutes: &HashSet<(String, String)>,
    observed_gateway_listeners: &HashMap<(String, String), HashSet<String>>,
) -> Option<PolicyError> {
    if target.cross_namespace
        && !acc.reference_grant_allows(
            &object.metadata.namespace,
            UDP_AMPLIFICATION_POLICY_GROUP,
            UDP_AMPLIFICATION_POLICY_KIND,
            &target.namespace,
            GATEWAY_API_GROUP,
            &target.kind,
            Some(&target.name),
        )
    {
        return Some(PolicyError::ref_not_permitted());
    }
    match target.kind.as_str() {
        "Gateway" => {
            let key = (target.namespace.clone(), target.name.clone());
            if !acc.gateway_class_name_by_gateway.contains_key(&key) {
                return Some(PolicyError::target_not_found());
            }
            if let Some(section) = target.section_name.as_deref() {
                let section_exists = observed_gateway_listeners
                    .get(&key)
                    .is_some_and(|names| names.contains(section));
                if !section_exists {
                    return Some(PolicyError::target_section_not_found());
                }
            }
        }
        "UDPRoute" => {
            if !observed_udproutes.contains(&(target.namespace.clone(), target.name.clone())) {
                return Some(PolicyError::target_not_found());
            }
        }
        _ => return Some(PolicyError::target_not_found()),
    }
    None
}

fn attachment_key_for_target(target: &TargetRef) -> Option<AttachmentKey> {
    match target.kind.as_str() {
        "UDPRoute" => Some(AttachmentKey::Route {
            namespace: target.namespace.clone(),
            name: target.name.clone(),
        }),
        "Gateway" => Some(AttachmentKey::Gateway {
            namespace: target.namespace.clone(),
            name: target.name.clone(),
            section: target.section_name.clone(),
        }),
        _ => None,
    }
}

fn policy_order(left: &IndexedPolicy, right: &IndexedPolicy) -> Ordering {
    if policy_is_preferred(left, right) {
        Ordering::Less
    } else if policy_is_preferred(right, left) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// Rebuild Direct-attachment winners in GEP-713 oldest-wins order.
///
/// A policy that cannot claim every named target is atomic: it occupies none
/// of them, so a later eligible candidate can still be promoted onto a target
/// the loser would otherwise have consumed. Conflicted Direct policies are
/// withdrawn from GatewayClass.parametersRef lookup as well. Repeated calls
/// are idempotent because winners are rebuilt from the same candidate set.
pub(crate) fn finalize_conflicts(acc: &mut K8sAccumulator) {
    acc.udp_amplification_policies
        .candidates
        .sort_by(|left, right| policy_order(&left.policy, &right.policy));

    let mut winners: HashMap<AttachmentKey, IndexedPolicy> = HashMap::new();
    let mut lost_any: HashSet<K8sResourceKey> = HashSet::new();
    for candidate in &acc.udp_amplification_policies.candidates {
        if candidate.targets.is_empty() {
            continue;
        }
        let blocked = candidate
            .targets
            .iter()
            .any(|target| winners.contains_key(target));
        if blocked {
            lost_any.insert(candidate.policy.resource.clone());
            continue;
        }
        for target in &candidate.targets {
            winners.insert(target.clone(), candidate.policy.clone());
        }
    }

    acc.udp_amplification_policies.by_attachment = winners;
    acc.udp_amplification_policies
        .by_name
        .retain(|_, policy| !lost_any.contains(&policy.resource));
    for status in &mut acc.udp_amplification_policy_statuses {
        if lost_any.contains(&status.policy) {
            status.accepted = false;
            status.accepted_reason = "Conflicted".to_string();
            status.accepted_message = CONFLICTED_MESSAGE.to_string();
        }
    }
}

/// Project the effective amplification policy onto one generated UDPRoute proxy.
///
/// Ferrum materializes one physical UDP proxy per route/rule/`listen_port`.
/// Every surviving concrete listener claim on that port is resolved independently
/// (route > Gateway section > Gateway > GatewayClass `parametersRef` > default)
/// and then fail-closed aggregated onto the proxy. Exact posture is recorded for
/// every represented parentRef from the actual physical protection.
pub(crate) fn apply_to_generated_proxy(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    proxy: &mut Proxy,
    listen_port: u16,
) {
    let (factor, posture, parent_refs) =
        resolve_for_route(acc, object, &proxy.namespace, listen_port);
    // `None` out of the resolver is the dual-acknowledged `mode: Unlimited`
    // override. Encode it as the explicit `0` sentinel so
    // `Proxy::normalize_fields()` cannot later project the finite default over
    // an override the operator deliberately requested. Resolution order,
    // aggregation, and posture recording are unchanged.
    proxy.udp_max_response_amplification_factor = Some(factor.unwrap_or(0.0));
    let route = K8sResourceKey::from_object(object);
    for parent_ref in parent_refs {
        acc.udp_amplification_route_postures
            .push(GatewayApiUdpAmplificationRoutePosture {
                route: route.clone(),
                parent_ref,
                posture,
            });
    }
}

/// `proxy_namespace` is the Gateway namespace the generated proxy lives in: a
/// cross-namespace UDPRoute materializes one proxy per parent Gateway
/// namespace, and each represents only the claims on that namespace's
/// listeners.
fn resolve_for_route(
    acc: &K8sAccumulator,
    object: &K8sObject,
    proxy_namespace: &str,
    listen_port: u16,
) -> (Option<f32>, UdpAmplificationPosture, Vec<String>) {
    let matching: Vec<_> = gateway_api::udp_route_surviving_listener_claims(object, acc)
        .into_iter()
        .filter(|claim| claim.port == listen_port && claim.listener.namespace == proxy_namespace)
        .collect();
    if matching.is_empty() {
        return (
            Some(DEFAULT_UDP_AMPLIFICATION_FACTOR),
            UdpAmplificationPosture::FiniteDefault,
            vec![String::new()],
        );
    }

    let mut parent_refs: Vec<String> = matching
        .iter()
        .map(|claim| claim.parent_ref.clone())
        .collect();
    parent_refs.sort();
    parent_refs.dedup();

    let route_key = AttachmentKey::Route {
        namespace: object.metadata.namespace.clone(),
        name: object.metadata.name.clone(),
    };
    if let Some(policy) = acc.udp_amplification_policies.by_attachment.get(&route_key) {
        let (factor, posture) = posture_from_body(&policy.body);
        return (factor, posture, parent_refs);
    }

    let resolutions: Vec<(Option<f32>, UdpAmplificationPosture)> = matching
        .iter()
        .map(|claim| resolve_for_claim(acc, claim))
        .collect();
    let (factor, posture) = aggregate_shared_port_policies(&resolutions);
    (factor, posture, parent_refs)
}

fn resolve_for_claim(
    acc: &K8sAccumulator,
    claim: &gateway_api::UdpListenerClaim,
) -> (Option<f32>, UdpAmplificationPosture) {
    let (gateway_ns, gateway_name) = match claim.listener.parent_kind {
        GatewayApiListenerParentKind::Gateway => (
            claim.listener.namespace.clone(),
            claim.listener.gateway.clone(),
        ),
        GatewayApiListenerParentKind::ListenerSet => acc
            .gateway_api_listener_policies
            .get(&claim.listener)
            .and_then(|policy| policy.parent_gateway.clone())
            .unwrap_or_else(|| {
                (
                    claim.listener.namespace.clone(),
                    claim.listener.gateway.clone(),
                )
            }),
    };
    // A section-scoped target is admitted only when `sectionName` names a
    // listener on the Gateway's own `spec.listeners`
    // (`authorize_and_resolve_target`), so it can never legitimately select a
    // ListenerSet-contributed listener. Consulting the section key for one
    // would silently widen a Gateway-listener policy — including an
    // `ExplicitUnlimited` one — onto a ListenerSet listener that merely shares
    // the name. ListenerSet claims fall through to the Gateway-wide key.
    if matches!(
        claim.listener.parent_kind,
        GatewayApiListenerParentKind::Gateway
    ) {
        let section_key = AttachmentKey::Gateway {
            namespace: gateway_ns.clone(),
            name: gateway_name.clone(),
            section: Some(claim.listener.listener.clone()),
        };
        if let Some(policy) = acc
            .udp_amplification_policies
            .by_attachment
            .get(&section_key)
        {
            return posture_from_body(&policy.body);
        }
    }
    let gateway_key = AttachmentKey::Gateway {
        namespace: gateway_ns.clone(),
        name: gateway_name.clone(),
        section: None,
    };
    if let Some(policy) = acc
        .udp_amplification_policies
        .by_attachment
        .get(&gateway_key)
    {
        return posture_from_body(&policy.body);
    }
    if let Some(class_name) = acc
        .gateway_class_name_by_gateway
        .get(&(gateway_ns, gateway_name))
        && let Some(factor) = class_default_factor(acc, class_name)
    {
        return posture_from_body(&ValidPolicyBody { factor });
    }
    (
        Some(DEFAULT_UDP_AMPLIFICATION_FACTOR),
        UdpAmplificationPosture::FiniteDefault,
    )
}

/// Fail-closed aggregation for one physical UDP proxy shared by several claims.
///
/// A finite factor dominates Unlimited. The smallest finite factor wins among
/// finite candidates. The proxy is unlimited only when every represented claim
/// is explicitly Unlimited.
fn aggregate_shared_port_policies(
    resolutions: &[(Option<f32>, UdpAmplificationPosture)],
) -> (Option<f32>, UdpAmplificationPosture) {
    if resolutions.is_empty() {
        return (
            Some(DEFAULT_UDP_AMPLIFICATION_FACTOR),
            UdpAmplificationPosture::FiniteDefault,
        );
    }
    let mut min_finite: Option<f32> = None;
    let mut min_from_policy = false;
    for &(factor, posture) in resolutions {
        let Some(factor) = factor else {
            continue;
        };
        match min_finite {
            None => {
                min_finite = Some(factor);
                min_from_policy = posture == UdpAmplificationPosture::FinitePolicy;
            }
            Some(current) => {
                let from_policy = posture == UdpAmplificationPosture::FinitePolicy;
                if factor < current {
                    min_finite = Some(factor);
                    min_from_policy = from_policy;
                } else if factor == current && from_policy {
                    min_from_policy = true;
                }
            }
        }
    }
    match min_finite {
        None => (None, UdpAmplificationPosture::ExplicitUnlimited),
        Some(factor) if min_from_policy => (Some(factor), UdpAmplificationPosture::FinitePolicy),
        Some(factor) => (Some(factor), UdpAmplificationPosture::FiniteDefault),
    }
}

fn class_default_factor(acc: &K8sAccumulator, class_name: &str) -> Option<Option<f32>> {
    let (namespace, name) = acc.gateway_class_parameters_ref.get(class_name)?;
    let policy = acc
        .udp_amplification_policies
        .by_name
        .get(&(namespace.clone(), name.clone()))?;
    Some(policy.body.factor)
}

fn posture_from_body(body: &ValidPolicyBody) -> (Option<f32>, UdpAmplificationPosture) {
    match body.factor {
        None => (None, UdpAmplificationPosture::ExplicitUnlimited),
        Some(factor) => (Some(factor), UdpAmplificationPosture::FinitePolicy),
    }
}

/// Aggregate every exact `(route, parent_ref)` posture.
///
/// Shared-port sibling parents are already fail-closed onto one physical proxy
/// before recording, so each exact parentRef here is the actual protection.
/// A wildcard parentRef can still materialize on several UDP ports, each with
/// its own physical proxy. Status for that parent is conservative and
/// order-independent: any `ExplicitUnlimited` makes the parent unprotected;
/// otherwise protection stays on, with `FinitePolicy` only when every matching
/// listener won a finite policy and `FiniteDefault` when at least one uses the
/// controller default. A missing exact parent does not inherit another parentRef.
pub(crate) fn lookup_route_posture(
    postures: &[GatewayApiUdpAmplificationRoutePosture],
    route: &K8sResourceKey,
    parent_ref: &str,
) -> Option<UdpAmplificationPosture> {
    let mut saw_exact = false;
    let mut saw_unlimited = false;
    let mut saw_finite_default = false;
    let mut saw_finite_policy = false;
    for entry in postures {
        if entry.route != *route || entry.parent_ref != parent_ref {
            continue;
        }
        saw_exact = true;
        match entry.posture {
            UdpAmplificationPosture::ExplicitUnlimited => saw_unlimited = true,
            UdpAmplificationPosture::FiniteDefault => saw_finite_default = true,
            UdpAmplificationPosture::FinitePolicy => saw_finite_policy = true,
        }
    }
    if !saw_exact {
        return None;
    }
    if saw_unlimited {
        return Some(UdpAmplificationPosture::ExplicitUnlimited);
    }
    if saw_finite_policy && !saw_finite_default {
        return Some(UdpAmplificationPosture::FinitePolicy);
    }
    Some(UdpAmplificationPosture::FiniteDefault)
}
