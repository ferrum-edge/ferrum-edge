//! Mesh authorization policy evaluation.
//!
//! This is the Layer 5 policy core used by the future `mesh_authz` plugin.
//! It evaluates the Layer 2 `MeshPolicy` model without changing the plugin
//! trait or proxy hot path.
//! Path matching is intentionally literal; callers must pass already-normalized
//! request paths when they want dot-segment, slash, or percent-decoding policy.
#![allow(dead_code)]

use std::collections::BTreeMap;

use std::net::IpAddr;

use crate::identity::SpiffeId;
use crate::modes::mesh::config::{
    ConditionMatch, MeshConditionKeyKind, MeshPolicy, MeshRule, PolicyAction, PrincipalMatch,
    RequestMatch, SourceNegationMatch, classify_mesh_condition_key,
    normalize_mesh_policy_header_map,
};
use crate::modes::mesh::slice::MeshSlice;

/// Protocol family of the evaluation context.
///
/// Istio gives "the attribute is absent" and "this protocol can never carry the
/// attribute" *different* semantics, so the evaluator must be able to tell them
/// apart. On a non-HTTP port Istio ignores HTTP-only `when` fields for `DENY`
/// (the rule still matches on its remaining constraints) and makes an `ALLOW`
/// rule that uses them never match. On HTTP the same key simply resolves to an
/// absent attribute and follows the ordinary values / notValues rules.
///
/// Defaults to [`MeshAuthzProtocol::L4`] — the restrictive side — so a caller
/// that forgets to set it cannot accidentally widen HTTP-only conditions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MeshAuthzProtocol {
    /// HTTP-family request: HTTP/1.1, HTTP/2, HTTP/3, gRPC, gRPC-Web,
    /// WebSocket upgrades, and HTTP relayed inside a mesh/HBONE CONNECT.
    /// Every documented attribute family is sourceable.
    Http,
    /// Layer-4 connection or session: raw TCP, TLS passthrough, UDP, and DTLS
    /// — everything authorized through `Plugin::on_stream_connect`, which has
    /// no HTTP header map and no validated-JWT context at all. HTTP-family
    /// attributes (`request.headers[...]`, `request.auth.*`) cannot be sourced.
    ///
    /// A mesh / HBONE CONNECT relay is deliberately NOT in this variant: it is
    /// authorized on the request path, where Ferrum has parsed the CONNECT's
    /// own header map and can genuinely source `request.headers[...]` from it.
    #[default]
    L4,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshAuthzRequest {
    pub source_principal: Option<SpiffeId>,
    /// JWT-derived request principal in `iss/sub` format, set by `jwks_auth`
    /// metadata. Used for Istio AuthorizationPolicy `requestPrincipals` matching.
    pub request_principal: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub headers: BTreeMap<String, String>,
    pub attributes: BTreeMap<String, MeshAuthzAttribute>,
    /// Direct connection peer IP (`source.ip`), used by Istio source
    /// `ipBlocks` / `notIpBlocks` matchers. `None` when the listener could
    /// not resolve a socket peer address; `when: source.ip` then treats the
    /// attribute as unsourceable and fails closed.
    pub source_ip: Option<std::net::IpAddr>,
    /// XFF-derived remote client IP (`remote.ip`), used by Istio source
    /// `remoteIpBlocks` / `notRemoteIpBlocks` matchers. `None` when no
    /// trusted forwarded address was resolved; `when: remote.ip` then treats
    /// the attribute as unsourceable and fails closed.
    pub remote_ip: Option<std::net::IpAddr>,
    /// Authoritative destination IP of the connection this request/session
    /// arrived on (`destination.ip`) — the pre-NAT original destination when
    /// the listener captured one, otherwise the connection's local address.
    /// Never inferred from client-supplied headers or application data.
    ///
    /// `None` means the path could not observe one, which is NOT the same as
    /// "the connection had no destination": a `destination.ip` condition then
    /// takes the unsourceable branch in [`matches_conditions`] and fails
    /// closed instead of quietly not matching.
    pub destination_ip: Option<std::net::IpAddr>,
    /// Protocol family this request is being authorized on. Decides whether
    /// HTTP-family `when` attributes are sourceable at all — see
    /// [`MeshAuthzProtocol`].
    pub protocol: MeshAuthzProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshAuthzAttribute {
    Scalar(String),
    StringList(Vec<String>),
}

impl From<String> for MeshAuthzAttribute {
    fn from(value: String) -> Self {
        Self::Scalar(value)
    }
}

impl From<&str> for MeshAuthzAttribute {
    fn from(value: &str) -> Self {
        Self::Scalar(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshAuthzDecision {
    Allow,
    Deny { policy: String },
    Audit { policy: String },
}

/// A matched Istio `action: CUSTOM` delegation, pending an external
/// authorization check.
///
/// Istio evaluates CUSTOM BEFORE DENY and ALLOW. The evaluator therefore
/// cannot decide a request that matched a CUSTOM rule on its own: it returns
/// the delegation alongside the decision the remaining (DENY/ALLOW/AUDIT)
/// tiers would produce, and the caller runs the provider check first. Only an
/// ALLOW verdict from the provider lets that decision take effect; a deny, an
/// error, or an unavailable executor denies outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuthzCustomDelegation {
    /// Name of the `AuthorizationPolicy` whose CUSTOM rule matched. Used for
    /// deny metadata / the policy-deny drilldown; never for provider lookup.
    pub policy: String,
    /// `meshConfig.extensionProviders[].name` this delegation binds.
    pub provider: String,
}

/// Full evaluation outcome: the CUSTOM delegation (if any) plus the decision
/// the non-CUSTOM tiers reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuthzEvaluation {
    /// `Some` when at least one CUSTOM rule matched and every matching CUSTOM
    /// rule named the SAME provider. Same-provider CUSTOM policies coalesce
    /// into one check (the delegation names the first matching policy, for
    /// deny attribution only).
    pub custom: Option<MeshAuthzCustomDelegation>,
    /// `true` when two or more DIFFERENT extension providers were applicable
    /// to this request.
    ///
    /// Istio permits at most ONE extension provider per workload, so this is a
    /// configuration error, not a precedence question. Picking the first match
    /// would make the enforcing authorizer depend on policy iteration order —
    /// an attacker-influenceable choice between two operators' authorizers —
    /// so the request is refused instead. `custom` is `None` in this state:
    /// there is no single delegation to run.
    pub custom_provider_conflict: bool,
    /// What DENY / ALLOW / AUDIT alone decided. Meaningful only after the
    /// CUSTOM delegation (if present) has returned an allow verdict.
    pub decision: MeshAuthzDecision,
}

/// The stable, fixed-cardinality policy name a refusal carries when two
/// distinct extension providers apply to one request. Never a provider name:
/// this reaches deny metadata, which is attacker-triggerable.
pub const MESH_AUTHZ_CUSTOM_PROVIDER_CONFLICT: &str = "custom:provider-conflict";

pub fn evaluate_mesh_authorization(
    slice: &MeshSlice,
    request: &MeshAuthzRequest,
) -> MeshAuthzDecision {
    evaluate_mesh_authorization_policies(&slice.mesh_policies, request)
}

/// Evaluate Layer 5 mesh authorization against an arbitrary policy iterator.
///
/// Mirrors [`evaluate_mesh_authorization`] but accepts any borrowing iterator
/// of `&MeshPolicy`. Lets node-waypoint topology apply a per-request scope
/// filter without cloning the full [`MeshSlice`] — the slice carries dozens
/// of unrelated Vec fields (workloads, services, destination_rules, etc.)
/// that the authz engine never reads, so cloning the slice just to swap
/// `mesh_policies` would be a major regression on the request hot path.
pub fn evaluate_mesh_authorization_policies<'a, I>(
    policies: I,
    request: &MeshAuthzRequest,
) -> MeshAuthzDecision
where
    I: IntoIterator<Item = &'a MeshPolicy>,
{
    let evaluation = evaluate_mesh_authorization_full(policies, request);
    if evaluation.custom_provider_conflict {
        return MeshAuthzDecision::Deny {
            policy: MESH_AUTHZ_CUSTOM_PROVIDER_CONFLICT.to_string(),
        };
    }
    match evaluation.custom {
        // A matched CUSTOM delegation that this caller cannot execute (it has
        // no external-authorization executor — the L4 / stream path, or a
        // generation whose provider set did not bind) MUST NOT fall through to
        // the ALLOW/DENY tiers: Istio runs CUSTOM first, so skipping it would
        // serve traffic the operator delegated away. Deny with a stable,
        // fixed-cardinality rule name.
        Some(delegation) => MeshAuthzDecision::Deny {
            policy: format!("custom:{}", delegation.policy),
        },
        None => evaluation.decision,
    }
}

/// Evaluate mesh authorization, surfacing a matched CUSTOM delegation instead
/// of collapsing it into a denial.
///
/// Istio's action order is CUSTOM → DENY → ALLOW, with AUDIT non-enforcing.
/// This function performs ONE pass and reports both halves:
///
/// * `custom` — the matching CUSTOM delegation, if any. Several matching
///   CUSTOM policies naming the SAME provider coalesce into one check. The
///   caller must run that check before anything else takes effect.
/// * `custom_provider_conflict` — set when matching CUSTOM rules name two or
///   more DIFFERENT providers. Istio permits at most one extension provider
///   per workload, so this is refused rather than resolved by iteration order.
/// * `decision` — what the DENY/ALLOW/AUDIT tiers decided on their own,
///   including the ALLOW implicit-deny floor.
///
/// A CUSTOM rule deliberately does NOT contribute to the ALLOW implicit-deny
/// floor: in Istio a CUSTOM policy delegates rather than grants, so it must
/// neither raise the floor for unrelated traffic nor satisfy an existing one.
pub fn evaluate_mesh_authorization_full<'a, I>(
    policies: I,
    request: &MeshAuthzRequest,
) -> MeshAuthzEvaluation
where
    I: IntoIterator<Item = &'a MeshPolicy>,
{
    let mut saw_allow = false;
    let mut matched_allow = false;
    let mut matched_audit = None;
    let mut matched_deny: Option<String> = None;
    let mut custom: Option<MeshAuthzCustomDelegation> = None;
    let mut custom_provider_conflict = false;
    let normalized_host = request.host.as_deref().and_then(normalize_match_host);

    for policy in policies {
        for rule in &policy.rules {
            // Hot-path guard: once a DENY has matched AND the delegation half
            // is settled (a conflict is terminal; otherwise every remaining
            // CUSTOM rule must still be inspected, because a SECOND distinct
            // provider is what turns one delegation into a refusal), skip the
            // comparatively expensive matcher. The check below is a
            // discriminant test, not a match evaluation.
            let is_custom = matches!(rule.action, PolicyAction::Custom { .. });
            if matched_deny.is_some() && (custom_provider_conflict || !is_custom) {
                continue;
            }
            if !rule_matches(rule, request, normalized_host.as_ref(), &policy.namespace) {
                continue;
            }
            match &rule.action {
                PolicyAction::Deny => {
                    // Record rather than return: a CUSTOM rule in a later
                    // policy still has to be reported so the caller cannot
                    // conclude "no delegation applied" from a deny it might
                    // later re-derive. The deny still wins the decision half.
                    matched_deny.get_or_insert_with(|| policy.name.clone());
                }
                PolicyAction::Allow => {
                    saw_allow = true;
                    matched_allow = true;
                }
                PolicyAction::Audit => {
                    matched_audit.get_or_insert_with(|| policy.name.clone());
                }
                PolicyAction::Custom { provider } => {
                    // `take` ends the borrow of `custom` before the arms
                    // assign to it.
                    match custom.take() {
                        // Same provider: Istio coalesces these into ONE check.
                        Some(existing) if existing.provider == *provider => custom = Some(existing),
                        // A second, DIFFERENT provider. Istio permits at most
                        // one extension provider per workload, so there is no
                        // correct winner — refuse rather than let iteration
                        // order pick the enforcing authorizer.
                        Some(_) => custom_provider_conflict = true,
                        None if custom_provider_conflict => {}
                        None => {
                            custom = Some(MeshAuthzCustomDelegation {
                                policy: policy.name.clone(),
                                provider: provider.clone(),
                            });
                        }
                    }
                }
            }
        }
        if policy
            .rules
            .iter()
            .any(|rule| rule.action == PolicyAction::Allow)
        {
            saw_allow = true;
        }
    }

    let decision = if let Some(policy) = matched_deny {
        MeshAuthzDecision::Deny { policy }
    } else if saw_allow && !matched_allow {
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string(),
        }
    } else if let Some(policy) = matched_audit {
        MeshAuthzDecision::Audit { policy }
    } else {
        MeshAuthzDecision::Allow
    };
    MeshAuthzEvaluation {
        custom,
        custom_provider_conflict,
        decision,
    }
}

/// Whether a rule's `to:` request scope COULD apply to a request with this
/// method / path / host.
///
/// Used ONLY to decide, before the `authorize` phase runs, whether a
/// body-inspecting CUSTOM rule can reach a request — i.e. whether that
/// provider's `maxRequestBytes` ceiling and the pre-`authorize` body buffer
/// apply at all. It must have NO FALSE NEGATIVES for a rule that will later
/// match, or a body-inspecting check would run without a body and — under
/// `failOpen` — admit the request without an authorization decision.
///
/// Method, path, and host are checked precisely against the `to:` block.
/// Every other predicate — `from:` source identity, `when:` conditions, and
/// the port/header fields of the same `to:` block — is treated as
/// satisfiable: those dimensions are incomplete or unavailable at the
/// prebuffer point (destination port is resolved later from orig-dst /
/// matched-proxy evidence), so consulting them here would false-negative a
/// rule that matches once authorize observes them. A request whose method,
/// path, and host cannot satisfy any `to:` entry keeps its ordinary accepted
/// body size. This path intentionally allocates nothing beyond an optional
/// host normalization when a `to:` entry actually constrains hosts.
pub fn mesh_rule_request_scope_may_apply(
    rule: &MeshRule,
    method: &str,
    path: &str,
    host: Option<&str>,
) -> bool {
    if rule.to.is_empty() {
        return true;
    }
    let needs_host = rule
        .to
        .iter()
        .any(|match_| !match_.hosts.is_empty() || !match_.not_hosts.is_empty());
    let normalized_host = if needs_host {
        host.and_then(normalize_match_host)
    } else {
        None
    };
    rule.to.iter().any(|match_| {
        request_scope_method_path_host_may_apply(match_, method, path, normalized_host.as_ref())
    })
}

/// Precise method/path/host narrowing for the pre-`authorize` body-buffer
/// decision. Ports, headers, and every other `to:` dimension are deliberately
/// ignored so an unavailable attribute cannot suppress buffering.
fn request_scope_method_path_host_may_apply(
    match_: &RequestMatch,
    method: &str,
    path: &str,
    normalized_host: Option<&NormalizedHost>,
) -> bool {
    if !match_.methods.is_empty()
        && !match_
            .methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
    {
        return false;
    }
    if !match_.not_methods.is_empty()
        && match_
            .not_methods
            .iter()
            .any(|denied| denied.eq_ignore_ascii_case(method))
    {
        return false;
    }
    if !match_.paths.is_empty()
        && !match_
            .paths
            .iter()
            .any(|pattern| wildcard_match(pattern, path))
    {
        return false;
    }
    if !match_.not_paths.is_empty()
        && match_
            .not_paths
            .iter()
            .any(|pattern| wildcard_match(pattern, path))
    {
        return false;
    }
    if !match_.hosts.is_empty() {
        match normalized_host {
            Some(host)
                if match_
                    .hosts
                    .iter()
                    .any(|pattern| normalized_host_matches(pattern, host)) => {}
            // Missing/unparseable host is satisfiable: authorize may still
            // observe one, and this predicate must not false-negative.
            None => {}
            Some(_) => return false,
        }
    }
    if !match_.not_hosts.is_empty()
        && let Some(host) = normalized_host
        && match_
            .not_hosts
            .iter()
            .any(|pattern| normalized_host_matches(pattern, host))
    {
        return false;
    }
    true
}

/// `policy_namespace` is the namespace of the owning [`MeshPolicy`] (the
/// `AuthorizationPolicy`'s own namespace on the Kubernetes path). Istio resolves
/// a bare `when: source.serviceAccount` value against it, so it has to reach
/// condition evaluation.
fn rule_matches(
    rule: &MeshRule,
    request: &MeshAuthzRequest,
    normalized_host: Option<&NormalizedHost>,
    policy_namespace: &str,
) -> bool {
    if rule.never_matches {
        return false;
    }
    matches_principals(&rule.from, request)
        && matches_request_principals(&rule.request_principals, request)
        && matches_not_request_principals(&rule.not_request_principals, request)
        && matches_source_negation(&rule.source_negation, request)
        && matches_requests(&rule.to, request, &rule.action, normalized_host)
        && matches_conditions(&rule.when, request, &rule.action, policy_namespace)
}

/// Enforce the conjunctive source-negative / IP-block matchers for one rule.
///
/// Each populated positive IP field is **fail-closed** when the request
/// attribute it tests is absent. Negative principal/namespace fields preserve
/// Istio semantics: when the source identity is absent it does not match any
/// excluded identity, so DENY policies such as `notPrincipals: ["*"]` can
/// intentionally catch anonymous traffic.
fn matches_source_negation(neg: &SourceNegationMatch, request: &MeshAuthzRequest) -> bool {
    if neg.is_empty() {
        return true;
    }
    // notPrincipals / notNamespaces — operate on the source SPIFFE ID.
    if let Some(source) = request.source_principal.as_ref() {
        if neg
            .not_spiffe_id_patterns
            .iter()
            .any(|pattern| source_principal_pattern_matches(pattern, source))
        {
            return false;
        }
        if !neg.not_namespace_patterns.is_empty()
            && extract_namespace(source.as_str()).is_some_and(|namespace| {
                neg.not_namespace_patterns
                    .iter()
                    .any(|pattern| wildcard_match(pattern, namespace))
            })
        {
            return false;
        }
        if neg
            .not_trust_domain_patterns
            .iter()
            .any(|pattern| wildcard_match(pattern, source.trust_domain().as_str()))
        {
            return false;
        }
    }
    // ipBlocks / notIpBlocks — direct connection peer IP (source.ip).
    if !neg.ip_blocks.is_empty() {
        let Some(ip) = request.source_ip else {
            return false;
        };
        if !neg.ip_blocks.iter().any(|cidr| cidr.contains(ip)) {
            return false;
        }
    }
    if !neg.not_ip_blocks.is_empty() {
        let Some(ip) = request.source_ip else {
            return false;
        };
        if neg.not_ip_blocks.iter().any(|cidr| cidr.contains(ip)) {
            return false;
        }
    }
    // remoteIpBlocks / notRemoteIpBlocks — XFF-derived remote client IP.
    if !neg.remote_ip_blocks.is_empty() {
        let Some(ip) = request.remote_ip else {
            return false;
        };
        if !neg.remote_ip_blocks.iter().any(|cidr| cidr.contains(ip)) {
            return false;
        }
    }
    if !neg.not_remote_ip_blocks.is_empty() {
        let Some(ip) = request.remote_ip else {
            return false;
        };
        if neg
            .not_remote_ip_blocks
            .iter()
            .any(|cidr| cidr.contains(ip))
        {
            return false;
        }
    }
    true
}

/// Istio `requestPrincipals` matching: JWT-derived `iss/sub` identity.
///
/// An empty list means "any" (no filter). A non-empty list requires a
/// matching `request_principal`; `None` (no JWT) fails the match.
fn matches_request_principals(patterns: &[String], request: &MeshAuthzRequest) -> bool {
    if patterns.is_empty() {
        return true;
    }
    request.request_principal.as_ref().is_some_and(|principal| {
        patterns
            .iter()
            .any(|pattern| wildcard_match(pattern, principal))
    })
}

/// Istio `notRequestPrincipals` matching: conjunctive negative match over the
/// JWT-derived `iss/sub` identity.
///
/// An empty list means "no negative filter". A non-empty list fails the match
/// when the request principal matches any pattern. When no request principal
/// is present the negative matcher succeeds, matching Istio's semantics and
/// enabling the canonical `DENY` `notRequestPrincipals: ["*"]` policy for
/// anonymous requests.
fn matches_not_request_principals(patterns: &[String], request: &MeshAuthzRequest) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let Some(principal) = request.request_principal.as_ref() else {
        return true;
    };
    !patterns
        .iter()
        .any(|pattern| wildcard_match(pattern, principal))
}

fn matches_principals(matches: &[PrincipalMatch], request: &MeshAuthzRequest) -> bool {
    if matches.is_empty() {
        return true;
    }
    matches
        .iter()
        .any(|principal| principal_match(principal, request.source_principal.as_ref()))
}

fn principal_match(match_: &PrincipalMatch, source: Option<&SpiffeId>) -> bool {
    let Some(source) = source else {
        return false;
    };
    if let Some(trust_domain) = match_.trust_domain.as_ref()
        && source.trust_domain() != trust_domain
    {
        return false;
    }
    if let Some(pattern) = match_.trust_domain_pattern.as_ref()
        && !wildcard_match(pattern, source.trust_domain().as_str())
    {
        return false;
    }
    if let Some(pattern) = match_.spiffe_id_pattern.as_ref()
        && !source_principal_pattern_matches(pattern, source)
    {
        return false;
    }
    if let Some(pattern) = match_.namespace_pattern.as_ref()
        && !extract_namespace(source.as_str()).is_some_and(|ns| wildcard_match(pattern, ns))
    {
        return false;
    }
    true
}

pub(crate) fn istio_source_principal(source: &SpiffeId) -> &str {
    source
        .as_str()
        .strip_prefix("spiffe://")
        .unwrap_or(source.as_str())
}

fn source_principal_pattern_matches(pattern: &str, source: &SpiffeId) -> bool {
    wildcard_match(pattern, source.as_str())
        || wildcard_match(pattern, istio_source_principal(source))
}

fn matches_requests(
    matches: &[RequestMatch],
    request: &MeshAuthzRequest,
    action: &PolicyAction,
    normalized_host: Option<&NormalizedHost>,
) -> bool {
    if matches.is_empty() {
        return true;
    }
    matches
        .iter()
        .any(|match_| request_match(match_, request, action, normalized_host))
}

fn request_match(
    match_: &RequestMatch,
    request: &MeshAuthzRequest,
    action: &PolicyAction,
    normalized_host: Option<&NormalizedHost>,
) -> bool {
    if !match_.methods.is_empty() {
        match request.method.as_ref() {
            Some(method)
                if match_
                    .methods
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(method)) => {}
            None if deny_missing_http_attribute_matches(action) => {}
            _ => return false,
        }
    }
    if !match_.not_methods.is_empty() {
        match request.method.as_ref() {
            Some(method)
                if match_
                    .not_methods
                    .iter()
                    .any(|denied| denied.eq_ignore_ascii_case(method)) =>
            {
                return false;
            }
            Some(_) => {}
            None if deny_missing_http_attribute_matches(action) => {}
            None => return false,
        }
    }
    if !match_.paths.is_empty() {
        match request.path.as_ref() {
            Some(path)
                if match_
                    .paths
                    .iter()
                    .any(|pattern| wildcard_match(pattern, path)) => {}
            None if deny_missing_http_attribute_matches(action) => {}
            _ => return false,
        }
    }
    if !match_.not_paths.is_empty() {
        match request.path.as_ref() {
            Some(path)
                if match_
                    .not_paths
                    .iter()
                    .any(|pattern| wildcard_match(pattern, path)) =>
            {
                return false;
            }
            Some(_) => {}
            None if deny_missing_http_attribute_matches(action) => {}
            None => return false,
        }
    }
    if !match_.hosts.is_empty() {
        match normalized_host {
            Some(host)
                if match_
                    .hosts
                    .iter()
                    .any(|pattern| normalized_host_matches(pattern, host)) => {}
            None if deny_missing_http_attribute_matches(action) => {}
            _ => return false,
        }
    }
    if !match_.not_hosts.is_empty() {
        match normalized_host {
            Some(host)
                if match_
                    .not_hosts
                    .iter()
                    .any(|pattern| normalized_host_matches(pattern, host)) =>
            {
                return false;
            }
            Some(_) => {}
            None if deny_missing_http_attribute_matches(action) => {}
            None => return false,
        }
    }
    if (!match_.ports.is_empty() || !match_.port_patterns.is_empty())
        && !request.port.is_some_and(|port| {
            match_.ports.contains(&port)
                || match_
                    .port_patterns
                    .iter()
                    .any(|pattern| port_pattern_matches(pattern, port))
        })
    {
        return false;
    }
    if !match_.not_ports.is_empty() || !match_.not_port_patterns.is_empty() {
        // Fail-closed on a missing port, matching `not_methods`/`not_paths`/
        // `not_hosts` above. A `notPorts` rule that silently passed
        // port-less traffic (e.g. a destination that never resolved a port)
        // would over-permit the very traffic the operator meant to gate.
        let Some(port) = request.port else {
            return false;
        };
        if match_.not_ports.contains(&port)
            || match_
                .not_port_patterns
                .iter()
                .any(|pattern| port_pattern_matches(pattern, port))
        {
            return false;
        }
    }
    for (name, pattern) in &match_.headers {
        match request_header_value(&request.headers, name) {
            Some(value) if wildcard_match(pattern, value) => {}
            None if deny_missing_http_attribute_matches(action) => {}
            _ => return false,
        }
    }
    true
}

/// Istio treats an unobservable HTTP attribute differently per action.
///
/// `DENY` **and `CUSTOM`** ignore the field — Istio documents HTTP-only fields
/// as "always matched" for both actions on a TCP port — so an unevaluable
/// attribute can never disarm a deny, nor quietly disarm a delegation. That is
/// what makes an L4 CUSTOM rule carrying path/method/header/JWT conditions
/// still match, and therefore still close the connection (the stream path has
/// no HTTP request to check, so a matched delegation is a refusal).
///
/// `ALLOW` and `AUDIT` can never match on it: access is never granted on
/// something this path cannot read.
fn deny_missing_http_attribute_matches(action: &PolicyAction) -> bool {
    matches!(action, PolicyAction::Deny | PolicyAction::Custom { .. })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedHost {
    name: String,
    authority: String,
}

fn normalized_host_matches(pattern: &str, host: &NormalizedHost) -> bool {
    // Patterns are pre-normalized at config-load time
    // (see `crate::modes::mesh::config::normalize_request_match_host_pattern`),
    // so the hot path can match directly against the request authority's
    // bare name (no port) and full authority (host[:port]) forms.
    wildcard_match(pattern, &host.name) || wildcard_match(pattern, &host.authority)
}

fn request_header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            headers.get(&name.to_ascii_lowercase()).map(String::as_str)
        } else {
            None
        }
    })
}

fn normalize_match_host(host: &str) -> Option<NormalizedHost> {
    let host = host.trim();
    if host.is_empty() || host.contains('@') {
        return None;
    }

    if host.starts_with('[') {
        let end = host.find(']')?;
        let literal = &host[..=end];
        let suffix = &host[end + 1..];
        if suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .is_some_and(is_valid_authority_port)
        {
            let name = literal.to_ascii_lowercase();
            let authority = if suffix.is_empty() {
                name.clone()
            } else {
                format!("{name}{suffix}")
            };
            return Some(NormalizedHost { name, authority });
        }
        return None;
    }

    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && is_valid_authority_port(port) => {
            let name = normalize_hostname(name)?;
            Some(NormalizedHost {
                authority: format!("{name}:{port}"),
                name,
            })
        }
        Some(_) => None,
        None => normalize_hostname(host).map(|name| NormalizedHost {
            authority: name.clone(),
            name,
        }),
    }
}

/// Direct port-pattern match without allocating a port string.
///
/// Istio + Ferrum direct-config validators only allow three pattern shapes
/// (`*`, `<digits>*`, `*<digits>`), so a `starts_with` / `ends_with` /
/// equality check on the digit form of `port` is enough — there is no need
/// to invoke the general glob matcher. Writing the port into a 5-byte stack
/// buffer (max `u16::MAX = 65535`) avoids the per-request `String` allocation
/// the previous implementation paid for every `port_patterns` check.
fn port_pattern_matches(pattern: &str, port: u16) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut buf = [0u8; 5];
    let port_str = format_u16(&mut buf, port);
    if let Some(prefix) = pattern.strip_suffix('*') {
        return port_str.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return port_str.ends_with(suffix);
    }
    pattern == port_str
}

fn format_u16(buf: &mut [u8; 5], port: u16) -> &str {
    let mut idx = 5;
    let mut value = port;
    if value == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while value > 0 {
            idx -= 1;
            buf[idx] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }
    // SAFETY: only ASCII digits are written above, so this subslice is valid UTF-8.
    unsafe { std::str::from_utf8_unchecked(&buf[idx..]) }
}

fn normalize_hostname(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn is_valid_authority_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

/// The per-condition facts value matching needs beyond the candidate and the
/// attribute: the classified key kind and the namespace of the owning
/// [`MeshPolicy`], which Istio resolves a bare `source.serviceAccount` value
/// against.
///
/// `Copy` and borrow-only, built once per `when[]` entry — nothing is allocated
/// or cloned per candidate on the request path.
#[derive(Debug, Clone, Copy)]
struct ConditionMatchContext<'a> {
    kind: MeshConditionKeyKind,
    policy_namespace: &'a str,
}

fn matches_conditions(
    matches: &[ConditionMatch],
    request: &MeshAuthzRequest,
    action: &PolicyAction,
    policy_namespace: &str,
) -> bool {
    matches.iter().all(|match_| {
        if match_.values.is_empty() && match_.not_values.is_empty() {
            return false;
        }
        // Classify once per condition, not once per candidate: the key kind
        // decides both the sourceability gate below and the value grammar the
        // candidate loops use.
        //
        // An unclassifiable key is treated as unsourceable — config validation
        // and Kubernetes translation both reject those before they can reach a
        // live policy, so this is a defence-in-depth default, not a path
        // operators can reach.
        let Some(kind) = classify_mesh_condition_key(&match_.key) else {
            return deny_missing_http_attribute_matches(action);
        };
        // Istio semantics for an attribute this path can never observe (an
        // HTTP-only key on a TCP/UDP port, or a documented key Ferrum has no
        // input for at all). Both directions are fail-closed:
        //   * DENY  — the field is ignored, so the rule still matches on its
        //     remaining constraints. An unevaluable condition must never
        //     disarm a DENY.
        //   * ALLOW / AUDIT — the rule can never match. Access is never
        //     granted (or audited as granted) on an attribute we cannot read.
        // This is deliberately NOT the same as an attribute that is merely
        // absent on a path that can source it (e.g. a header the client did
        // not send), which follows the ordinary values / notValues rules
        // below exactly as Istio compiles them.
        if !condition_kind_is_sourceable(kind, request) {
            return deny_missing_http_attribute_matches(action);
        }
        let context = ConditionMatchContext {
            kind,
            policy_namespace,
        };
        let value = request.attributes.get(&match_.key);
        if !match_.values.is_empty()
            && !value.is_some_and(|value| {
                match_
                    .values
                    .iter()
                    .any(|candidate| condition_value_matches(context, candidate, value))
            })
        {
            return false;
        }
        if !match_.not_values.is_empty()
            && value.is_some_and(|value| {
                match_
                    .not_values
                    .iter()
                    .any(|candidate| condition_value_matches(context, candidate, value))
            })
        {
            return false;
        }
        true
    })
}

fn condition_value_matches(
    context: ConditionMatchContext<'_>,
    candidate: &str,
    value: &MeshAuthzAttribute,
) -> bool {
    match value {
        MeshAuthzAttribute::Scalar(value) => {
            condition_scalar_value_matches(context, candidate, value)
        }
        MeshAuthzAttribute::StringList(values) => values
            .iter()
            .any(|value| condition_scalar_value_matches(context, candidate, value)),
    }
}

/// Per-key `when[]` value grammar.
///
/// Most Istio condition keys compile to `matcher.StringMatcherWithPrefix`, but
/// three deliberately do not, and each divergence is load-bearing:
///
/// * IP-valued keys (`source.ip` / `remote.ip` / `destination.ip`) are CIDR
///   containment, not string matching.
/// * `source.serviceAccount` is an EXACT match over
///   `<namespace>/<service-account>`, with a bare `<service-account>` resolved
///   against the owning policy's namespace (`serviceAccountRegex` in
///   `pilot/pkg/security/authz/model/generator.go`). Shared validation rejects
///   any `*` here, so there is no wildcard case to consider.
/// * `source.namespace` compiles to a regex with EVERY `*` replaced by `.*`
///   (`srcNamespaceGenerator`), i.e. an arbitrary-substring wildcard at any
///   position — including mid-string and repeated stars, which the generic
///   matcher would silently treat as literal text.
///
/// `source.trustDomain` keeps the generic matcher on purpose: shared validation
/// already guarantees Istio's restricted `CheckTrustDomainValues` grammar
/// (exact, presence `*`, one leading `*`, or one trailing `*`), which the
/// presence / prefix / suffix matcher implements exactly.
fn condition_scalar_value_matches(
    context: ConditionMatchContext<'_>,
    candidate: &str,
    value: &str,
) -> bool {
    if context.kind.is_ip_valued() {
        return value
            .parse::<IpAddr>()
            .is_ok_and(|ip| cidr_contains(candidate, ip));
    }
    match context.kind {
        MeshConditionKeyKind::SourceServiceAccount => {
            istio_service_account_match(candidate, value, context.policy_namespace)
        }
        MeshConditionKeyKind::SourceNamespace => wildcard_match(candidate, value),
        _ => istio_condition_string_match(candidate, value),
    }
}

/// Istio's namespace-relative `source.serviceAccount` comparison.
///
/// `value` is the materialized attribute, always `<namespace>/<service-account>`
/// derived from the verified peer SPIFFE identity. `candidate` is the policy's
/// configured value: either the same explicit form (compared verbatim) or a bare
/// `<service-account>`, which Istio resolves against the namespace of the
/// `AuthorizationPolicy` that declared it.
///
/// Allocation-free on the request path: the bare form compares the two halves of
/// the attribute in place rather than building `<policy-namespace>/<candidate>`
/// per candidate.
///
/// Fail-closed on degenerate input — a malformed attribute with no `/`, or a
/// policy carrying an empty namespace, simply never satisfies the bare form.
fn istio_service_account_match(candidate: &str, value: &str, policy_namespace: &str) -> bool {
    if candidate.contains('/') {
        return candidate == value;
    }
    let Some((namespace, service_account)) = value.split_once('/') else {
        return false;
    };
    namespace == policy_namespace && service_account == candidate
}

/// Can this evaluation context observe the attribute of kind `kind`?
///
/// Separate from "is the attribute present": see the fail-closed branch in
/// [`matches_conditions`], which also resolves an unclassifiable key as
/// unsourceable before reaching this gate.
fn condition_kind_is_sourceable(kind: MeshConditionKeyKind, request: &MeshAuthzRequest) -> bool {
    match kind {
        // No Envoy filter chain exists in Ferrum, so the dynamic metadata
        // Istio matches here is never populated on any protocol.
        MeshConditionKeyKind::ExperimentalEnvoyFilter => false,
        // Istio marks these "HTTP only".
        MeshConditionKeyKind::RequestHeader
        | MeshConditionKeyKind::RequestAuthPrincipal
        | MeshConditionKeyKind::RequestAuthPresenter
        | MeshConditionKeyKind::RequestAuthAudiences
        | MeshConditionKeyKind::RequestAuthClaim => request.protocol == MeshAuthzProtocol::Http,
        // Every connection has source, remote, and destination addresses. An
        // unresolved typed value is therefore missing transport evidence, not
        // a genuinely absent optional attribute. Treat it as unsourceable so a
        // parse/capture failure cannot silently disarm a DENY condition.
        MeshConditionKeyKind::SourceIp => request.source_ip.is_some(),
        MeshConditionKeyKind::RemoteIp => request.remote_ip.is_some(),
        MeshConditionKeyKind::DestinationIp => request.destination_ip.is_some(),
        MeshConditionKeyKind::DestinationPort => request.port.is_some(),
        MeshConditionKeyKind::SourcePrincipal
        | MeshConditionKeyKind::SourceNamespace
        | MeshConditionKeyKind::SourceServiceAccount
        | MeshConditionKeyKind::SourceTrustDomain
        | MeshConditionKeyKind::ConnectionSni => true,
    }
}

/// Istio's GENERIC `when[]` value grammar, matching
/// `matcher.StringMatcherWithPrefix`: `*` is a presence check, a trailing `*` is
/// a prefix match, a leading `*` is a suffix match, and everything else —
/// including a mid-string `*` — is an exact match on the literal text.
///
/// This is not the grammar for every key. `source.serviceAccount` and
/// `source.namespace` have their own Istio matchers; see
/// [`condition_scalar_value_matches`] for the exceptions and why they exist.
fn istio_condition_string_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return !value.is_empty();
    }
    // Istio checks a leading wildcard before a trailing one. This ordering is
    // observable for `*value*`: it is a suffix match for the literal `value*`,
    // not a contains match and not a prefix match for the literal `*value`.
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

fn extract_namespace(spiffe_id: &str) -> Option<&str> {
    let mut segments = spiffe_id.split('/');
    while let Some(segment) = segments.next() {
        if segment == "ns" {
            return segments.next();
        }
    }
    None
}

/// Returns `true` when `ip` falls inside the CIDR (or bare IP) `cidr`.
///
/// Allocation-light: `IpAddr` / `Ipv4Addr` / `Ipv6Addr` `FromStr` parse into
/// stack values with no heap allocation, and the prefix comparison is a pure
/// integer bitmask. IPv4-mapped IPv6 addresses on either side are folded to
/// IPv4 so a `10.0.0.0/8` block still matches a `::ffff:10.0.0.1` peer,
/// matching the gateway's `client_ip` CIDR semantics. A bare IP (no `/`) is
/// treated as a host route (`/32` or `/128`). CIDRs are validated before they
/// reach request evaluation, so a malformed entry here simply fails to match
/// as a final guard.
fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return false;
    }
    let ip = canonicalize_ip_for_match(ip);
    let (network_str, prefix) = match cidr.split_once('/') {
        Some((net, prefix_str)) => match prefix_str.parse::<u8>() {
            Ok(prefix) => (net, Some(prefix)),
            Err(_) => return false,
        },
        None => (cidr, None),
    };
    let Ok(network) = network_str.parse::<IpAddr>() else {
        return false;
    };
    let Some((network, prefix)) = canonicalize_cidr_network_for_match(network, prefix) else {
        return false;
    };
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            if prefix > 32 {
                return false;
            }
            matches_prefix_u32(u32::from(net), u32::from(addr), prefix)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            if prefix > 128 {
                return false;
            }
            matches_prefix_u128(u128::from(net), u128::from(addr), prefix)
        }
        // Family mismatch (after canonicalization) never matches.
        _ => false,
    }
}

fn canonicalize_cidr_network_for_match(
    network: IpAddr,
    prefix: Option<u8>,
) -> Option<(IpAddr, u8)> {
    match network {
        IpAddr::V4(v4) => Some((IpAddr::V4(v4), prefix.unwrap_or(32))),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                let prefix = match prefix {
                    Some(prefix) if prefix >= 96 => prefix - 96,
                    Some(_) => return None,
                    None => 32,
                };
                Some((IpAddr::V4(v4), prefix))
            } else {
                Some((IpAddr::V6(v6), prefix.unwrap_or(128)))
            }
        }
    }
}

/// Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) down to its IPv4 form so
/// CIDR comparisons treat both representations identically.
#[inline]
fn canonicalize_ip_for_match(ip: IpAddr) -> IpAddr {
    crate::util::client_identity::canonical_ip(ip)
}

#[inline]
fn matches_prefix_u32(network: u32, addr: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
    (network & mask) == (addr & mask)
}

#[inline]
fn matches_prefix_u128(network: u128, addr: u128, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
    (network & mask) == (addr & mask)
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == value;
    }

    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .peekable();
    if parts.peek().is_none() {
        return true;
    }

    let mut value_pos = 0usize;
    let mut value_limit = value.len();

    if anchored_start {
        let Some(first) = parts.next() else {
            return true;
        };
        if !value.starts_with(first) {
            return false;
        }
        value_pos = first.len();
    }

    if anchored_end {
        let Some(last) = pattern.rsplit('*').find(|part| !part.is_empty()) else {
            return true;
        };
        if !value.ends_with(last) {
            return false;
        }
        let suffix_start = value.len() - last.len();
        if suffix_start < value_pos {
            return false;
        }
        value_limit = suffix_start;
    }

    while let Some(part) = parts.next() {
        if anchored_end && parts.peek().is_none() {
            break;
        }
        let Some(index) = value[value_pos..value_limit].find(part) else {
            return false;
        };
        value_pos += index + part.len();
    }

    true
}

pub(crate) fn normalize_mesh_policy_header_names(
    policy: &mut crate::modes::mesh::config::MeshPolicy,
) {
    for rule in &mut policy.rules {
        for request in &mut rule.to {
            normalize_mesh_policy_header_map(&mut request.headers);
        }
    }
}

pub(crate) fn mesh_policy_has_header_rules(
    policy: &crate::modes::mesh::config::MeshPolicy,
) -> bool {
    policy
        .rules
        .iter()
        .flat_map(|rule| &rule.to)
        .any(|request| !request.headers.is_empty())
}

pub(crate) fn mesh_policies_have_header_rules(
    policies: &[crate::modes::mesh::config::MeshPolicy],
) -> bool {
    policies.iter().any(mesh_policy_has_header_rules)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::identity::spiffe::TrustDomain;
    use crate::modes::mesh::config::{
        ConditionMatch, MeshPolicy, MeshRule, ParsedCidr, PolicyAction, PolicyScope,
        PrincipalMatch, RequestMatch, WorkloadSelector,
    };

    fn policy(name: &str, action: PolicyAction, from: Vec<PrincipalMatch>) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector::default(),
            },
            rules: vec![MeshRule {
                from,
                to: Vec::new(),
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action,
            }],
        }
    }

    fn request(source: &str) -> MeshAuthzRequest {
        MeshAuthzRequest {
            source_principal: Some(SpiffeId::new(source).expect("valid spiffe id")),
            ..MeshAuthzRequest::default()
        }
    }

    /// An HTTP-family evaluation context carrying `attributes`.
    ///
    /// `MeshAuthzRequest::default()` is deliberately [`MeshAuthzProtocol::L4`]
    /// — the fail-closed side, so a caller that forgets to declare the protocol
    /// cannot widen HTTP-only `when:` conditions onto a raw connection. Tests
    /// that model an HTTP request therefore have to say so explicitly.
    fn http_request(attributes: BTreeMap<String, MeshAuthzAttribute>) -> MeshAuthzRequest {
        MeshAuthzRequest {
            attributes,
            protocol: MeshAuthzProtocol::Http,
            ..MeshAuthzRequest::default()
        }
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let slice = MeshSlice {
            mesh_policies: vec![
                policy("allow-all", PolicyAction::Allow, Vec::new()),
                policy("deny-all", PolicyAction::Deny, Vec::new()),
            ],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "deny-all".to_string()
            }
        );
    }

    #[test]
    fn allow_policy_implies_default_deny_when_no_rule_matches() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-client",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".into()),
                    namespace_pattern: None,
                    trust_domain: None,
                    trust_domain_pattern: None,
                }],
            )],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/other")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_checks_method_path_host_port_and_headers() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-http".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        methods: vec!["GET".to_string()],
                        paths: vec!["/v1/*".to_string()],
                        hosts: vec!["api.*".to_string()],
                        headers: BTreeMap::from([("x-tenant".to_string(), "prod-*".to_string())])
                            .into_iter()
                            .collect(),
                        ports: vec![8080],
                        port_patterns: Vec::new(),
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let mut headers = BTreeMap::new();
        headers.insert("x-tenant".to_string(), "prod-a".to_string());
        let request = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/v1/items".to_string()),
            host: Some("api.default".to_string()),
            port: Some(8080),
            headers,
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn wildcard_match_respects_suffix_anchor_with_repeated_literals() {
        assert!(wildcard_match("*foo", "barfoofoo"));
        assert!(wildcard_match(
            "spiffe://*/sa/admin",
            "spiffe://cluster.local/ns/sa/sa/admin"
        ));
        assert!(!wildcard_match("*foo", "barfoobar"));
        assert!(!wildcard_match("foo*foo", "foo"));
    }

    #[test]
    fn wildcard_match_handles_degenerate_patterns_without_panics() {
        assert!(wildcard_match("exact", "exact"));
        assert!(!wildcard_match("exact", "other"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("**", ""));
        assert!(wildcard_match("***", "anything"));
        assert!(wildcard_match("a**b", "ab"));
        assert!(wildcard_match("a**b", "axxb"));
        assert!(!wildcard_match("a**b", "ac"));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "anything"));
        assert!(!wildcard_match("*suffix", ""));
    }

    #[test]
    fn normalize_mesh_policy_header_names_lowercases_keys_once() {
        let mut policy = MeshPolicy {
            name: "headers".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    headers: BTreeMap::from([("X-Tenant".to_string(), "prod".to_string())])
                        .into_iter()
                        .collect(),
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                action: PolicyAction::Allow,
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
            }],
        };

        normalize_mesh_policy_header_names(&mut policy);

        assert!(mesh_policy_has_header_rules(&policy));
        assert!(policy.rules[0].to[0].headers.contains_key("x-tenant"));
        assert!(!policy.rules[0].to[0].headers.contains_key("X-Tenant"));
    }

    #[test]
    fn normalize_mesh_policy_header_names_collapses_conflicting_case_collisions() {
        let mut policy = MeshPolicy {
            name: "headers".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    headers: BTreeMap::from([
                        ("X-Tenant".to_string(), "prod".to_string()),
                        ("x-tenant".to_string(), "dev".to_string()),
                    ])
                    .into_iter()
                    .collect(),
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                action: PolicyAction::Allow,
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
            }],
        };

        normalize_mesh_policy_header_names(&mut policy);

        assert_eq!(policy.rules[0].to[0].headers.len(), 1);
        assert!(!policy.rules[0].to[0].headers.contains_key("X-Tenant"));
        assert!(policy.rules[0].to[0].headers.contains_key("x-tenant"));
    }

    #[test]
    fn normalize_mesh_policy_header_names_collapses_duplicate_case_collisions() {
        let mut policy = MeshPolicy {
            name: "headers".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    headers: BTreeMap::from([
                        ("X-Tenant".to_string(), "prod".to_string()),
                        ("x-tenant".to_string(), "prod".to_string()),
                    ])
                    .into_iter()
                    .collect(),
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                action: PolicyAction::Allow,
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
            }],
        };

        normalize_mesh_policy_header_names(&mut policy);

        assert_eq!(policy.rules[0].to[0].headers.len(), 1);
        assert!(policy.rules[0].to[0].headers.contains_key("x-tenant"));
    }

    #[test]
    fn request_match_normalizes_host_authority_before_matching() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("Api.Default:443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_normalizes_bracketed_ipv6_authority() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["[2001:db8::1]".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("[2001:DB8::1]:443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_preserves_authority_port_for_host_policy() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default:8443".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("Api.Default:8443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_rejects_different_authority_port_for_host_policy() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default:8443".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("api.default:9443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn never_match_allow_rule_triggers_implicit_deny_without_matching() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-nothing".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: true,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_supports_wildcard_authority_port_for_host_policy() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-any-port-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default:*".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("api.default:8443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_combines_explicit_ports_and_port_patterns() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-mixed-ports".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        ports: vec![80],
                        port_patterns: vec!["8*".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let request_80 = MeshAuthzRequest {
            port: Some(80),
            ..MeshAuthzRequest::default()
        };
        let request_8443 = MeshAuthzRequest {
            port: Some(8443),
            ..MeshAuthzRequest::default()
        };
        let request_9000 = MeshAuthzRequest {
            port: Some(9000),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request_80),
            MeshAuthzDecision::Allow
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &request_8443),
            MeshAuthzDecision::Allow
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &request_9000),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_normalises_trailing_dot_host_pattern_at_config_load() {
        let mut config = crate::modes::mesh::config::MeshConfig {
            mesh_policies: vec![MeshPolicy {
                name: "allow-trailing-dot".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["Example.COM.".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..crate::modes::mesh::config::MeshConfig::default()
        };
        config.normalize();
        let slice = MeshSlice {
            mesh_policies: config.mesh_policies,
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("example.com".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn port_pattern_matches_handles_all_three_pattern_shapes() {
        assert!(port_pattern_matches("*", 80));
        assert!(port_pattern_matches("*", 65535));
        assert!(port_pattern_matches("8*", 80));
        assert!(port_pattern_matches("8*", 8443));
        assert!(!port_pattern_matches("8*", 9080));
        assert!(port_pattern_matches("*443", 443));
        assert!(port_pattern_matches("*443", 8443));
        assert!(!port_pattern_matches("*443", 8080));
        assert!(port_pattern_matches("80", 80));
        assert!(!port_pattern_matches("80", 8080));
    }

    #[test]
    fn request_match_checks_istio_port_patterns() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port-pattern".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        port_patterns: vec!["8*".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            port: Some(8443),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    // ── Empty-rule Istio semantics ───────────────────────────────────────
    //
    // Istio: ALLOW with no rules = allow-nothing. The Istio K8s translation
    // layer is responsible for emitting a `never_matches: true` rule so the
    // evaluator's `saw_allow` fires. An empty `rules` vec at the evaluator
    // level is a genuine no-op for all action types.
    //
    // The `never_match_allow_rule_triggers_implicit_deny_without_matching`
    // test (above) covers the canonical allow-nothing path.

    #[test]
    fn allow_policy_with_empty_rules_vec_is_noop() {
        // An ALLOW policy with a literally empty `rules` vec does not raise
        // `saw_allow` because the inner `.any()` scan finds nothing. This
        // is correct at the evaluator layer -- the translation layer emits
        // a `never_matches` rule for the Istio allow-nothing case.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-empty".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn deny_policy_with_empty_rules_is_noop() {
        // Istio: DENY with no rules = no-op (deny nothing). Empty rules
        // means no DENY rule fires.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-nothing".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn audit_policy_with_empty_rules_is_noop() {
        // Istio: AUDIT with no rules = no-op. No audit rule fires.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "audit-nothing".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn never_matches_allow_is_allow_nothing_semantics() {
        // Istio allow-nothing: the translation layer emits a never_matches
        // ALLOW rule. This raises `saw_allow` but never `matched_allow`,
        // producing implicit deny for all requests.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-nothing-istio".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: true,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn never_matches_deny_is_noop() {
        // A never_matches DENY rule never fires. Consistent with Istio
        // DENY-with-no-rules = no-op semantics.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-noop".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: true,
                    action: PolicyAction::Deny,
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn allow_with_rules_plus_deny_with_empty_rules() {
        // DENY with empty rules is a no-op, so only the ALLOW policy matters.
        let slice = MeshSlice {
            mesh_policies: vec![
                MeshPolicy {
                    name: "deny-nothing".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    rules: Vec::new(),
                },
                policy(
                    "allow-client",
                    PolicyAction::Allow,
                    vec![PrincipalMatch {
                        spiffe_id_pattern: Some(
                            "spiffe://cluster.local/ns/default/sa/client".into(),
                        ),
                        namespace_pattern: None,
                        trust_domain: None,
                        trust_domain_pattern: None,
                    }],
                ),
            ],
            ..MeshSlice::default()
        };

        // Matching source is allowed.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
        // Non-matching source gets implicit deny from the ALLOW policy.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/other")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    // ── DENY-first precedence ────────────────────────────────────────────

    #[test]
    fn first_deny_match_wins_second_deny_not_evaluated() {
        // Two DENY policies with different names; the first match returns
        // immediately with its policy name.
        let slice = MeshSlice {
            mesh_policies: vec![
                policy("deny-first", PolicyAction::Deny, Vec::new()),
                policy("deny-second", PolicyAction::Deny, Vec::new()),
            ],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "deny-first".to_string()
            }
        );
    }

    #[test]
    fn deny_and_allow_both_match_same_request_deny_wins() {
        // ALLOW matches the source, but DENY also matches, so DENY wins.
        let spiffe = "spiffe://cluster.local/ns/default/sa/client";
        let principal = PrincipalMatch {
            spiffe_id_pattern: Some(spiffe.into()),
            namespace_pattern: None,
            trust_domain: None,
            trust_domain_pattern: None,
        };
        let slice = MeshSlice {
            mesh_policies: vec![
                policy("allow-client", PolicyAction::Allow, vec![principal.clone()]),
                policy("deny-client", PolicyAction::Deny, vec![principal]),
            ],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request(spiffe)),
            MeshAuthzDecision::Deny {
                policy: "deny-client".to_string()
            }
        );
    }

    // ── Implicit deny edge cases ─────────────────────────────────────────

    #[test]
    fn no_allow_rules_at_all_means_default_allow() {
        // When no ALLOW rules exist, `saw_allow` stays false and the
        // default decision is Allow (no implicit deny).
        let slice = MeshSlice {
            mesh_policies: Vec::new(),
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn multiple_allow_policies_none_match_implicit_deny() {
        // Two ALLOW policies, neither matches the source; implicit deny.
        let slice = MeshSlice {
            mesh_policies: vec![
                policy(
                    "allow-admin",
                    PolicyAction::Allow,
                    vec![PrincipalMatch {
                        spiffe_id_pattern: Some(
                            "spiffe://cluster.local/ns/default/sa/admin".into(),
                        ),
                        namespace_pattern: None,
                        trust_domain: None,
                        trust_domain_pattern: None,
                    }],
                ),
                policy(
                    "allow-monitor",
                    PolicyAction::Allow,
                    vec![PrincipalMatch {
                        spiffe_id_pattern: Some(
                            "spiffe://cluster.local/ns/default/sa/monitor".into(),
                        ),
                        namespace_pattern: None,
                        trust_domain: None,
                        trust_domain_pattern: None,
                    }],
                ),
            ],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    // ── Principal matching edge cases ────────────────────────────────────

    #[test]
    fn wildcard_principal_matches_any_source() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-any",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: Some("*".into()),
                    namespace_pattern: None,
                    trust_domain: None,
                    trust_domain_pattern: None,
                }],
            )],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://some-other-domain.com/ns/prod/sa/backend")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn namespace_glob_pattern_matches() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-default-ns",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: None,
                    namespace_pattern: Some("default".into()),
                    trust_domain: None,
                    trust_domain_pattern: None,
                }],
            )],
            ..MeshSlice::default()
        };

        // Source in "default" namespace matches.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
        // Source in "prod" namespace does not match.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/prod/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn namespace_wildcard_glob_matches_any_namespace() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-all-ns",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: None,
                    namespace_pattern: Some("*".into()),
                    trust_domain: None,
                    trust_domain_pattern: None,
                }],
            )],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/anything/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn istio_principal_format_matches_source_spiffe_id() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-client",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: Some("cluster.local/ns/default/sa/client".into()),
                    namespace_pattern: None,
                    trust_domain: None,
                    trust_domain_pattern: None,
                }],
            )],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn trust_domain_mismatch_rejects() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-prod",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: None,
                    namespace_pattern: None,
                    trust_domain: Some(TrustDomain::new("prod.local").unwrap()),
                    trust_domain_pattern: None,
                }],
            )],
            ..MeshSlice::default()
        };

        // Trust domain is "cluster.local", not "prod.local".
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
        // Correct trust domain matches.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://prod.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn empty_principals_list_matches_any_source() {
        // When `from` is empty, any source is accepted (no constraint).
        let slice = MeshSlice {
            mesh_policies: vec![policy("allow-no-from", PolicyAction::Allow, Vec::new())],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/anything")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn multiple_principals_or_semantics() {
        // Multiple principal matches use OR: any one matching is enough.
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-multi",
                PolicyAction::Allow,
                vec![
                    PrincipalMatch {
                        spiffe_id_pattern: Some(
                            "spiffe://cluster.local/ns/default/sa/admin".into(),
                        ),
                        namespace_pattern: None,
                        trust_domain: None,
                        trust_domain_pattern: None,
                    },
                    PrincipalMatch {
                        spiffe_id_pattern: Some(
                            "spiffe://cluster.local/ns/default/sa/client".into(),
                        ),
                        namespace_pattern: None,
                        trust_domain: None,
                        trust_domain_pattern: None,
                    },
                ],
            )],
            ..MeshSlice::default()
        };

        // First principal matches.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/admin")
            ),
            MeshAuthzDecision::Allow
        );
        // Second principal matches.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
        // Neither matches.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/other")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn principal_match_rejects_no_source_principal() {
        // A rule with principal constraints must reject when the request
        // has no source_principal at all.
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-with-principal",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: Some("*".into()),
                    namespace_pattern: None,
                    trust_domain: None,
                    trust_domain_pattern: None,
                }],
            )],
            ..MeshSlice::default()
        };

        let req = MeshAuthzRequest {
            source_principal: None,
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &req),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    // ── Request matching edge cases ──────────────────────────────────────

    #[test]
    fn empty_methods_list_matches_any_method() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-any-method".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        methods: Vec::new(),
                        paths: vec!["/api".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        for method in &["GET", "POST", "DELETE", "PATCH"] {
            let req = MeshAuthzRequest {
                method: Some(method.to_string()),
                path: Some("/api".to_string()),
                ..MeshAuthzRequest::default()
            };
            assert_eq!(
                evaluate_mesh_authorization(&slice, &req),
                MeshAuthzDecision::Allow,
                "method {method} should be allowed with empty methods list"
            );
        }
    }

    #[test]
    fn empty_paths_list_matches_any_path() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-any-path".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        methods: vec!["GET".to_string()],
                        paths: Vec::new(),
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let req = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/anything/at/all".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &req),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn method_matching_is_case_insensitive() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-get".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        methods: vec!["GET".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let req = MeshAuthzRequest {
            method: Some("get".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &req),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn host_wildcard_glob_matches() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-example-hosts".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["*.example.com".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let match_req = MeshAuthzRequest {
            host: Some("api.example.com".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &match_req),
            MeshAuthzDecision::Allow
        );

        let no_match_req = MeshAuthzRequest {
            host: Some("api.other.com".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &no_match_req),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        // Headers stored with mixed case should match rules written lowercase.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-tenant".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        headers: BTreeMap::from([("x-tenant".to_string(), "prod".to_string())])
                            .into_iter()
                            .collect(),
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let mut headers = BTreeMap::new();
        headers.insert("x-tenant".to_string(), "prod".to_string());
        let req = MeshAuthzRequest {
            headers,
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &req),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn multiple_headers_all_must_match() {
        // Header matching uses AND semantics: every header rule must pass.
        let mut rule_headers = HashMap::new();
        rule_headers.insert("x-tenant".to_string(), "prod".to_string());
        rule_headers.insert("x-env".to_string(), "staging".to_string());
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-multi-header".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        headers: rule_headers,
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // Both headers present and matching.
        let mut both = BTreeMap::new();
        both.insert("x-tenant".to_string(), "prod".to_string());
        both.insert("x-env".to_string(), "staging".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    headers: both,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
        );

        // Only one header present.
        let mut one_only = BTreeMap::new();
        one_only.insert("x-tenant".to_string(), "prod".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    headers: one_only,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn port_matching_with_explicit_port_values() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        ports: vec![443, 8443],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    port: Some(443),
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
        );
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    port: Some(80),
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn no_port_on_request_fails_port_rule() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        ports: vec![8080],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // Request with no port should not match a port rule.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    port: None,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    // ── Condition matching ───────────────────────────────────────────────

    #[test]
    fn condition_values_or_semantics() {
        // `values` uses OR: any value match is sufficient.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-region".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: vec![ConditionMatch {
                        key: "request.auth.claims[region]".to_string(),
                        values: vec!["us-east-1".to_string(), "eu-west-1".to_string()],
                        not_values: Vec::new(),
                    }],
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let mut attrs_east = BTreeMap::new();
        attrs_east.insert(
            "request.auth.claims[region]".to_string(),
            "us-east-1".into(),
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_east)),
            MeshAuthzDecision::Allow
        );

        let mut attrs_west = BTreeMap::new();
        attrs_west.insert(
            "request.auth.claims[region]".to_string(),
            "eu-west-1".into(),
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_west)),
            MeshAuthzDecision::Allow
        );

        let mut attrs_other = BTreeMap::new();
        attrs_other.insert(
            "request.auth.claims[region]".to_string(),
            "ap-south-1".into(),
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_other)),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn condition_values_support_istio_wildcards() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-badbot".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "request.headers[user-agent]".to_string(),
                        values: vec!["BadBot/*".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        let mut attrs = BTreeMap::new();
        attrs.insert(
            "request.headers[user-agent]".to_string(),
            "BadBot/1.0".into(),
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs)),
            MeshAuthzDecision::Deny {
                policy: "deny-badbot".to_string()
            }
        );
    }

    #[test]
    fn condition_presence_wildcard_requires_non_empty_attribute() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-present-env".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "request.headers[x-env]".to_string(),
                        values: vec!["*".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        let mut empty = BTreeMap::new();
        empty.insert("request.headers[x-env]".to_string(), "".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(empty)),
            MeshAuthzDecision::Allow
        );

        let mut present = BTreeMap::new();
        present.insert("request.headers[x-env]".to_string(), "prod".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(present)),
            MeshAuthzDecision::Deny {
                policy: "deny-present-env".to_string()
            }
        );
    }

    /// Istio's `StringMatcherWithPrefix` only treats a leading or trailing `*`
    /// as a wildcard; a mid-string `*` is an exact match on the literal text.
    /// `pr*d` therefore does not match `prod`.
    ///
    /// This holds for the keys that compile to that matcher — `source.namespace`
    /// does NOT (Istio's `srcNamespaceGenerator` rewrites every `*` to `.*`), so
    /// the key here is deliberately a `request.headers[...]` one. The
    /// `source.namespace` behaviour is covered by the conformance and
    /// `mesh_authz` e2e suites.
    #[test]
    fn condition_values_treat_middle_globs_as_literal_text() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-middle-glob".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "request.headers[x-env]".to_string(),
                        values: vec!["pr*d".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        let mut attrs = BTreeMap::new();
        attrs.insert("request.headers[x-env]".to_string(), "prod".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs)),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn condition_ip_values_support_cidr_blocks() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-private-source-ip".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "source.ip".to_string(),
                        values: vec!["10.0.0.0/8".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        let mut attrs = BTreeMap::new();
        attrs.insert("source.ip".to_string(), "10.2.3.4".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs)),
            MeshAuthzDecision::Deny {
                policy: "deny-private-source-ip".to_string()
            }
        );
    }

    #[test]
    fn condition_jwt_claim_values_match_any_list_item() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-group".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "request.auth.claims[groups]".to_string(),
                        values: vec!["ops".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        let mut attrs = BTreeMap::new();
        attrs.insert(
            "request.auth.claims[groups]".to_string(),
            MeshAuthzAttribute::StringList(vec!["dev".to_string(), "ops".to_string()]),
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs)),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn condition_jwt_scalar_claim_does_not_split_commas() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-ops".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "request.auth.claims[groups]".to_string(),
                        values: vec!["ops".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        let mut attrs = BTreeMap::new();
        attrs.insert("request.auth.claims[groups]".to_string(), "dev,ops".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs)),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn condition_not_values_rejects_matching_attribute() {
        // `not_values`: if the attribute value matches any not_value, reject.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-internal".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: vec![ConditionMatch {
                        key: "source.namespace".to_string(),
                        values: Vec::new(),
                        not_values: vec!["internal".to_string()],
                    }],
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Deny,
                }],
            }],
            ..MeshSlice::default()
        };

        // Attribute matches not_values: rule does NOT match (condition fails).
        let mut attrs_internal = BTreeMap::new();
        attrs_internal.insert("source.namespace".to_string(), "internal".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_internal)),
            MeshAuthzDecision::Allow
        );

        // Attribute does not match not_values: condition passes, DENY fires.
        let mut attrs_external = BTreeMap::new();
        attrs_external.insert("source.namespace".to_string(), "external".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_external)),
            MeshAuthzDecision::Deny {
                policy: "deny-internal".to_string()
            }
        );
    }

    #[test]
    fn condition_values_and_not_values_combined() {
        // Both `values` and `not_values` on the same condition: must be
        // IN values AND NOT IN not_values.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-region-not-staging".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: vec![ConditionMatch {
                        key: "request.headers[x-env]".to_string(),
                        values: vec!["prod".to_string(), "staging".to_string(), "dev".to_string()],
                        not_values: vec!["staging".to_string()],
                    }],
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // "prod" is in values, not in not_values: match.
        let mut attrs_prod = BTreeMap::new();
        attrs_prod.insert("request.headers[x-env]".to_string(), "prod".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_prod)),
            MeshAuthzDecision::Allow
        );

        // "staging" is in both: not_values blocks it.
        let mut attrs_staging = BTreeMap::new();
        attrs_staging.insert("request.headers[x-env]".to_string(), "staging".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_staging)),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn condition_missing_attribute_fails_values_check() {
        // If the attribute key is absent from the request, `values` check
        // fails (value.is_some_and(...) returns false).
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-with-attr".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: vec![ConditionMatch {
                        key: "request.headers[x-required]".to_string(),
                        values: vec!["required".to_string()],
                        not_values: Vec::new(),
                    }],
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // No attributes at all.
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(BTreeMap::new())),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    /// Istio's non-HTTP-port rule: a DENY rule using an HTTP-only `when:` key
    /// against L4 traffic ignores that field and still matches. On an HTTP
    /// request the same key is sourceable, so an absent claim simply fails the
    /// `values` check and the DENY does not fire.
    #[test]
    fn deny_condition_http_only_attribute_is_ignored_on_l4_but_evaluated_on_http() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-admin-jwt".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "request.auth.claims[role]".to_string(),
                        values: vec!["admin".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Deny {
                policy: "deny-admin-jwt".to_string()
            },
            "a raw TCP/UDP connection cannot carry JWT claims, so the DENY must \
             not be disarmed by the unevaluable condition"
        );

        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(BTreeMap::new())),
            MeshAuthzDecision::Allow,
            "on HTTP the claim is sourceable and simply absent, so the values \
             check fails and the DENY does not fire (Istio semantics)"
        );

        let mut admin = BTreeMap::new();
        admin.insert("request.auth.claims[role]".to_string(), "admin".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(admin)),
            MeshAuthzDecision::Deny {
                policy: "deny-admin-jwt".to_string()
            }
        );
    }

    #[test]
    fn deny_condition_missing_non_http_attribute_still_fails_values_check() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-default-namespace".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "source.namespace".to_string(),
                        values: vec!["default".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn condition_not_values_absent_passes_present_match_fails() {
        // Istio `notValues` semantics: a condition is satisfied unless the
        // attribute is present AND matches one of `notValues`. When the
        // attribute is absent the `not_rule` has nothing to match, so the
        // condition passes (Envoy RBAC `not_rule(matcher)` is true when the
        // inner matcher is false). This mirrors Istio's compiled behavior.
        //
        // Previously this path was untestable end-to-end because both authz
        // entry points hard-coded `attributes: BTreeMap::new()`, so a
        // `when`-gated rule could never observe a populated attribute. Now
        // that attributes are populated from request context, this test
        // exercises both the absent (passes) and present-matching (fails)
        // arms so a `when`-gated DENY actually fires when it should and a
        // `when`-gated ALLOW correctly stops matching.
        let allow_unless_blocked = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-not-blocked".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "request.headers[x-env]".to_string(),
                        values: Vec::new(),
                        not_values: vec!["blocked".to_string()],
                    }],
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        // Key absent: not_values has nothing to match, condition passes, the
        // ALLOW rule matches.
        assert_eq!(
            evaluate_mesh_authorization(&allow_unless_blocked, &http_request(BTreeMap::new())),
            MeshAuthzDecision::Allow
        );

        // Key present and matching not_values: condition fails, the ALLOW
        // rule does not match, so the lone ALLOW policy falls through to
        // implicit deny.
        let mut blocked = BTreeMap::new();
        blocked.insert("request.headers[x-env]".to_string(), "blocked".into());
        assert_eq!(
            evaluate_mesh_authorization(&allow_unless_blocked, &http_request(blocked)),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn multiple_conditions_all_must_match() {
        // Conditions use AND semantics: every condition must pass.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-multi-cond".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: vec![
                        ConditionMatch {
                            key: "request.headers[x-env]".to_string(),
                            values: vec!["prod".to_string()],
                            not_values: Vec::new(),
                        },
                        ConditionMatch {
                            key: "request.headers[x-region]".to_string(),
                            values: vec!["us-east-1".to_string()],
                            not_values: Vec::new(),
                        },
                    ],
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // Both conditions met.
        let mut attrs_both = BTreeMap::new();
        attrs_both.insert("request.headers[x-env]".to_string(), "prod".into());
        attrs_both.insert("request.headers[x-region]".to_string(), "us-east-1".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_both)),
            MeshAuthzDecision::Allow
        );

        // Only one condition met.
        let mut attrs_one = BTreeMap::new();
        attrs_one.insert("request.headers[x-env]".to_string(), "prod".into());
        attrs_one.insert("request.headers[x-region]".to_string(), "eu-west-1".into());
        assert_eq!(
            evaluate_mesh_authorization(&slice, &http_request(attrs_one)),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    // ── Audit decision ───────────────────────────────────────────────────

    #[test]
    fn audit_rule_returns_audit_decision_when_no_allow_deny() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "audit-all".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Audit,
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Audit {
                policy: "audit-all".to_string()
            }
        );
    }

    #[test]
    fn deny_takes_precedence_over_audit() {
        let slice = MeshSlice {
            mesh_policies: vec![
                MeshPolicy {
                    name: "audit-all".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    rules: vec![MeshRule {
                        from: Vec::new(),
                        to: Vec::new(),
                        when: Vec::new(),
                        request_principals: Vec::new(),
                        not_request_principals: Vec::new(),
                        source_negation: Default::default(),
                        never_matches: false,
                        action: PolicyAction::Audit,
                    }],
                },
                policy("deny-all", PolicyAction::Deny, Vec::new()),
            ],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "deny-all".to_string()
            }
        );
    }

    // ── requestPrincipals matching ──────────────────────────────────────

    #[test]
    fn request_principals_exact_match_allows() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "require-jwt".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    request_principals: vec!["https://accounts.google.com/user-42".to_string()],
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            request_principal: Some("https://accounts.google.com/user-42".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_principals_wildcard_suffix_match() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "require-jwt".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    request_principals: vec!["https://accounts.google.com/*".to_string()],
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            request_principal: Some("https://accounts.google.com/any-subject".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_principals_missing_jwt_triggers_implicit_deny() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "require-jwt".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    request_principals: vec!["*".to_string()],
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest::default();

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_principals_non_matching_triggers_implicit_deny() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "require-google".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    request_principals: vec!["https://accounts.google.com/*".to_string()],
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            request_principal: Some("https://evil.com/attacker".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_principals_deny_blocks_matching_jwt() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-admin".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    request_principals: vec!["https://auth.example.com/admin-*".to_string()],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            request_principal: Some("https://auth.example.com/admin-root".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Deny {
                policy: "deny-admin".to_string()
            }
        );
    }

    #[test]
    fn request_principals_deny_skips_non_matching_jwt() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-admin".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    request_principals: vec!["https://auth.example.com/admin-*".to_string()],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            request_principal: Some("https://auth.example.com/user-123".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_principals_empty_list_allows_anonymous() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "no-jwt-required".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest::default();

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    // ── Extract namespace ────────────────────────────────────────────────

    #[test]
    fn extract_namespace_from_spiffe_id() {
        assert_eq!(
            extract_namespace("spiffe://cluster.local/ns/default/sa/client"),
            Some("default")
        );
        assert_eq!(
            extract_namespace("spiffe://cluster.local/ns/prod/sa/admin"),
            Some("prod")
        );
        // No "/ns/" segment.
        assert_eq!(extract_namespace("spiffe://cluster.local/sa/client"), None);
        // "/ns/" at the very end with no following segment.
        assert_eq!(extract_namespace("spiffe://cluster.local/ns/"), Some(""));
    }

    // ── Istio-style negative-match (notMethods/notPaths/notHosts/notPorts) ─

    fn policy_with_request_match(
        name: &str,
        action: PolicyAction,
        request: RequestMatch,
    ) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![request],
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action,
            }],
        }
    }

    fn allow_policy_with_request_match(name: &str, request: RequestMatch) -> MeshPolicy {
        policy_with_request_match(name, PolicyAction::Allow, request)
    }

    fn deny_policy_with_request_match(name: &str, request: RequestMatch) -> MeshPolicy {
        policy_with_request_match(name, PolicyAction::Deny, request)
    }

    #[test]
    fn request_match_not_methods_only_allows_other_methods() {
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "deny-post",
                RequestMatch {
                    not_methods: vec!["POST".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        let get_request = MeshAuthzRequest {
            method: Some("GET".to_string()),
            ..MeshAuthzRequest::default()
        };
        let post_request = MeshAuthzRequest {
            method: Some("POST".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &get_request),
            MeshAuthzDecision::Allow,
            "GET should match the rule (notMethods=[POST] does not exclude GET)"
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &post_request),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            },
            "POST should fall through to implicit-deny (rule rejects POST)"
        );
    }

    #[test]
    fn request_match_not_methods_is_case_insensitive() {
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "deny-post",
                RequestMatch {
                    not_methods: vec!["post".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        let post_request = MeshAuthzRequest {
            method: Some("POST".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &post_request),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_methods_and_not_paths_combine_as_conjunction() {
        // ALLOW with methods=[GET] AND notPaths=[/admin/*]:
        // GET /api passes (positive method match + negative path mismatch).
        // GET /admin/users fails (positive method match BUT negative path matches → reject).
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "allow-get-except-admin",
                RequestMatch {
                    methods: vec!["GET".to_string()],
                    not_paths: vec!["/admin/*".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        let get_api = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/api/items".to_string()),
            ..MeshAuthzRequest::default()
        };
        let get_admin = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/admin/users".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &get_api),
            MeshAuthzDecision::Allow,
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &get_admin),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_hosts_and_not_hosts_combine_as_conjunction() {
        // ALLOW with hosts=[*.example.com] AND notHosts=[evil.example.com]:
        // good.example.com passes (positive match + negative miss).
        // evil.example.com fails (positive match + negative match → reject).
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "allow-domain-except-evil",
                RequestMatch {
                    hosts: vec!["*.example.com".to_string()],
                    not_hosts: vec!["evil.example.com".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        let good = MeshAuthzRequest {
            host: Some("good.example.com".to_string()),
            ..MeshAuthzRequest::default()
        };
        let evil = MeshAuthzRequest {
            host: Some("evil.example.com".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &good),
            MeshAuthzDecision::Allow
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &evil),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_not_hosts_normalized_at_config_load() {
        // The not_hosts entry written in mixed case + trailing dot must be
        // normalised to ASCII-lowercase (sans trailing dot) so the hot path
        // matches against the already-normalised request authority without
        // re-allocating.
        let mut config = crate::modes::mesh::config::MeshConfig {
            mesh_policies: vec![allow_policy_with_request_match(
                "deny-evil",
                RequestMatch {
                    hosts: vec!["*.example.com".to_string()],
                    not_hosts: vec!["Evil.Example.COM.".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..crate::modes::mesh::config::MeshConfig::default()
        };
        config.normalize();

        let slice = MeshSlice {
            mesh_policies: config.mesh_policies,
            ..MeshSlice::default()
        };

        let evil = MeshAuthzRequest {
            host: Some("evil.example.com".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &evil),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_not_ports_blocks_specific_ports() {
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "deny-8080",
                RequestMatch {
                    not_ports: vec![8080],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        let port_9090 = MeshAuthzRequest {
            port: Some(9090),
            ..MeshAuthzRequest::default()
        };
        let port_8080 = MeshAuthzRequest {
            port: Some(8080),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &port_9090),
            MeshAuthzDecision::Allow,
            "Port 9090 not in not_ports list → rule matches → allow"
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &port_8080),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            },
            "Port 8080 in not_ports list → rule rejects → implicit deny"
        );
    }

    #[test]
    fn request_match_not_port_patterns_block_matching_ports() {
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "deny-8-prefix",
                RequestMatch {
                    not_port_patterns: vec!["8*".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        let port_9090 = MeshAuthzRequest {
            port: Some(9090),
            ..MeshAuthzRequest::default()
        };
        let port_8080 = MeshAuthzRequest {
            port: Some(8080),
            ..MeshAuthzRequest::default()
        };
        let port_8443 = MeshAuthzRequest {
            port: Some(8443),
            ..MeshAuthzRequest::default()
        };
        let missing_port = MeshAuthzRequest {
            port: None,
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &port_9090),
            MeshAuthzDecision::Allow,
            "Port 9090 is outside notPorts prefix 8* → rule matches → allow"
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &port_8080),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            },
            "Port 8080 matches notPorts prefix 8* → rule rejects → implicit deny"
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &port_8443),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            },
            "Port 8443 matches notPorts prefix 8* → rule rejects → implicit deny"
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &missing_port),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            },
            "Absent destination port must fail closed for notPorts patterns"
        );
    }

    #[test]
    fn request_match_ports_and_not_port_patterns_remain_conjunctive() {
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "allow-9-except-90-prefix",
                RequestMatch {
                    ports: vec![9090, 9180],
                    not_port_patterns: vec!["90*".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        let allowed = MeshAuthzRequest {
            port: Some(9180),
            ..MeshAuthzRequest::default()
        };
        let excluded_by_negative = MeshAuthzRequest {
            port: Some(9090),
            ..MeshAuthzRequest::default()
        };
        let excluded_by_positive = MeshAuthzRequest {
            port: Some(8080),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &allowed),
            MeshAuthzDecision::Allow,
            "9180 is in ports and outside notPorts 90* → allow"
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &excluded_by_negative),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            },
            "9090 is in ports but matches notPorts 90* → conjunctive fail → deny"
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &excluded_by_positive),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            },
            "8080 is outside positive ports → deny even though notPorts does not match"
        );
    }

    #[test]
    fn request_match_http_only_not_predicates_fail_match_on_stream_request() {
        // Stream-level authz (`MeshAuthz::on_stream_connect`) builds a
        // `MeshAuthzRequest` with only `port` populated — `method`, `path`,
        // and `host` are `None`. An ALLOW rule that mentions an HTTP-only
        // negative predicate (`notMethods`/`notPaths`/`notHosts`) must NOT
        // match such a request — symmetric with how the positive
        // `methods`/`paths`/`hosts` predicates fail when the corresponding
        // attribute is absent. Otherwise translated Istio policies would
        // accidentally allow raw TCP connections that should fall through
        // to implicit deny.
        let cases: [(&str, RequestMatch); 3] = [
            (
                "not_methods",
                RequestMatch {
                    not_methods: vec!["POST".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "not_paths",
                RequestMatch {
                    not_paths: vec!["/admin/*".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "not_hosts",
                RequestMatch {
                    not_hosts: vec!["evil.example.com".to_string()],
                    ..RequestMatch::default()
                },
            ),
        ];

        for (label, request_match) in cases {
            let slice = MeshSlice {
                mesh_policies: vec![allow_policy_with_request_match(
                    "allow-with-http-only-negative",
                    request_match,
                )],
                ..MeshSlice::default()
            };

            let stream_request = MeshAuthzRequest {
                port: Some(8080),
                ..MeshAuthzRequest::default()
            };

            assert_eq!(
                evaluate_mesh_authorization(&slice, &stream_request),
                MeshAuthzDecision::Deny {
                    policy: "implicit-deny".to_string()
                },
                "{label}: HTTP-only negative predicate must fail the match on a \
                 stream-level request (no method/path/host) → implicit deny"
            );
        }
    }

    #[test]
    fn deny_request_match_http_only_predicates_match_on_stream_request() {
        let cases: [(&str, RequestMatch); 7] = [
            (
                "methods",
                RequestMatch {
                    methods: vec!["POST".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "not_methods",
                RequestMatch {
                    not_methods: vec!["GET".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "paths",
                RequestMatch {
                    paths: vec!["/admin/*".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "not_paths",
                RequestMatch {
                    not_paths: vec!["/public/*".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "hosts",
                RequestMatch {
                    hosts: vec!["admin.example.com".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "not_hosts",
                RequestMatch {
                    not_hosts: vec!["public.example.com".to_string()],
                    ..RequestMatch::default()
                },
            ),
            (
                "headers",
                RequestMatch {
                    headers: BTreeMap::from([("x-admin".to_string(), "true".to_string())])
                        .into_iter()
                        .collect(),
                    ..RequestMatch::default()
                },
            ),
        ];

        for (label, mut request_match) in cases {
            request_match.ports = vec![8080];
            let slice = MeshSlice {
                mesh_policies: vec![deny_policy_with_request_match(
                    "deny-http-only-on-port",
                    request_match,
                )],
                ..MeshSlice::default()
            };
            let stream_request = MeshAuthzRequest {
                port: Some(8080),
                ..MeshAuthzRequest::default()
            };

            assert_eq!(
                evaluate_mesh_authorization(&slice, &stream_request),
                MeshAuthzDecision::Deny {
                    policy: "deny-http-only-on-port".to_string()
                },
                "{label}: DENY must treat a missing HTTP-only attribute as a match"
            );
        }
    }

    #[test]
    fn request_match_multiple_not_methods_any_match_rejects() {
        let slice = MeshSlice {
            mesh_policies: vec![allow_policy_with_request_match(
                "deny-mutations",
                RequestMatch {
                    not_methods: vec!["POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
                    ..RequestMatch::default()
                },
            )],
            ..MeshSlice::default()
        };

        for method in ["POST", "PUT", "DELETE"] {
            let request = MeshAuthzRequest {
                method: Some(method.to_string()),
                ..MeshAuthzRequest::default()
            };
            assert_eq!(
                evaluate_mesh_authorization(&slice, &request),
                MeshAuthzDecision::Deny {
                    policy: "implicit-deny".to_string()
                },
                "method {method} should be rejected by not_methods list"
            );
        }

        let get_request = MeshAuthzRequest {
            method: Some("GET".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &get_request),
            MeshAuthzDecision::Allow
        );
    }

    // ── Source negation / IP-block matchers ──────────────────────────────

    fn allow_with_source_negation(neg: SourceNegationMatch) -> MeshSlice {
        MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-gated-source".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    source_negation: neg,
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        }
    }

    #[test]
    fn not_principals_blocks_matching_source_and_admits_others() {
        let slice = allow_with_source_negation(SourceNegationMatch {
            not_spiffe_id_patterns: vec!["spiffe://cluster.local/ns/default/sa/bad".to_string()],
            ..SourceNegationMatch::default()
        });
        // Matching notPrincipals → rule fails → implicit deny.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/bad")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
        // Different source → admitted.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/good")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn not_principals_accepts_istio_principal_format() {
        let slice = allow_with_source_negation(SourceNegationMatch {
            not_spiffe_id_patterns: vec!["cluster.local/ns/default/sa/bad".to_string()],
            ..SourceNegationMatch::default()
        });

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/bad")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn not_principals_allow_absent_source_identity() {
        let slice = allow_with_source_negation(SourceNegationMatch {
            not_spiffe_id_patterns: vec!["spiffe://cluster.local/ns/default/sa/bad".to_string()],
            ..SourceNegationMatch::default()
        });
        // Istio negative source identity matchers are true when the source
        // identity is absent; DENY notPrincipals:["*"] uses this to catch
        // anonymous/plaintext traffic.
        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn not_namespaces_blocks_matching_namespace() {
        let slice = allow_with_source_negation(SourceNegationMatch {
            not_namespace_patterns: vec!["kube-system".to_string()],
            ..SourceNegationMatch::default()
        });
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/kube-system/sa/x")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &request("spiffe://cluster.local/ns/default/sa/x")),
            MeshAuthzDecision::Allow
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn deny_not_principals_star_blocks_anonymous_source_identity() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-plaintext".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    source_negation: SourceNegationMatch {
                        not_spiffe_id_patterns: vec!["*".to_string()],
                        ..SourceNegationMatch::default()
                    },
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Deny {
                policy: "deny-plaintext".to_string()
            }
        );

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn ip_blocks_allow_only_inside_range_and_fail_closed_without_ip() {
        let slice = allow_with_source_negation(SourceNegationMatch {
            ip_blocks: vec![ParsedCidr::parse("10.0.0.0/8").unwrap()],
            ..SourceNegationMatch::default()
        });
        let inside = MeshAuthzRequest {
            source_ip: Some("10.1.2.3".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &inside),
            MeshAuthzDecision::Allow
        );
        let outside = MeshAuthzRequest {
            source_ip: Some("192.168.1.1".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &outside),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
        // ipBlocks present but no source IP → fail closed.
        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn not_ip_blocks_block_inside_range() {
        let slice = allow_with_source_negation(SourceNegationMatch {
            not_ip_blocks: vec![ParsedCidr::parse("10.0.0.0/8").unwrap()],
            ..SourceNegationMatch::default()
        });
        let inside = MeshAuthzRequest {
            source_ip: Some("10.1.2.3".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &inside),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
        let outside = MeshAuthzRequest {
            source_ip: Some("192.168.1.1".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &outside),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn remote_ip_blocks_use_remote_ip_not_source_ip() {
        let slice = allow_with_source_negation(SourceNegationMatch {
            remote_ip_blocks: vec![ParsedCidr::parse("203.0.113.0/24").unwrap()],
            ..SourceNegationMatch::default()
        });
        // remote.ip inside, source.ip irrelevant → allow.
        let req = MeshAuthzRequest {
            source_ip: Some("10.0.0.1".parse().unwrap()),
            remote_ip: Some("203.0.113.7".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &req),
            MeshAuthzDecision::Allow
        );
        // remote.ip outside → deny even though source.ip would not matter.
        let req_out = MeshAuthzRequest {
            remote_ip: Some("198.51.100.1".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &req_out),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn not_request_principals_blocks_matching_jwt_and_allows_absent_principal() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-unless-admin".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    not_request_principals: vec!["https://issuer/admin".to_string()],
                    action: PolicyAction::Allow,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        // Matching request principal → blocked.
        let admin = MeshAuthzRequest {
            request_principal: Some("https://issuer/admin".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &admin),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
        // Different request principal → admitted.
        let user = MeshAuthzRequest {
            request_principal: Some("https://issuer/user".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &user),
            MeshAuthzDecision::Allow
        );
        // No JWT at all → negative request-principal match succeeds.
        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn deny_not_request_principals_star_blocks_anonymous_requests() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-anonymous".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    not_request_principals: vec!["*".to_string()],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Deny {
                policy: "deny-anonymous".to_string()
            }
        );

        let authenticated = MeshAuthzRequest {
            request_principal: Some("https://issuer/user".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &authenticated),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn deny_gated_on_when_condition_now_fires() {
        // The canonical fail-open case: a DENY gated on a `when:` condition.
        // Before attributes were populated, this DENY never fired (traffic
        // admitted). Now a matching attribute makes it fire.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "deny-prod-callers".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    when: vec![ConditionMatch {
                        key: "source.namespace".to_string(),
                        values: vec!["prod".to_string()],
                        not_values: Vec::new(),
                    }],
                    action: PolicyAction::Deny,
                    ..MeshRule::default()
                }],
            }],
            ..MeshSlice::default()
        };
        let mut attrs = BTreeMap::new();
        attrs.insert("source.namespace".to_string(), "prod".into());
        let req = MeshAuthzRequest {
            attributes: attrs,
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &req),
            MeshAuthzDecision::Deny {
                policy: "deny-prod-callers".to_string()
            }
        );
        // Without the attribute (e.g. different namespace) the DENY does not
        // fire and the request is allowed (no ALLOW policy → default allow).
        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn cidr_contains_handles_ipv4_ipv6_and_mapped() {
        assert!(cidr_contains("10.0.0.0/8", "10.255.0.1".parse().unwrap()));
        assert!(!cidr_contains("10.0.0.0/8", "11.0.0.1".parse().unwrap()));
        assert!(cidr_contains("192.168.1.1", "192.168.1.1".parse().unwrap()));
        assert!(!cidr_contains(
            "192.168.1.1",
            "192.168.1.2".parse().unwrap()
        ));
        // IPv4-mapped IPv6 peer matches an IPv4 block.
        assert!(cidr_contains(
            "10.0.0.0/8",
            "::ffff:10.0.0.5".parse().unwrap()
        ));
        // IPv4-mapped IPv6 CIDRs use their IPv4-equivalent prefix.
        assert!(cidr_contains(
            "::ffff:10.0.0.0/104",
            "10.255.0.1".parse().unwrap()
        ));
        assert!(!cidr_contains(
            "::ffff:10.0.0.0/104",
            "11.0.0.1".parse().unwrap()
        ));
        // Validation accepts surrounding whitespace; matching trims it too.
        assert!(cidr_contains(" 10.0.0.0/8 ", "10.1.2.3".parse().unwrap()));
        // IPv6 block.
        assert!(cidr_contains(
            "2001:db8::/32",
            "2001:db8::1".parse().unwrap()
        ));
        assert!(!cidr_contains(
            "2001:db8::/32",
            "2001:dead::1".parse().unwrap()
        ));
        // /0 matches anything of the same family.
        assert!(cidr_contains("0.0.0.0/0", "8.8.8.8".parse().unwrap()));
        // Malformed CIDR never matches.
        assert!(!cidr_contains("not-a-cidr", "10.0.0.1".parse().unwrap()));
        assert!(!cidr_contains("10.0.0.0/40", "10.0.0.1".parse().unwrap()));
    }
}
