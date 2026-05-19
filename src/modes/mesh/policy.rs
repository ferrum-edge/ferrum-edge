//! Mesh authorization policy evaluation.
//!
//! This is the Layer 5 policy core used by the future `mesh_authz` plugin.
//! It evaluates the Layer 2 `MeshPolicy` model without changing the plugin
//! trait or proxy hot path.
//! Path matching is intentionally literal; callers must pass already-normalized
//! request paths when they want dot-segment, slash, or percent-decoding policy.
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::identity::SpiffeId;
use crate::modes::mesh::config::{
    ConditionMatch, MeshPolicy, MeshRule, PolicyAction, PrincipalMatch, RequestMatch,
    normalize_mesh_policy_header_map,
};
use crate::modes::mesh::slice::MeshSlice;

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
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshAuthzDecision {
    Allow,
    Deny { policy: String },
    Audit { policy: String },
}

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
    let mut saw_allow = false;
    let mut matched_allow = false;
    let mut matched_audit = None;

    for policy in policies {
        for rule in &policy.rules {
            if !rule_matches(rule, request) {
                continue;
            }
            match rule.action {
                PolicyAction::Deny => {
                    return MeshAuthzDecision::Deny {
                        policy: policy.name.clone(),
                    };
                }
                PolicyAction::Allow => {
                    saw_allow = true;
                    matched_allow = true;
                }
                PolicyAction::Audit => {
                    matched_audit.get_or_insert_with(|| policy.name.clone());
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

    if saw_allow && !matched_allow {
        return MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string(),
        };
    }
    if let Some(policy) = matched_audit {
        return MeshAuthzDecision::Audit { policy };
    }
    MeshAuthzDecision::Allow
}

fn rule_matches(rule: &MeshRule, request: &MeshAuthzRequest) -> bool {
    if rule.never_matches {
        return false;
    }
    matches_principals(&rule.from, request)
        && matches_request_principals(&rule.request_principals, request)
        && matches_requests(&rule.to, request)
        && matches_conditions(&rule.when, request)
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
    if let Some(pattern) = match_.spiffe_id_pattern.as_ref()
        && !wildcard_match(pattern, source.as_str())
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

fn matches_requests(matches: &[RequestMatch], request: &MeshAuthzRequest) -> bool {
    if matches.is_empty() {
        return true;
    }
    matches.iter().any(|match_| request_match(match_, request))
}

fn request_match(match_: &RequestMatch, request: &MeshAuthzRequest) -> bool {
    if !match_.methods.is_empty()
        && !request.method.as_ref().is_some_and(|method| {
            match_
                .methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
        })
    {
        return false;
    }
    // HTTP-only negative predicates (`not_methods`, `not_paths`, `not_hosts`)
    // fail the match when the corresponding HTTP attribute is absent. This
    // mirrors how the positive `methods`/`paths`/`hosts` checks above behave
    // for the same case (e.g. raw-TCP `on_stream_connect`, which only carries
    // a port) — without this, an ALLOW rule that mentions an HTTP-only field
    // would over-permissively match non-HTTP traffic that should fall through
    // to implicit deny.
    if !match_.not_methods.is_empty() {
        let Some(method) = request.method.as_ref() else {
            return false;
        };
        if match_
            .not_methods
            .iter()
            .any(|denied| denied.eq_ignore_ascii_case(method))
        {
            return false;
        }
    }
    if !match_.paths.is_empty()
        && !request.path.as_ref().is_some_and(|path| {
            match_
                .paths
                .iter()
                .any(|pattern| wildcard_match(pattern, path))
        })
    {
        return false;
    }
    if !match_.not_paths.is_empty() {
        let Some(path) = request.path.as_ref() else {
            return false;
        };
        if match_
            .not_paths
            .iter()
            .any(|pattern| wildcard_match(pattern, path))
        {
            return false;
        }
    }
    let normalized_host = request.host.as_deref().and_then(normalize_match_host);
    if !match_.hosts.is_empty()
        && !normalized_host.as_ref().is_some_and(|host| {
            match_
                .hosts
                .iter()
                .any(|pattern| normalized_host_matches(pattern, host))
        })
    {
        return false;
    }
    if !match_.not_hosts.is_empty() {
        let Some(host) = normalized_host.as_ref() else {
            return false;
        };
        if match_
            .not_hosts
            .iter()
            .any(|pattern| normalized_host_matches(pattern, host))
        {
            return false;
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
    if !match_.not_ports.is_empty()
        && request
            .port
            .is_some_and(|port| match_.not_ports.contains(&port))
    {
        return false;
    }
    for (name, pattern) in &match_.headers {
        let Some(value) = request_header_value(&request.headers, name) else {
            return false;
        };
        if !wildcard_match(pattern, value) {
            return false;
        }
    }
    true
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
    // SAFETY: only ASCII digits written above, which are valid UTF-8.
    std::str::from_utf8(&buf[idx..]).expect("ASCII digits are valid UTF-8")
}

fn normalize_hostname(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn is_valid_authority_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

fn matches_conditions(matches: &[ConditionMatch], request: &MeshAuthzRequest) -> bool {
    matches.iter().all(|match_| {
        let value = request.attributes.get(&match_.key).map(String::as_str);
        if !match_.values.is_empty()
            && !value.is_some_and(|value| match_.values.iter().any(|v| v == value))
        {
            return false;
        }
        if !match_.not_values.is_empty()
            && value.is_some_and(|value| match_.not_values.iter().any(|v| v == value))
        {
            return false;
        }
        true
    })
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
        ConditionMatch, MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch,
        RequestMatch, WorkloadSelector,
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
                never_matches: false,
            }],
        };

        normalize_mesh_policy_header_names(&mut policy);

        assert!(mesh_policy_has_header_rules(&policy));
        assert!(policy.rules[0].to[0].headers.contains_key("x-tenant"));
        assert!(!policy.rules[0].to[0].headers.contains_key("X-Tenant"));
    }

    #[test]
    fn normalize_mesh_policy_header_names_preserves_conflicting_case_collisions() {
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
                never_matches: false,
            }],
        };

        normalize_mesh_policy_header_names(&mut policy);

        assert_eq!(policy.rules[0].to[0].headers.len(), 2);
        assert!(policy.rules[0].to[0].headers.contains_key("X-Tenant"));
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
    fn trust_domain_mismatch_rejects() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-prod",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: None,
                    namespace_pattern: None,
                    trust_domain: Some(TrustDomain::new("prod.local").unwrap()),
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
                    },
                    PrincipalMatch {
                        spiffe_id_pattern: Some(
                            "spiffe://cluster.local/ns/default/sa/client".into(),
                        ),
                        namespace_pattern: None,
                        trust_domain: None,
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
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let mut attrs_east = BTreeMap::new();
        attrs_east.insert(
            "request.auth.claims[region]".to_string(),
            "us-east-1".to_string(),
        );
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_east,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
        );

        let mut attrs_west = BTreeMap::new();
        attrs_west.insert(
            "request.auth.claims[region]".to_string(),
            "eu-west-1".to_string(),
        );
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_west,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
        );

        let mut attrs_other = BTreeMap::new();
        attrs_other.insert(
            "request.auth.claims[region]".to_string(),
            "ap-south-1".to_string(),
        );
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_other,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
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
                    never_matches: false,
                    action: PolicyAction::Deny,
                }],
            }],
            ..MeshSlice::default()
        };

        // Attribute matches not_values: rule does NOT match (condition fails).
        let mut attrs_internal = BTreeMap::new();
        attrs_internal.insert("source.namespace".to_string(), "internal".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_internal,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
        );

        // Attribute does not match not_values: condition passes, DENY fires.
        let mut attrs_external = BTreeMap::new();
        attrs_external.insert("source.namespace".to_string(), "external".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_external,
                    ..MeshAuthzRequest::default()
                }
            ),
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
                        key: "env".to_string(),
                        values: vec!["prod".to_string(), "staging".to_string(), "dev".to_string()],
                        not_values: vec!["staging".to_string()],
                    }],
                    request_principals: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // "prod" is in values, not in not_values: match.
        let mut attrs_prod = BTreeMap::new();
        attrs_prod.insert("env".to_string(), "prod".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_prod,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
        );

        // "staging" is in both: not_values blocks it.
        let mut attrs_staging = BTreeMap::new();
        attrs_staging.insert("env".to_string(), "staging".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_staging,
                    ..MeshAuthzRequest::default()
                }
            ),
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
                        key: "some.key".to_string(),
                        values: vec!["required".to_string()],
                        not_values: Vec::new(),
                    }],
                    request_principals: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // No attributes at all.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: BTreeMap::new(),
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn condition_missing_attribute_passes_not_values_check() {
        // If the attribute key is absent, `not_values` check passes because
        // `value.is_some_and(...)` returns false.
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-not-blocked".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: vec![ConditionMatch {
                        key: "blocked.key".to_string(),
                        values: Vec::new(),
                        not_values: vec!["bad".to_string()],
                    }],
                    request_principals: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // Key absent: not_values does not trigger, condition passes.
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: BTreeMap::new(),
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
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
                            key: "env".to_string(),
                            values: vec!["prod".to_string()],
                            not_values: Vec::new(),
                        },
                        ConditionMatch {
                            key: "region".to_string(),
                            values: vec!["us-east-1".to_string()],
                            not_values: Vec::new(),
                        },
                    ],
                    request_principals: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        // Both conditions met.
        let mut attrs_both = BTreeMap::new();
        attrs_both.insert("env".to_string(), "prod".to_string());
        attrs_both.insert("region".to_string(), "us-east-1".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_both,
                    ..MeshAuthzRequest::default()
                }
            ),
            MeshAuthzDecision::Allow
        );

        // Only one condition met.
        let mut attrs_one = BTreeMap::new();
        attrs_one.insert("env".to_string(), "prod".to_string());
        attrs_one.insert("region".to_string(), "eu-west-1".to_string());
        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &MeshAuthzRequest {
                    attributes: attrs_one,
                    ..MeshAuthzRequest::default()
                }
            ),
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

    fn allow_policy_with_request_match(name: &str, request: RequestMatch) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![request],
                when: Vec::new(),
                request_principals: Vec::new(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }
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
}
