//! Integration coverage for `AuthorizationPolicy` negative-match fields
//! (`notMethods`, `notPaths`, `notHosts`, `notPorts`).
//!
//! Exercises the canonical Istio scenario end-to-end through the
//! `mesh_authz` plugin: an ALLOW policy that combines a positive `methods`
//! match with a negative `notPaths` match — the resulting rule must
//! authorise GET /api but deny BOTH GET /admin (negative match fires) AND
//! POST /admin (positive method match fails).
//!
//! This is the same scenario covered by inline policy.rs and istio.rs
//! tests; this integration test additionally drives it through the plugin
//! surface (`MeshAuthz::authorize`) so the wiring between the JSON
//! plugin-config schema, the policy evaluator, and the plugin's reject
//! semantics is validated together.
use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    ConditionMatch, MeshPolicy, MeshRule, ParsedCidr, PolicyAction, PolicyScope, PrincipalMatch,
    RequestMatch, SourceNegationMatch, WorkloadSelector,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, StreamConnectionContext};
use serde_json::json;

/// A raw Layer-4 session: no HTTP request, and therefore no header map at all.
fn stream_context() -> StreamConnectionContext {
    StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        None,
        15443,
        BackendScheme::Tcps,
        Arc::new(ConsumerIndex::new(&[])),
    )
}

fn policy_allow_get_except_admin() -> MeshPolicy {
    MeshPolicy {
        name: "allow-get-except-admin".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".to_string()],
                not_paths: vec!["/admin/*".to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

fn request_context(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.peer_spiffe_id = Some(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("valid spiffe id"),
    );
    ctx
}

fn policy_allow_example_except_admin_mixed_case_not_host() -> MeshPolicy {
    MeshPolicy {
        name: "allow-example-except-admin".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                hosts: vec!["*.example.com".to_string()],
                not_hosts: vec!["Admin.Example.COM.".to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_authorizes_get_to_non_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/api/items");

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "GET /api should be allowed (positive method match + negative path mismatch), got {result:?}"
    );
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_get_to_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/admin/users");

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "GET /admin should be rejected (negative path match → rule fails → \
             implicit deny), got {other:?}"
        ),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_post_to_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("POST", "/admin/users");

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "POST /admin should be rejected (positive method does not match GET \
             → rule fails → implicit deny), got {other:?}"
        ),
    }
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_post_to_non_admin_path() {
    // Sanity: POST /api also fails because the positive method=GET predicate
    // does not match POST. This is independent of the negative-match logic
    // but locks in conjunctive-AND semantics across positive + negative.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("POST", "/api/items");

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "POST /api should fall through to implicit-deny, got {result:?}"
    );
}

#[tokio::test]
async fn direct_plugin_config_normalizes_not_hosts() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_example_except_admin_mixed_case_not_host()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/api/items");
    ctx.headers
        .insert("host".to_string(), "admin.example.com".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "admin.example.com should be denied because mixed-case/trailing-dot not_hosts must normalize, got {result:?}"
    );
}

// ── `when:` condition enforcement (previously fail-open) ──────────────────

fn deny_when_source_namespace(namespace: &str) -> MeshPolicy {
    MeshPolicy {
        name: "deny-source-namespace".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            when: vec![ConditionMatch {
                key: "source.namespace".to_string(),
                values: vec![namespace.to_string()],
                not_values: Vec::new(),
            }],
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

#[tokio::test]
async fn deny_gated_on_when_source_namespace_now_fires_through_plugin() {
    // Regression: `when:` conditions were inert because both authz entry
    // points hard-coded empty attributes. A DENY gated on the source
    // namespace must now actually deny a caller from that namespace.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [deny_when_source_namespace("prod")]
    }))
    .expect("plugin config");

    // Caller SPIFFE id encodes ns/prod → source.namespace = "prod" → DENY.
    let mut prod_ctx = request_context("GET", "/api");
    prod_ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/prod/sa/client").expect("spiffe"));
    let prod_result = plugin.authorize(&mut prod_ctx).await;
    assert!(
        matches!(
            prod_result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "caller in ns/prod must be denied by when-gated DENY, got {prod_result:?}"
    );

    // Caller in a different namespace is not denied (DENY does not fire, and
    // with no ALLOW policy the default decision is allow).
    let mut staging_ctx = request_context("GET", "/api");
    staging_ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/staging/sa/client").expect("spiffe"));
    let staging_result = plugin.authorize(&mut staging_ctx).await;
    assert!(
        matches!(staging_result, PluginResult::Continue),
        "caller in ns/staging must not be denied, got {staging_result:?}"
    );
}

#[tokio::test]
async fn allow_with_not_namespaces_enforced_through_plugin() {
    // ALLOW gated by a source `notNamespaces` matcher: callers in the listed
    // namespace fall through to implicit deny; others are admitted.
    let allow = MeshPolicy {
        name: "allow-except-kube-system".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                not_namespace_patterns: vec!["kube-system".to_string()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [allow] })).expect("plugin config");

    let mut blocked = request_context("GET", "/api");
    blocked.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/kube-system/sa/probe").expect("spiffe"));
    assert!(
        matches!(
            plugin.authorize(&mut blocked).await,
            PluginResult::Reject { .. }
        ),
        "kube-system caller must be denied by notNamespaces"
    );

    let mut allowed = request_context("GET", "/api");
    allowed.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    assert!(
        matches!(plugin.authorize(&mut allowed).await, PluginResult::Continue),
        "default-namespace caller must be allowed"
    );
}

#[tokio::test]
async fn allow_with_remote_ip_blocks_enforced_through_plugin() {
    // ALLOW gated by a source `remoteIpBlocks` matcher resolved from the
    // gateway-computed client IP. In-range clients are admitted; others fall
    // through to implicit deny.
    let allow = MeshPolicy {
        name: "allow-from-corp-range".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                remote_ip_blocks: vec![ParsedCidr::parse("203.0.113.0/24").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [allow] })).expect("plugin config");

    let mut in_range = RequestContext::new(
        "203.0.113.45".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    in_range.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    assert!(
        matches!(
            plugin.authorize(&mut in_range).await,
            PluginResult::Continue
        ),
        "client in 203.0.113.0/24 must be allowed"
    );

    let mut out_of_range = RequestContext::new(
        "198.51.100.7".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    out_of_range.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    assert!(
        matches!(
            plugin.authorize(&mut out_of_range).await,
            PluginResult::Reject { .. }
        ),
        "client outside 203.0.113.0/24 must be denied"
    );
}

#[tokio::test]
async fn source_ip_blocks_use_direct_peer_not_forwarded_client_ip() {
    let allow_source = MeshPolicy {
        name: "allow-direct-peer-range".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                ip_blocks: vec![ParsedCidr::parse("10.0.0.0/8").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin =
        MeshAuthz::new(&json!({ "mesh_policies": [allow_source] })).expect("plugin config");

    let mut ctx = RequestContext::new(
        "10.1.2.3".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    ctx.client_ip = "203.0.113.45".to_string();

    assert!(
        matches!(plugin.authorize(&mut ctx).await, PluginResult::Continue),
        "source.ip must be the direct socket peer, not the XFF-resolved remote.ip"
    );

    let deny_forwarded_as_source = MeshPolicy {
        name: "allow-forwarded-range-as-source".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                ip_blocks: vec![ParsedCidr::parse("203.0.113.0/24").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [deny_forwarded_as_source] }))
        .expect("plugin config");
    let mut ctx = RequestContext::new(
        "10.1.2.3".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe"));
    ctx.client_ip = "203.0.113.45".to_string();

    assert!(
        matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Reject { .. }
        ),
        "forwarded remote.ip must not satisfy source.ip ipBlocks"
    );
}

fn policy_allow_except_8_prefix_ports() -> MeshPolicy {
    MeshPolicy {
        name: "allow-except-8-prefix".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".to_string()],
                not_port_patterns: vec!["8*".to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

fn http_ctx_with_port(method: &str, path: &str, port: Option<u16>) -> RequestContext {
    let mut ctx = request_context(method, path);
    ctx.frontend_listen_port = port;
    ctx
}

#[tokio::test]
async fn allow_with_not_port_patterns_admits_non_matching_listener_port() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_except_8_prefix_ports()]
    }))
    .expect("plugin config");
    let mut ctx = http_ctx_with_port("GET", "/api", Some(9090));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "GET on 9090 should be allowed (outside notPorts 8*), got {result:?}"
    );
}

#[tokio::test]
async fn allow_with_not_port_patterns_denies_matching_listener_port() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_except_8_prefix_ports()]
    }))
    .expect("plugin config");
    let mut ctx = http_ctx_with_port("GET", "/api", Some(8080));

    let result = plugin.authorize(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => {
            panic!("GET on 8080 should be rejected by notPorts 8* → implicit deny, got {other:?}")
        }
    }
}

#[tokio::test]
async fn allow_with_not_port_patterns_fails_closed_when_listener_port_absent() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_except_8_prefix_ports()]
    }))
    .expect("plugin config");
    let mut ctx = http_ctx_with_port("GET", "/api", None);

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "absent destination/listener port must fail closed for notPorts patterns, got {result:?}"
    );
}

#[tokio::test]
async fn allow_with_ports_and_not_port_patterns_stays_conjunctive() {
    let policy = MeshPolicy {
        name: "allow-9xxx-except-90-prefix".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                ports: vec![9180, 9090],
                not_port_patterns: vec!["90*".to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [policy] })).expect("plugin config");

    let mut allowed = http_ctx_with_port("GET", "/api", Some(9180));
    assert!(
        matches!(plugin.authorize(&mut allowed).await, PluginResult::Continue),
        "9180 is in ports and outside notPorts 90*"
    );

    let mut blocked_negative = http_ctx_with_port("GET", "/api", Some(9090));
    assert!(
        matches!(
            plugin.authorize(&mut blocked_negative).await,
            PluginResult::Reject { .. }
        ),
        "9090 matches both ports and notPorts 90* → conjunctive fail"
    );

    let mut blocked_positive = http_ctx_with_port("GET", "/api", Some(8080));
    assert!(
        matches!(
            plugin.authorize(&mut blocked_positive).await,
            PluginResult::Reject { .. }
        ),
        "8080 is outside positive ports → implicit deny"
    );
}

// ── `to.headers` present / non-matching / absent parity (issue #5067) ──────
//
// Istio's "an HTTP-only field is always matched" rule is about an attribute the
// path cannot SOURCE, not one it read and found absent. On an HTTP-family
// request Ferrum has parsed the header map, so a header the client did not send
// is genuinely absent and must fail a positive predicate for EVERY action —
// exactly what the sibling `when: request.headers[...]` condition has always
// done, and what Envoy's `HeaderMatcher` specifies. On an L4 session there is
// no header map at all, so the fail-closed DENY/CUSTOM behaviour is preserved.

fn header_scoped_policy(name: &str, action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            to: vec![RequestMatch {
                headers: HashMap::from([("x-mode".to_string(), "blocked".to_string())]),
                ..RequestMatch::default()
            }],
            action,
            ..MeshRule::default()
        }],
    }
}

fn header_condition_policy(name: &str, action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            when: vec![ConditionMatch {
                key: "request.headers[x-mode]".to_string(),
                values: vec!["blocked".to_string()],
                not_values: Vec::new(),
            }],
            action,
            ..MeshRule::default()
        }],
    }
}

fn header_ctx(value: Option<&str>) -> RequestContext {
    let mut ctx = request_context("GET", "/ordinary");
    if let Some(value) = value {
        ctx.headers.insert("x-mode".to_string(), value.to_string());
    }
    ctx
}

fn custom_action() -> PolicyAction {
    PolicyAction::Custom {
        provider: "ext-authz".to_string(),
    }
}

/// A DENY scoped by `to.headers` refuses only requests that CARRY the header
/// with a matching value. `to.headers` and the equivalent `when` condition
/// agree on all three inputs.
#[tokio::test]
async fn http_deny_header_predicate_matches_only_a_present_matching_header() {
    let deny = PolicyAction::Deny;
    for (label, policy) in [
        ("to.headers", header_scoped_policy("header", deny.clone())),
        ("when", header_condition_policy("header", deny.clone())),
    ] {
        let plugin = MeshAuthz::new(&json!({ "mesh_policies": [policy] })).expect("plugin config");

        let mut matching = header_ctx(Some("blocked"));
        let result = plugin.authorize(&mut matching).await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "{label}: a present, matching header must be denied, got {result:?}"
        );

        let mut non_matching = header_ctx(Some("normal"));
        let result = plugin.authorize(&mut non_matching).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{label}: a present, non-matching header must not be denied, got {result:?}"
        );

        let mut absent = header_ctx(None);
        let result = plugin.authorize(&mut absent).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{label}: an ABSENT header on HTTP is not unsourceable and must not satisfy a \
             positive DENY predicate, got {result:?}"
        );
    }
}

/// The ALLOW side is unchanged: an absent header still fails the predicate, and
/// the implicit-deny floor then refuses the request.
#[tokio::test]
async fn http_allow_header_predicate_still_fails_closed_on_an_absent_header() {
    let allow = PolicyAction::Allow;
    for (label, policy) in [
        ("to.headers", header_scoped_policy("header", allow.clone())),
        ("when", header_condition_policy("header", allow.clone())),
    ] {
        let plugin = MeshAuthz::new(&json!({ "mesh_policies": [policy] })).expect("plugin config");

        let mut matching = header_ctx(Some("blocked"));
        let result = plugin.authorize(&mut matching).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{label}: a present, matching header must be allowed, got {result:?}"
        );

        for (case, value) in [("non-matching", Some("normal")), ("absent", None)] {
            let mut ctx = header_ctx(value);
            let result = plugin.authorize(&mut ctx).await;
            assert!(
                matches!(result, PluginResult::Reject { .. }),
                "{label}: a {case} header must not satisfy an ALLOW, so implicit deny applies"
            );
        }
    }
}

/// A CUSTOM rule shares the same request matcher. Its delegation is
/// unexecutable in a direct `mesh_policies` config (no provider source), so a
/// matched rule DENIES — which makes it an exact probe for whether the header
/// predicate matched.
#[tokio::test]
async fn http_custom_header_predicate_is_not_delegated_on_an_absent_header() {
    let policy = header_scoped_policy("delegate", custom_action());
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [policy] })).expect("plugin config");

    let mut matching = header_ctx(Some("blocked"));
    let result = plugin.authorize(&mut matching).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "a matched CUSTOM delegation with no executor denies, got {result:?}"
    );

    for (case, value) in [("non-matching", Some("normal")), ("absent", None)] {
        let mut ctx = header_ctx(value);
        let result = plugin.authorize(&mut ctx).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "a {case} header must not select the CUSTOM rule on HTTP, got {result:?}"
        );
    }
}

/// The L4 side is UNCHANGED and still fails closed: a raw stream has no header
/// map, so the predicate is unsourceable and Istio's non-HTTP-port model
/// applies — DENY (and CUSTOM) ignore it and still match.
#[tokio::test]
async fn l4_deny_header_predicate_still_matches_a_session_with_no_header_map() {
    for action in [PolicyAction::Deny, custom_action()] {
        let policy = header_scoped_policy("header", action.clone());
        let plugin = MeshAuthz::new(&json!({ "mesh_policies": [policy] })).expect("plugin config");

        let mut ctx = stream_context();
        let result = plugin.on_stream_connect(&mut ctx).await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "{action:?}: an unsourceable header predicate must not disarm an L4 refusal"
        );
    }
}

/// An L4 ALLOW carrying a header predicate can never match, so the implicit
/// deny floor still refuses the session.
#[tokio::test]
async fn l4_allow_header_predicate_can_never_match_a_session_with_no_header_map() {
    let policy = header_scoped_policy("header", PolicyAction::Allow);
    let plugin = MeshAuthz::new(&json!({ "mesh_policies": [policy] })).expect("plugin config");

    let mut ctx = stream_context();
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "an ALLOW is never granted on an attribute the L4 path cannot read"
    );
}
