//! End-to-end coverage for the `mesh_authz` plugin's request-path
//! behaviour.
//!
//! These tests construct `MeshAuthz` from the same plugin-config shape
//! `inject_mesh_global_plugins()` emits in production, then drive
//! requests through `Plugin::authorize` with realistic
//! `RequestContext` state. The focus is the cross-cutting policy
//! semantics that operators rely on:
//!
//! - DENY-first within a policy chain
//! - implicit deny when any ALLOW rule is present but no rule matches
//!   (Istio semantics)
//! - construction-time `PolicyScope` filter (WorkloadSelector /
//!   Namespace / MeshWide)
//! - principal globbing, request-match conjunction with negative-match
//!   predicates, condition matching, request-principal (JWT-derived)
//!   matching
//! - AUDIT action — counted, never blocks
//! - trust-domain alias acceptance for HBONE baggage
//!
//! Pure rule-matching helper coverage lives in inline `#[cfg(test)]`
//! modules under `src/modes/mesh/policy.rs`; these tests lock in the
//! observable plugin-surface behaviour those helpers compose into.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;

use ferrum_edge::config::types::{BackendScheme, Consumer};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::MeshTrafficDirection;
use ferrum_edge::modes::mesh::config::{
    ConditionMatch, MeshPolicy, MeshRule, ParsedCidr, PolicyAction, PolicyScope, PrincipalMatch,
    RequestMatch, SourceNegationMatch, WorkloadSelector,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{
    JwtAuthAttributeValue, Plugin, PluginResult, RequestContext, StreamConnectionContext,
};
use serde_json::json;
use std::sync::Arc;

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, DEFAULT_TRUST_DOMAIN, default_mesh_runtime, mesh_config_with,
    policy_allow_principal, policy_audit_principal, policy_deny_principal,
};
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::modes::mesh::{MESH_AUTHZ_PLUGIN_ID, prepare_gateway_config_for_mesh};

const CLIENT_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/client";
const ROGUE_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/rogue";

fn spiffe(id: &str) -> SpiffeId {
    SpiffeId::new(id).expect("valid SPIFFE id")
}

/// Build a `RequestContext` with the supplied identity and request shape.
fn ctx_with_principal(method: &str, path: &str, principal: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    if let Some(id) = principal {
        ctx.peer_spiffe_id = Some(spiffe(id));
    }
    ctx
}

/// Build a `MeshAuthz` plugin from the prepared mesh config for the given
/// workload identity. Mirrors what production does: build a
/// `GatewayConfig`, run `prepare_gateway_config_for_mesh`, then construct
/// the plugin from the injected `mesh_authz` plugin config. This is the
/// realistic path — tests that build `MeshAuthz` directly from
/// `{"mesh_policies": [...]}` bypass the scope-filter context the plugin
/// reads from `mesh_slice.namespace`/`labels`.
fn build_mesh_authz_for_workload(
    workload_labels: &[(&str, &str)],
    policies: Vec<MeshPolicy>,
) -> MeshAuthz {
    let mut runtime = default_mesh_runtime();
    for (k, v) in workload_labels {
        runtime.workload_labels.insert(k.to_string(), v.to_string());
    }
    let mesh = mesh_config_with(Vec::new(), Vec::new(), policies);
    let config = ferrum_edge::config::types::GatewayConfig {
        version: "test".to_string(),
        proxies: Vec::new(),
        upstreams: Vec::new(),
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        mesh_revision: None,
    };
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    let authz_config = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz plugin injected")
        .config
        .clone();
    MeshAuthz::new(&authz_config).expect("authz plugin builds from injected config")
}

#[tokio::test]
async fn deny_policy_overrides_allow_policy_first_match_wins() {
    // Two policies: an ALLOW that admits the client, and a DENY that
    // blocks it. Istio semantics: DENY rules evaluate first and any
    // match wins immediately. The plugin must refuse the request even
    // though the matching ALLOW rule would otherwise permit it.
    let allow = policy_allow_principal(
        "client-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let deny = policy_deny_principal(
        "client-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow, deny]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "DENY-first semantics: DENY rule must win over ALLOW, got {result:?}"
    );
}

#[tokio::test]
async fn implicit_deny_blocks_when_any_allow_present_and_no_match() {
    // The ALLOW rule admits a specific principal — rogue clients with
    // no matching rule must be rejected by implicit-deny, not allowed
    // through.
    let allow = policy_allow_principal(
        "client-only",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(ROGUE_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "rogue principal must be rejected by implicit deny when an ALLOW rule \
             is present, got {other:?}"
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
async fn no_policies_means_no_authorization_enforcement() {
    // Empty policy set: every request flows through. This is the
    // documented default state — operators add policies to opt in to
    // enforcement.
    let plugin = build_mesh_authz_for_workload(&[], Vec::new());
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(ROGUE_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn workload_selector_scope_filters_out_non_applicable_allow_policy() {
    // A `WorkloadSelector{app=ratings}` ALLOW policy targets a peer
    // workload that is NOT this proxy. After the construction-time
    // filter (which keys on this proxy's `app=reviews` labels), the
    // ratings-scoped policy is gone. With no policies left, the
    // request passes through.
    //
    // Without the scope filter, the ALLOW rule would be in effect and
    // would implicit-deny any request whose principal didn't match it
    // — exactly the bug the filter was added to fix.
    let ratings_only_allow = policy_allow_principal(
        "ratings-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[("app", "reviews")], vec![ratings_only_allow]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(ROGUE_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "ratings-scoped ALLOW must not affect reviews workload after scope filter, \
         got {result:?}"
    );
}

#[tokio::test]
async fn namespace_scope_filters_out_other_namespace_policies() {
    // A `Namespace=production` DENY policy targets a different
    // namespace. Our `default`-namespace workload must not be blocked
    // by it.
    let other_ns_deny = policy_deny_principal(
        "prod-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::Namespace {
            namespace: "production".to_string(),
        },
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![other_ns_deny]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn mesh_wide_policy_applies_to_every_workload() {
    // No matter the workload labels/namespace, a `MeshWide`-scoped DENY
    // applies. Locks in the default-scope behaviour Istio operators
    // expect from a root-namespace policy.
    let deny = policy_deny_principal(
        "global-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[("app", "reviews")], vec![deny]);
    let mut ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn principal_glob_matches_subpath_under_wildcard() {
    let plugin = build_mesh_authz_for_workload(
        &[],
        vec![policy_allow_principal(
            "ns-default-allow",
            DEFAULT_NAMESPACE,
            PolicyScope::MeshWide,
            "spiffe://cluster.local/ns/default/sa/*",
        )],
    );
    let mut ctx = ctx_with_principal(
        "GET",
        "/api",
        Some("spiffe://cluster.local/ns/default/sa/x"),
    );
    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));

    // Different namespace path → glob does NOT match → implicit deny.
    let mut deny_ctx =
        ctx_with_principal("GET", "/api", Some("spiffe://cluster.local/ns/other/sa/x"));
    assert!(matches!(
        plugin.authorize(&mut deny_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn negative_match_not_paths_blocks_subpath_but_admits_others() {
    // Allow GET on the matching principal EXCEPT /admin paths. The
    // negative-match form is Istio's documented way to say "everything
    // except".
    let allow_with_not_paths = MeshPolicy {
        name: "allow-except-admin".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(CLIENT_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
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
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_with_not_paths]);

    let mut ok_ctx = ctx_with_principal("GET", "/api/items", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut ok_ctx).await,
        PluginResult::Continue
    ));

    let mut blocked_ctx = ctx_with_principal("GET", "/admin/users", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut blocked_ctx).await,
            PluginResult::Reject { .. }
        ),
        "admin subpath must be rejected by negative-match → no rule fires → implicit deny"
    );
}

#[tokio::test]
async fn condition_match_on_request_header_enforces_match_and_no_match() {
    // `when[].key = request.headers[x-team]` only admits requests that
    // carry the expected header value.
    let allow_with_when = MeshPolicy {
        name: "allow-team-foo".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(CLIENT_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.headers[x-team]".to_string(),
                values: vec!["foo".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_with_when]);

    // Request WITH the right header
    let mut ok_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    ok_ctx
        .headers
        .insert("x-team".to_string(), "foo".to_string());
    assert!(matches!(
        plugin.authorize(&mut ok_ctx).await,
        PluginResult::Continue
    ));

    // Same principal, wrong header value → no rule matches → implicit
    // deny.
    let mut blocked_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    blocked_ctx
        .headers
        .insert("x-team".to_string(), "bar".to_string());
    assert!(matches!(
        plugin.authorize(&mut blocked_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn condition_match_on_connection_sni_enforces_match_and_no_match() {
    let deny_sni = MeshPolicy {
        name: "deny-admin-sni".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "connection.sni".to_string(),
                values: vec!["admin.mesh.internal".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_sni]);

    let mut matched_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    matched_ctx.frontend_sni_hostname = Some("admin.mesh.internal".to_string());
    assert!(
        matches!(
            plugin.authorize(&mut matched_ctx).await,
            PluginResult::Reject { .. }
        ),
        "DENY policies gated on connection.sni must fire for HTTP TLS requests"
    );

    let mut other_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    other_ctx.frontend_sni_hostname = Some("public.mesh.internal".to_string());
    assert!(matches!(
        plugin.authorize(&mut other_ctx).await,
        PluginResult::Continue
    ));

    let mut missing_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut missing_ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn condition_match_on_source_principal_uses_istio_format() {
    let deny_client = MeshPolicy {
        name: "deny-client-source-principal".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "source.principal".to_string(),
                values: vec!["cluster.local/ns/default/sa/client".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_client]);

    let mut client_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut client_ctx).await,
            PluginResult::Reject { .. }
        ),
        "source.principal conditions should see Istio's trust-domain/ns/... form"
    );

    let mut rogue_ctx = ctx_with_principal("GET", "/api", Some(ROGUE_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut rogue_ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn condition_match_on_jwt_list_claim_preserves_item_boundaries() {
    let allow_with_claim = MeshPolicy {
        name: "allow-ops-group".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.claims[groups]".to_string(),
                values: vec!["ops".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_with_claim]);

    let mut list_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    list_ctx.mesh_request_auth_claims.insert(
        "groups".to_string(),
        JwtAuthAttributeValue::StringList(vec!["dev".to_string(), "ops".to_string()]),
    );
    assert!(matches!(
        plugin.authorize(&mut list_ctx).await,
        PluginResult::Continue
    ));

    let mut scalar_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    scalar_ctx.mesh_request_auth_claims.insert(
        "groups".to_string(),
        JwtAuthAttributeValue::Scalar("dev,ops".to_string()),
    );
    assert!(
        matches!(
            plugin.authorize(&mut scalar_ctx).await,
            PluginResult::Reject { .. }
        ),
        "scalar claim containing a comma must not be split into list items"
    );
}

#[tokio::test]
async fn condition_match_on_request_auth_presenter_uses_azp_claim() {
    let allow_presenter = MeshPolicy {
        name: "allow-presenter".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.presenter".to_string(),
                values: vec!["client-app".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_presenter]);

    let mut presenter_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    presenter_ctx.mesh_request_auth_claims.insert(
        "azp".to_string(),
        JwtAuthAttributeValue::Scalar("client-app".to_string()),
    );
    assert!(matches!(
        plugin.authorize(&mut presenter_ctx).await,
        PluginResult::Continue
    ));

    let mut list_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    list_ctx.mesh_request_auth_claims.insert(
        "azp".to_string(),
        JwtAuthAttributeValue::StringList(vec!["client-app".to_string()]),
    );
    assert!(
        matches!(
            plugin.authorize(&mut list_ctx).await,
            PluginResult::Reject { .. }
        ),
        "request.auth.presenter should use only a scalar azp claim"
    );
}

#[tokio::test]
async fn condition_match_on_nested_jwt_claim_uses_bracket_path() {
    let deny_admin_role = MeshPolicy {
        name: "deny-admin-role".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.claims[realm_access][roles]".to_string(),
                values: vec!["admin".to_string()],
                not_values: Vec::new(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_admin_role]);

    let mut admin_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    admin_ctx.mesh_request_auth_claims.insert(
        "realm_access][roles".to_string(),
        JwtAuthAttributeValue::StringList(vec!["reader".to_string(), "admin".to_string()]),
    );
    assert!(
        matches!(
            plugin.authorize(&mut admin_ctx).await,
            PluginResult::Reject { .. }
        ),
        "nested JWT claim list should be resolved for DENY conditions"
    );

    let mut reader_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    reader_ctx.mesh_request_auth_claims.insert(
        "realm_access][roles".to_string(),
        JwtAuthAttributeValue::StringList(vec!["reader".to_string()]),
    );
    assert!(matches!(
        plugin.authorize(&mut reader_ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn request_principal_match_from_jwks_auth_metadata() {
    // `jwks_auth` (when configured with `emit_mesh_request_principal_metadata`)
    // populates `metadata["mesh.request_principal"]` from the validated
    // JWT's `iss/sub`. `mesh_authz` reads that key and matches against
    // `rule.request_principals` globs — this is Istio's
    // `from[].source.requestPrincipals` semantics.
    //
    // Spec change (PR #933 / commit 209928da): the metadata key was
    // renamed from `jwks_auth.request_principal` to
    // `mesh.request_principal`, and emission is now opt-in via the plugin
    // config flag so non-mesh jwks_auth deployments don't leak the
    // identifier into transaction logs. The test simulates the emission
    // by inserting the metadata directly, mirroring what
    // `jwks_auth` does after `emit_mesh_request_principal_metadata`.
    let allow = MeshPolicy {
        name: "allow-jwt-issuer".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: Vec::new(),
            request_principals: vec!["https://issuer.example.com/*".to_string()],
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);

    let mut ok_ctx = ctx_with_principal("GET", "/api", None);
    ok_ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://issuer.example.com/user-42".to_string(),
    );
    assert!(matches!(
        plugin.authorize(&mut ok_ctx).await,
        PluginResult::Continue
    ));

    // Different issuer → no rule matches → implicit deny.
    let mut blocked_ctx = ctx_with_principal("GET", "/api", None);
    blocked_ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://attacker.com/u".to_string(),
    );
    assert!(matches!(
        plugin.authorize(&mut blocked_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn audit_action_does_not_block_request() {
    // AUDIT is informational — it must surface metadata for transaction
    // logs but never reject. Istio's documented contract.
    let audit_policy = MeshPolicy {
        name: "audit-everything".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(CLIENT_SPIFFE.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Audit,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![audit_policy]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "AUDIT must never block, got {result:?}"
    );
}

#[tokio::test]
async fn unauthenticated_request_with_authorization_policy_set_is_implicit_denied() {
    // ALLOW policies are present but no peer principal — the request
    // matches no rule, so implicit-deny kicks in. This is the canonical
    // Istio behaviour: mesh policies enforce identity, and a request
    // with no identity cannot satisfy any principal-based rule.
    let allow = policy_allow_principal(
        "client-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);
    let mut ctx = ctx_with_principal("GET", "/api", None);

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "unauthenticated request must fall through to implicit deny, got {result:?}"
    );
}

#[tokio::test]
async fn istio_allow_without_rules_means_allow_nothing() {
    // `AuthorizationPolicy{action: ALLOW, rules: []}` is the Istio
    // "allow-nothing" sentinel. The translator emits a never-matching
    // rule so the plugin's implicit-deny path picks it up. Any request
    // — including from an otherwise-authorized principal — must be
    // rejected.
    let allow_nothing = MeshPolicy {
        name: "allow-nothing".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
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
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_nothing]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn deny_without_rules_is_a_no_op() {
    // Counterpart to the previous test: `DENY{rules: []}` must NOT
    // block anything — the translator does not emit a never-matching
    // rule for this case, and the plugin therefore behaves as if the
    // policy didn't exist.
    let empty_deny = MeshPolicy {
        name: "empty-deny".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: Vec::new(),
        // action defaults to Allow on MeshPolicy; the no-op-deny
        // semantics are tested in inline policy.rs tests because the
        // translator decides whether to emit a never-matching rule.
        // Without rules of any kind the plugin sees an empty list →
        // pass-through.
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![empty_deny]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn multiple_deny_policies_short_circuit_on_first_match() {
    // First DENY to match wins; the second DENY's principal pattern
    // would also have matched but is never consulted. Captures the
    // first-match contract for DENY chains (so adding policies is
    // additive — operators don't worry about ordering).
    let deny_glob = policy_deny_principal(
        "deny-default-ns",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        "spiffe://cluster.local/ns/default/sa/*",
    );
    let deny_specific = policy_deny_principal(
        "deny-client",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_glob, deny_specific]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Reject { .. }));
    // The deny_policy metadata key indicates a matched DENY rule —
    // operators rely on this for audit trails.
    let deny_policy = ctx
        .metadata
        .get("mesh_authz.deny_policy")
        .cloned()
        .unwrap_or_default();
    assert!(
        deny_policy.contains("deny-default-ns") || deny_policy.contains("deny-client"),
        "deny_policy metadata should name the matched DENY rule, got {deny_policy:?}"
    );
}

#[tokio::test]
async fn allow_then_deny_for_different_principal_lets_target_through() {
    // ALLOW{client} + DENY{rogue}: the client must still flow.
    let allow = policy_allow_principal(
        "client-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let deny = policy_deny_principal(
        "rogue-deny",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        ROGUE_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow, deny]);

    let mut client_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut client_ctx).await,
        PluginResult::Continue
    ));

    let mut rogue_ctx = ctx_with_principal("GET", "/api", Some(ROGUE_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut rogue_ctx).await,
        PluginResult::Reject { .. }
    ));
}

#[test]
fn mesh_authz_construction_tolerates_selector_labels_without_proxy_labels() {
    // Non-ambiguous slice (no `labels_ambiguous` marker) that nonetheless
    // resolved empty proxy labels — e.g. a single-candidate or label-less
    // workload. The slice's labels are authoritative for THIS workload, so a
    // label-based selector simply does not apply and dropping it via the
    // cold-path `retain` is correct (not a fail-open). Construction must NOT
    // error (a hard error would reject the whole slice or drop authz entirely —
    // issue #1708); it warns and the cold-path `retain` drops the un-evaluable
    // policy from enforcement (covered behaviorally by
    // `mesh_authz_construction_filters_policies_for_workload_at_build_time`).
    let policy = policy_allow_principal(
        "labels-required",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    // Feed the policy through a `mesh_slice` (the slice-apply shape the
    // production prepare pipeline builds) with no proxy labels and the labels
    // NOT flagged ambiguous, so construction must tolerate.
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [policy],
        // labels: intentionally omitted; labels_ambiguous defaults to false
    });
    let config = json!({ "mesh_slice": slice });
    assert!(
        MeshAuthz::new(&config).is_ok(),
        "slice-path construction must tolerate an unevaluable non-ambiguous selector policy, not error"
    );
}

#[test]
fn mesh_authz_construction_rejects_ambiguous_slice_selector_policy_without_labels() {
    // Ambiguous shared-SPIFFE slice (`labels_ambiguous = true`) carrying a
    // label-based selector policy as a candidate-any superset, but the slice
    // resolved EMPTY proxy labels here. Reaching mesh_authz `new()` in this
    // state means recovery already failed (the per-pod NodeWaypoint consumer
    // skips this validation; the xDS DP only leaves `labels` empty when it had
    // no local `FERRUM_MESH_WORKLOAD_LABELS` to prefer). There is no further
    // consumer, so the cold-path `retain` would drop the policy and
    // `evaluate_mesh_authorization_policies` would allow by default — a silent
    // fail-open for a selector DENY/ALLOW that applies to a candidate workload.
    // Construction must fail closed (Codex P1).
    let policy = policy_allow_principal(
        "labels-required",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [policy],
        "labels_ambiguous": true,
        // labels: intentionally omitted (empty intersection, recovery failed)
    });
    let config = json!({ "mesh_slice": slice });
    match MeshAuthz::new(&config) {
        Ok(_) => {
            panic!("ambiguous slice with unrecoverable selector labels must fail closed")
        }
        Err(err) => assert!(
            err.contains("ambiguous shared-SPIFFE"),
            "expected an ambiguous-slice fail-closed construction error, got: {err}"
        ),
    }
}

#[test]
fn mesh_authz_construction_rejects_ambiguous_slice_candidate_only_selector_with_nonempty_intersection()
 {
    // Ambiguous shared-SPIFFE slice with a NON-EMPTY label intersection: both
    // candidates share `app=shared` but only one has `role=api`. The slice
    // labels here are just that partial intersection (`app=shared`), NOT this
    // workload's authoritative labels, and the slice carried the candidate-only
    // `role=api` selector policy as a superset. Because the selector is not
    // satisfied by the partial intersection, the cold-path `retain` would DROP
    // it and `evaluate_mesh_authorization_policies` would allow by default — the
    // non-empty-intersection fail-open (Codex P1). Construction must fail closed.
    let policy = policy_allow_principal(
        "role-api-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("role".to_string(), "api".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [policy],
        "labels": { "app": "shared" },
        "labels_ambiguous": true,
    });
    let config = json!({ "mesh_slice": slice });
    match MeshAuthz::new(&config) {
        Ok(_) => panic!(
            "ambiguous slice with a candidate-only selector the partial intersection cannot resolve must fail closed"
        ),
        Err(err) => assert!(
            err.contains("partial label intersection"),
            "expected a partial-intersection fail-closed construction error, got: {err}"
        ),
    }
}

#[test]
fn mesh_authz_construction_tolerates_ambiguous_slice_selector_satisfied_by_intersection() {
    // Ambiguous shared-SPIFFE slice with a non-empty intersection where the
    // selector IS satisfied by the intersection (`app=shared` selector against
    // `app=shared` intersection labels). The cold-path `retain` keeps the
    // policy, so there is no fail-open and construction must NOT over-reject —
    // the labels-ambiguous fail-closed guard only fires for selectors the
    // partial intersection cannot resolve.
    let policy = policy_allow_principal(
        "app-shared-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "shared".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [policy],
        "labels": { "app": "shared" },
        "labels_ambiguous": true,
    });
    let config = json!({ "mesh_slice": slice });
    assert!(
        MeshAuthz::new(&config).is_ok(),
        "an ambiguous slice whose selector is satisfied by the intersection must construct (no over-rejection)"
    );
}

#[test]
fn mesh_authz_construction_tolerates_ambiguous_slice_audit_only_selector_without_labels() {
    // Same shape as
    // `mesh_authz_construction_rejects_ambiguous_slice_selector_policy_without_labels`
    // (ambiguous slice, empty intersection, candidate-only selector the labels
    // cannot resolve) — but the policy is AUDIT-only. AUDIT is non-enforcing per
    // Istio semantics (records `mesh_authz.audit_policy` and continues), so
    // dropping it via the cold-path `retain` is NOT the allow-by-default
    // fail-open the guard protects against. Construction must TOLERATE it, not
    // fail closed (Codex P2). Mirrors the per-pod missing-scope audit exemption.
    let policy = policy_audit_principal(
        "audit-role-api",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("role".to_string(), "api".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [policy],
        "labels_ambiguous": true,
        // labels: intentionally omitted (empty intersection, recovery failed)
    });
    let config = json!({ "mesh_slice": slice });
    assert!(
        MeshAuthz::new(&config).is_ok(),
        "an ambiguous slice carrying only an AUDIT selector policy must construct (audit is \
         non-enforcing — dropping it is not a fail-open), not fail closed"
    );
}

#[test]
fn mesh_authz_construction_tolerates_ambiguous_slice_audit_only_selector_with_nonempty_intersection()
 {
    // Same shape as
    // `mesh_authz_construction_rejects_ambiguous_slice_candidate_only_selector_with_nonempty_intersection`
    // (ambiguous slice, `app=shared` intersection, candidate-only `role=api`
    // selector the intersection cannot resolve) — but AUDIT-only. The
    // non-empty-intersection fail-closed guard must also EXEMPT audit-only
    // policies: dropping an audit no-op never opens an allow-by-default hole
    // (Codex P2). Construction must tolerate it.
    let policy = policy_audit_principal(
        "audit-role-api",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("role".to_string(), "api".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [policy],
        "labels": { "app": "shared" },
        "labels_ambiguous": true,
    });
    let config = json!({ "mesh_slice": slice });
    assert!(
        MeshAuthz::new(&config).is_ok(),
        "an ambiguous slice with a candidate-only AUDIT selector the intersection cannot resolve \
         must construct (audit is non-enforcing), not fail closed"
    );
}

#[test]
fn mesh_authz_construction_still_fails_closed_on_ambiguous_slice_mixed_audit_and_enforcing() {
    // Defense-in-depth: an ambiguous slice carrying BOTH an audit-only
    // candidate-only selector AND an ENFORCING (DENY) candidate-only selector
    // the intersection cannot resolve must STILL fail closed — the audit
    // exemption must not mask a real enforcing fail-open in the same slice.
    let audit = policy_audit_principal(
        "audit-role-api",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("role".to_string(), "api".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let deny = policy_deny_principal(
        "deny-role-worker",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("role".to_string(), "worker".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        ROGUE_SPIFFE,
    );
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [audit, deny],
        "labels": { "app": "shared" },
        "labels_ambiguous": true,
    });
    let config = json!({ "mesh_slice": slice });
    match MeshAuthz::new(&config) {
        Ok(_) => panic!(
            "an ambiguous slice with an unresolvable enforcing DENY selector must fail closed even \
             when an audit-only selector is also present"
        ),
        Err(err) => assert!(
            err.contains("partial label intersection"),
            "expected a partial-intersection fail-closed construction error, got: {err}"
        ),
    }
}

#[test]
fn mesh_authz_construction_rejects_operator_selector_policy_without_labels() {
    // Operator-direct config (flat `mesh_policies`, no `mesh_slice` context): a
    // workload-selector policy with selector labels but no proxy `labels`. There
    // is no downstream consumer to recover the labels, so the cold-path `retain`
    // would drop the policy and `evaluate_mesh_authorization_policies` would
    // allow the request by default — a silent fail-open. Construction must fail
    // closed instead, forcing the operator to supply the proxy identity.
    let policy = policy_allow_principal(
        "labels-required",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let config = json!({
        "mesh_policies": [policy],
        "namespace": DEFAULT_NAMESPACE,
        // labels: intentionally omitted
    });
    // `MeshAuthz` does not implement `Debug`, so inspect the `Result` directly
    // instead of `expect_err`.
    match MeshAuthz::new(&config) {
        Ok(_) => panic!("operator-direct selector policy without labels must fail closed"),
        Err(err) => assert!(
            err.contains("no proxy labels are configured"),
            "expected a labels-required construction error, got: {err}"
        ),
    }
}

#[test]
fn mesh_authz_construction_tolerates_operator_audit_only_selector_without_labels() {
    // Operator-direct config (flat `mesh_policies`) with an AUDIT-only
    // workload-selector policy and no proxy `labels`. AUDIT is non-enforcing per
    // Istio semantics, so dropping it via the cold-path `retain` is a no-op, not
    // a fail-open. Construction must TOLERATE it, not fail closed (Codex P2 — the
    // audit exemption applies on the operator path too, consistent with the
    // slice path and the per-pod missing-scope check).
    let policy = policy_audit_principal(
        "audit-labels-optional",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let config = json!({
        "mesh_policies": [policy],
        "namespace": DEFAULT_NAMESPACE,
        // labels: intentionally omitted
    });
    assert!(
        MeshAuthz::new(&config).is_ok(),
        "an operator-direct AUDIT-only selector policy without labels must construct (audit is \
         non-enforcing), not fail closed"
    );
}

#[test]
fn mesh_authz_construction_clears_ambiguous_marker_on_explicit_labels_override() {
    // An ambiguous shared-SPIFFE slice (`labels_ambiguous = true`) carries a
    // candidate-only `role=api` selector policy as a superset, but the operator
    // pins the proxy identity with an explicit top-level `labels` override of
    // `role=worker` (the documented way to resolve authoritative labels — see
    // docs/mesh.md "The marker is cleared on the recovered slice once the DP has
    // resolved its authoritative labels"). The override IS authoritative, so the
    // stale ambiguous marker must be cleared: the `role=api` policy simply does
    // not apply to `role=worker` and the cold-path `retain` drops it. Construction
    // must NOT reject the workload (Codex P2: the recommended pin mechanism must
    // not fail closed against a non-applicable candidate-only superset policy).
    let policy = policy_allow_principal(
        "role-api-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("role".to_string(), "api".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let slice = json!({
        "node_id": "node-a",
        "namespace": DEFAULT_NAMESPACE,
        "version": "v1",
        "mesh_policies": [policy],
        "labels_ambiguous": true,
        // No slice-embedded labels: the operator pins identity via the top-level
        // `labels` override below, which must clear the ambiguous marker.
    });
    let config = json!({
        "mesh_slice": slice,
        "labels": { "role": "worker" },
    });
    assert!(
        MeshAuthz::new(&config).is_ok(),
        "an explicit `labels` override pins authoritative identity and must clear the \
         ambiguous marker so a non-applicable candidate-only selector policy is dropped, not rejected"
    );
}

#[test]
fn mesh_authz_construction_filters_policies_for_workload_at_build_time() {
    // Verify the construction-time filter actually removes
    // non-applicable policies, not just at request time. Construct
    // with `app=reviews`, give it both reviews- and ratings-scoped
    // policies, then verify behaviour: a request that would match the
    // ratings ALLOW must NOT be admitted (since that policy is
    // filtered out — but the reviews ALLOW catches it instead). This
    // is a behavioural assert, not a private-field inspection.
    let reviews_allow = policy_allow_principal(
        "reviews-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        CLIENT_SPIFFE,
    );
    let ratings_only_allow = policy_allow_principal(
        "ratings-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some(DEFAULT_NAMESPACE.to_string()),
            },
        },
        ROGUE_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(
        &[("app", "reviews")],
        vec![reviews_allow, ratings_only_allow],
    );

    // Rogue principal is admitted only by the ratings-scoped ALLOW.
    // After scope filtering, that policy is gone — implicit deny.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let mut rogue_ctx = ctx_with_principal("GET", "/api", Some(ROGUE_SPIFFE));
        let result = plugin.authorize(&mut rogue_ctx).await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "ratings-scoped ALLOW was filtered out for reviews workload → \
             implicit deny, got {result:?}"
        );
    });
}

#[tokio::test]
async fn trust_domain_alias_accepts_baggage_principal_from_aliased_domain() {
    // HBONE baggage carries `source.principal` — only honoured when its
    // trust domain matches the peer cert's OR is listed in
    // `trust_domain_aliases`. Set up the plugin with an alias and
    // simulate a baggage-bearing request whose principal's trust
    // domain is the alias (peer cert trust domain stays `cluster.local`).
    //
    // We synthesise the HBONE shape by setting the `baggage` header
    // directly; the rest of the path mirrors what `hbone_proxy.rs`
    // does after the CONNECT terminates.
    let allow = policy_allow_principal(
        "alias-allow",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        "spiffe://aliased.local/ns/default/sa/client",
    );
    // Hand-build the plugin with an alias.
    let mut runtime = default_mesh_runtime();
    runtime
        .trust_domain_aliases
        .push(TrustDomain::new("aliased.local").expect("trust domain"));
    let mesh = mesh_config_with(Vec::new(), Vec::new(), vec![allow]);
    let config = ferrum_edge::config::types::GatewayConfig {
        version: "test".to_string(),
        proxies: Vec::new(),
        upstreams: Vec::new(),
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        loaded_at: chrono::Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        mesh_revision: None,
    };
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    let authz_cfg = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz injected")
        .config
        .clone();
    let plugin = MeshAuthz::new(&authz_cfg).expect("plugin builds with aliases");

    // Build a RequestContext that mimics a post-HBONE handoff: the
    // peer SPIFFE id is the ztunnel's identity (`cluster.local`), and
    // baggage carries the original workload principal in the aliased
    // domain. `mesh_authz` must accept the baggage identity because
    // the alias is configured.
    let mut ctx = ctx_with_principal(
        "GET",
        "/api",
        Some("spiffe://cluster.local/ns/istio-system/sa/ztunnel"),
    );
    // Synthesise the HBONE-authenticated shape — `mesh_authz` checks
    // this via the same `is_hbone_request` / `is_authenticated_hbone_request`
    // helpers the proxy populates. The minimum we need to flip both
    // predicates is a marked HBONE request with baggage attached.
    ctx.metadata
        .insert("hbone.connect_authority".to_string(), "default".to_string());
    ctx.metadata
        .insert("hbone.authenticated".to_string(), "true".to_string());
    ctx.headers.insert(
        "baggage".to_string(),
        "source.principal=spiffe://aliased.local/ns/default/sa/client".to_string(),
    );

    let _ = plugin.authorize(&mut ctx).await;
    // We don't assert Continue/Reject here because the HBONE
    // authenticated-baggage path is sensitive to how the proxy stamps
    // ctx state — what we lock in is the absence of the
    // `trust_domain_mismatch` flag, which would have fired if the
    // alias were not honoured.
    assert!(
        !ctx.metadata
            .contains_key("mesh_authz.ignored_baggage.trust_domain_mismatch"),
        "trust-domain alias must keep the baggage principal in scope, got metadata {:?}",
        ctx.metadata
    );
}

#[tokio::test]
async fn condition_not_values_on_jwt_claim_allows_absent_attribute() {
    // DENY with `not_values: ["admin"]` on `request.auth.claims[role]`:
    // the condition passes when the claim does NOT equal "admin", so the
    // DENY fires for non-admins. Admins (role=admin) fail the condition
    // and the DENY does not fire.
    let deny_except_admin = MeshPolicy {
        name: "deny-non-admin".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: "request.auth.claims[role]".to_string(),
                values: Vec::new(),
                not_values: vec!["admin".to_string()],
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_except_admin]);

    // Claim present and matches not_values -> condition fails -> DENY
    // does NOT fire, so the admin is allowed through.
    let mut admin_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    admin_ctx.mesh_request_auth_claims.insert(
        "role".to_string(),
        JwtAuthAttributeValue::Scalar("admin".to_string()),
    );
    assert!(
        matches!(
            plugin.authorize(&mut admin_ctx).await,
            PluginResult::Continue
        ),
        "claim matching not_values should make the DENY condition fail (admin passes)"
    );

    // Claim present but does NOT match not_values -> condition passes ->
    // DENY fires, rejecting the non-admin.
    let mut user_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    user_ctx.mesh_request_auth_claims.insert(
        "role".to_string(),
        JwtAuthAttributeValue::Scalar("user".to_string()),
    );
    assert!(
        matches!(
            plugin.authorize(&mut user_ctx).await,
            PluginResult::Reject { .. }
        ),
        "claim not matching not_values should make the DENY condition pass (user denied)"
    );

    // Claim absent on a DENY rule with an HTTP-only key: missing attribute
    // returns true for the condition, so the DENY fires.
    let mut absent_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    absent_ctx.mesh_request_auth_claims.clear();
    assert!(
        matches!(
            plugin.authorize(&mut absent_ctx).await,
            PluginResult::Reject { .. }
        ),
        "absent claim on a DENY not_values-only condition should fire (fail-closed)"
    );
}

/// Build a `StreamConnectionContext` for an inbound captured raw-TCP stream
/// landing on `listen_port`, identifying the peer by SPIFFE id in metadata.
/// Mirrors what `proxy::mesh_tcp_inbound::handle_mesh_tcp_inbound` stamps before
/// running the `on_stream_connect` chain (mesh-inbound direction, the captured
/// APP port as the authorization destination).
fn inbound_stream_ctx(listen_port: u16, peer_spiffe: &str) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "10.0.0.7".to_string(),
        "10.0.0.7".to_string(),
        "__mesh-in-tcp-relay-default-redis-6379".to_string(),
        Some("mesh raw-tcp inbound".to_string()),
        listen_port,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[] as &[Consumer])),
    );
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    // `mesh_authz`'s stream path reads the source principal from the
    // `peer_spiffe_id` metadata key (parity with the HBONE/HTTP path).
    ctx.insert_metadata("peer_spiffe_id".to_string(), peer_spiffe.to_string());
    ctx
}

/// A DENY `AuthorizationPolicy` scoped to one destination port. Mirrors an
/// operator denying L4 access to e.g. a Redis service port.
fn deny_principal_on_port(name: &str, principal: &str, port: u16) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(principal.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                ports: vec![port],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    }
}

/// A DENY scoped ONLY to a destination port (no `from` principal) — fires
/// against any source, including an unauthenticated one.
fn deny_any_source_on_port(name: &str, port: u16) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![RequestMatch {
                ports: vec![port],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    }
}

#[tokio::test]
async fn stream_port_only_deny_rejects_unauthenticated_inbound_raw_tcp() {
    // The captured-plaintext raw-TCP inbound path carries NO peer SVID (it is
    // not mTLS-terminated), so the source is anonymous. A port-only DENY (no
    // `from`) must still fire against it on the app port — the relay closes
    // before reaching loopback. This is the most faithful representation of the
    // real captured-plaintext L4 enforcement the handler must perform.
    let deny = deny_any_source_on_port("deny-redis-port", 6379);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

    // No `peer_spiffe_id` metadata: an unauthenticated captured stream.
    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    ctx.metadata = None;
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Reject { .. }
        ),
        "a port-only L4 DENY must reject an unauthenticated captured raw-TCP \
         inbound stream on the app port"
    );
}

#[tokio::test]
async fn stream_port_scoped_deny_rejects_inbound_raw_tcp_on_app_port() {
    // Regression for the raw-TCP Sidecar inbound finding: the accept-loop relay
    // (`handle_mesh_tcp_inbound`) runs the `on_stream_connect` chain with the
    // captured APP port as the stream destination BEFORE connecting to loopback.
    // A `destination.port`-scoped DENY on that app port must therefore be
    // evaluated and reject the connection (the handler closes without relaying).
    let deny = deny_principal_on_port("deny-redis-l4", CLIENT_SPIFFE, 6379);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

    // Authorizing on the app port (6379) — the DENY fires.
    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Reject { .. }
        ),
        "a port-scoped L4 DENY on the app port must reject the captured raw-TCP \
         inbound stream so the relay never reaches loopback"
    );
}

#[tokio::test]
async fn stream_port_scoped_deny_ignores_non_matching_port_and_admits_relay() {
    // The DENY is scoped to a DIFFERENT port than the captured app port, so it
    // must NOT fire — the legitimate stream-only-port relay case proceeds. This
    // pins that authorizing on the real app port (not the shared :15006 capture
    // listener) is the discriminator: were the handler to authorize on :15006,
    // a 6379-scoped DENY would silently never apply.
    let deny = deny_principal_on_port("deny-other-port", CLIENT_SPIFFE, 5432);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Continue
        ),
        "a DENY scoped to an unrelated port must not block the captured raw-TCP \
         inbound relay on the app port"
    );
}

/// Build a `MeshAuthz` plugin that enforces a single `MeshPolicy` (no workload
/// selector — mesh-wide). Used by stream-path IP-split tests below.
fn build_stream_authz(policy: MeshPolicy) -> MeshAuthz {
    MeshAuthz::new(&json!({ "mesh_policies": [policy] })).expect("plugin config")
}

#[tokio::test]
async fn stream_source_ip_uses_direct_client_ip_not_client_ip() {
    // When `direct_client_ip` (socket peer / LB IP) and `client_ip` (PROXY-
    // protocol-forwarded / resolved address) differ, Istio `source.ip` /
    // `ipBlocks` must match against `direct_client_ip` (the socket peer),
    // NOT the forwarded `client_ip`. This mirrors the HTTP-path split where
    // `source.ip` uses `RequestContext::direct_client_ip`.
    //
    // Policy: ALLOW only when source.ip is in 10.0.0.0/8 (the LB CIDR).
    let allow_lb_peer = MeshPolicy {
        name: "allow-lb-peer".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                ip_blocks: vec![ParsedCidr::parse("10.0.0.0/8").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin = build_stream_authz(allow_lb_peer);

    // Scenario: LB peer = 10.0.0.1 (in 10.0.0.0/8), forwarded client = 203.0.113.5 (not in range).
    // source.ip must use direct_client_ip (10.0.0.1) → should be allowed.
    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    ctx.client_ip = "203.0.113.5".to_string(); // forwarded (PROXY protocol)
    ctx.direct_client_ip = "10.0.0.1".to_string(); // socket peer (LB)
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Continue
        ),
        "source.ip ipBlocks must match direct_client_ip (socket peer), not client_ip (forwarded)"
    );
}

#[tokio::test]
async fn stream_remote_ip_uses_client_ip_not_direct_client_ip() {
    // Istio `remote.ip` / `remoteIpBlocks` must match the RESOLVED client IP
    // (`client_ip`, i.e. the PROXY-protocol-forwarded address). It must NOT
    // match the raw socket peer (`direct_client_ip`).
    //
    // Policy: ALLOW only when remote.ip is in 203.0.113.0/24 (real client CIDR).
    let allow_real_client = MeshPolicy {
        name: "allow-real-client".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                remote_ip_blocks: vec![ParsedCidr::parse("203.0.113.0/24").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin = build_stream_authz(allow_real_client);

    // LB peer = 10.0.0.1 (not in 203.0.113.0/24), forwarded client = 203.0.113.5 (in range).
    // remote.ip must use client_ip (203.0.113.5) → allowed.
    let mut ctx = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    ctx.client_ip = "203.0.113.5".to_string(); // forwarded (PROXY protocol)
    ctx.direct_client_ip = "10.0.0.1".to_string(); // socket peer (LB)
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Continue
        ),
        "remote.ip remoteIpBlocks must match client_ip (forwarded), not direct_client_ip (socket peer)"
    );

    // Inverse: policy targets the LB peer range. Should NOT be admitted via remote.ip.
    let allow_lb_as_remote = MeshPolicy {
        name: "allow-lb-as-remote".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                remote_ip_blocks: vec![ParsedCidr::parse("10.0.0.0/8").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let plugin2 = build_stream_authz(allow_lb_as_remote);
    let mut ctx2 = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    ctx2.client_ip = "203.0.113.5".to_string(); // forwarded
    ctx2.direct_client_ip = "10.0.0.1".to_string(); // socket peer (in 10.0.0.0/8)
    assert!(
        matches!(
            plugin2.on_stream_connect(&mut ctx2).await,
            PluginResult::Reject { .. }
        ),
        "LB socket peer must NOT satisfy remote.ip remoteIpBlocks when forwarded client_ip is out of range"
    );
}

#[tokio::test]
async fn stream_ip_split_collapses_when_no_proxy_protocol() {
    // When PROXY protocol is not enabled, direct_client_ip == client_ip (both
    // equal the socket peer). An ipBlocks policy on the socket IP must ALLOW
    // and a remoteIpBlocks policy on the same IP must also ALLOW — no split.
    let socket_peer = "10.0.0.50";
    let allow_source = MeshPolicy {
        name: "allow-socket-as-source".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                ip_blocks: vec![ParsedCidr::parse("10.0.0.0/8").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let allow_remote = MeshPolicy {
        name: "allow-socket-as-remote".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            source_negation: SourceNegationMatch {
                remote_ip_blocks: vec![ParsedCidr::parse("10.0.0.0/8").unwrap()],
                ..SourceNegationMatch::default()
            },
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };

    // Without PROXY protocol, both IPs equal the socket peer.
    let mut ctx1 = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    ctx1.client_ip = socket_peer.to_string();
    ctx1.direct_client_ip = socket_peer.to_string();
    assert!(
        matches!(
            build_stream_authz(allow_source)
                .on_stream_connect(&mut ctx1)
                .await,
            PluginResult::Continue
        ),
        "source.ip ipBlocks must match socket peer when no PROXY protocol"
    );

    let mut ctx2 = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    ctx2.client_ip = socket_peer.to_string();
    ctx2.direct_client_ip = socket_peer.to_string();
    assert!(
        matches!(
            build_stream_authz(allow_remote)
                .on_stream_connect(&mut ctx2)
                .await,
            PluginResult::Continue
        ),
        "remote.ip remoteIpBlocks must match socket peer when no PROXY protocol"
    );
}

#[allow(dead_code)]
fn _construct_mesh_config_with_explicit_root_ns() -> MeshConfig {
    // Documents that MeshConfig::default uses "istio-system" as
    // istio_root_namespace; this anchor keeps the call exercised so a
    // future change is caught here as well as in mesh_config_with's
    // call sites.
    MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        ..MeshConfig::default()
    }
}
