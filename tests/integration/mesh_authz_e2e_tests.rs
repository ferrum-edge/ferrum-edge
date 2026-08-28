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
use ferrum_edge::policy_path::canonicalize_policy_path;
use ferrum_edge::proxy::stream_match::{StreamMatchArm, StreamMatchCriteria, StreamMatchEvidence};
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
    let authz_config = prepared_mesh_plugin_configs(&runtime, mesh)
        .into_iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz plugin injected")
        .config;
    MeshAuthz::new(&authz_config).expect("authz plugin builds from injected config")
}

/// Run the production mesh-preparation pipeline and return the plugin configs
/// it injected. Shared by the `mesh_authz` builder above and by the tests that
/// need a SECOND mesh-managed plugin from the same generation (the outbound
/// registry), so both always read the same injection path.
fn prepared_mesh_plugin_configs(
    runtime: &ferrum_edge::modes::mesh::MeshRuntimeConfig,
    mesh: MeshConfig,
) -> Vec<ferrum_edge::config::types::PluginConfig> {
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
        frontend_tls_certificate_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        http_tls_listen_ports: Default::default(),
        mesh_revision: None,
        node_waypoint_udp_steer_destinations: Vec::new(),
        node_waypoint_udp_destination_routes: Vec::new(),
        k8s_mesh_overlay: Default::default(),
        gateway_trust_bundles: Vec::new(),
    };
    prepare_gateway_config_for_mesh(config, runtime)
        .expect("mesh-prepared")
        .plugin_configs
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
async fn condition_match_on_http_pseudo_headers_uses_typed_request_facts() {
    let allow_pseudo_headers = MeshPolicy {
        name: "allow-pseudo-headers".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![
                ConditionMatch {
                    key: "request.headers[:authority]".to_string(),
                    values: vec!["api.example.com:8443".to_string()],
                    not_values: Vec::new(),
                },
                ConditionMatch {
                    key: "request.headers[:method]".to_string(),
                    values: vec!["GET".to_string()],
                    not_values: Vec::new(),
                },
                ConditionMatch {
                    key: "request.headers[:path]".to_string(),
                    values: vec!["/v1/items".to_string()],
                    not_values: Vec::new(),
                },
                ConditionMatch {
                    key: "request.headers[:scheme]".to_string(),
                    values: vec!["https".to_string()],
                    not_values: Vec::new(),
                },
            ],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_pseudo_headers]);

    let mut matching = ctx_with_principal("GET", "/v1/items", Some(CLIENT_SPIFFE));
    matching.request_authority = Some("api.example.com:8443".to_string());
    matching.request_is_secure = true;
    assert!(matches!(
        plugin.authorize(&mut matching).await,
        PluginResult::Continue
    ));

    matching.request_authority = Some("other.example.com:8443".to_string());
    assert!(
        matches!(
            plugin.authorize(&mut matching).await,
            PluginResult::Reject { .. }
        ),
        "a typed pseudo-header mismatch must not satisfy an ALLOW condition"
    );
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
async fn condition_source_service_account_and_trust_domain_use_verified_spiffe_identity() {
    for (key, value) in [
        ("source.serviceAccount", "default/client"),
        ("source.trustDomain", "cluster.local"),
    ] {
        let deny = condition_policy(
            "deny-source-component",
            PolicyAction::Deny,
            key,
            vec![value],
            Vec::new(),
        );
        let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

        let mut http = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
        assert!(
            matches!(
                plugin.authorize(&mut http).await,
                PluginResult::Reject { .. }
            ),
            "{key} must be materialized from the verified HTTP peer SPIFFE identity"
        );

        let mut stream = inbound_stream_ctx(6379, CLIENT_SPIFFE);
        assert!(
            matches!(
                plugin.on_stream_connect(&mut stream).await,
                PluginResult::Reject { .. }
            ),
            "{key} must be materialized from the verified stream peer SPIFFE identity"
        );
    }
}

/// Istio resolves a bare `when: source.serviceAccount` value against the
/// namespace of the `AuthorizationPolicy` that declared it, so the plugin path
/// must carry the owning policy's namespace into condition evaluation. The
/// explicit `<namespace>/<service-account>` form stays namespace-independent,
/// and both forms are matched EXACTLY (never as a prefix).
#[tokio::test]
async fn condition_bare_source_service_account_resolves_against_the_policy_namespace() {
    // CLIENT_SPIFFE is `.../ns/default/sa/client`, i.e. attribute
    // `default/client`.
    let own_namespace = condition_policy(
        "deny-bare-service-account",
        PolicyAction::Deny,
        "source.serviceAccount",
        vec!["client"],
        Vec::new(),
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![own_namespace.clone()]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    let decision = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(decision, PluginResult::Reject { .. }),
        "a bare service account must match within the policy's own namespace"
    );

    let mut foreign_namespace = own_namespace.clone();
    foreign_namespace.namespace = "payments".to_string();
    let plugin = build_mesh_authz_for_workload(&[], vec![foreign_namespace]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    let decision = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(decision, PluginResult::Continue),
        "the same bare value owned by another namespace must resolve to payments/client"
    );

    let mut explicit = condition_policy(
        "deny-explicit-service-account",
        PolicyAction::Deny,
        "source.serviceAccount",
        vec!["default/client"],
        Vec::new(),
    );
    explicit.namespace = "payments".to_string();
    let plugin = build_mesh_authz_for_workload(&[], vec![explicit]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    let decision = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(decision, PluginResult::Reject { .. }),
        "the explicit form is namespace-independent"
    );

    let prefix_shaped = condition_policy(
        "deny-prefix-shaped-service-account",
        PolicyAction::Deny,
        "source.serviceAccount",
        vec!["default/cli"],
        Vec::new(),
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![prefix_shaped]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    let decision = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(decision, PluginResult::Continue),
        "source.serviceAccount is exact — it must never behave as a prefix match"
    );
}

/// Istio's `srcNamespaceGenerator` turns every `*` in a `source.namespace` value
/// into an arbitrary substring, including mid-string and repeated stars. The
/// generic string matcher would treat those as literal text and silently never
/// match, which is fail-OPEN for a DENY.
#[tokio::test]
async fn condition_source_namespace_supports_arbitrary_star_placement() {
    for pattern in ["d*t", "*efaul*", "def*"] {
        let deny = condition_policy(
            "deny-source-namespace-glob",
            PolicyAction::Deny,
            "source.namespace",
            vec![pattern],
            Vec::new(),
        );
        let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

        let mut http = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
        let decision = plugin.authorize(&mut http).await;
        assert!(
            matches!(decision, PluginResult::Reject { .. }),
            "'{pattern}' must match the peer namespace 'default' on the request path"
        );

        let mut stream = inbound_stream_ctx(6379, CLIENT_SPIFFE);
        let decision = plugin.on_stream_connect(&mut stream).await;
        assert!(
            matches!(decision, PluginResult::Reject { .. }),
            "'{pattern}' must match the peer namespace 'default' on the stream path"
        );
    }

    let unrelated = condition_policy(
        "deny-unrelated-namespace",
        PolicyAction::Deny,
        "source.namespace",
        vec!["p*ments"],
        Vec::new(),
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![unrelated]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    let decision = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(decision, PluginResult::Continue),
        "a wildcard whose literal segments are absent must not match"
    );
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

// ── Inbound-only enforcement (issue #4158) ────────────────────────────────
//
// Istio `AuthorizationPolicy` is a DESTINATION-side contract: a policy without
// `targetRefs` authorizes traffic arriving AT the workloads it selects, and an
// Envoy sidecar carries no RBAC filter on its outbound listeners. Ferrum
// injects `__mesh_authz` as a GLOBAL plugin and the plugin cache starts every
// proxy's chain from the full global list, so the same inbound policy set also
// ran on the Sidecar/Ambient plaintext OUTBOUND capture listener (`:15001`) —
// where the peer is the co-located application over loopback and no source
// principal can ever exist.
//
// The implicit-deny floor is raised by policy PRESENCE, not by a match, so a
// single namespace-scoped ALLOW took the whole namespace's egress offline. The
// tests below pin the fix and, just as importantly, pin that every inbound
// contract it could have weakened still holds.
//
// The discriminator is the LISTENER that accepted the connection, stamped onto
// the context by the mesh listener-spawn path from
// `MeshRuntimeConfig::listener_plan`, never inferred from a port number at
// request time. What still enforces egress after the change is exercised by
// `registry_only_still_refuses_unknown_destinations_on_the_outbound_leg`.

/// The Sidecar/Ambient plaintext outbound capture port.
const OUTBOUND_CAPTURE_PORT: u16 = 15001;

/// A request captured on the OUTBOUND leg: the accepting listener stamped
/// `MeshTrafficDirection::Outbound`, and — because the peer is the local
/// application over plaintext loopback — there is no peer SPIFFE identity.
fn outbound_capture_ctx(method: &str, path: &str, host: &str) -> RequestContext {
    let mut ctx = ctx_with_principal(method, path, None);
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    ctx.frontend_listen_port = Some(OUTBOUND_CAPTURE_PORT);
    ctx.headers.insert("host".to_string(), host.to_string());
    ctx
}

/// The same request shape on the INBOUND leg, where mTLS supplies the peer
/// identity. Used as the control in every test below: the outbound assertion
/// only means something next to proof that the policy still enforces inbound.
fn inbound_leg_ctx(method: &str, path: &str, principal: Option<&str>) -> RequestContext {
    let mut ctx = ctx_with_principal(method, path, principal);
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    ctx
}

/// The canonical Istio recipe from the issue: an `AuthorizationPolicy` in
/// `default` with no selector, admitting one service account.
fn namespace_allow_from_client() -> MeshPolicy {
    policy_allow_principal(
        "allow-from-client",
        DEFAULT_NAMESPACE,
        PolicyScope::Namespace {
            namespace: DEFAULT_NAMESPACE.to_string(),
        },
        CLIENT_SPIFFE,
    )
}

#[tokio::test]
async fn namespace_scoped_allow_does_not_implicit_deny_the_outbound_capture_leg() {
    // The reproduction from issue #4158. A namespace-scoped ALLOW keyed on
    // `from.principals` can never match on the capture leg — the peer is the
    // local app over loopback — and `saw_allow` is set by the policy's
    // presence, so before the fix every egress request in the namespace was
    // rejected with `mesh_authz.deny_policy = implicit-deny`.
    let plugin = build_mesh_authz_for_workload(&[], vec![namespace_allow_from_client()]);

    let mut outbound = outbound_capture_ctx("GET", "/api/items", "payments.default.svc:8080");
    let result = plugin.authorize(&mut outbound).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a namespace-scoped inbound ALLOW must not deny egress, got {result:?}"
    );
    assert!(
        !outbound.metadata.contains_key("mesh_authz.deny_policy"),
        "the outbound leg must not record an authorization denial"
    );

    // Control: the SAME policy still implicit-denies the unauthenticated
    // request on the inbound leg. The fix is about the leg, not about
    // weakening the floor.
    let mut inbound = inbound_leg_ctx("GET", "/api/items", None);
    assert!(
        matches!(
            plugin.authorize(&mut inbound).await,
            PluginResult::Reject { .. }
        ),
        "inbound implicit-deny must still hold for an unauthenticated request"
    );

    // And the admitted principal still gets through inbound.
    let mut admitted = inbound_leg_ctx("GET", "/api/items", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut admitted).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn path_scoped_allow_does_not_implicit_deny_unrelated_outbound_requests() {
    // The amplifying case: the trigger is broader than `from.principals`. An
    // ALLOW scoped by `to.operation.paths` raises the same floor, so before the
    // fix every egress request to any OTHER path was denied — even from a
    // workload the policy admits.
    let allow_api = MeshPolicy {
        name: "allow-api-paths".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::Namespace {
            namespace: DEFAULT_NAMESPACE.to_string(),
        },
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![RequestMatch {
                paths: vec!["/api/*".to_string()],
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
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_api]);

    let mut outbound = outbound_capture_ctx("GET", "/metrics", "vendor.example.com");
    assert!(
        matches!(
            plugin.authorize(&mut outbound).await,
            PluginResult::Continue
        ),
        "a path-scoped inbound ALLOW must not blackhole egress to other paths"
    );

    // Control: inbound, the non-matching path still falls to implicit deny and
    // the matching path is still admitted.
    let mut inbound_other = inbound_leg_ctx("GET", "/metrics", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut inbound_other).await,
        PluginResult::Reject { .. }
    ));
    let mut inbound_api = inbound_leg_ctx("GET", "/api/items", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut inbound_api).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn istio_allow_without_rules_still_leaves_egress_working() {
    // `AuthorizationPolicy{action: ALLOW, rules: []}` is Istio's
    // "allow-nothing" sentinel, translated to a never-matching ALLOW rule so
    // the implicit-deny floor applies. That is correct INBOUND — pinned by
    // `istio_allow_without_rules_means_allow_nothing` — and it was the worst
    // outbound case, because the rule cannot match anything by construction.
    let allow_nothing = MeshPolicy {
        name: "allow-nothing".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::Namespace {
            namespace: DEFAULT_NAMESPACE.to_string(),
        },
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

    let mut outbound = outbound_capture_ctx("POST", "/v1/charge", "vendor.example.com");
    assert!(
        matches!(
            plugin.authorize(&mut outbound).await,
            PluginResult::Continue
        ),
        "allow-nothing is a destination-side sentinel; it must not close egress"
    );

    let mut inbound = inbound_leg_ctx("POST", "/v1/charge", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut inbound).await,
            PluginResult::Reject { .. }
        ),
        "allow-nothing must still allow nothing inbound"
    );
}

#[tokio::test]
async fn deny_first_ordering_is_unchanged_on_the_inbound_leg() {
    // The invariant most at risk from a direction gate: DENY rules evaluate
    // first and the first match wins. Pinned here with the direction stamped
    // explicitly, so the gate cannot silently reorder or skip the DENY tier on
    // the leg that still enforces.
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

    let mut inbound = inbound_leg_ctx("GET", "/api/items", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut inbound).await,
            PluginResult::Reject { .. }
        ),
        "DENY must still win over a matching ALLOW on the inbound leg"
    );

    // Istio parity, stated as a test rather than left implicit: an inbound
    // DENY is a destination-side rule and is NOT enforced on the source's
    // capture leg. The destination's own inbound leg refuses the request, so
    // the DENY is still enforced end to end — on one leg, not two.
    let mut outbound = outbound_capture_ctx("GET", "/api/items", "payments.default.svc:8080");
    assert!(matches!(
        plugin.authorize(&mut outbound).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn stream_authorization_is_inbound_only_too() {
    // The L4 path has the same shape as the HTTP path and is gated by the same
    // shared predicate. No stream listener that runs this chain stamps
    // `Outbound` today — captured raw-TCP egress is relayed over HBONE outside
    // the plugin chain — so this pins the contract rather than a live
    // behaviour change, and stops a future outbound stream listener from
    // reintroducing the implicit-deny floor on egress.
    let deny = deny_principal_on_port("deny-redis", CLIENT_SPIFFE, 6379);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny]);

    let mut inbound = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut inbound).await,
            PluginResult::Reject { .. }
        ),
        "the port-scoped DENY must still refuse the inbound raw-TCP stream"
    );

    // Same principal, same destination port — only the accepting leg differs.
    let mut outbound = StreamConnectionContext::new(
        "10.0.0.7".to_string(),
        "10.0.0.7".to_string(),
        "__mesh-outbound-capture".to_string(),
        Some("mesh raw-tcp egress".to_string()),
        OUTBOUND_CAPTURE_PORT,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[] as &[Consumer])),
    );
    outbound.mesh_direction = Some(MeshTrafficDirection::Outbound);
    outbound.destination_port = Some(6379);
    outbound.insert_metadata("peer_spiffe_id".to_string(), CLIENT_SPIFFE.to_string());
    assert!(
        matches!(
            plugin.on_stream_connect(&mut outbound).await,
            PluginResult::Continue
        ),
        "an inbound DENY must not be applied to a captured outbound stream"
    );
}

#[tokio::test]
async fn registry_only_still_refuses_unknown_destinations_on_the_outbound_leg() {
    // What remains enforced on egress after `mesh_authz` stands down. Istio's
    // `outboundTrafficPolicy: REGISTRY_ONLY` is the egress-scoping surface, and
    // it is enforced on the SAME capture leg by `mesh_outbound_registry` for
    // HTTP-family traffic (`MeshOutboundEnforcement` covers the stream family).
    // Neither is touched by the direction gate, so a namespace-scoped ALLOW no
    // longer denies egress while an unregistered destination still cannot be
    // reached.
    let mut runtime = default_mesh_runtime();
    let capture_addr = format!("127.0.0.1:{OUTBOUND_CAPTURE_PORT}");
    runtime.outbound_listen_addr = capture_addr.parse().expect("outbound capture addr");
    runtime.outbound_traffic_policy =
        ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;

    let workload = super::mesh_test_support::workload_for(
        "payments",
        DEFAULT_NAMESPACE,
        [("app", "payments")],
        ["10.0.0.5"],
    );
    let service =
        super::mesh_test_support::service_for("payments", DEFAULT_NAMESPACE, &[&workload]);
    let policies = vec![namespace_allow_from_client()];
    let mesh = mesh_config_with(vec![workload], vec![service], policies);
    let plugin_configs = prepared_mesh_plugin_configs(&runtime, mesh);

    let authz_config = plugin_configs
        .iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz plugin injected")
        .config
        .clone();
    let authz = MeshAuthz::new(&authz_config).expect("authz plugin builds from injected config");
    let registry_config = plugin_configs
        .iter()
        .find(|p| p.id == ferrum_edge::modes::mesh::MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        .expect("REGISTRY_ONLY injects the outbound registry plugin")
        .config
        .clone();
    let built_registry =
        ferrum_edge::plugins::mesh::outbound_registry::OutboundRegistry::new(&registry_config);
    let registry = built_registry.expect("outbound registry builds from injected config");

    // Drive the admit case with a destination the injected registry actually
    // carries, so the test asserts reachability instead of re-deriving the
    // mesh's own naming rules. Finding no entry at all is itself a failure.
    let registered_host = registry_config
        .get("registry")
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| {
            entries
                .iter()
                .filter_map(serde_json::Value::as_str)
                .find(|entry| entry.starts_with("payments.") && entry.ends_with(":8080"))
        })
        .expect("the mesh service must be in the injected REGISTRY_ONLY registry")
        .to_string();

    // A registered in-mesh destination: admitted by both surfaces.
    let mut known = outbound_capture_ctx("GET", "/api/items", &registered_host);
    assert!(matches!(
        authz.authorize(&mut known).await,
        PluginResult::Continue
    ));
    assert!(
        matches!(
            registry.on_request_received(&mut known).await,
            PluginResult::Continue
        ),
        "a registered mesh destination must still be reachable"
    );

    // An unregistered external destination: `mesh_authz` no longer speaks for
    // it, and REGISTRY_ONLY still refuses it.
    let mut unknown = outbound_capture_ctx("GET", "/", "not-in-registry.example.com");
    assert!(matches!(
        authz.authorize(&mut unknown).await,
        PluginResult::Continue
    ));
    let result = registry.on_request_received(&mut unknown).await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "REGISTRY_ONLY must still refuse an unregistered egress destination, got {result:?}"
    );
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
    // Pin the relaying ztunnel by EXACT SPIFFE id. It asserts an identity in
    // `default` while living in `istio-system`, and a bare service-account
    // assertor only carries same-namespace authority (issue #4274); without the
    // pin the baggage would be dropped for a namespace reason and this test
    // would stop exercising the trust-domain alias at all.
    runtime.trusted_hbone_assertors =
        vec!["spiffe://cluster.local/ns/istio-system/sa/ztunnel".to_string()];
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
        frontend_tls_certificate_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        http_tls_listen_ports: Default::default(),
        mesh_revision: None,
        node_waypoint_udp_steer_destinations: Vec::new(),
        node_waypoint_udp_destination_routes: Vec::new(),
        k8s_mesh_overlay: Default::default(),
        gateway_trust_bundles: Vec::new(),
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
    assert!(
        !ctx.metadata.contains_key("mesh_authz.ignored_baggage"),
        "an exact-SPIFFE assertor keeps cross-namespace authority, got metadata {:?}",
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
async fn stream_authz_prefers_trusted_original_destination_port_over_capture_listener() {
    // A transparent listener commonly accepts on :15006 while the trusted
    // capture tuple says the client addressed :6379. Both the ordinary Istio
    // operation-port matcher and `when: destination.port` must use :6379;
    // authorizing on :15006 would silently disarm either DENY.
    let operation_deny = deny_any_source_on_port("deny-original-operation-port", 6379);
    let operation_plugin = build_mesh_authz_for_workload(&[], vec![operation_deny]);
    let mut operation_ctx = inbound_stream_ctx(15006, CLIENT_SPIFFE);
    operation_ctx.destination_port = Some(6379);
    assert!(matches!(
        operation_plugin.on_stream_connect(&mut operation_ctx).await,
        PluginResult::Reject { .. }
    ));

    let condition_deny = condition_policy(
        "deny-original-condition-port",
        PolicyAction::Deny,
        "destination.port",
        vec!["6379"],
        Vec::new(),
    );
    let condition_plugin = build_mesh_authz_for_workload(&[], vec![condition_deny]);
    let mut condition_ctx = inbound_stream_ctx(15006, CLIENT_SPIFFE);
    condition_ctx.destination_port = Some(6379);
    assert!(matches!(
        condition_plugin.on_stream_connect(&mut condition_ctx).await,
        PluginResult::Reject { .. }
    ));
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

#[tokio::test]
async fn stream_ingress_listener_port_deny_rejects_on_declared_port_not_backend() {
    // Issue #3260: Sidecar ingress stream listeners authorize on the DECLARED
    // listener port (orig-dst), not the defaultEndpoint backend port — matching
    // HTTP ingress authz. A DENY scoped to the listener port must fire; a DENY
    // scoped only to the backend port must not.
    let deny_listener = deny_any_source_on_port("deny-ingress-listener", 16379);
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_listener]);

    let mut ctx = inbound_stream_ctx(16379, CLIENT_SPIFFE);
    ctx.metadata = None;
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Reject { .. }
        ),
        "a DENY on the declared ingress listener port must reject the stream"
    );

    let deny_backend_only = deny_any_source_on_port("deny-backend-only", 6379);
    let plugin_backend = build_mesh_authz_for_workload(&[], vec![deny_backend_only]);
    let mut ctx_listener = inbound_stream_ctx(16379, CLIENT_SPIFFE);
    ctx_listener.metadata = None;
    assert!(
        matches!(
            plugin_backend.on_stream_connect(&mut ctx_listener).await,
            PluginResult::Continue
        ),
        "a DENY scoped only to the defaultEndpoint backend port must not block \
         an ingress stream authorized on the listener port"
    );
}

fn allow_except_not_port_pattern(name: &str, pattern: &str) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![RequestMatch {
                not_port_patterns: vec![pattern.to_string()],
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
async fn stream_not_port_pattern_denies_matching_app_port() {
    let allow = allow_except_not_port_pattern("allow-except-6-prefix", "6*");
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);

    let mut blocked = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut blocked).await,
            PluginResult::Reject { .. }
        ),
        "stream app port 6379 matching notPorts 6* must fall through to implicit deny"
    );

    let mut allowed = inbound_stream_ctx(5432, CLIENT_SPIFFE);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut allowed).await,
            PluginResult::Continue
        ),
        "stream app port 5432 outside notPorts 6* must be allowed"
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

// ── Istio `when: destination.ip` and protocol-correct condition semantics ──
// Issue #3236.

/// Build a mesh-wide policy carrying a single `when[]` condition.
fn condition_policy(
    name: &str,
    action: PolicyAction,
    key: &str,
    values: Vec<&str>,
    not_values: Vec<&str>,
) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: vec![ConditionMatch {
                key: key.to_string(),
                values: values.into_iter().map(str::to_string).collect(),
                not_values: not_values.into_iter().map(str::to_string).collect(),
            }],
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action,
        }],
    }
}

/// The HTTP request path materializes `destination.ip` from the connection's
/// observed destination and CIDR-matches it. Nothing client-settable feeds it.
#[tokio::test]
async fn condition_match_on_destination_ip_uses_connection_destination() {
    let deny_vip = condition_policy(
        "deny-vip",
        PolicyAction::Deny,
        "destination.ip",
        vec!["10.96.0.0/12"],
        Vec::new(),
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_vip]);

    let mut inside = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    inside.destination_ip = Some("10.96.4.7".parse().expect("ip"));
    assert!(
        matches!(
            plugin.authorize(&mut inside).await,
            PluginResult::Reject { .. }
        ),
        "a DENY gated on destination.ip must fire for a destination inside the CIDR"
    );

    let mut outside = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    outside.destination_ip = Some("192.168.1.5".parse().expect("ip"));
    assert!(matches!(
        plugin.authorize(&mut outside).await,
        PluginResult::Continue
    ));

    // A `Host` header naming the VIP must not be able to select the rule: only
    // the transport-observed destination counts.
    let mut spoofed = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    spoofed.destination_ip = Some("192.168.1.5".parse().expect("ip"));
    spoofed
        .headers
        .insert("host".to_string(), "10.96.4.7".to_string());
    assert!(
        matches!(plugin.authorize(&mut spoofed).await, PluginResult::Continue),
        "destination.ip must never be derived from a client-supplied header"
    );

    // No destination evidence at all: the DENY must not be disarmed.
    let mut unknown = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    unknown.destination_ip = None;
    assert!(
        matches!(
            plugin.authorize(&mut unknown).await,
            PluginResult::Reject { .. }
        ),
        "missing destination evidence is unsourceable, so the DENY stays armed"
    );
}

/// A captured pre-NAT original destination wins over the socket's local
/// address: on a capture listener the socket address is the interception port,
/// not the address the client dialled.
#[tokio::test]
async fn condition_destination_ip_prefers_captured_original_destination() {
    let deny_vip = condition_policy(
        "deny-vip",
        PolicyAction::Deny,
        "destination.ip",
        vec!["10.96.0.0/12"],
        Vec::new(),
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_vip]);

    let mut captured = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    captured.destination_ip = Some("127.0.0.1".parse().expect("ip"));
    captured.orig_dst = Some("10.96.4.7:9080".parse().expect("socket addr"));
    assert!(
        matches!(
            plugin.authorize(&mut captured).await,
            PluginResult::Reject { .. }
        ),
        "the captured original destination must win over the interception socket address"
    );
}

/// An ALLOW gated on `destination.ip` cannot match without destination
/// evidence — access is never granted on an attribute the path cannot read.
#[tokio::test]
async fn condition_allow_on_destination_ip_fails_closed_without_evidence() {
    let allow_vip = condition_policy(
        "allow-vip",
        PolicyAction::Allow,
        "destination.ip",
        vec!["10.96.0.0/12"],
        Vec::new(),
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_vip]);

    let mut known = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    known.destination_ip = Some("10.96.4.7".parse().expect("ip"));
    assert!(matches!(
        plugin.authorize(&mut known).await,
        PluginResult::Continue
    ));

    let mut unknown = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    unknown.destination_ip = None;
    assert!(
        matches!(
            plugin.authorize(&mut unknown).await,
            PluginResult::Reject { .. }
        ),
        "an ALLOW gated on an unobservable destination.ip must never match"
    );
}

/// A connection always has source and remote addresses. If their typed
/// transport evidence cannot be recovered, that is an observation failure —
/// not an absent optional attribute — so both DENY and ALLOW must fail closed.
#[tokio::test]
async fn condition_source_and_remote_ip_fail_closed_without_typed_evidence() {
    for (key, clear_source) in [("source.ip", true), ("remote.ip", false)] {
        let deny = condition_policy(
            "deny-private",
            PolicyAction::Deny,
            key,
            vec!["10.0.0.0/8"],
            Vec::new(),
        );
        let deny_plugin = build_mesh_authz_for_workload(&[], vec![deny]);
        let mut deny_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
        if clear_source {
            deny_ctx.direct_client_ip = "not-an-ip".to_string();
        } else {
            deny_ctx.client_ip = "not-an-ip".to_string();
        }
        assert!(
            matches!(
                deny_plugin.authorize(&mut deny_ctx).await,
                PluginResult::Reject { .. }
            ),
            "missing {key} evidence must not disarm a DENY"
        );

        let allow = condition_policy(
            "allow-private",
            PolicyAction::Allow,
            key,
            vec!["10.0.0.0/8"],
            Vec::new(),
        );
        let allow_plugin = build_mesh_authz_for_workload(&[], vec![allow]);
        let mut allow_ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
        if clear_source {
            allow_ctx.direct_client_ip = "not-an-ip".to_string();
        } else {
            allow_ctx.client_ip = "not-an-ip".to_string();
        }
        assert!(
            matches!(
                allow_plugin.authorize(&mut allow_ctx).await,
                PluginResult::Reject { .. }
            ),
            "missing {key} evidence must never grant an ALLOW"
        );
    }
}

/// The L4 stream path sources `destination.ip` from the connection destination
/// fact. Capture/PROXY original-destination evidence wins, while an ordinary
/// TCP listener may use its accepted socket's local address for authz without
/// publishing that address as L4 route-selection evidence.
#[tokio::test]
async fn stream_condition_match_on_destination_ip_uses_connection_destination() {
    let deny_vip = condition_policy(
        "deny-vip",
        PolicyAction::Deny,
        "destination.ip",
        vec!["10.96.0.0/12"],
        Vec::new(),
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![deny_vip]);

    let mut inside = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    inside.connection_destination_ip = Some("10.96.4.7".parse().expect("ip"));
    assert!(
        inside.destination_ip.is_none(),
        "mesh authz connection evidence must not require stream_match evidence"
    );
    assert!(
        matches!(
            plugin.on_stream_connect(&mut inside).await,
            PluginResult::Reject { .. }
        ),
        "a DENY gated on destination.ip must fire for a captured stream destination"
    );

    let mut outside = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    outside.connection_destination_ip = Some("192.168.1.5".parse().expect("ip"));
    assert!(matches!(
        plugin.on_stream_connect(&mut outside).await,
        PluginResult::Continue
    ));

    // UDP/DTLS sessions carry no destination evidence today.
    let mut unknown = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    unknown.destination_ip = None;
    unknown.connection_destination_ip = None;
    assert!(
        matches!(
            plugin.on_stream_connect(&mut unknown).await,
            PluginResult::Reject { .. }
        ),
        "a stream with no destination evidence must not disarm the DENY"
    );
}

#[test]
fn direct_listener_destination_is_not_original_destination_route_evidence() {
    let mut stream = inbound_stream_ctx(15432, CLIENT_SPIFFE);
    stream.connection_destination_ip = Some("127.0.0.1".parse().expect("ip"));
    let matcher = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            destination_subnets: vec!["127.0.0.0/8".to_string()],
            ..Default::default()
        }],
    }
    .compile()
    .expect("matcher");

    assert!(stream.destination_ip.is_none());
    assert!(!matcher.matches(&StreamMatchEvidence {
        destination_ip: stream.destination_ip,
        ..Default::default()
    }));

    stream.destination_ip = Some("127.0.0.1".parse().expect("ip"));
    assert!(matcher.matches(&StreamMatchEvidence {
        destination_ip: stream.destination_ip,
        ..Default::default()
    }));
}

/// Istio's non-HTTP-port semantics on the live stream path: a DENY ignores an
/// HTTP-only `when` field and still matches, while an ALLOW gated on one can
/// never match — including a `notValues`-only condition, which on HTTP would be
/// satisfied by the absent attribute.
#[tokio::test]
async fn stream_http_only_conditions_follow_istio_non_http_port_semantics() {
    let deny_header = condition_policy(
        "deny-header",
        PolicyAction::Deny,
        "request.headers[x-team]",
        vec!["blocked"],
        Vec::new(),
    );
    let deny_plugin = build_mesh_authz_for_workload(&[], vec![deny_header.clone()]);
    let mut stream = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            deny_plugin.on_stream_connect(&mut stream).await,
            PluginResult::Reject { .. }
        ),
        "a raw TCP connection carries no HTTP headers, so the DENY stays armed"
    );

    // The same policy on HTTP evaluates the header normally.
    let http_plugin = build_mesh_authz_for_workload(&[], vec![deny_header]);
    let mut without_header = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            http_plugin.authorize(&mut without_header).await,
            PluginResult::Continue
        ),
        "on HTTP the header is sourceable and absent, so the values check fails"
    );
    let mut with_header = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    with_header
        .headers
        .insert("x-team".to_string(), "blocked".to_string());
    assert!(matches!(
        http_plugin.authorize(&mut with_header).await,
        PluginResult::Reject { .. }
    ));

    let allow_not_header = condition_policy(
        "allow-not-header",
        PolicyAction::Allow,
        "request.headers[x-team]",
        Vec::new(),
        vec!["blocked"],
    );
    let allow_plugin = build_mesh_authz_for_workload(&[], vec![allow_not_header]);
    let mut stream = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(
        matches!(
            allow_plugin.on_stream_connect(&mut stream).await,
            PluginResult::Reject { .. }
        ),
        "a notValues-only HTTP-only ALLOW condition must not grant a raw TCP connection"
    );
}

/// `experimental.envoy.filters.*` installs (dropping it would be fail-open for
/// a DENY) but can never be sourced, on either protocol family.
#[tokio::test]
async fn condition_experimental_envoy_filter_key_installs_and_fails_closed() {
    let key = "experimental.envoy.filters.network.mysql_proxy[db.table]";

    let deny = condition_policy(
        "deny-experimental",
        PolicyAction::Deny,
        key,
        vec!["books"],
        Vec::new(),
    );
    let deny_plugin = build_mesh_authz_for_workload(&[], vec![deny]);
    let mut http = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(matches!(
        deny_plugin.authorize(&mut http).await,
        PluginResult::Reject { .. }
    ));
    let mut stream = inbound_stream_ctx(6379, CLIENT_SPIFFE);
    assert!(matches!(
        deny_plugin.on_stream_connect(&mut stream).await,
        PluginResult::Reject { .. }
    ));

    let allow = condition_policy(
        "allow-experimental",
        PolicyAction::Allow,
        key,
        Vec::new(),
        vec!["books"],
    );
    let allow_plugin = build_mesh_authz_for_workload(&[], vec![allow]);
    let mut http = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            allow_plugin.authorize(&mut http).await,
            PluginResult::Reject { .. }
        ),
        "an ALLOW gated on an unsourceable experimental key must never match"
    );
}

/// A malformed condition rejects the plugin instance at construction, so a
/// never-matching DENY can never be installed by a config source that skipped
/// the Kubernetes translator (xDS / MeshSubscribe / file).
#[test]
fn mesh_authz_construction_rejects_malformed_conditions() {
    for (key, values, expected) in [
        ("destination.ip", vec!["10.0.0.0/40"], "values[0]"),
        ("destination.port", vec!["http"], "values[0]"),
        ("destination.labels[app]", vec!["payments"], "key"),
        ("connection.sni", vec![""], "values[0]"),
    ] {
        let policy = condition_policy("bad", PolicyAction::Deny, key, values, Vec::new());
        let error = MeshAuthz::new(&json!({"mesh_policies": [policy]}))
            .err()
            .unwrap_or_else(|| panic!("malformed condition '{key}' must reject the plugin"));
        assert!(
            error.contains(expected) && error.contains("invalid condition"),
            "expected a field-specific '{expected}' diagnostic for '{key}', got: {error}"
        );
    }
}

/// Reload/update/delete: a rebuilt plugin instance reflects the new condition
/// set. The old policy's condition must stop applying, and a newly added one
/// must take effect immediately — not only on first start.
#[tokio::test]
async fn condition_set_follows_policy_reload_update_and_delete() {
    let deny_vip_a = condition_policy(
        "deny-vip",
        PolicyAction::Deny,
        "destination.ip",
        vec!["10.96.0.0/12"],
        Vec::new(),
    );
    let first = build_mesh_authz_for_workload(&[], vec![deny_vip_a]);
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    ctx.destination_ip = Some("10.96.4.7".parse().expect("ip"));
    assert!(matches!(
        first.authorize(&mut ctx).await,
        PluginResult::Reject { .. }
    ));

    // UPDATE: same policy name, different CIDR. The old block stops matching
    // and the new one starts.
    let deny_vip_b = condition_policy(
        "deny-vip",
        PolicyAction::Deny,
        "destination.ip",
        vec!["172.16.0.0/12"],
        Vec::new(),
    );
    let updated = build_mesh_authz_for_workload(&[], vec![deny_vip_b]);
    let mut old_target = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    old_target.destination_ip = Some("10.96.4.7".parse().expect("ip"));
    assert!(
        matches!(
            updated.authorize(&mut old_target).await,
            PluginResult::Continue
        ),
        "the withdrawn CIDR must stop matching after the policy update"
    );
    let mut new_target = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    new_target.destination_ip = Some("172.16.9.9".parse().expect("ip"));
    assert!(matches!(
        updated.authorize(&mut new_target).await,
        PluginResult::Reject { .. }
    ));

    // DELETE: no policies at all — the condition-key index is empty again and
    // the request is admitted.
    let deleted = build_mesh_authz_for_workload(&[], Vec::new());
    let mut ctx = ctx_with_principal("GET", "/api", Some(CLIENT_SPIFFE));
    ctx.destination_ip = Some("172.16.9.9".parse().expect("ip"));
    assert!(matches!(
        deleted.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

// ── Canonical request path (issues #1701 and #4149) ────────────────────────
//
// Istio `paths:` / `notPaths:` are matched LITERALLY, so an authorization
// decision is only sound while the string the matcher reads is the string the
// backend resolves. Two spellings break that on their own:
//
//   * an encoded separator — `/admin%2Fsecret` (issue #1701), and
//   * a dot segment — `/public/../admin/secret` (issue #4149, recorded in
//     #1701 as its remaining half).
//
// Either lets a DENY on `/admin/*` miss, or an ALLOW on `/public/*` match,
// while a normalizing backend (nginx, Spring, Go's `http.ServeMux`, or the
// `url` crate behind the gateway's own dispatch) still serves
// `/admin/secret`.
//
// Ferrum closes both halves with ONE mechanism, in one place: every HTTP/1.1,
// HTTP/2, and HTTP/3 request target is canonicalized at the frontend boundary,
// and a target with more than one reading is REFUSED with a 400 rather than
// rewritten. Removing `..` would itself be a second reading, so a backend that
// does not remove it would still disagree with policy; refusing cannot
// disagree with anything. `mesh_authz` then re-runs the same canonicalizer —
// the identity, and allocation-free, on everything the boundary admits — so it
// fails closed instead of matching raw even if some future entry point ever
// built a context without passing the boundary.

/// Exactly what `handle_proxy_request_inner` and the H3 handler do at the
/// boundary: canonicalize the raw target, then build the request context on
/// the canonical form.
///
/// `None` means the boundary refused the target — the client got a 400 and no
/// authorization decision is ever taken for that spelling.
fn boundary_ctx(method: &str, raw_path: &str, principal: Option<&str>) -> Option<RequestContext> {
    let canonical = canonicalize_policy_path(raw_path).ok()?;
    Some(ctx_with_principal(method, &canonical, principal))
}

/// The same, for a target the boundary is expected to admit.
fn canonical_ctx(method: &str, raw_path: &str, principal: Option<&str>) -> RequestContext {
    boundary_ctx(method, raw_path, principal).expect("target must be admitted at the boundary")
}

/// A policy with one rule carrying the supplied `to.operation` match.
fn policy_with_request_match(name: &str, action: PolicyAction, to: RequestMatch) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![to],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action,
        }],
    }
}

/// ALLOW `GET` on everything EXCEPT `/admin/*`.
///
/// `methods` and `notPaths` live in ONE `RequestMatch`, which is Istio's
/// conjunctive AND-block. The repo contract forbids splitting a negative match
/// into a separate DENY policy, and these tests would not detect that
/// regression if they did.
fn allow_get_except_admin() -> MeshPolicy {
    policy_with_request_match(
        "allow-except-admin",
        PolicyAction::Allow,
        RequestMatch {
            methods: vec!["GET".to_string()],
            not_paths: vec!["/admin/*".to_string()],
            ..RequestMatch::default()
        },
    )
}

/// A source-agnostic policy on the supplied `paths:` patterns.
fn policy_on_paths(name: &str, action: PolicyAction, patterns: &[&str]) -> MeshPolicy {
    policy_with_request_match(
        name,
        action,
        RequestMatch {
            paths: patterns.iter().map(|p| p.to_string()).collect(),
            ..RequestMatch::default()
        },
    )
}

/// Every spelling of `/admin/secret` a client can put on the wire: plain,
/// literal dot segments in each position, `%2e` / `%2E` escaped dot segments,
/// a double-encoded dot segment, and the issue #1701 encoded-slash forms.
const ADMIN_SPELLINGS: [&str; 12] = [
    "/admin/secret",
    "/public/../admin/secret",
    "/x/../admin/secret",
    "/./admin/secret",
    "/admin/./secret",
    "/admin/../admin/secret",
    "/x/%2e%2e/admin/secret",
    "/x/%2E%2E/admin/secret",
    "/x/.%2e/admin/secret",
    "/x/%252e%252e/admin/secret",
    "/admin%2fsecret",
    "/admin%252Fsecret",
];

#[test]
fn every_ambiguous_spelling_of_a_protected_path_is_refused_at_the_boundary() {
    // Each of these is a 400 before routing, before every plugin phase, and
    // before backend dispatch, so `mesh_authz` never evaluates the target at
    // all. The resolved spelling is the only one that survives.
    for raw in ADMIN_SPELLINGS {
        if raw == "/admin/secret" {
            continue;
        }
        assert!(
            canonicalize_policy_path(raw).is_err(),
            "{raw:?} must be refused, not resolved to one of its readings"
        );
    }
    // A trailing dot segment and a bare one are refused too.
    for raw in ["/admin/secret/..", "/admin/secret/.", "/..", "/."] {
        assert!(
            canonicalize_policy_path(raw).is_err(),
            "{raw:?} must be refused as a dot segment"
        );
    }
    // Issue #1701's own half, spelled out so a regression there is named.
    for raw in ["/admin%2fsecret", "/admin%2Fsecret", "/admin%252Fsecret"] {
        assert!(
            canonicalize_policy_path(raw).is_err(),
            "{raw:?} (encoded separator) must stay refused"
        );
    }
}

#[tokio::test]
async fn no_spelling_of_a_protected_path_escapes_the_not_paths_negative_match() {
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_get_except_admin()]);

    // The ALLOW grant works for what it actually names.
    let mut granted = canonical_ctx("GET", "/api/items", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut granted).await,
        PluginResult::Continue
    ));

    // The path a normalizing backend actually serves is refused: `notPaths`
    // fires, the ALLOW rule does not match, and the implicit-deny floor
    // applies.
    let mut resolved = canonical_ctx("GET", "/admin/secret", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut resolved).await,
        PluginResult::Reject { .. }
    ));

    // No other spelling of that same resource obtains a wider answer: each is
    // either refused at the boundary, or reaches the same denial.
    for raw in ADMIN_SPELLINGS {
        let Some(mut ctx) = boundary_ctx("GET", raw, Some(CLIENT_SPIFFE)) else {
            continue;
        };
        let canonical = ctx.path.clone();
        let result = plugin.authorize(&mut ctx).await;
        assert!(
            matches!(result, PluginResult::Reject { .. }),
            "{raw:?} canonicalized to {canonical:?} and was ALLOWED; a \
             normalizing backend would serve /admin/secret"
        );
    }
}

#[tokio::test]
async fn a_dot_segment_cannot_widen_an_allow_grant_onto_a_protected_path() {
    // The issue's ALLOW-widening half. `paths: ["/public/*"]` matches
    // `/public/../admin/secret` literally, which a normalizing backend then
    // serves as `/admin/secret`.
    let policy = policy_on_paths("allow-public", PolicyAction::Allow, &["/public/*"]);
    let plugin = build_mesh_authz_for_workload(&[], vec![policy]);

    assert!(
        canonicalize_policy_path("/public/../admin/secret").is_err(),
        "the widening spelling must never reach an authorization decision"
    );

    let mut raw = ctx_with_principal("GET", "/public/../admin/secret", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut raw).await,
            PluginResult::Reject { .. }
        ),
        "handed the raw target directly, the grant must not widen onto /admin"
    );

    let mut inside = canonical_ctx("GET", "/public/index", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut inside).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn authorize_fails_closed_on_a_raw_ambiguous_target() {
    // Defense in depth behind the boundary. Before issue #4149 the plugin
    // matched `ctx.path` literally after folding only `%2F`, so handed the raw
    // `/public/../admin/secret` the negative match never saw `/admin/...`: the
    // ALLOW rule fired and the request was permitted while a normalizing
    // backend served the protected resource. It must now deny instead.
    let plugin = build_mesh_authz_for_workload(&[], vec![allow_get_except_admin()]);

    for raw in [
        "/public/../admin/secret",
        "/x/%2e%2e/admin/secret",
        "/admin%2fsecret",
    ] {
        let mut ctx = ctx_with_principal("GET", raw, Some(CLIENT_SPIFFE));
        let result = plugin.authorize(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
            other => panic!("{raw:?} must fail closed, got {other:?}"),
        }
        let deny_policy = ctx.metadata.get("mesh_authz.deny_policy");
        assert_eq!(
            deny_policy.map(String::as_str),
            Some("non_canonical_path"),
            "{raw:?} must be attributed to the canonical-path gate, not a rule"
        );
        // The recorded reason is a compiled-in token and never echoes request
        // bytes.
        assert!(
            ctx.metadata.contains_key("mesh_authz.non_canonical_path"),
            "{raw:?} must record why the target was unjudgeable"
        );
    }
}

#[tokio::test]
async fn dots_inside_a_segment_name_are_reachable_and_matched_literally() {
    // `/a..b` is NOT a dot segment: RFC 3986 `remove_dot_segments` leaves it
    // alone, so it must clear the boundary byte-for-byte and still be matched
    // literally by an operator's rule. Normalizing it away is the regression a
    // naive "strip `..`" fix would introduce.
    for raw in ["/a..b", "/..a", "/a..", "/...", "/x/..b/y", "/x/b../y"] {
        let canonical = canonicalize_policy_path(raw)
            .unwrap_or_else(|rejection| panic!("{raw:?} refused at boundary: {rejection:?}"));
        assert_eq!(
            canonical, raw,
            "{raw:?} must survive the boundary unchanged"
        );
    }

    let policy = policy_on_paths("deny-dots", PolicyAction::Deny, &["/a..b"]);
    let plugin = build_mesh_authz_for_workload(&[], vec![policy]);

    let mut denied = canonical_ctx("GET", "/a..b", Some(CLIENT_SPIFFE));
    assert!(
        matches!(
            plugin.authorize(&mut denied).await,
            PluginResult::Reject { .. }
        ),
        "the literal rule must still fire on a segment name that contains dots"
    );

    // The DENY is the only policy, so anything it does not match is admitted —
    // no ALLOW rule exists to raise an implicit-deny floor.
    let mut admitted = canonical_ctx("GET", "/ab", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut admitted).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn prefix_suffix_and_exact_path_matcher_shapes_all_hold_on_the_canonical_path() {
    // Istio's three `paths:` shapes. Each must fire on the resolved path, must
    // not be reachable by an ambiguous spelling of it, and must not turn into
    // a blanket DENY.
    for pattern in ["/admin/*", "*/secret", "/admin/secret"] {
        let policy = policy_on_paths("deny-shape", PolicyAction::Deny, &[pattern]);
        let plugin = build_mesh_authz_for_workload(&[], vec![policy]);

        let mut resolved = canonical_ctx("GET", "/admin/secret", Some(CLIENT_SPIFFE));
        assert!(
            matches!(
                plugin.authorize(&mut resolved).await,
                PluginResult::Reject { .. }
            ),
            "paths: [{pattern:?}] must deny the resolved /admin/secret"
        );

        for raw in ADMIN_SPELLINGS {
            let Some(mut ctx) = boundary_ctx("GET", raw, Some(CLIENT_SPIFFE)) else {
                continue;
            };
            let canonical = ctx.path.clone();
            let result = plugin.authorize(&mut ctx).await;
            assert!(
                matches!(result, PluginResult::Reject { .. }),
                "paths: [{pattern:?}] was evaded by {raw:?} (canonical {canonical:?})"
            );
        }

        let mut other = canonical_ctx("GET", "/public/index", Some(CLIENT_SPIFFE));
        assert!(
            matches!(plugin.authorize(&mut other).await, PluginResult::Continue),
            "paths: [{pattern:?}] must not deny an unrelated path"
        );
    }
}

#[tokio::test]
async fn canonical_path_gate_does_not_disturb_the_allow_implicit_deny_floor() {
    // The gate must be invisible to Istio's documented semantics: an ordinary
    // canonical path that matches no rule is still denied by the ALLOW floor,
    // and is still attributed to `implicit-deny` rather than to the gate.
    let allow = policy_allow_principal(
        "client-only",
        DEFAULT_NAMESPACE,
        PolicyScope::MeshWide,
        CLIENT_SPIFFE,
    );
    let plugin = build_mesh_authz_for_workload(&[], vec![allow]);

    let mut allowed = canonical_ctx("GET", "/public/index", Some(CLIENT_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut allowed).await,
        PluginResult::Continue
    ));

    let mut floored = canonical_ctx("GET", "/public/index", Some(ROGUE_SPIFFE));
    assert!(matches!(
        plugin.authorize(&mut floored).await,
        PluginResult::Reject { .. }
    ));
    let deny_policy = floored.metadata.get("mesh_authz.deny_policy");
    assert_eq!(
        deny_policy.map(String::as_str),
        Some("implicit-deny"),
        "an ordinary non-match must not be attributed to the canonical-path gate"
    );
}
