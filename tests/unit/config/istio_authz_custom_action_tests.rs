//! Istio `AuthorizationPolicy` `action: CUSTOM` translation, provider
//! admission, and evaluation ordering (issue #3235).
//!
//! The load-bearing invariants under test:
//!
//! * A CUSTOM policy is admitted only when `spec.provider.name` resolves
//!   against the ROOT-namespace `meshConfig.extensionProviders`. Absent,
//!   unsupported, malformed, and cross-namespace names are refused with
//!   distinct, field-shaped diagnostics — never accepted-but-inert.
//! * Istio's action order (CUSTOM → DENY → ALLOW, AUDIT non-enforcing) is
//!   preserved, and an ALLOW can never bypass a matching CUSTOM delegation.
//! * An unexecutable delegation (no executor / L4 session) DENIES.
//! * Provider transport, timeout, header, and body options that Ferrum cannot
//!   enforce equivalently are refused at admission rather than dropped.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshExtAuthzProvider, MeshPolicy, MeshRule, PolicyAction, PolicyScope, RequestMatch,
};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization_full,
    evaluate_mesh_authorization_policies,
};
use serde_json::{Value, json};

const ROOT_NS: &str = "istio-system";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_istio_root_namespace(ROOT_NS.to_string())
    .with_mesh_overlay_authority(true)
}

fn object(api_version: &str, kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

/// The Istio meshConfig ConfigMap, in the root namespace, declaring `mesh` as
/// an embedded YAML document exactly as Istio ships it.
fn mesh_config_map(namespace: &str, mesh_yaml: &str) -> K8sObject {
    object(
        "v1",
        "ConfigMap",
        namespace,
        "istio",
        json!({ "data": { "mesh": mesh_yaml } }),
    )
}

fn ext_authz_config_map() -> K8sObject {
    mesh_config_map(
        ROOT_NS,
        r#"
extensionProviders:
- name: sample-ext-authz
  envoyExtAuthzHttp:
    service: ext-authz.istio-system.svc.cluster.local
    port: 8000
    scheme: https
    timeout: 0.5s
    pathPrefix: /check
    includeRequestHeadersInCheck:
    - x-request-id
    includeAdditionalHeadersInCheck:
      x-ferrum-check: "1"
"#,
    )
}

fn custom_policy(provider: Value) -> K8sObject {
    let mut spec = serde_json::Map::new();
    spec.insert("action".to_string(), json!("CUSTOM"));
    if !provider.is_null() {
        spec.insert("provider".to_string(), provider);
    }
    spec.insert(
        "rules".to_string(),
        json!([{ "to": [{ "operation": { "paths": ["/admin/*"] } }] }]),
    );
    object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "default",
        "delegate-admin",
        Value::Object(spec),
    )
}

fn translate(objects: &[K8sObject]) -> Result<MeshConfig, String> {
    translate_k8s_objects(objects, options())
        .map(|translation| {
            *translation
                .config
                .mesh
                .clone()
                .expect("mesh present in translation")
        })
        .map_err(|error| error.to_string())
}

// ── Translation: the happy path ───────────────────────────────────────────

#[test]
fn custom_action_binds_the_root_namespace_ext_authz_provider() {
    let mesh = translate(&[
        ext_authz_config_map(),
        custom_policy(json!({ "name": "sample-ext-authz" })),
    ])
    .expect("a CUSTOM policy with a declared provider is admitted");

    let policy = mesh
        .mesh_policies
        .iter()
        .find(|policy| policy.name == "delegate-admin")
        .expect("the CUSTOM policy is translated, not dropped");
    assert_eq!(
        policy.rules[0].action,
        PolicyAction::Custom {
            provider: "sample-ext-authz".to_string()
        },
        "the resolved provider name must ride the action so the two can never be separated"
    );

    let provider = mesh
        .ext_authz_providers
        .iter()
        .find(|provider| provider.name == "sample-ext-authz")
        .expect("the bound provider is published on the mesh, not merely counted");
    assert_eq!(provider.service, "ext-authz.istio-system.svc.cluster.local");
    assert_eq!(provider.port, 8000);
    assert!(provider.tls, "scheme: https must select TLS transport");
    assert_eq!(provider.timeout_ms, 500, "'0.5s' is 500ms");
    assert_eq!(provider.path_prefix.as_deref(), Some("/check"));
    assert_eq!(
        provider.include_request_headers_in_check,
        vec!["x-request-id".to_string()]
    );
    assert_eq!(
        provider.include_additional_headers_in_check.len(),
        1,
        "operator-authored fixed check headers are retained"
    );
    assert!(
        !provider.fail_open,
        "failOpen must default to false: an unreachable provider denies"
    );
    assert_eq!(provider.status_on_error, 403);
}

#[test]
fn admitted_provider_set_is_bounded_to_what_a_policy_actually_binds() {
    let config_map = mesh_config_map(
        ROOT_NS,
        r#"
extensionProviders:
- name: sample-ext-authz
  envoyExtAuthzHttp:
    service: ext-authz.istio-system.svc.cluster.local
    port: 8000
    scheme: https
- name: unused-ext-authz
  envoyExtAuthzHttp:
    service: other.istio-system.svc.cluster.local
    port: 9000
    scheme: https
"#,
    );
    let mesh = translate(&[config_map, custom_policy(json!({ "name": "sample-ext-authz" }))])
        .expect("translation succeeds");

    assert_eq!(
        mesh.ext_authz_providers.len(),
        1,
        "only the bound provider is published; an unreferenced provider's endpoint must not \
         ride every workload's configuration"
    );
    assert_eq!(mesh.ext_authz_providers[0].name, "sample-ext-authz");
}

// ── Translation: fail-closed rejection, one diagnostic per failure mode ───

#[test]
fn custom_action_without_a_provider_block_is_refused() {
    let error = translate(&[ext_authz_config_map(), custom_policy(Value::Null)])
        .expect_err("a CUSTOM policy with no provider cannot be represented");
    assert!(
        error.contains("provider.name"),
        "diagnostic must name the missing field, got: {error}"
    );
}

#[test]
fn custom_action_with_an_empty_provider_name_is_refused() {
    let error = translate(&[
        ext_authz_config_map(),
        custom_policy(json!({ "name": "   " })),
    ])
    .expect_err("a blank provider name cannot bind");
    assert!(
        error.contains("non-empty"),
        "diagnostic must say the name is empty, got: {error}"
    );
}

#[test]
fn custom_action_naming_an_undeclared_provider_is_refused() {
    let error = translate(&[
        ext_authz_config_map(),
        custom_policy(json!({ "name": "typo-ext-authz" })),
    ])
    .expect_err("an undeclared provider name cannot bind");
    assert!(
        error.contains("not declared in meshConfig.extensionProviders"),
        "diagnostic must distinguish 'not declared' from other failures, got: {error}"
    );
    assert!(
        error.contains(ROOT_NS),
        "diagnostic must name the root namespace the lookup used, got: {error}"
    );
}

#[test]
fn custom_action_naming_a_tracing_provider_is_refused_with_a_distinct_reason() {
    let config_map = mesh_config_map(
        ROOT_NS,
        r#"
extensionProviders:
- name: zipkin-prod
  zipkin:
    service: zipkin.istio-system.svc.cluster.local
    port: 9411
"#,
    );
    let error = translate(&[config_map, custom_policy(json!({ "name": "zipkin-prod" }))])
        .expect_err("a tracing provider is not an authorization provider");
    assert!(
        error.contains("is not an external authorization provider"),
        "a declared-but-wrong-kind provider needs its own diagnostic, got: {error}"
    );
}

#[test]
fn custom_action_naming_a_grpc_ext_authz_provider_is_refused_not_downgraded() {
    let config_map = mesh_config_map(
        ROOT_NS,
        r#"
extensionProviders:
- name: grpc-ext-authz
  envoyExtAuthzGrpc:
    service: ext-authz.istio-system.svc.cluster.local
    port: 9000
"#,
    );
    let error = translate(&[config_map, custom_policy(json!({ "name": "grpc-ext-authz" }))])
        .expect_err("the gRPC check API is not implementable here and must fail closed");
    assert!(
        error.contains("does not implement"),
        "an unsupported provider VARIANT must be reported as such, not as 'not declared', \
         got: {error}"
    );
}

#[test]
fn a_provider_declared_only_in_a_tenant_namespace_cannot_be_bound() {
    // The same ConfigMap content, in the workload's own namespace instead of
    // the Istio root namespace. Cross-namespace provider resolution must be
    // structurally impossible, not merely filtered.
    let tenant_config_map = mesh_config_map(
        "default",
        r#"
extensionProviders:
- name: sample-ext-authz
  envoyExtAuthzHttp:
    service: ext-authz.default.svc.cluster.local
    port: 8000
    scheme: https
"#,
    );
    let error = translate(&[
        tenant_config_map,
        custom_policy(json!({ "name": "sample-ext-authz" })),
    ])
    .expect_err("a tenant namespace cannot introduce an ext-authz provider");
    assert!(
        error.contains("not declared in meshConfig.extensionProviders"),
        "got: {error}"
    );
}

#[test]
fn custom_action_without_rules_is_refused() {
    let policy = object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "default",
        "delegate-nothing",
        json!({
            "action": "CUSTOM",
            "provider": { "name": "sample-ext-authz" },
        }),
    );
    let error = translate(&[ext_authz_config_map(), policy])
        .expect_err("a CUSTOM policy with no rules has no matching surface");
    assert!(
        error.contains("requires at least one rule"),
        "got: {error}"
    );
}

#[test]
fn a_provider_block_on_a_non_custom_action_is_refused() {
    let policy = object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "default",
        "allow-with-provider",
        json!({
            "action": "ALLOW",
            "provider": { "name": "sample-ext-authz" },
            "rules": [{}],
        }),
    );
    let error = translate(&[ext_authz_config_map(), policy]).expect_err(
        "a provider on an ALLOW policy would read as a delegation that never happens",
    );
    assert!(error.contains("only valid with action CUSTOM"), "got: {error}");
}

// ── Provider admission: unrepresentable options fail closed ───────────────

fn translate_provider_only(mesh_yaml: &str) -> Result<MeshConfig, String> {
    translate(&[
        mesh_config_map(ROOT_NS, mesh_yaml),
        custom_policy(json!({ "name": "p" })),
    ])
}

#[test]
fn plaintext_transport_to_a_non_loopback_provider_is_refused() {
    let error = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: ext-authz.istio-system.svc.cluster.local
    port: 8000
"#,
    )
    .expect_err("an unencrypted off-box ext-authz check must not be admitted");
    assert!(
        error.contains("https"),
        "diagnostic must point at the transport, got: {error}"
    );
}

#[test]
fn plaintext_transport_to_loopback_is_admitted() {
    let mesh = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
"#,
    )
    .expect("a loopback provider needs no TLS: the check never leaves the pod");
    assert!(!mesh.ext_authz_providers[0].tls);
}

#[test]
fn an_unmodelled_provider_field_is_refused_rather_than_ignored() {
    let error = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
    includeHeadersInCheck:
    - authorization
"#,
    )
    .expect_err("a field Ferrum does not model changes what the check authorizes");
    assert!(
        error.contains("does not support field"),
        "got: {error}"
    );
}

#[test]
fn wildcard_header_rules_are_refused() {
    let error = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
    includeRequestHeadersInCheck:
    - "x-custom-*"
"#,
    )
    .expect_err("a prefix rule cannot be shown to exclude reserved headers");
    assert!(error.contains("wildcard"), "got: {error}");
}

#[test]
fn hop_by_hop_and_gateway_reserved_headers_cannot_be_forwarded() {
    for header in ["connection", "host", "x-ferrum-internal", "baggage"] {
        let error = translate_provider_only(&format!(
            r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
    includeRequestHeadersInCheck:
    - "{header}"
"#
        ))
        .unwrap_err();
        assert!(
            error.contains("hop-by-hop, framing, routing, or gateway-reserved"),
            "'{header}' must be refused, got: {error}"
        );
    }
}

#[test]
fn upstream_and_allow_response_mutation_are_refused_at_admission() {
    for field in ["headersToUpstreamOnAllow", "headersToDownstreamOnAllow"] {
        let error = translate_provider_only(&format!(
            r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
    {field}:
    - x-authz-decision
"#
        ))
        .unwrap_err();
        assert!(
            error.contains("not supported"),
            "{field} must be refused rather than silently dropped, got: {error}"
        );
    }
}

#[test]
fn deny_response_headers_are_supported() {
    let mesh = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
    headersToDownstreamOnDeny:
    - www-authenticate
"#,
    )
    .expect("headers on the gateway-authored denial carry no ordering ambiguity");
    assert_eq!(
        mesh.ext_authz_providers[0].headers_to_downstream_on_deny,
        vec!["www-authenticate".to_string()]
    );
}

#[test]
fn pack_as_bytes_body_check_is_refused() {
    let error = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
    includeRequestBodyInCheck:
      maxRequestBytes: 1024
      packAsBytes: true
"#,
    )
    .expect_err("packAsBytes is a gRPC-check-API encoding Ferrum cannot honour");
    assert!(error.contains("packAsBytes"), "got: {error}");
}

#[test]
fn an_over_ceiling_provider_timeout_is_refused() {
    let error = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
    timeout: 120s
"#,
    )
    .expect_err("an unbounded provider timeout would hold the request path open");
    assert!(error.contains("timeout"), "got: {error}");
}

#[test]
fn a_duplicate_provider_name_with_divergent_configuration_is_refused() {
    let error = translate_provider_only(
        r#"
extensionProviders:
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 8000
- name: p
  envoyExtAuthzHttp:
    service: 127.0.0.1
    port: 9000
"#,
    )
    .expect_err("which endpoint a delegation reaches must never depend on document order");
    assert!(error.contains("more than once"), "got: {error}");
}

// ── Evaluation ordering ───────────────────────────────────────────────────

fn provider(name: &str) -> MeshExtAuthzProvider {
    MeshExtAuthzProvider {
        name: name.to_string(),
        service: "127.0.0.1".to_string(),
        port: 9000,
        tls: false,
        path_prefix: None,
        timeout_ms: 250,
        fail_open: false,
        status_on_error: 403,
        include_request_headers_in_check: Vec::new(),
        include_additional_headers_in_check: Vec::new(),
        include_request_body_in_check: None,
        headers_to_upstream_on_allow: Vec::new(),
        headers_to_downstream_on_deny: Vec::new(),
        headers_to_downstream_on_allow: Vec::new(),
    }
}

fn policy_with(name: &str, action: PolicyAction, paths: &[&str]) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            action,
            to: if paths.is_empty() {
                Vec::new()
            } else {
                vec![RequestMatch {
                    paths: paths.iter().map(|path| path.to_string()).collect(),
                    ..RequestMatch::default()
                }]
            },
            ..MeshRule::default()
        }],
    }
}

fn http_request(path: &str) -> MeshAuthzRequest {
    MeshAuthzRequest {
        path: Some(path.to_string()),
        method: Some("GET".to_string()),
        protocol: ferrum_edge::modes::mesh::policy::MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

#[test]
fn a_matching_allow_cannot_bypass_a_matching_custom_delegation() {
    let policies = vec![
        policy_with("allow-admin", PolicyAction::Allow, &["/admin/*"]),
        policy_with(
            "delegate-admin",
            PolicyAction::Custom {
                provider: "p".to_string(),
            },
            &["/admin/*"],
        ),
    ];
    let evaluation = evaluate_mesh_authorization_full(policies.iter(), &http_request("/admin/x"));
    assert_eq!(
        evaluation.custom.as_ref().map(|c| c.provider.as_str()),
        Some("p"),
        "a matching ALLOW must not consume the request before the delegation runs"
    );
    assert_eq!(
        evaluation.decision,
        MeshAuthzDecision::Allow,
        "the ALLOW tier still allows; the delegation decides first"
    );
}

#[test]
fn a_matching_deny_still_wins_after_the_delegation_allows() {
    let policies = vec![
        policy_with("deny-admin", PolicyAction::Deny, &["/admin/*"]),
        policy_with(
            "delegate-admin",
            PolicyAction::Custom {
                provider: "p".to_string(),
            },
            &["/admin/*"],
        ),
    ];
    let evaluation = evaluate_mesh_authorization_full(policies.iter(), &http_request("/admin/x"));
    assert!(
        evaluation.custom.is_some(),
        "the delegation is still reported so the caller cannot skip the check"
    );
    assert_eq!(
        evaluation.decision,
        MeshAuthzDecision::Deny {
            policy: "deny-admin".to_string()
        },
        "DENY still refuses a request the provider was willing to admit"
    );
}

#[test]
fn a_custom_rule_does_not_raise_the_allow_implicit_deny_floor() {
    // A CUSTOM policy DELEGATES; it does not grant. It must not turn unrelated
    // traffic into implicit-deny the way an ALLOW policy does.
    let policies = vec![policy_with(
        "delegate-admin",
        PolicyAction::Custom {
            provider: "p".to_string(),
        },
        &["/admin/*"],
    )];
    let evaluation = evaluate_mesh_authorization_full(policies.iter(), &http_request("/public"));
    assert!(evaluation.custom.is_none(), "the rule does not match /public");
    assert_eq!(
        evaluation.decision,
        MeshAuthzDecision::Allow,
        "an unmatched CUSTOM policy must not deny unrelated traffic"
    );
}

#[test]
fn an_unexecutable_delegation_denies_rather_than_falling_through() {
    // This is the contract the L4 / stream path and an executor-less
    // generation both rely on: the plain wrapper never lets a matched CUSTOM
    // rule reach the ALLOW tier.
    let policies = vec![
        policy_with("allow-admin", PolicyAction::Allow, &["/admin/*"]),
        policy_with(
            "delegate-admin",
            PolicyAction::Custom {
                provider: "p".to_string(),
            },
            &["/admin/*"],
        ),
    ];
    assert_eq!(
        evaluate_mesh_authorization_policies(policies.iter(), &http_request("/admin/x")),
        MeshAuthzDecision::Deny {
            policy: "custom:delegate-admin".to_string()
        }
    );
}

// ── Native / file boundary validation ─────────────────────────────────────

#[test]
fn a_hand_authored_mesh_with_an_unbound_custom_policy_fails_validation() {
    let mesh = MeshConfig {
        mesh_policies: vec![policy_with(
            "delegate-admin",
            PolicyAction::Custom {
                provider: "missing".to_string(),
            },
            &["/admin/*"],
        )],
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("not declared in meshConfig.extensionProviders")),
        "the native/file boundary must refuse an unbound CUSTOM policy too, got: {errors:?}"
    );
}

#[test]
fn a_bound_custom_policy_passes_validation() {
    let mesh = MeshConfig {
        mesh_policies: vec![policy_with(
            "delegate-admin",
            PolicyAction::Custom {
                provider: "p".to_string(),
            },
            &["/admin/*"],
        )],
        ext_authz_providers: vec![provider("p")],
        ..MeshConfig::default()
    };
    assert!(
        mesh.validate().is_empty(),
        "a bound CUSTOM policy is valid: {:?}",
        mesh.validate()
    );
}

#[test]
fn a_structurally_invalid_provider_fails_validation_at_the_native_boundary() {
    let mut bad = provider("p");
    bad.service = "off-box.example.com".to_string();
    bad.tls = false;
    let mesh = MeshConfig {
        ext_authz_providers: vec![bad],
        ..MeshConfig::default()
    };
    assert!(
        mesh.validate().iter().any(|error| error.contains("https")),
        "a plaintext off-box provider must be refused on every source"
    );
}
