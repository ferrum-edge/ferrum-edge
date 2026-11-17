//! GHSA-2r85-85hh-23mw: a refused Istio security resource keeps failing closed.
//!
//! The Kubernetes translator used to drop an AuthorizationPolicy,
//! PeerAuthentication or Sidecar it refused and publish the rest of the
//! snapshot, so a refused DENY stopped denying, a refused CUSTOM stopped
//! delegating, a refused ALLOW lost the implicit-deny floor, a refused STRICT
//! PeerAuthentication fell back to a laxer tier, and a refused Sidecar widened
//! egress. Like the #6656 RequestAuthentication fix, each refused resource is
//! now published as a fail-closed marker while status still reports it
//! rejected. These tests drive `translate_k8s_objects_collecting_skips` (the
//! reconciler's translation) and then the published config's consumers:
//! mesh authorization, PeerAuthentication resolution, and the slice builder.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslation, K8sTranslationOptions,
    translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MtlsMode, OutboundTrafficPolicy, PolicyAction, PolicyScope,
};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzProtocol, MeshAuthzRequest, evaluate_mesh_authorization_policies,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest, resolve_effective_mtls_mode};
use serde_json::{Value, json};

const ROOT_NS: &str = "istio-system";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_istio_root_namespace(ROOT_NS.to_string())
}

fn object(api_version: &str, kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn authorization_policy(name: &str, spec: Value) -> K8sObject {
    object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "default",
        name,
        spec,
    )
}

/// Translate as the reconciler does and return the translation plus the
/// names of the resources it refused.
fn translate(objects: &[K8sObject]) -> (K8sTranslation, Vec<String>) {
    let (translation, skipped) = translate_k8s_objects_collecting_skips(objects, options())
        .expect("translation completes with refused resources skipped");
    let mut refused: Vec<String> = skipped.keys().map(|key| key.name.clone()).collect();
    refused.sort();
    (translation, refused)
}

fn mesh(translation: &K8sTranslation) -> &MeshConfig {
    translation
        .config
        .mesh
        .as_deref()
        .expect("fail-closed markers are published")
}

fn http(path: &str) -> MeshAuthzRequest {
    MeshAuthzRequest {
        method: Some("GET".to_string()),
        path: Some(path.to_string()),
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

fn l4() -> MeshAuthzRequest {
    MeshAuthzRequest {
        port: Some(5432),
        protocol: MeshAuthzProtocol::L4,
        ..MeshAuthzRequest::default()
    }
}

fn decide(mesh: &MeshConfig, request: &MeshAuthzRequest) -> MeshAuthzDecision {
    evaluate_mesh_authorization_policies(mesh.mesh_policies.iter(), request)
}

fn is_deny(decision: &MeshAuthzDecision) -> bool {
    matches!(decision, MeshAuthzDecision::Deny { .. })
}

fn assert_admitted(translation: &K8sTranslation) {
    let errors = translation.config.validate_mesh_fields();
    assert!(
        errors.is_empty(),
        "published fail-closed markers must pass mesh admission: {errors:?}"
    );
}

// ── AuthorizationPolicy ──────────────────────────────────────────────────

/// A refused ALLOW that was the workload's only ALLOW must not turn it into
/// allow-all: the marker keeps the implicit-deny floor and grants nothing.
#[test]
fn refused_only_allow_policy_keeps_the_implicit_deny_floor() {
    let refused = authorization_policy(
        "allow-office",
        json!({
            "selector": {"matchLabels": {"app": "api"}},
            "action": "ALLOW",
            "rules": [{"from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[refused]);
    assert_eq!(refused_names, vec!["allow-office".to_string()]);
    let mesh = mesh(&translation);
    assert_eq!(mesh.mesh_policies.len(), 1);
    let marker = &mesh.mesh_policies[0];
    assert_eq!(marker.name, "allow-office");
    match &marker.scope {
        PolicyScope::WorkloadSelector { selector } => {
            assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
        }
        other => panic!("the marker keeps the selector scope, got {other:?}"),
    }
    assert!(
        marker
            .rules
            .iter()
            .all(|rule| rule.never_matches && rule.action == PolicyAction::Allow),
        "a refused ALLOW grants nothing: {:?}",
        marker.rules
    );

    assert!(
        is_deny(&decide(mesh, &http("/anything"))),
        "with the only ALLOW refused, unmatched HTTP traffic is implicitly denied"
    );
    assert!(
        is_deny(&decide(mesh, &l4())),
        "with the only ALLOW refused, unmatched L4 traffic is implicitly denied"
    );
    assert_admitted(&translation);
}

/// The ALLOW marker grants nothing but blocks nothing another ALLOW grants.
#[test]
fn refused_allow_policy_leaves_sibling_allow_grants_in_force() {
    let refused = authorization_policy(
        "allow-office",
        json!({
            "action": "ALLOW",
            "rules": [{"from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}]}]
        }),
    );
    let sibling = authorization_policy(
        "allow-public",
        json!({
            "action": "ALLOW",
            "rules": [{"to": [{"operation": {"paths": ["/public"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[refused, sibling]);
    assert_eq!(refused_names, vec!["allow-office".to_string()]);
    let mesh = mesh(&translation);
    assert_eq!(decide(mesh, &http("/public")), MeshAuthzDecision::Allow);
    assert!(is_deny(&decide(mesh, &http("/private"))));
}

/// A refused DENY must not silently stop denying: the marker denies every
/// request and connection to its scope.
#[test]
fn refused_deny_policy_denies_everything_in_scope() {
    let refused = authorization_policy(
        "deny-admin",
        json!({
            "action": "DENY",
            "rules": [{
                "from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}],
                "to": [{"operation": {"paths": ["/admin/*"]}}]
            }]
        }),
    );
    let (translation, refused_names) = translate(&[refused]);
    assert_eq!(refused_names, vec!["deny-admin".to_string()]);
    let mesh = mesh(&translation);
    let marker = &mesh.mesh_policies[0];
    assert_eq!(
        marker.scope,
        PolicyScope::Namespace {
            namespace: "default".to_string()
        }
    );
    assert!(is_deny(&decide(mesh, &http("/admin/users"))));
    assert!(is_deny(&decide(mesh, &http("/"))));
    assert!(is_deny(&decide(mesh, &l4())));
    assert_admitted(&translation);
}

/// The advisory's reproduction: a CUSTOM policy naming an `envoyExtAuthzGrpc`
/// provider is refused, and requests to its workloads must be denied rather
/// than served without an authorization check.
#[test]
fn refused_custom_policy_denies_instead_of_skipping_the_external_check() {
    let config_map = object(
        "v1",
        "ConfigMap",
        ROOT_NS,
        "istio",
        json!({ "data": { "mesh": "extensionProviders:\n- name: opa\n  envoyExtAuthzGrpc:\n    service: opa.istio-system.svc.cluster.local\n    port: 9191\n" } }),
    );
    let refused = authorization_policy(
        "ext",
        json!({
            "selector": {"matchLabels": {"app": "api"}},
            "action": "CUSTOM",
            "provider": {"name": "opa"},
            "rules": [{"to": [{"operation": {"paths": ["/admin/*"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[config_map, refused]);
    assert_eq!(refused_names, vec!["ext".to_string()]);
    let mesh = mesh(&translation);
    assert_eq!(mesh.mesh_policies.len(), 1);
    assert!(
        mesh.mesh_policies[0]
            .rules
            .iter()
            .all(|rule| rule.action == PolicyAction::Deny),
        "the marker never names the provider it could not bind"
    );
    assert!(is_deny(&decide(mesh, &http("/admin/users"))));
    assert_admitted(&translation);
}

/// A CUSTOM policy naming a provider the root meshConfig does not declare
/// (GitOps ordering, typo) is refused the same way.
#[test]
fn refused_custom_policy_with_undeclared_provider_denies() {
    let refused = authorization_policy(
        "ext",
        json!({
            "action": "CUSTOM",
            "provider": {"name": "not-declared"},
            "rules": [{"to": [{"operation": {"paths": ["/admin/*"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[refused]);
    assert_eq!(refused_names, vec!["ext".to_string()]);
    assert!(is_deny(&decide(mesh(&translation), &http("/admin/users"))));
}

/// AUDIT changes no decision, so a refused AUDIT policy publishes nothing.
#[test]
fn refused_audit_policy_publishes_no_marker() {
    let refused = authorization_policy(
        "audit",
        json!({
            "action": "AUDIT",
            "rules": [{"from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[refused]);
    assert_eq!(refused_names, vec!["audit".to_string()]);
    let published = translation
        .config
        .mesh
        .as_deref()
        .map(|mesh| mesh.mesh_policies.len())
        .unwrap_or(0);
    assert_eq!(published, 0);
}

/// An unreadable action is treated like DENY: Ferrum cannot tell what the
/// operator wanted it to enforce.
#[test]
fn refused_policy_with_unknown_action_denies() {
    let refused = authorization_policy("typo", json!({ "action": "DENNY" }));
    let (translation, refused_names) = translate(&[refused]);
    assert_eq!(refused_names, vec!["typo".to_string()]);
    assert!(is_deny(&decide(mesh(&translation), &http("/"))));
}

/// A refused `targetRefs` policy's attachment cannot be trusted to resolve, so
/// its marker covers the policy's namespace (the mesh in the root namespace).
#[test]
fn refused_target_refs_policy_covers_its_namespace() {
    let refused = authorization_policy(
        "deny-entry",
        json!({
            "action": "DENY",
            "targetRefs": [{
                "group": "networking.istio.io",
                "kind": "ServiceEntry",
                "name": "external"
            }],
            "rules": [{}]
        }),
    );
    let root = object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        ROOT_NS,
        "root-deny-entry",
        json!({
            "action": "DENY",
            "targetRefs": [{
                "group": "networking.istio.io",
                "kind": "ServiceEntry",
                "name": "external"
            }],
            "rules": [{}]
        }),
    );
    let (translation, refused_names) = translate(&[refused, root]);
    assert_eq!(
        refused_names,
        vec!["deny-entry".to_string(), "root-deny-entry".to_string()]
    );
    let mesh = mesh(&translation);
    let scope_of = |name: &str| {
        mesh.mesh_policies
            .iter()
            .find(|policy| policy.name == name)
            .map(|policy| policy.scope.clone())
            .expect("marker published")
    };
    assert_eq!(
        scope_of("deny-entry"),
        PolicyScope::Namespace {
            namespace: "default".to_string()
        }
    );
    assert_eq!(scope_of("root-deny-entry"), PolicyScope::MeshWide);
}

/// Reload: a policy that was accepted and later edited into a refused shape
/// keeps restricting instead of disappearing from the next publication.
#[test]
fn a_policy_refused_on_reload_keeps_restricting() {
    let accepted = authorization_policy(
        "deny-admin",
        json!({
            "action": "DENY",
            "rules": [{"to": [{"operation": {"paths": ["/admin/*"]}}]}]
        }),
    );
    let (first, refused_names) = translate(&[accepted]);
    assert!(refused_names.is_empty());
    assert!(is_deny(&decide(mesh(&first), &http("/admin/users"))));
    assert_eq!(decide(mesh(&first), &http("/")), MeshAuthzDecision::Allow);

    let edited = authorization_policy(
        "deny-admin",
        json!({
            "action": "DENY",
            "rules": [{
                "from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}],
                "to": [{"operation": {"paths": ["/admin/*"]}}]
            }]
        }),
    );
    let (second, refused_names) = translate(&[edited]);
    assert_eq!(refused_names, vec!["deny-admin".to_string()]);
    assert!(
        is_deny(&decide(mesh(&second), &http("/admin/users"))),
        "the refused edit must not lift the DENY it replaced"
    );
}

/// An accepted policy is published as written, never as a marker.
#[test]
fn accepted_policy_is_not_replaced_by_a_marker() {
    let accepted = authorization_policy(
        "allow-public",
        json!({
            "action": "ALLOW",
            "rules": [{"to": [{"operation": {"paths": ["/public"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[accepted]);
    assert!(refused_names.is_empty());
    let mesh = mesh(&translation);
    assert_eq!(mesh.mesh_policies.len(), 1);
    assert!(
        mesh.mesh_policies[0]
            .rules
            .iter()
            .all(|rule| !rule.never_matches)
    );
    assert_eq!(decide(mesh, &http("/public")), MeshAuthzDecision::Allow);
}

// ── PeerAuthentication ───────────────────────────────────────────────────

/// A refused workload-scoped STRICT PeerAuthentication (an out-of-range
/// `portLevelMtls` key) must not downgrade the workload to the namespace's
/// PERMISSIVE posture.
#[test]
fn refused_workload_peer_authentication_holds_the_workload_at_strict() {
    let namespace_permissive = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "default",
        "namespace-permissive",
        json!({ "mtls": {"mode": "PERMISSIVE"} }),
    );
    let refused = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "default",
        "api-strict",
        json!({
            "selector": {"matchLabels": {"app": "api"}},
            "mtls": {"mode": "STRICT"},
            "portLevelMtls": {"99999": {"mode": "PERMISSIVE"}}
        }),
    );
    let (translation, refused_names) = translate(&[namespace_permissive, refused]);
    assert_eq!(refused_names, vec!["api-strict".to_string()]);
    let mesh = mesh(&translation);
    let marker = mesh
        .peer_authentications
        .iter()
        .find(|pa| pa.name == "api-strict")
        .expect("the refused PeerAuthentication is published as a marker");
    assert_eq!(marker.mtls_mode, MtlsMode::Strict);
    assert!(marker.port_overrides.is_empty());

    let api = HashMap::from([("app".to_string(), "api".to_string())]);
    let other = HashMap::from([("app".to_string(), "web".to_string())]);
    for port in [8080, 9090] {
        assert_eq!(
            resolve_effective_mtls_mode(&mesh.peer_authentications, "default", &api, port),
            MtlsMode::Strict,
            "the selected workload stays STRICT on port {port}"
        );
    }
    assert_eq!(
        resolve_effective_mtls_mode(&mesh.peer_authentications, "default", &other, 8080),
        MtlsMode::Permissive,
        "the marker keeps its own selector scope"
    );
    assert_admitted(&translation);
}

/// A refused PeerAuthentication with an unknown mode resolves STRICT too.
#[test]
fn refused_peer_authentication_with_unknown_mode_is_strict() {
    let refused = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "default",
        "typo",
        json!({ "mtls": {"mode": "STICT"} }),
    );
    let (translation, refused_names) = translate(&[refused]);
    assert_eq!(refused_names, vec!["typo".to_string()]);
    let labels: HashMap<String, String> = HashMap::new();
    assert_eq!(
        resolve_effective_mtls_mode(
            &mesh(&translation).peer_authentications,
            "default",
            &labels,
            8080
        ),
        MtlsMode::Strict
    );
}

// ── Sidecar ──────────────────────────────────────────────────────────────

fn service_entry(name: &str, host: &str) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "ServiceEntry",
        "default",
        name,
        json!({
            "hosts": [host],
            "location": "MESH_EXTERNAL",
            "resolution": "DNS",
            "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
        }),
    )
}

fn enforced_slice(translation: &K8sTranslation) -> MeshSlice {
    let config = GatewayConfig {
        mesh: translation.config.mesh.clone(),
        ..GatewayConfig::default()
    };
    MeshSlice::from_gateway_config(
        &config,
        MeshSliceRequest {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            enforce_sidecar_egress: true,
            ..MeshSliceRequest::default()
        },
    )
}

/// A refused Sidecar with a malformed `egress` must not widen the workload's
/// egress scope or REGISTRY_ONLY registry: it blocks all egress instead.
#[test]
fn refused_sidecar_egress_blocks_all_egress_with_registry_only() {
    let refused = object(
        "networking.istio.io/v1",
        "Sidecar",
        "default",
        "default",
        json!({
            "egress": [{"hosts": "not-an-array"}],
            "outboundTrafficPolicy": {"mode": "ALLOW_ANY"}
        }),
    );
    let (translation, refused_names) =
        translate(&[refused, service_entry("external", "api.example.com")]);
    assert_eq!(refused_names, vec!["default".to_string()]);
    let mesh = mesh(&translation);
    assert_eq!(mesh.sidecars.len(), 1);
    let marker = &mesh.sidecars[0];
    assert!(!marker.egress_inherits_defaults);
    assert!(marker.egress.is_empty());
    assert_eq!(
        marker.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );

    let slice = enforced_slice(&translation);
    assert!(
        slice.service_entries.is_empty(),
        "no external host is admitted by a block-all marker: {:?}",
        slice.service_entries
    );
    assert_eq!(
        slice.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "the workload's registry gate is armed, not left at ALLOW_ANY"
    );
    assert_admitted(&translation);
}

/// A refused Sidecar whose `egress` does translate keeps that egress exactly,
/// and its malformed `ingress` replaces the default inbound listeners with
/// none instead of restoring them.
#[test]
fn refused_sidecar_ingress_declares_no_inbound_listeners_and_keeps_valid_egress() {
    let refused = object(
        "networking.istio.io/v1",
        "Sidecar",
        "default",
        "default",
        json!({
            "egress": [{"hosts": ["*/api.example.com"]}],
            "ingress": "not-an-array"
        }),
    );
    let (translation, refused_names) = translate(&[
        refused,
        service_entry("allowed", "api.example.com"),
        service_entry("unlisted", "other.example.com"),
    ]);
    assert_eq!(refused_names, vec!["default".to_string()]);
    let marker = &mesh(&translation).sidecars[0];
    assert!(marker.ingress_declared);
    assert!(marker.ingress.is_empty());
    assert_eq!(marker.egress.len(), 1);
    assert_eq!(marker.outbound_traffic_policy, None);

    let slice = enforced_slice(&translation);
    assert!(
        slice.sidecar_ingress_declared,
        "the default inbound listeners stay replaced"
    );
    let admitted: Vec<&str> = slice
        .service_entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(admitted, vec!["allowed"]);
}

// ── Scope: markers reach only the workloads they select ────────────────────
//
// `decide` above evaluates every published policy. These tests instead build
// the per-workload slice (`MeshSlice::from_gateway_config`, which narrows
// policies with `policy_scope_applies_to_workload`) so the markers' blast
// radius is pinned end to end, not just by the `PolicyScope` value.

fn workload_slice(translation: &K8sTranslation, namespace: &str, app: &str) -> MeshSlice {
    let config = GatewayConfig {
        mesh: translation.config.mesh.clone(),
        ..GatewayConfig::default()
    };
    MeshSlice::from_gateway_config(
        &config,
        MeshSliceRequest {
            node_id: format!("{namespace}-{app}"),
            namespace: namespace.to_string(),
            labels: std::collections::BTreeMap::from([("app".to_string(), app.to_string())]),
            ..MeshSliceRequest::default()
        },
    )
}

fn decide_for(slice: &MeshSlice, request: &MeshAuthzRequest) -> MeshAuthzDecision {
    evaluate_mesh_authorization_policies(slice.mesh_policies.iter(), request)
}

/// A refused selector-scoped ALLOW denies only the workloads it selects.
#[test]
fn refused_selector_allow_marker_reaches_only_selected_workloads() {
    let refused = authorization_policy(
        "allow-office",
        json!({
            "selector": {"matchLabels": {"app": "api"}},
            "action": "ALLOW",
            "rules": [{"from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[refused]);
    assert_eq!(refused_names, vec!["allow-office".to_string()]);

    let api = workload_slice(&translation, "default", "api");
    assert!(
        is_deny(&decide_for(&api, &http("/anything"))),
        "the selected workload keeps the implicit-deny floor"
    );
    for (namespace, app) in [("default", "web"), ("other", "api")] {
        let slice = workload_slice(&translation, namespace, app);
        assert!(
            slice.mesh_policies.is_empty(),
            "{namespace}/{app} is not selected: {:?}",
            slice.mesh_policies
        );
        assert_eq!(
            decide_for(&slice, &http("/anything")),
            MeshAuthzDecision::Allow,
            "{namespace}/{app} must not inherit the refused policy's floor"
        );
    }
}

/// A refused selector-less DENY covers its namespace and nothing else; the
/// same policy in the Istio root namespace covers the mesh.
#[test]
fn refused_deny_marker_covers_its_namespace_or_the_mesh_from_the_root() {
    let tenant = authorization_policy(
        "deny-tenant",
        json!({
            "action": "DENY",
            "rules": [{"from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}]}]
        }),
    );
    let (translation, _) = translate(&[tenant]);
    assert!(is_deny(&decide_for(
        &workload_slice(&translation, "default", "web"),
        &http("/")
    )));
    assert_eq!(
        decide_for(&workload_slice(&translation, "other", "web"), &http("/")),
        MeshAuthzDecision::Allow,
        "a namespace-scoped marker must not reach another namespace"
    );

    let root = object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        ROOT_NS,
        "deny-root",
        json!({
            "action": "DENY",
            "rules": [{"from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}]}]
        }),
    );
    let (translation, refused_names) = translate(&[root]);
    assert_eq!(refused_names, vec!["deny-root".to_string()]);
    for namespace in ["default", "other"] {
        assert!(
            is_deny(&decide_for(
                &workload_slice(&translation, namespace, "web"),
                &l4()
            )),
            "a refused mesh-wide DENY denies {namespace} too"
        );
    }
}

/// A refused workload-scoped STRICT PeerAuthentication, resolved through each
/// workload's own slice: the selected workload is STRICT, a sibling keeps the
/// namespace's PERMISSIVE posture.
#[test]
fn refused_peer_authentication_marker_reaches_only_selected_workloads() {
    let namespace_permissive = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "default",
        "namespace-permissive",
        json!({ "mtls": {"mode": "PERMISSIVE"} }),
    );
    let refused = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "default",
        "api-strict",
        json!({
            "selector": {"matchLabels": {"app": "api"}},
            "mtls": {"mode": "STRICT"},
            "portLevelMtls": {"99999": {"mode": "PERMISSIVE"}}
        }),
    );
    let (translation, refused_names) = translate(&[namespace_permissive, refused]);
    assert_eq!(refused_names, vec!["api-strict".to_string()]);
    assert_eq!(
        workload_slice(&translation, "default", "api").resolve_inbound_mtls_mode_fail_closed(8080),
        MtlsMode::Strict
    );
    assert_eq!(
        workload_slice(&translation, "default", "web").resolve_inbound_mtls_mode_fail_closed(8080),
        MtlsMode::Permissive
    );
}
