//! AuthorizationPolicy `targetRefs` attachment matching and fail-closed config
//! validation (issue #3226).
//!
//! The load-bearing invariant here is that **slice retention is OR over the
//! whole attachment list and never prunes the non-matching arms**, so no
//! runtime consumer may infer "this policy is loaded, therefore its Gateway
//! arm matched". Every test that mixes a matching Service ref with a
//! non-matching waypoint ref is guarding that boundary.

use std::collections::HashMap;

use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshPolicy, MeshProxyConfig, MeshRequestAuthentication, MeshRule, MeshService,
    MeshWaypointBinding, PeerAuthentication, PolicyAction, PolicyScope, PolicyTargetAttachment,
    WaypointAttachment, Workload, WorkloadSelector, policy_scope_applies_with_waypoint,
};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization_policies,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

const WAYPOINT_NS: &str = "default";
const WAYPOINT_A: &str = "waypoint-a";
const WAYPOINT_B: &str = "waypoint-b";
const CLASS_ISTIO: &str = "istio-waypoint";
const CLASS_FERRUM: &str = "ferrum-waypoint";

fn spiffe(id: &str) -> SpiffeId {
    SpiffeId::new(id).expect("valid spiffe")
}

fn waypoint_a() -> WaypointAttachment<'static> {
    WaypointAttachment {
        namespace: WAYPOINT_NS,
        name: Some(WAYPOINT_A),
        gateway_class: Some(CLASS_ISTIO),
    }
}

/// A non-waypoint proxy (Sidecar / NodeWaypoint): no attachment may apply.
fn not_a_waypoint() -> WaypointAttachment<'static> {
    WaypointAttachment {
        namespace: WAYPOINT_NS,
        name: None,
        gateway_class: None,
    }
}

fn policy(name: &str, action: PolicyAction, scope: PolicyScope) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: WAYPOINT_NS.to_string(),
        scope,
        rules: vec![MeshRule {
            action,
            ..MeshRule::default()
        }],
    }
}

fn target_refs(attachments: Vec<PolicyTargetAttachment>) -> PolicyScope {
    PolicyScope::TargetRefs { attachments }
}

fn service_ref(name: &str) -> PolicyTargetAttachment {
    PolicyTargetAttachment::Service {
        namespace: WAYPOINT_NS.to_string(),
        name: name.to_string(),
    }
}

fn gateway_ref(name: &str) -> PolicyTargetAttachment {
    PolicyTargetAttachment::Gateway {
        namespace: WAYPOINT_NS.to_string(),
        name: name.to_string(),
    }
}

fn class_ref(name: &str) -> PolicyTargetAttachment {
    PolicyTargetAttachment::GatewayClass {
        name: name.to_string(),
    }
}

fn workload_for(service: &str) -> Workload {
    Workload {
        spiffe_id: spiffe(&format!(
            "spiffe://cluster.local/ns/{WAYPOINT_NS}/sa/{service}"
        )),
        selector: WorkloadSelector {
            // Deliberately IDENTICAL across services: shared pod-selector
            // labels must never make one service inherit another's policy.
            labels: HashMap::from([("app".to_string(), "backend".to_string())]),
            namespace: Some(WAYPOINT_NS.to_string()),
        },
        service_name: service.to_string(),
        service_namespace: None,
        addresses: vec!["10.0.0.1".to_string()],
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: WAYPOINT_NS.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(service.to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

/// A destination scope as the `mesh_authz` index builds it: keyed by the
/// Service it was indexed under, not by `Workload.service_name`.
fn destination(service: &str) -> PolicyScopeCache {
    PolicyScopeCache::for_destination_service(&workload_for(service), WAYPOINT_NS, service)
}

fn decision_for(policies: &[MeshPolicy], scope: &PolicyScopeCache) -> MeshAuthzDecision {
    let request = MeshAuthzRequest {
        method: Some("GET".to_string()),
        path: Some("/".to_string()),
        ..MeshAuthzRequest::default()
    };
    evaluate_mesh_authorization_policies(
        policies
            .iter()
            .filter(|policy| scope.policy_applies_for_destination(policy, waypoint_a())),
        &request,
    )
}

// ── Exact attachment matching ────────────────────────────────────────────

#[test]
fn waypoint_attachment_matches_only_the_exact_gateway_and_class() {
    let waypoint = waypoint_a();

    assert!(waypoint.matches(&gateway_ref(WAYPOINT_A)));
    assert!(!waypoint.matches(&gateway_ref(WAYPOINT_B)));
    assert!(
        !waypoint.matches(&PolicyTargetAttachment::Gateway {
            namespace: "other".to_string(),
            name: WAYPOINT_A.to_string(),
        }),
        "a same-named Gateway in another namespace is a different resource"
    );

    assert!(waypoint.matches(&class_ref(CLASS_ISTIO)));
    assert!(
        !waypoint.matches(&class_ref(CLASS_FERRUM)),
        "istio-waypoint must never attach to a ferrum-waypoint Gateway"
    );

    // Service identity is never decided by the waypoint predicate.
    assert!(!waypoint.matches(&service_ref("reviews")));

    // Missing class evidence fails closed; a non-waypoint proxy matches nothing.
    let no_class = WaypointAttachment {
        gateway_class: None,
        ..waypoint
    };
    assert!(!no_class.matches(&class_ref(CLASS_ISTIO)));
    assert!(
        no_class.matches(&gateway_ref(WAYPOINT_A)),
        "an unknown class does not invalidate an exact Gateway-name attachment"
    );
    assert!(!not_a_waypoint().matches(&gateway_ref(WAYPOINT_A)));
    assert!(!not_a_waypoint().matches(&class_ref(CLASS_ISTIO)));
}

// ── Finding 1: mixed attachments must not broaden ────────────────────────

/// `targetRefs: [Service reviews, Gateway waypoint-b]` is legitimately retained
/// at waypoint-a because the Service arm matches. The unmatched `waypoint-b`
/// arm must NOT make the policy apply to every other destination at waypoint-a.
#[test]
fn mixed_service_and_other_gateway_ref_does_not_broaden_to_sibling_destinations() {
    let deny = policy(
        "deny-reviews",
        PolicyAction::Deny,
        target_refs(vec![service_ref("reviews"), gateway_ref(WAYPOINT_B)]),
    );

    assert!(destination("reviews").policy_applies_for_destination(&deny, waypoint_a()));
    assert!(
        !destination("ratings").policy_applies_for_destination(&deny, waypoint_a()),
        "the unmatched waypoint-b Gateway arm must not attach the policy to a sibling service"
    );

    // And the real authorization outcome follows: DENY on the named service,
    // untouched on the sibling.
    assert_eq!(
        decision_for(std::slice::from_ref(&deny), &destination("reviews")),
        MeshAuthzDecision::Deny {
            policy: "deny-reviews".to_string()
        }
    );
    assert_eq!(
        decision_for(std::slice::from_ref(&deny), &destination("ratings")),
        MeshAuthzDecision::Allow
    );
}

/// Same shape with an unmatched `GatewayClass` arm.
#[test]
fn mixed_service_and_other_gateway_class_ref_does_not_broaden_to_sibling_destinations() {
    let deny = policy(
        "deny-reviews",
        PolicyAction::Deny,
        target_refs(vec![service_ref("reviews"), class_ref(CLASS_FERRUM)]),
    );

    assert!(destination("reviews").policy_applies_for_destination(&deny, waypoint_a()));
    assert!(
        !destination("ratings").policy_applies_for_destination(&deny, waypoint_a()),
        "an unmatched ferrum-waypoint class arm must not attach at an istio-waypoint waypoint"
    );
    assert_eq!(
        decision_for(std::slice::from_ref(&deny), &destination("ratings")),
        MeshAuthzDecision::Allow
    );
}

/// The ALLOW half of finding 1. An `ALLOW` policy that reaches a destination
/// brings Istio's implicit deny with it, so a broadened `ALLOW` is just as
/// dangerous as a broadened `DENY` — it locks out the sibling service.
#[test]
fn mixed_ref_allow_policy_does_not_implicit_deny_a_sibling_destination() {
    // An ALLOW rule that matches nothing (Istio empty-rule "allow-nothing").
    let allow = MeshPolicy {
        name: "allow-reviews".to_string(),
        namespace: WAYPOINT_NS.to_string(),
        scope: target_refs(vec![service_ref("reviews"), gateway_ref(WAYPOINT_B)]),
        rules: vec![MeshRule {
            action: PolicyAction::Allow,
            never_matches: true,
            ..MeshRule::default()
        }],
    };

    assert_eq!(
        decision_for(std::slice::from_ref(&allow), &destination("reviews")),
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        },
        "the named destination gets the ALLOW policy's implicit deny"
    );
    assert_eq!(
        decision_for(std::slice::from_ref(&allow), &destination("ratings")),
        MeshAuthzDecision::Allow,
        "a sibling destination must not inherit the implicit deny through an unmatched arm"
    );
}

#[test]
fn multiple_matching_service_refs_each_attach_and_others_do_not() {
    let deny = policy(
        "deny-two",
        PolicyAction::Deny,
        target_refs(vec![service_ref("reviews"), service_ref("ratings")]),
    );

    assert!(destination("reviews").policy_applies_for_destination(&deny, waypoint_a()));
    assert!(destination("ratings").policy_applies_for_destination(&deny, waypoint_a()));
    assert!(!destination("details").policy_applies_for_destination(&deny, waypoint_a()));
}

#[test]
fn matching_gateway_ref_applies_to_every_destination_at_that_waypoint() {
    let deny = policy(
        "deny-waypoint",
        PolicyAction::Deny,
        target_refs(vec![gateway_ref(WAYPOINT_A)]),
    );
    for service in ["reviews", "ratings", "details"] {
        assert!(
            destination(service).policy_applies_for_destination(&deny, waypoint_a()),
            "a Gateway attachment governs the whole waypoint"
        );
    }

    let elsewhere = policy(
        "deny-other-waypoint",
        PolicyAction::Deny,
        target_refs(vec![gateway_ref(WAYPOINT_B)]),
    );
    assert!(!destination("reviews").policy_applies_for_destination(&elsewhere, waypoint_a()));
}

#[test]
fn service_target_ref_matches_only_named_destination_not_shared_selector_labels() {
    let deny = policy(
        "deny-reviews",
        PolicyAction::Deny,
        target_refs(vec![service_ref("reviews")]),
    );

    // Both destinations carry identical pod-selector labels by construction.
    assert!(destination("reviews").policy_applies_for_destination(&deny, waypoint_a()));
    assert!(!destination("ratings").policy_applies_for_destination(&deny, waypoint_a()));

    // Bare source-scope matching must never broaden a targeted policy.
    assert!(!destination("reviews").policy_applies(&deny));
}

#[test]
fn destination_membership_is_absent_on_source_scopes_and_fails_closed() {
    let deny = policy(
        "deny-reviews",
        PolicyAction::Deny,
        target_refs(vec![service_ref("reviews")]),
    );

    // `from_workload` / `new` are SOURCE scopes: they carry no destination
    // service membership, so a Service attachment cannot match through them.
    let source = PolicyScopeCache::from_workload(&workload_for("reviews"));
    assert!(source.service_name.is_empty());
    assert!(source.service_namespace.is_empty());
    assert!(!source.policy_applies_for_destination(&deny, waypoint_a()));

    let bare = PolicyScopeCache::new(
        spiffe("spiffe://cluster.local/ns/default/sa/reviews"),
        WAYPOINT_NS,
        HashMap::new(),
    );
    assert!(bare.service_name.is_empty());
    assert!(!bare.policy_applies_for_destination(&deny, waypoint_a()));
}

/// One pod projected through several Services must stay ONE source attestation:
/// `PolicyScopeCache` equality is the collapse used by ambient UDP source
/// indexing and NodeWaypoint capture-destination resolution.
#[test]
fn source_scopes_for_one_pod_collapse_across_service_projections() {
    let via_api = workload_for("api");
    let mut via_alias = workload_for("api");
    via_alias.service_name = "api-alias".to_string();

    assert_eq!(
        PolicyScopeCache::from_workload(&via_api),
        PolicyScopeCache::from_workload(&via_alias),
        "differing Service projections must not become a source-scope conflict"
    );

    let mut divergent = via_alias.clone();
    divergent.selector.labels = HashMap::from([("app".to_string(), "other".to_string())]);
    assert_ne!(
        PolicyScopeCache::from_workload(&via_api),
        PolicyScopeCache::from_workload(&divergent),
        "genuinely divergent labels remain a source-scope conflict"
    );

    // Destination scopes keyed by different Services do differ — that is the
    // whole point of `for_destination_service`.
    assert_ne!(destination("api"), destination("api-alias"));
}

/// `targetRefs` policies apply at waypoint proxies only. On a Sidecar or
/// NodeWaypoint destination path they must match nothing rather than becoming
/// effectively mesh-wide.
#[test]
fn target_refs_never_apply_without_waypoint_context() {
    for scope in [
        target_refs(vec![service_ref("reviews")]),
        target_refs(vec![gateway_ref(WAYPOINT_A)]),
        target_refs(vec![class_ref(CLASS_ISTIO)]),
    ] {
        let deny = policy("deny", PolicyAction::Deny, scope);
        assert!(
            !destination("reviews").policy_applies_for_destination(&deny, not_a_waypoint()),
            "a targeted policy must not apply on a non-waypoint proxy"
        );
    }
}

#[test]
fn policy_scope_applies_with_waypoint_delegates_to_the_shared_predicate() {
    let labels: HashMap<String, String> = HashMap::new();
    let gateway = policy(
        "gw",
        PolicyAction::Deny,
        target_refs(vec![gateway_ref(WAYPOINT_A)]),
    );
    let class = policy(
        "class",
        PolicyAction::Deny,
        target_refs(vec![class_ref(CLASS_ISTIO)]),
    );

    assert!(policy_scope_applies_with_waypoint(
        &gateway,
        WAYPOINT_NS,
        &labels,
        Some(WAYPOINT_A),
        Some(CLASS_ISTIO),
    ));
    assert!(!policy_scope_applies_with_waypoint(
        &gateway,
        WAYPOINT_NS,
        &labels,
        Some(WAYPOINT_B),
        Some(CLASS_ISTIO),
    ));
    assert!(policy_scope_applies_with_waypoint(
        &class,
        WAYPOINT_NS,
        &labels,
        Some(WAYPOINT_A),
        Some(CLASS_ISTIO),
    ));
    assert!(!policy_scope_applies_with_waypoint(
        &class,
        WAYPOINT_NS,
        &labels,
        Some(WAYPOINT_A),
        Some(CLASS_FERRUM),
    ));
    // Missing class evidence fails closed — never "any waypoint".
    assert!(!policy_scope_applies_with_waypoint(
        &class,
        WAYPOINT_NS,
        &labels,
        Some(WAYPOINT_A),
        None,
    ));
    // No waypoint at all: nothing attaches.
    assert!(!policy_scope_applies_with_waypoint(
        &gateway,
        WAYPOINT_NS,
        &labels,
        None,
        None,
    ));
}

// ── Config-boundary validation ───────────────────────────────────────────

fn mesh_service(namespace: &str, name: &str) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
        uid: None,
    }
}

fn binding(namespace: &str, name: &str, class: Option<&str>) -> MeshWaypointBinding {
    MeshWaypointBinding {
        name: name.to_string(),
        namespace: namespace.to_string(),
        waypoint_for: "service".to_string(),
        gateway_class_name: class.map(str::to_string),
        services: Vec::new(),
    }
}

#[test]
fn empty_target_refs_attachments_fail_closed_at_config_boundary() {
    let errors = MeshConfig {
        mesh_policies: vec![policy("deny", PolicyAction::Deny, target_refs(Vec::new()))],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("attachments must not be empty")),
        "expected empty-attachments error, got {errors:?}"
    );
}

#[test]
fn mesh_policy_target_refs_require_referenced_service() {
    let errors = MeshConfig {
        mesh_policies: vec![policy(
            "deny",
            PolicyAction::Deny,
            target_refs(vec![service_ref("missing")]),
        )],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("Service 'default/missing' was not found")),
        "expected missing Service error, got {errors:?}"
    );
}

#[test]
fn mesh_policy_gateway_target_refs_require_waypoint_binding() {
    let scope = target_refs(vec![gateway_ref(WAYPOINT_A)]);
    let with_binding = MeshConfig {
        mesh_policies: vec![policy("deny", PolicyAction::Deny, scope.clone())],
        waypoint_bindings: vec![binding(WAYPOINT_NS, WAYPOINT_A, Some(CLASS_ISTIO))],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        with_binding
            .iter()
            .all(|error| !error.contains("Gateway 'default/waypoint-a'")),
        "present binding must validate: {with_binding:?}"
    );

    // An empty bindings inventory cannot prove absence (DP slices reconstruct
    // MeshConfig without waypoint_bindings). Runtime matching stays exact.
    let empty_inventory = MeshConfig {
        mesh_policies: vec![policy("deny", PolicyAction::Deny, scope.clone())],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        empty_inventory
            .iter()
            .all(|error| !error.contains("Gateway 'default/waypoint-a' was not found")),
        "empty bindings inventory must not invent a missing-Gateway rejection: {empty_inventory:?}"
    );

    let missing = MeshConfig {
        mesh_policies: vec![policy("deny", PolicyAction::Deny, scope)],
        waypoint_bindings: vec![binding(WAYPOINT_NS, WAYPOINT_B, Some(CLASS_ISTIO))],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        missing
            .iter()
            .any(|error| error.contains("Gateway 'default/waypoint-a' was not found")),
        "expected missing Gateway error against a real bindings inventory, got {missing:?}"
    );
}

/// A mixed `{valid Service, missing/inapplicable Gateway}` policy must validate:
/// the unresolved sibling arm must not reject the whole MeshConfig when a valid
/// applicable target remains. Runtime matching stays exact (no broadening).
#[test]
fn mixed_valid_and_missing_gateway_target_refs_do_not_reject_config() {
    let errors = MeshConfig {
        services: vec![mesh_service(WAYPOINT_NS, "reviews")],
        waypoint_bindings: vec![binding(WAYPOINT_NS, WAYPOINT_A, Some(CLASS_ISTIO))],
        mesh_policies: vec![policy(
            "deny",
            PolicyAction::Deny,
            target_refs(vec![service_ref("reviews"), gateway_ref(WAYPOINT_B)]),
        )],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .all(|error| !error.contains("target_refs") && !error.contains("Gateway")),
        "mixed valid Service + missing Gateway must validate: {errors:?}"
    );
}

/// A non-root `GatewayClass` arm is an OWNERSHIP refusal, not an inventory
/// miss, so it must hard-fail even when a valid sibling Service arm would
/// otherwise keep the policy alive.
///
/// Unlike a missing Service/Gateway — which names an exact `(namespace, name)`
/// that nothing can match — a `GatewayClass` arm is matched by class name
/// ALONE (`WaypointAttachment::matches`): no namespace, no Gateway name. If it
/// were deferred and dropped, any namespace could buy cluster-wide reach over
/// every waypoint of that class simply by pairing it with one valid
/// same-namespace Service arm. The K8s translator rejects this
/// unconditionally; the native/file/`MeshSubscribe` boundary must match.
#[test]
fn non_root_gateway_class_hard_fails_even_beside_a_valid_service_arm() {
    let errors = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![mesh_service(WAYPOINT_NS, "reviews")],
        // The Service arm is valid and applicable; it must NOT launder the
        // class-wide arm into an accepted policy.
        mesh_policies: vec![policy(
            "deny",
            PolicyAction::Deny,
            target_refs(vec![service_ref("reviews"), class_ref(CLASS_FERRUM)]),
        )],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("GatewayClass") && error.contains("root namespace")),
        "a non-root GatewayClass arm must reject even beside a valid Service arm: {errors:?}"
    );

    // Control: the same policy owned BY the root namespace is accepted, so the
    // rejection above is the ownership rule and not blanket mixed-arm refusal.
    let root_owned = MeshConfig {
        istio_root_namespace: WAYPOINT_NS.to_string(),
        services: vec![mesh_service(WAYPOINT_NS, "reviews")],
        mesh_policies: vec![policy(
            "deny",
            PolicyAction::Deny,
            target_refs(vec![service_ref("reviews"), class_ref(CLASS_FERRUM)]),
        )],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        root_owned
            .iter()
            .all(|error| !error.contains("GatewayClass") && !error.contains("root namespace")),
        "a root-owned Service + GatewayClass policy must validate: {root_owned:?}"
    );
}

/// All-invalid / no-applicable-target boundary: every attachment unresolved
/// must still fail closed so the policy cannot silently broaden.
#[test]
fn all_invalid_target_refs_fail_closed_without_broadening() {
    let missing_only = MeshConfig {
        waypoint_bindings: vec![binding(WAYPOINT_NS, WAYPOINT_B, Some(CLASS_ISTIO))],
        mesh_policies: vec![policy(
            "deny",
            PolicyAction::Deny,
            target_refs(vec![gateway_ref(WAYPOINT_A), service_ref("missing")]),
        )],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        missing_only.iter().any(|error| {
            error.contains("Gateway 'default/waypoint-a' was not found")
                || error.contains("Service 'default/missing' was not found")
        }),
        "all-unresolved attachments must fail closed: {missing_only:?}"
    );

    let non_root_class_only = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        mesh_policies: vec![policy(
            "deny",
            PolicyAction::Deny,
            target_refs(vec![class_ref(CLASS_ISTIO)]),
        )],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        non_root_class_only
            .iter()
            .any(|error| error.contains("GatewayClass") && error.contains("root namespace")),
        "a sole non-root GatewayClass policy must still fail closed: {non_root_class_only:?}"
    );
}

/// Istio lists Service / Gateway `targetRefs` as same-namespace only. The
/// native/file boundary must not accept what the K8s translator rejects — a
/// cross-namespace attachment would additionally be dropped by the CP's own
/// owner-namespace filter before reaching the target DP slice.
#[test]
fn cross_namespace_target_refs_fail_closed_at_config_boundary() {
    let errors = MeshConfig {
        services: vec![mesh_service("other", "payments")],
        waypoint_bindings: vec![binding("other", WAYPOINT_A, Some(CLASS_ISTIO))],
        mesh_policies: vec![policy(
            "deny",
            PolicyAction::Deny,
            target_refs(vec![
                PolicyTargetAttachment::Service {
                    namespace: "other".to_string(),
                    name: "payments".to_string(),
                },
                PolicyTargetAttachment::Gateway {
                    namespace: "other".to_string(),
                    name: WAYPOINT_A.to_string(),
                },
            ]),
        )],
        ..MeshConfig::default()
    }
    .validate();

    assert!(
        errors
            .iter()
            .any(|e| e.contains("Service 'other/payments'") && e.contains("same-namespace only")),
        "cross-namespace Service attachment must reject: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("Gateway 'other/waypoint-a'") && e.contains("same-namespace only")),
        "cross-namespace Gateway attachment must reject: {errors:?}"
    );
}

#[test]
fn gateway_class_target_refs_require_root_namespace_ownership() {
    let scope = target_refs(vec![class_ref(CLASS_ISTIO)]);

    // Owned by a non-root namespace → rejected.
    let non_root = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        mesh_policies: vec![policy("deny", PolicyAction::Deny, scope.clone())],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        non_root
            .iter()
            .any(|e| e.contains("GatewayClass") && e.contains("root namespace")),
        "a non-root GatewayClass policy must reject: {non_root:?}"
    );

    // Owned by the root namespace → accepted.
    let root_owned = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        mesh_policies: vec![MeshPolicy {
            namespace: "istio-system".to_string(),
            ..policy("deny", PolicyAction::Deny, scope)
        }],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        root_owned.iter().all(|e| !e.contains("GatewayClass")),
        "a root-namespace GatewayClass policy must validate: {root_owned:?}"
    );
}

#[test]
fn unsupported_gateway_class_name_fails_closed() {
    let errors = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        mesh_policies: vec![MeshPolicy {
            namespace: "istio-system".to_string(),
            ..policy(
                "deny",
                PolicyAction::Deny,
                target_refs(vec![class_ref("some-other-class")]),
            )
        }],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("GatewayClass 'some-other-class' is unsupported")),
        "expected unsupported-class error, got {errors:?}"
    );
}

#[test]
fn target_refs_rejected_on_shared_scope_consumers() {
    let scope = target_refs(vec![service_ref("reviews")]);
    let mesh = MeshConfig {
        services: vec![mesh_service(WAYPOINT_NS, "reviews")],
        peer_authentications: vec![PeerAuthentication {
            name: "pa".to_string(),
            namespace: WAYPOINT_NS.to_string(),
            scope: Some(scope.clone()),
            selector: None,
            mtls_mode: Default::default(),
            port_overrides: HashMap::new(),
        }],
        request_authentications: vec![MeshRequestAuthentication {
            name: "ra".to_string(),
            namespace: WAYPOINT_NS.to_string(),
            scope: scope.clone(),
            jwt_rules: Vec::new(),
        }],
        proxy_configs: vec![MeshProxyConfig {
            name: "pc".to_string(),
            namespace: WAYPOINT_NS.to_string(),
            scope: scope.clone(),
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: None,
        }],
        telemetry_resources: vec![ferrum_edge::modes::mesh::config::MeshTelemetryResource {
            name: "tel".to_string(),
            namespace: WAYPOINT_NS.to_string(),
            scope,
            config: Default::default(),
        }],
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    for kind in [
        "PeerAuthentication",
        "MeshRequestAuthentication",
        "MeshProxyConfig",
        "MeshTelemetryResource",
    ] {
        assert!(
            errors
                .iter()
                .any(|error| error.contains(kind) && error.contains("target_refs is not supported")),
            "expected {kind} targetRefs rejection, got {errors:?}"
        );
    }
}

/// Ferrum has no ServiceEntry-to-waypoint association model, so the attachment
/// variant does not exist at all — a hand-authored native/file config naming it
/// fails to deserialize rather than producing an inert security policy.
#[test]
fn service_entry_attachment_kind_is_not_a_representable_scope() {
    let json = serde_json::json!({
        "kind": "target_refs",
        "attachments": [{
            "kind": "service_entry",
            "namespace": "default",
            "name": "ext"
        }]
    });
    let parsed: Result<PolicyScope, _> = serde_json::from_value(json);
    assert!(
        parsed.is_err(),
        "a service_entry attachment must not deserialize into a PolicyScope"
    );
}

#[test]
fn workload_selector_still_matches_without_target_refs() {
    let selector = policy(
        "selector",
        PolicyAction::Deny,
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "backend".to_string())]),
                namespace: Some(WAYPOINT_NS.to_string()),
            },
        },
    );
    let cache = PolicyScopeCache::new(
        spiffe("spiffe://cluster.local/ns/default/sa/reviews"),
        WAYPOINT_NS,
        HashMap::from([("app".to_string(), "backend".to_string())]),
    );
    assert!(cache.policy_applies(&selector));
    assert!(cache.policy_applies_for_destination(&selector, waypoint_a()));
}
