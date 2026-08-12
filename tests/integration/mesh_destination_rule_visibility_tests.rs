//! DestinationRule export visibility and lookup-tier resolution
//! (issues #2465 and #2469).
//!
//! These two behaviours are one semantic change and are tested together
//! because they compose: `exportTo` decides whether a rule is a candidate at
//! all, and only then does the client → target-service → root lookup order
//! decide which candidate wins. Testing them separately would miss the
//! interesting failure — a root-namespace fallback resurrecting a rule the
//! subscriber was never allowed to see.
//!
//! Coverage:
//!
//! * Kubernetes `spec.exportTo` parsing: omitted, explicitly empty, `.`, `*`,
//!   explicit allowlists, and the fail-closed rejection of unsupported,
//!   malformed, conflicting, and over-long values.
//! * Native/file semantics for an omitted-or-empty list (namespace-local by
//!   Ferrum convention) and validation rejection of hostile values.
//! * Slice narrowing: a namespace-local rule never reaches an external
//!   subscriber, an allowlisted namespace does, an unlisted one does not.
//! * Lookup tiers with the namespaces deliberately sorted BOTH ways, so a
//!   passing result cannot be an accident of lexical resource order.
//! * Client → service → root fallback, a custom root namespace, and
//!   same-tier merge determinism.
//! * Carrier/native parity and reload/dedupe behaviour for a visibility-only
//!   or root-namespace-only change.
//! * Composition with Sidecar egress scope.
//! * Target-service OWNERSHIP: a ServiceEntry's declaring namespace is the
//!   service tier for its external host; an unrelated namespace cannot become
//!   one by publishing a rule; contested ownership disables the tier instead
//!   of guessing an owner; and the admission resolver never disagrees with
//!   `destination_rule_host_matches` in a direction that invents a tier.
//! * CP/DP agreement on that ownership for a MACHINE-SYNTHESIZED upstream: an
//!   EgressGateway upstream is stamped with the gateway's own namespace, so the
//!   materialization tier pass must resolve the external host's owner from the
//!   ServiceEntry index rather than from the upstream — and must still refuse a
//!   claimant that does not own it.

use std::collections::HashMap;

use ferrum_edge::config::types::{GatewayConfig, Upstream, UpstreamTarget};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshDestinationRule, MeshLoadBalancer, MeshOutlierDetection,
    MeshService, MeshSidecar, MeshSidecarEgress, MeshSimpleLb, MeshTrafficPolicy,
    MeshTrafficPolicyTls, MtlsMode, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
    Workload, WorkloadRef, destination_rule_exported_to_namespace,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh};
use serde_json::{Value, json};

use super::mesh_test_support::{default_mesh_runtime, http_proxy, http_upstream};

const TRUST_DOMAIN: &str = "cluster.local";

// ── Fixtures ─────────────────────────────────────────────────────────────

fn service_in(namespace: &str, name: &str) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: Default::default(),
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: SpiffeId::new(format!("spiffe://{TRUST_DOMAIN}/ns/{namespace}/sa/{name}"))
                .expect("valid spiffe id"),
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
    }
}

fn workload_in(namespace: &str, name: &str) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(format!("spiffe://{TRUST_DOMAIN}/ns/{namespace}/sa/{name}"))
            .expect("valid spiffe id"),
        selector: Default::default(),
        service_name: name.to_string(),
        service_namespace: None,
        addresses: Vec::new(),
        ports: Vec::new(),
        trust_domain: TrustDomain::new(TRUST_DOMAIN).expect("trust domain"),
        namespace: namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

/// A DestinationRule carrying one identifiable knob (`connect_timeout_ms`) so a
/// test can tell WHICH rule won, not merely that some rule applied.
fn rule(
    namespace: &str,
    name: &str,
    host: &str,
    connect_timeout_ms: u64,
    export_to: &[&str],
) -> MeshDestinationRule {
    MeshDestinationRule {
        name: name.to_string(),
        namespace: namespace.to_string(),
        host: host.to_string(),
        traffic_policy: Some(MeshTrafficPolicy {
            connect_timeout_ms: Some(connect_timeout_ms),
            ..MeshTrafficPolicy::default()
        }),
        port_level_settings: HashMap::new(),
        subsets: Vec::new(),
        export_to: export_to.iter().map(|e| (*e).to_string()).collect(),
    }
}

fn config_with(mesh: MeshConfig) -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

fn request_for(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: format!("node-{namespace}"),
        namespace: namespace.to_string(),
        cluster_domain: TRUST_DOMAIN.to_string(),
        ..MeshSliceRequest::default()
    }
    .with_enforce_sidecar_egress(true)
}

/// A namespace-default Sidecar whose egress scope admits everything (`*/*`).
///
/// Cross-namespace DestinationRule lookup only arises under an applicable
/// Sidecar — without one the slice is namespace-local (`services` is narrowed
/// the same way), so the destination has no upstream to carry policy onto.
/// Using the maximally permissive scope keeps `exportTo` and lookup-tier
/// behaviour as the ONLY thing these tests measure.
fn permissive_sidecar(namespace: &str) -> MeshSidecar {
    sidecar_admitting(namespace, &["*/*"])
}

/// The slice a subscriber in `namespace` receives, with an all-admitting
/// Sidecar in the subscriber's namespace (added only when the fixture does not
/// declare its own) so cross-namespace destinations are in scope.
fn slice_for(mesh: &MeshConfig, namespace: &str) -> MeshSlice {
    let mut mesh = mesh.clone();
    if mesh.sidecars.is_empty() {
        mesh.sidecars.push(permissive_sidecar(namespace));
    }
    MeshSlice::from_gateway_config(&config_with(mesh), request_for(namespace))
}

/// Names of the rules a subscriber in `namespace` actually receives.
fn admitted_rule_names(mesh: &MeshConfig, namespace: &str) -> Vec<String> {
    slice_for(mesh, namespace)
        .destination_rules
        .into_iter()
        .map(|dr| dr.name)
        .collect()
}

// ── Kubernetes `spec.exportTo` parsing ───────────────────────────────────

fn k8s_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "beta".to_string(),
        TrustDomain::new(TRUST_DOMAIN).expect("trust domain"),
    )
}

fn dr_object(namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "DestinationRule".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn translate_dr(spec: Value) -> Result<MeshDestinationRule, String> {
    let result = translate_k8s_objects(&[dr_object("beta", "reviews-dr", spec)], k8s_options())
        .map_err(|e| e.to_string())?;
    let mesh = result
        .config
        .mesh
        .ok_or_else(|| "no mesh config".to_string())?;
    mesh.destination_rules
        .into_iter()
        .next()
        .ok_or_else(|| "no destination rule".to_string())
}

#[test]
fn k8s_omitted_export_to_is_materialized_as_istios_public_default() {
    let dr = translate_dr(json!({ "host": "reviews.beta.svc.cluster.local" }))
        .expect("translation succeeds");
    assert_eq!(
        dr.export_to,
        vec!["*".to_string()],
        "an omitted spec.exportTo must become an explicit ['*'] — leaving it \
         empty would silently make every Kubernetes DestinationRule \
         namespace-local"
    );
    assert!(destination_rule_exported_to_namespace(&dr, "alpha"));
}

#[test]
fn k8s_explicitly_empty_export_to_is_also_istios_public_default() {
    let dr = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": [],
    }))
    .expect("translation succeeds");
    assert_eq!(dr.export_to, vec!["*".to_string()]);
}

#[test]
fn k8s_dot_export_to_is_namespace_local() {
    let dr = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": ["."],
    }))
    .expect("translation succeeds");
    assert_eq!(dr.export_to, vec![".".to_string()]);
    assert!(
        destination_rule_exported_to_namespace(&dr, "beta"),
        "'.' must expand against the DECLARING namespace"
    );
    assert!(!destination_rule_exported_to_namespace(&dr, "alpha"));
}

#[test]
fn k8s_wildcard_and_explicit_allowlist_export_to_are_preserved() {
    let public = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": ["*"],
    }))
    .expect("translation succeeds");
    assert!(destination_rule_exported_to_namespace(&public, "anything"));

    let allowlisted = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": ["alpha", "gamma"],
    }))
    .expect("translation succeeds");
    assert_eq!(
        allowlisted.export_to,
        vec!["alpha".to_string(), "gamma".to_string()]
    );
    assert!(destination_rule_exported_to_namespace(
        &allowlisted,
        "alpha"
    ));
    assert!(destination_rule_exported_to_namespace(
        &allowlisted,
        "gamma"
    ));
    assert!(
        !destination_rule_exported_to_namespace(&allowlisted, "delta"),
        "a namespace absent from the allowlist must not see the rule"
    );
    assert!(
        !destination_rule_exported_to_namespace(&allowlisted, "beta"),
        "an explicit allowlist that omits the declaring namespace does not \
         implicitly re-add it"
    );
}

#[test]
fn k8s_rejects_unsupported_and_malformed_export_to_values_fail_closed() {
    for (label, spec) in [
        (
            "tilde is not a supported exportTo value",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["~"]}),
        ),
        (
            "empty entry",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": [""]}),
        ),
        (
            "uppercase namespace",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["Alpha"]}),
        ),
        (
            "namespace with a slash",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["alpha/reviews"]}),
        ),
        (
            "wildcard conflicting with an explicit namespace",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": ["*", "alpha"]}),
        ),
        (
            "non-array exportTo",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": "alpha"}),
        ),
        (
            "non-string entry",
            json!({"host": "reviews.beta.svc.cluster.local", "exportTo": [7]}),
        ),
    ] {
        let outcome = translate_dr(spec);
        assert!(
            outcome.is_err(),
            "{label}: must be rejected rather than interpreted, got {outcome:?}"
        );
    }
}

#[test]
fn k8s_rejects_an_over_long_export_to_list() {
    let entries: Vec<String> = (0..65).map(|i| format!("ns-{i}")).collect();
    let outcome = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": entries,
    }));
    assert!(outcome.is_err(), "an unbounded visibility list is rejected");
}

#[test]
fn k8s_export_to_rejection_does_not_echo_the_hostile_value() {
    let hostile = "A".repeat(200);
    let message = translate_dr(json!({
        "host": "reviews.beta.svc.cluster.local",
        "exportTo": [hostile.clone()],
    }))
    .expect_err("hostile value is rejected");
    assert!(
        !message.contains(&hostile),
        "the diagnostic must name the field and index, never echo the raw \
         operator-supplied value; got: {message}"
    );
    assert!(
        message.contains("exportTo[0]"),
        "the diagnostic must still identify the offending entry; got: {message}"
    );
}

// ── Native / file semantics and validation ───────────────────────────────

#[test]
fn native_empty_export_to_is_namespace_local_not_public() {
    let dr = rule(
        "beta",
        "reviews-dr",
        "reviews.beta.svc.cluster.local",
        1,
        &[],
    );
    assert!(
        destination_rule_exported_to_namespace(&dr, "beta"),
        "an omitted native/file export_to keeps the rule visible in its own \
         namespace"
    );
    assert!(
        !destination_rule_exported_to_namespace(&dr, "alpha"),
        "fail closed by omission: the native/file source requires an explicit \
         ['*'] to publish a rule mesh-wide"
    );
}

#[test]
fn native_validation_rejects_unsupported_export_to_values() {
    for (label, export_to) in [
        ("tilde", vec!["~".to_string()]),
        ("empty entry", vec![String::new()]),
        ("uppercase", vec!["Alpha".to_string()]),
        (
            "wildcard plus namespace",
            vec!["*".to_string(), "alpha".to_string()],
        ),
    ] {
        let mesh = MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                export_to,
                ..rule(
                    "beta",
                    "reviews-dr",
                    "reviews.beta.svc.cluster.local",
                    1,
                    &[],
                )
            }],
            ..MeshConfig::default()
        };
        let errors = mesh.validate();
        assert!(
            errors.iter().any(|e| e.contains("exportTo")),
            "{label}: expected an exportTo validation error, got {errors:?}"
        );
    }
}

#[test]
fn native_validation_accepts_supported_export_to_values() {
    for export_to in [
        vec![],
        vec![".".to_string()],
        vec!["*".to_string()],
        vec!["alpha".to_string(), "gamma-1".to_string()],
    ] {
        let mesh = MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                export_to: export_to.clone(),
                ..rule(
                    "beta",
                    "reviews-dr",
                    "reviews.beta.svc.cluster.local",
                    1,
                    &[],
                )
            }],
            ..MeshConfig::default()
        };
        let errors = mesh.validate();
        assert!(
            !errors.iter().any(|e| e.contains("exportTo")),
            "{export_to:?} must validate, got {errors:?}"
        );
    }
}

#[test]
fn native_normalization_canonicalizes_export_to_for_carriers_and_dedupe() {
    let mut mesh = MeshConfig {
        destination_rules: vec![rule(
            "beta",
            "reviews-dr",
            "reviews.beta.svc.cluster.local",
            1111,
            &[" alpha ", " . "],
        )],
        ..MeshConfig::default()
    };

    mesh.normalize();

    assert_eq!(
        mesh.destination_rules[0].export_to,
        vec!["alpha".to_string(), ".".to_string()],
        "native/file visibility must have one canonical representation before \
         it is sliced, compared, or serialized into a carrier"
    );
    assert!(mesh.validate().is_empty());
}

// ── Slice narrowing: visibility (#2465) ──────────────────────────────────

/// The headline #2465 scenario: `beta` owns `reviews` and declares its policy
/// namespace-local. An `alpha` client must not receive it even though `beta`
/// IS the target service namespace — the tier that made the rule reachable
/// before.
#[test]
fn namespace_local_rule_never_reaches_a_client_in_another_namespace() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![rule(
            "beta",
            "reviews-private",
            "reviews.beta.svc.cluster.local",
            1111,
            &["."],
        )],
        ..MeshConfig::default()
    };

    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "exportTo ['.'] must not cross the declaring namespace boundary"
    );
    assert_eq!(
        admitted_rule_names(&mesh, "beta"),
        vec!["reviews-private".to_string()],
        "the owning namespace still sees its own rule"
    );
}

#[test]
fn public_and_allowlisted_rules_reach_exactly_the_declared_namespaces() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![
            rule(
                "beta",
                "reviews-public",
                "reviews.beta.svc.cluster.local",
                1111,
                &["*"],
            ),
            rule(
                "beta",
                "ratings-allowlisted",
                "ratings.beta.svc.cluster.local",
                2222,
                &["alpha"],
            ),
        ],
        ..MeshConfig::default()
    };

    let alpha = admitted_rule_names(&mesh, "alpha");
    assert!(alpha.contains(&"reviews-public".to_string()));
    assert!(alpha.contains(&"ratings-allowlisted".to_string()));

    let gamma = admitted_rule_names(&mesh, "gamma");
    assert_eq!(
        gamma,
        vec!["reviews-public".to_string()],
        "gamma is not on the allowlist, so only the public rule reaches it"
    );
}

/// #2465 must not be reopened by #2469's root fallback: a root-namespace rule
/// is still subject to `exportTo`.
#[test]
fn a_namespace_local_root_namespace_rule_is_not_visible_mesh_wide() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "istio-system",
            "root-private",
            "reviews.beta.svc.cluster.local",
            9999,
            &["."],
        )],
        ..MeshConfig::default()
    };

    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "a root-namespace rule exported only to its own namespace must not \
         become a mesh-wide default"
    );
    assert!(
        admitted_rule_names(&mesh, "beta").is_empty(),
        "nor may it reach the target service's namespace"
    );
    assert_eq!(
        admitted_rule_names(&mesh, "istio-system"),
        vec!["root-private".to_string()]
    );
}

// ── Slice narrowing: lookup tiers (#2469) ────────────────────────────────

/// Both directions of the lexical/semantic conflict. Resource-name
/// ordering must be irrelevant, so the same topology is asserted with the
/// client namespace sorting BEFORE and AFTER the service namespace.
#[test]
fn client_namespace_rule_wins_regardless_of_how_the_namespaces_sort() {
    for (client_ns, service_ns) in [("alpha", "zeta"), ("zeta", "alpha")] {
        let host = format!("reviews.{service_ns}.svc.cluster.local");
        let mesh = MeshConfig {
            services: vec![service_in(service_ns, "reviews")],
            workloads: vec![
                workload_in(service_ns, "reviews"),
                workload_in(client_ns, "web"),
            ],
            destination_rules: vec![
                rule(service_ns, "service-default", &host, 2222, &["*"]),
                rule(client_ns, "client-override", &host, 1111, &["*"]),
            ],
            ..MeshConfig::default()
        };

        assert_eq!(
            admitted_rule_names(&mesh, client_ns),
            vec!["client-override".to_string()],
            "client namespace {client_ns:?} must win over service namespace \
             {service_ns:?}; lexical order must not decide"
        );
    }
}

#[test]
fn service_namespace_rule_is_used_when_the_client_declares_none() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "beta",
            "service-default",
            "reviews.beta.svc.cluster.local",
            2222,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["service-default".to_string()]
    );
}

#[test]
fn root_namespace_rule_is_the_fallback_when_neither_client_nor_service_declares_one() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "istio-system",
            "mesh-default",
            "reviews.beta.svc.cluster.local",
            3333,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["mesh-default".to_string()],
        "the configured root namespace is Istio's last lookup tier and must \
         not be dropped from the slice"
    );
}

#[test]
fn a_custom_root_namespace_is_honored_and_the_default_one_is_not() {
    let mesh = MeshConfig {
        istio_root_namespace: "mesh-config".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![
            rule(
                "mesh-config",
                "custom-root-default",
                "reviews.beta.svc.cluster.local",
                3333,
                &["*"],
            ),
            rule(
                "istio-system",
                "not-the-root-namespace",
                "reviews.beta.svc.cluster.local",
                4444,
                &["*"],
            ),
        ],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["custom-root-default".to_string()],
        "only the CONFIGURED root namespace is a lookup tier; `istio-system` \
         has no special standing once the operator moved the root"
    );
}

#[test]
fn service_namespace_rule_outranks_the_root_default() {
    // `istio-system` sorts BEFORE `zeta`, so a lexical last-writer would pick
    // the service rule for the wrong reason. Assert the reverse pairing too.
    for (service_ns, root_ns) in [("zeta", "istio-system"), ("alpha", "zzz-root")] {
        let host = format!("reviews.{service_ns}.svc.cluster.local");
        let mesh = MeshConfig {
            istio_root_namespace: root_ns.to_string(),
            services: vec![service_in(service_ns, "reviews")],
            workloads: vec![workload_in(service_ns, "reviews")],
            destination_rules: vec![
                rule(root_ns, "mesh-default", &host, 3333, &["*"]),
                rule(service_ns, "service-default", &host, 2222, &["*"]),
            ],
            ..MeshConfig::default()
        };
        assert_eq!(
            admitted_rule_names(&mesh, "client-ns"),
            vec!["service-default".to_string()],
            "service namespace {service_ns:?} must outrank root {root_ns:?}"
        );
    }
}

#[test]
fn a_third_party_namespace_rule_is_refused_outright() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "evil",
            "steal-reviews",
            "reviews.beta.svc.cluster.local",
            6666,
            // Even an explicit, self-granted public export cannot make a
            // third-party namespace part of the lookup path.
            &["*"],
        )],
        ..MeshConfig::default()
    };
    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "a namespace that is neither the client, the target service, nor the \
         configured root is not a lookup tier"
    );
}

#[test]
fn same_tier_rules_are_all_retained_in_deterministic_order() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![
            rule(
                "beta",
                "z-second",
                "reviews.beta.svc.cluster.local",
                2222,
                &["*"],
            ),
            rule(
                "beta",
                "a-first",
                "reviews.beta.svc.cluster.local",
                1111,
                &["*"],
            ),
        ],
        ..MeshConfig::default()
    };
    let admitted = admitted_rule_names(&mesh, "alpha");
    assert_eq!(
        admitted.len(),
        2,
        "same-namespace rules for one host share a tier and both survive \
         narrowing (Istio's merge case), got {admitted:?}"
    );
    assert_eq!(
        admitted,
        admitted_rule_names(&mesh, "alpha"),
        "narrowing is deterministic across repeated builds"
    );
}

#[test]
fn same_tier_duplicate_names_use_host_spelling_as_a_stable_final_tiebreak() {
    let short = rule("beta", "shared-name", "reviews.beta", 1111, &["*"]);
    let fqdn = rule(
        "beta",
        "shared-name",
        "reviews.beta.svc.cluster.local",
        2222,
        &["*"],
    );

    for destination_rules in [
        vec![short.clone(), fqdn.clone()],
        vec![fqdn.clone(), short.clone()],
    ] {
        let mesh = MeshConfig {
            services: vec![service_in("beta", "reviews")],
            workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
            destination_rules,
            sidecars: vec![permissive_sidecar("alpha")],
            ..MeshConfig::default()
        };
        assert_eq!(
            materialized_connect_timeout(mesh, "alpha", "beta"),
            2222,
            "the normalized FQDN sorts after the two-label spelling and must win regardless of source order"
        );
    }
}

// ── Materialization: the winning rule is the one that takes effect ───────

fn materialized_connect_timeout(mesh: MeshConfig, client_namespace: &str, service_ns: &str) -> u64 {
    let host = format!("reviews.{service_ns}.svc.cluster.local");
    let mut upstream = http_upstream("reviews-u", &host, 8080);
    upstream.namespace = service_ns.to_string();
    upstream.name = Some(host.clone());
    let mut proxy = http_proxy("reviews-p", &host, 8080);
    proxy.namespace = service_ns.to_string();
    proxy.upstream_id = Some("reviews-u".to_string());

    let config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let runtime = MeshRuntimeConfig {
        namespace: client_namespace.to_string(),
        sidecar_enforced: true,
        ..default_mesh_runtime()
    };
    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");
    prepared
        .proxies
        .iter()
        .find(|p| p.id == "reviews-p")
        .expect("operator proxy survives mesh preparation")
        .backend_connect_timeout_ms
}

/// End-to-end through slice narrowing AND `apply_destination_rules`: the
/// client-namespace policy is the one that actually reaches the proxy, with the
/// namespaces sorted both ways so no result can be a lexical accident.
#[test]
fn the_client_namespace_policy_is_the_one_materialized() {
    for (client_ns, service_ns) in [("alpha", "zeta"), ("zeta", "alpha")] {
        let host = format!("reviews.{service_ns}.svc.cluster.local");
        let mesh = MeshConfig {
            services: vec![service_in(service_ns, "reviews")],
            workloads: vec![
                workload_in(service_ns, "reviews"),
                workload_in(client_ns, "web"),
            ],
            destination_rules: vec![
                rule(service_ns, "service-default", &host, 2222, &["*"]),
                rule(client_ns, "client-override", &host, 1111, &["*"]),
            ],
            sidecars: vec![permissive_sidecar(client_ns)],
            ..MeshConfig::default()
        };
        assert_eq!(
            materialized_connect_timeout(mesh, client_ns, service_ns),
            1111,
            "client {client_ns:?} / service {service_ns:?}: the client-tier \
             connect timeout must be the effective one"
        );
    }
}

/// The security assertion for #2465 at the point where policy actually takes
/// effect: a namespace-local rule cannot change an external client's behaviour.
#[test]
fn a_namespace_local_rule_cannot_alter_an_external_clients_effective_policy() {
    let mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![MeshDestinationRule {
            traffic_policy: Some(MeshTrafficPolicy {
                connect_timeout_ms: Some(1),
                load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                ..MeshTrafficPolicy::default()
            }),
            ..rule(
                "beta",
                "reviews-private",
                "reviews.beta.svc.cluster.local",
                1,
                &["."],
            )
        }],
        sidecars: vec![permissive_sidecar("alpha")],
        ..MeshConfig::default()
    };

    let host = "reviews.beta.svc.cluster.local";
    let mut upstream = http_upstream("reviews-u", host, 8080);
    upstream.namespace = "beta".to_string();
    upstream.name = Some(host.to_string());
    let mut proxy = http_proxy("reviews-p", host, 8080);
    proxy.namespace = "beta".to_string();
    proxy.upstream_id = Some("reviews-u".to_string());
    let baseline_timeout = proxy.backend_connect_timeout_ms;

    let config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let runtime = MeshRuntimeConfig {
        namespace: "alpha".to_string(),
        sidecar_enforced: true,
        ..default_mesh_runtime()
    };
    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "reviews-p")
        .expect("operator proxy survives mesh preparation");
    assert_eq!(
        proxy.backend_connect_timeout_ms, baseline_timeout,
        "the alpha client must keep its own connect timeout"
    );
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("operator upstream survives mesh preparation");
    assert_eq!(
        upstream.algorithm,
        ferrum_edge::config::types::LoadBalancerAlgorithm::RoundRobin,
        "and its load balancing must be untouched by beta's private policy"
    );
}

// ── Carrier / native parity, reload, and dedupe ──────────────────────────

/// The Ferrum-private ECDS DestinationRule carrier serializes the rule as
/// JSON, so visibility rides the carrier verbatim. (This is Ferrum's own
/// carrier contract; it is not stock Envoy/Istio xDS interoperability.)
#[test]
fn carrier_json_round_trip_preserves_export_to() {
    for export_to in [
        vec![],
        vec![".".to_string()],
        vec!["*".to_string()],
        vec!["alpha".to_string(), "gamma".to_string()],
    ] {
        let dr = MeshDestinationRule {
            export_to: export_to.clone(),
            ..rule(
                "beta",
                "reviews-dr",
                "reviews.beta.svc.cluster.local",
                1,
                &[],
            )
        };
        let encoded = serde_json::to_vec(&dr).expect("encode");
        let decoded: MeshDestinationRule = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.export_to, export_to);
        assert_eq!(decoded, dr);
    }
}

#[test]
fn a_carrier_without_export_to_decodes_as_namespace_local() {
    let decoded: MeshDestinationRule = serde_json::from_value(json!({
        "name": "reviews-dr",
        "namespace": "beta",
        "host": "reviews.beta.svc.cluster.local",
    }))
    .expect("decode");
    assert!(decoded.export_to.is_empty());
    assert!(destination_rule_exported_to_namespace(&decoded, "beta"));
    assert!(
        !destination_rule_exported_to_namespace(&decoded, "alpha"),
        "an absent carrier field must fail closed, not default to public"
    );
}

/// A visibility-only edit changes nothing structural about the rule, so if
/// `content_eq` ignored it the subscriber would keep serving the old policy.
#[test]
fn a_visibility_only_change_is_not_deduped_away() {
    let base = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "beta",
            "reviews-dr",
            "reviews.beta.svc.cluster.local",
            1111,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    let mut narrowed = base.clone();
    narrowed.destination_rules[0].export_to = vec![".".to_string()];

    let before = slice_for(&base, "alpha");
    let after = slice_for(&narrowed, "alpha");
    assert!(
        !before.content_eq(&after),
        "narrowing visibility must produce a different slice for the external \
         subscriber so the policy is withdrawn promptly"
    );
    assert!(after.destination_rules.is_empty());
}

/// The same rule, still fully visible, but re-scoped from `*` to an explicit
/// allowlist that DOES include this subscriber: the effective set is unchanged
/// for this node, and dedupe may legitimately suppress the re-send.
#[test]
fn a_visibility_change_that_does_not_affect_this_subscriber_is_stable() {
    let mut public = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: vec![rule(
            "beta",
            "reviews-dr",
            "reviews.beta.svc.cluster.local",
            1111,
            &["*"],
        )],
        ..MeshConfig::default()
    };
    let before = slice_for(&public, "alpha");
    public.destination_rules[0].export_to = vec!["alpha".to_string()];
    let after = slice_for(&public, "alpha");
    assert_eq!(
        after.destination_rules.len(),
        1,
        "alpha is on the allowlist, so the rule still applies"
    );
    assert!(!before.content_eq(&after));
}

#[test]
fn a_root_namespace_only_change_is_not_deduped_away() {
    let base = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews")],
        destination_rules: Vec::new(),
        ..MeshConfig::default()
    };
    let mut with_root = base.clone();
    with_root.destination_rules.push(rule(
        "istio-system",
        "mesh-default",
        "reviews.beta.svc.cluster.local",
        3333,
        &["*"],
    ));

    let before = slice_for(&base, "alpha");
    let after = slice_for(&with_root, "alpha");
    assert!(!before.content_eq(&after));
    assert_eq!(after.destination_rules.len(), 1);
}

/// Deleting the winning client-namespace rule must promote the service-tier
/// rule immediately rather than leaving the destination with no policy.
#[test]
fn deleting_the_client_rule_falls_back_to_the_service_rule() {
    let host = "reviews.beta.svc.cluster.local";
    let mut mesh = MeshConfig {
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![
            rule("beta", "service-default", host, 2222, &["*"]),
            rule("alpha", "client-override", host, 1111, &["*"]),
        ],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["client-override".to_string()]
    );

    mesh.destination_rules.retain(|dr| dr.namespace != "alpha");
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["service-default".to_string()],
        "withdrawing the client-tier rule promotes the service-tier rule"
    );
}

// ── Composition with Sidecar egress scope ────────────────────────────────

fn sidecar_admitting(namespace: &str, hosts: &[&str]) -> MeshSidecar {
    MeshSidecar {
        name: "default-sc".to_string(),
        namespace: namespace.to_string(),
        workload_selector: None,
        egress_inherits_defaults: false,
        egress: vec![MeshSidecarEgress {
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            port: None,
        }],
        ingress_declared: false,
        ingress: Vec::new(),
        outbound_traffic_policy: None,
    }
}

/// Sidecar egress scope and `exportTo` are independent gates and BOTH must
/// pass. An egress scope that admits `beta/*` does not grant visibility of
/// `beta`'s namespace-local rules.
#[test]
fn sidecar_egress_scope_does_not_override_export_to() {
    let mesh = MeshConfig {
        sidecars: vec![sidecar_admitting("alpha", &["beta/*"])],
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![
            rule(
                "beta",
                "reviews-private",
                "reviews.beta.svc.cluster.local",
                1111,
                &["."],
            ),
            rule(
                "beta",
                "reviews-public",
                "reviews.beta.svc.cluster.local",
                2222,
                &["*"],
            ),
        ],
        ..MeshConfig::default()
    };

    let slice = MeshSlice::from_gateway_config(&config_with(mesh), request_for("alpha"));
    let names: Vec<String> = slice
        .destination_rules
        .into_iter()
        .map(|dr| dr.name)
        .collect();
    assert_eq!(
        names,
        vec!["reviews-public".to_string()],
        "the Sidecar admits the host, but only the exported rule is visible"
    );
}

/// The converse: `exportTo: ['*']` does not widen the Sidecar egress scope.
#[test]
fn export_to_does_not_override_sidecar_egress_scope() {
    let mesh = MeshConfig {
        sidecars: vec![sidecar_admitting("alpha", &["./*"])],
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![rule(
            "beta",
            "reviews-public",
            "reviews.beta.svc.cluster.local",
            2222,
            &["*"],
        )],
        ..MeshConfig::default()
    };

    let slice = MeshSlice::from_gateway_config(&config_with(mesh), request_for("alpha"));
    assert!(
        slice.destination_rules.is_empty(),
        "a publicly exported rule for a host outside the Sidecar egress scope \
         still must not be carried"
    );
}

// ── Target-service ownership: who is allowed to BE the service tier ──────
//
// The service tier is a security boundary — it names the third-party namespace
// that may write traffic policy for a destination. These cases pin that it is
// granted only on evidence of ownership, and that an unresolvable or contested
// owner DISABLES the tier rather than defaulting to the rule's own namespace
// (which would let any namespace vouch for itself).

const EXTERNAL_HOST: &str = "api.example.com";

/// A `ServiceEntry` declaring an external host, visible to every namespace.
fn external_service_entry(namespace: &str, name: &str, host: &str) -> ServiceEntry {
    ServiceEntry {
        name: name.to_string(),
        namespace: namespace.to_string(),
        hosts: vec![host.to_string()],
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 443,
            protocol: Default::default(),
            name: Some("https".to_string()),
            target_port: None,
        }],
        export_to: vec!["*".to_string()],
        workload_selector: None,
    }
}

/// Effective connect timeout on an operator upstream for an EXTERNAL host,
/// end to end through slice narrowing AND `apply_destination_rules`.
///
/// `upstream_namespace` is the namespace the materialization pass reads as the
/// upstream's owner; the admission pass independently resolves ownership from
/// the visible ServiceEntry, so the two are supplied separately on purpose —
/// a test can then observe them DISAGREEING rather than being told they agree.
fn materialized_external_connect_timeout(
    mesh: MeshConfig,
    client_namespace: &str,
    upstream_namespace: &str,
) -> (u64, u64) {
    let mut upstream = http_upstream("ext-u", EXTERNAL_HOST, 443);
    upstream.namespace = upstream_namespace.to_string();
    upstream.name = Some(EXTERNAL_HOST.to_string());
    let mut proxy = http_proxy("ext-p", EXTERNAL_HOST, 443);
    proxy.namespace = upstream_namespace.to_string();
    proxy.upstream_id = Some("ext-u".to_string());
    let baseline = proxy.backend_connect_timeout_ms;

    let config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let runtime = MeshRuntimeConfig {
        namespace: client_namespace.to_string(),
        sidecar_enforced: true,
        ..default_mesh_runtime()
    };
    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");
    let effective = prepared
        .proxies
        .iter()
        .find(|p| p.id == "ext-p")
        .expect("operator proxy survives mesh preparation")
        .backend_connect_timeout_ms;
    (effective, baseline)
}

/// A mesh with one `beta`-owned external host, an `alpha` client, and whatever
/// DestinationRules the case under test supplies.
fn external_host_mesh(entries: Vec<ServiceEntry>, rules: Vec<MeshDestinationRule>) -> MeshConfig {
    MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        service_entries: entries,
        workloads: vec![workload_in("alpha", "web")],
        destination_rules: rules,
        sidecars: vec![permissive_sidecar("alpha")],
        ..MeshConfig::default()
    }
}

#[test]
fn a_service_entrys_declaring_namespace_is_the_service_tier_for_its_external_host() {
    let mesh = external_host_mesh(
        vec![external_service_entry(
            "beta",
            "external-api",
            EXTERNAL_HOST,
        )],
        vec![rule("beta", "owner-policy", EXTERNAL_HOST, 2222, &["*"])],
    );
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["owner-policy".to_string()],
        "the namespace that DECLARES the ServiceEntry owns its external host \
         and is therefore the service tier for it"
    );
}

/// The #2469 boundary at admission: an unrelated namespace cannot make itself
/// the owner of an external host merely by publishing a rule for it.
#[test]
fn an_unrelated_namespace_rule_for_a_service_entry_host_is_refused() {
    let mesh = external_host_mesh(
        vec![external_service_entry(
            "beta",
            "external-api",
            EXTERNAL_HOST,
        )],
        vec![rule("evil", "hijack", EXTERNAL_HOST, 6666, &["*"])],
    );
    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "`evil` is neither the client, the ServiceEntry's owning namespace, \
         nor the configured root, so a self-granted public export must not \
         make it a lookup tier for `beta`'s external host"
    );
}

/// The same boundary where policy actually takes effect. Both shapes the root
/// finding described are covered: the unrelated rule alone (it would otherwise
/// be the sole match and simply apply) and the unrelated rule alongside the
/// legitimate root-namespace fallback (where sharing the lowest bucket let
/// lexical order overwrite the fallback — `evil` sorts after `istio-system`).
#[test]
fn an_unrelated_namespace_rule_cannot_alter_the_materialized_external_upstream() {
    let entries = vec![external_service_entry(
        "beta",
        "external-api",
        EXTERNAL_HOST,
    )];

    let (alone, baseline) = materialized_external_connect_timeout(
        external_host_mesh(
            entries.clone(),
            vec![rule("evil", "hijack", EXTERNAL_HOST, 6666, &["*"])],
        ),
        "alpha",
        "beta",
    );
    assert_eq!(
        alone, baseline,
        "an unrelated namespace's rule must not reach the client's upstream \
         even when it is the only rule that matches the host"
    );

    let (with_root, _) = materialized_external_connect_timeout(
        external_host_mesh(
            entries,
            vec![
                rule("evil", "hijack", EXTERNAL_HOST, 6666, &["*"]),
                rule("istio-system", "mesh-default", EXTERNAL_HOST, 3333, &["*"]),
            ],
        ),
        "alpha",
        "beta",
    );
    assert_eq!(
        with_root, 3333,
        "the configured root namespace's mesh-wide default is the fallback; \
         `evil` must not overwrite it by sorting later"
    );
}

/// Client → ServiceEntry-owning namespace → configured root, on ONE external
/// host, peeled one tier at a time.
#[test]
fn client_then_service_entry_owner_then_root_resolve_in_order_for_an_external_host() {
    let entries = vec![external_service_entry(
        "beta",
        "external-api",
        EXTERNAL_HOST,
    )];
    let client = rule("alpha", "client-override", EXTERNAL_HOST, 1111, &["*"]);
    let owner = rule("beta", "owner-policy", EXTERNAL_HOST, 2222, &["*"]);
    let root = rule("istio-system", "mesh-default", EXTERNAL_HOST, 3333, &["*"]);

    let all = external_host_mesh(entries.clone(), vec![root.clone(), owner.clone(), client]);
    assert_eq!(
        admitted_rule_names(&all, "alpha"),
        vec!["client-override".to_string()],
        "the client namespace wins outright over the owner and the root"
    );
    assert_eq!(
        materialized_external_connect_timeout(all, "alpha", "beta").0,
        1111
    );

    let without_client = external_host_mesh(entries.clone(), vec![root.clone(), owner.clone()]);
    assert_eq!(
        admitted_rule_names(&without_client, "alpha"),
        vec!["owner-policy".to_string()],
        "with no client rule, the ServiceEntry's owning namespace wins over \
         the root — and `beta` sorts BEFORE `istio-system`, so a lexical \
         last-writer would have produced the opposite result"
    );
    assert_eq!(
        materialized_external_connect_timeout(without_client, "alpha", "beta").0,
        2222
    );

    let root_only = external_host_mesh(entries, vec![root]);
    assert_eq!(
        admitted_rule_names(&root_only, "alpha"),
        vec!["mesh-default".to_string()],
        "the configured root namespace is the fallback tier"
    );
    assert_eq!(
        materialized_external_connect_timeout(root_only, "alpha", "beta").0,
        3333
    );
}

/// Contested ownership is refused, not guessed.
///
/// Two visible ServiceEntries in DIFFERENT namespaces declare one host, so
/// there is no single owner. The fail-closed contract is that the SERVICE TIER
/// is disabled for that host: neither claimant may write policy for it, and
/// only the client and root namespaces can. Picking either claimant would hand
/// one of two mutually untrusting namespaces policy control over the other's
/// clients; picking by iteration order would reintroduce exactly the
/// spelling-dependent precedence #2469 removes.
#[test]
fn ambiguous_service_entry_ownership_does_not_widen_policy_admission() {
    let entries = vec![
        external_service_entry("beta", "external-api", EXTERNAL_HOST),
        external_service_entry("gamma", "external-api", EXTERNAL_HOST),
    ];

    for claimant in ["beta", "gamma"] {
        let mesh = external_host_mesh(
            entries.clone(),
            vec![rule(
                claimant,
                "claimant-policy",
                EXTERNAL_HOST,
                2222,
                &["*"],
            )],
        );
        assert!(
            admitted_rule_names(&mesh, "alpha").is_empty(),
            "{claimant}: with ownership contested, neither claimant is the \
             service tier"
        );
        assert_eq!(
            materialized_external_connect_timeout(mesh, "alpha", claimant).0,
            materialized_external_connect_timeout(
                external_host_mesh(entries.clone(), Vec::new()),
                "alpha",
                claimant,
            )
            .0,
            "{claimant}: and nothing reaches the materialized upstream"
        );
    }

    let client_and_root = external_host_mesh(
        entries.clone(),
        vec![
            rule("alpha", "client-override", EXTERNAL_HOST, 1111, &["*"]),
            rule("istio-system", "mesh-default", EXTERNAL_HOST, 3333, &["*"]),
        ],
    );
    assert_eq!(
        admitted_rule_names(&client_and_root, "alpha"),
        vec!["client-override".to_string()],
        "the client and root tiers are unaffected by contested ownership, and \
         the client still outranks the root"
    );

    let root_only = external_host_mesh(
        entries,
        vec![rule(
            "istio-system",
            "mesh-default",
            EXTERNAL_HOST,
            3333,
            &["*"],
        )],
    );
    assert_eq!(
        admitted_rule_names(&root_only, "alpha"),
        vec!["mesh-default".to_string()],
        "and the root namespace remains the fallback"
    );
}

/// Duplicates WITHIN one namespace are still a single owner — Istio merges
/// those, so this must not be mistaken for contested ownership.
#[test]
fn duplicate_service_entries_in_one_namespace_are_still_a_single_owner() {
    let mesh = external_host_mesh(
        vec![
            external_service_entry("beta", "external-api", EXTERNAL_HOST),
            external_service_entry("beta", "external-api-dup", EXTERNAL_HOST),
        ],
        vec![rule("beta", "owner-policy", EXTERNAL_HOST, 2222, &["*"])],
    );
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["owner-policy".to_string()],
        "two ServiceEntries in one namespace name one owner, not two"
    );
}

/// A ServiceEntry the client cannot SEE cannot establish ownership for it
/// either, so the service tier is disabled rather than silently granted.
#[test]
fn an_invisible_service_entry_grants_no_service_tier() {
    let mut entry = external_service_entry("beta", "external-api", EXTERNAL_HOST);
    entry.export_to = vec![".".to_string()];
    let mesh = external_host_mesh(
        vec![entry],
        vec![rule("beta", "owner-policy", EXTERNAL_HOST, 2222, &["*"])],
    );
    assert!(
        admitted_rule_names(&mesh, "alpha").is_empty(),
        "`alpha` cannot see the ServiceEntry, so it has no evidence that \
         `beta` owns the host"
    );
}

// ── Qualified Kubernetes shorthand vs. the materialization host matcher ──

/// `destination_rule_host_matches` treats a two-label rule host as Kubernetes
/// shorthand and matches it against `reviews.beta.svc.*` upstreams. The
/// admission resolver must not disagree by resolving that same host to the
/// RULE's namespace, or an unrelated namespace becomes an invented service
/// tier for a host the matcher will happily bind to `beta`'s upstream.
///
/// Both inventory states are covered, because the disagreement only appears
/// when the service inventory cannot confirm the pair.
#[test]
fn a_two_label_host_never_makes_an_unrelated_namespace_the_service_tier() {
    for (label, services) in [
        (
            "service present in the inventory",
            vec![service_in("beta", "reviews")],
        ),
        ("service absent from the inventory", Vec::new()),
    ] {
        let mesh = MeshConfig {
            istio_root_namespace: "istio-system".to_string(),
            services,
            workloads: vec![workload_in("alpha", "web")],
            destination_rules: vec![rule("evil", "hijack", "reviews.beta", 6666, &["*"])],
            sidecars: vec![permissive_sidecar("alpha")],
            ..MeshConfig::default()
        };
        assert!(
            admitted_rule_names(&mesh, "alpha").is_empty(),
            "{label}: `evil` is not the client, not `beta`, and not the root"
        );

        let host = "reviews.beta.svc.cluster.local";
        let mut upstream = http_upstream("reviews-u", host, 8080);
        upstream.namespace = "beta".to_string();
        upstream.name = Some(host.to_string());
        let mut proxy = http_proxy("reviews-p", host, 8080);
        proxy.namespace = "beta".to_string();
        proxy.upstream_id = Some("reviews-u".to_string());
        let baseline = proxy.backend_connect_timeout_ms;
        let config = GatewayConfig {
            proxies: vec![proxy],
            upstreams: vec![upstream],
            mesh: Some(Box::new(mesh)),
            ..GatewayConfig::default()
        };
        let runtime = MeshRuntimeConfig {
            namespace: "alpha".to_string(),
            sidecar_enforced: true,
            ..default_mesh_runtime()
        };
        let prepared =
            prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");
        assert_eq!(
            prepared
                .proxies
                .iter()
                .find(|p| p.id == "reviews-p")
                .expect("operator proxy survives mesh preparation")
                .backend_connect_timeout_ms,
            baseline,
            "{label}: and it must not reach the upstream the matcher binds \
             `reviews.beta` to"
        );
    }
}

/// The legitimate counterpart: with inventory evidence, the target service's
/// own namespace IS the service tier for the same two-label host.
#[test]
fn a_two_label_host_confirmed_by_the_inventory_resolves_to_the_service_namespace() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        workloads: vec![workload_in("beta", "reviews"), workload_in("alpha", "web")],
        destination_rules: vec![rule("beta", "owner-policy", "reviews.beta", 2222, &["*"])],
        sidecars: vec![permissive_sidecar("alpha")],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["owner-policy".to_string()],
        "`beta/reviews` exists, so `reviews.beta` resolves to `beta` and its \
         own namespace is the service tier"
    );
}

/// A `.svc`-qualified host pins the namespace in its own SYNTAX, so it needs
/// no inventory evidence and no ServiceEntry can claim it by declaring the
/// same string.
#[test]
fn a_svc_qualified_host_is_owned_by_the_namespace_in_the_host_not_by_a_claimant() {
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        service_entries: vec![external_service_entry(
            "evil",
            "claim-reviews",
            "reviews.beta.svc.cluster.local",
        )],
        workloads: vec![workload_in("alpha", "web")],
        destination_rules: vec![
            rule(
                "evil",
                "hijack",
                "reviews.beta.svc.cluster.local",
                6666,
                &["*"],
            ),
            rule(
                "beta",
                "owner-policy",
                "reviews.beta.svc.cluster.local",
                2222,
                &["*"],
            ),
        ],
        sidecars: vec![permissive_sidecar("alpha")],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["owner-policy".to_string()],
        "a ServiceEntry declaring a `.svc`-qualified Kubernetes host does not \
         transfer ownership of it to the declaring namespace"
    );
}

/// A wildcard host has no resolvable owner, so only the client and root tiers
/// may write policy for it.
#[test]
fn a_wildcard_host_grants_no_service_tier() {
    let rules = vec![
        rule("evil", "hijack", "*.example.com", 6666, &["*"]),
        rule("alpha", "client-override", "*.example.com", 1111, &["*"]),
    ];
    let mesh = MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        workloads: vec![workload_in("alpha", "web")],
        destination_rules: rules,
        sidecars: vec![permissive_sidecar("alpha")],
        ..MeshConfig::default()
    };
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["client-override".to_string()],
        "a wildcard host cannot be owned, so a third-party rule for it is \
         refused and the client's own rule stands"
    );
}

// ── Per-host tier arbitration ────────────────────────────────────────────

const SPAN_A_HOST: &str = "a.alpha.svc.cluster.local";
const SPAN_B_HOST: &str = "b.beta.svc.cluster.local";

/// One operator-authored upstream whose targets are `targets`, plus the mesh
/// inventory both destinations need, viewed as an `alpha` subscriber.
///
/// `name` is cleared so the upstream's own name is not a second match surface —
/// the cases below are about the TARGET hosts.
fn spanning_upstream_config(
    targets: &[(&str, u16)],
    destination_rules: Vec<MeshDestinationRule>,
) -> GatewayConfig {
    let mesh = MeshConfig {
        services: vec![service_in("alpha", "a"), service_in("beta", "b")],
        workloads: vec![
            workload_in("alpha", "a"),
            workload_in("beta", "b"),
            workload_in("alpha", "web"),
        ],
        destination_rules,
        sidecars: vec![permissive_sidecar("alpha")],
        ..MeshConfig::default()
    };

    let (first_host, first_port) = targets[0];
    let mut upstream = http_upstream("mixed-u", first_host, first_port);
    upstream.namespace = "alpha".to_string();
    upstream.name = None;
    for (host, port) in &targets[1..] {
        upstream.targets.push(UpstreamTarget {
            host: (*host).to_string(),
            port: *port,
            service_port_policy_key: None,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        });
    }
    let mut proxy = http_proxy("mixed-p", first_host, first_port);
    proxy.namespace = "alpha".to_string();
    proxy.upstream_id = Some("mixed-u".to_string());

    GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

fn alpha_subscriber_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        namespace: "alpha".to_string(),
        sidecar_enforced: true,
        ..default_mesh_runtime()
    }
}

/// Istio resolves a DestinationRule PER DESTINATION HOST, and this pass does
/// too — but an `Upstream` has only ONE set of slots for the resolved policy.
/// Load balancer, hash keys, backend TLS, outlier thresholds, connection-pool
/// caps, locality, and subsets are all upstream-WIDE, so two destinations that
/// resolve to different winning rules cannot both be represented.
///
/// Applying them anyway is cross-service policy transfer decided by sort order:
/// `beta`'s rule would govern traffic to `alpha`'s service purely because
/// `beta` sorts later. The apply pass refuses instead, before mutating
/// anything, and mesh's fail-closed-by-retention contract keeps the last good
/// config.
#[test]
fn an_upstream_spanning_two_services_with_distinct_winners_is_refused() {
    let mut beta_rule = rule("beta", "beta-owner", SPAN_B_HOST, 4444, &["*"]);
    beta_rule.traffic_policy = Some(MeshTrafficPolicy {
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
        ..MeshTrafficPolicy::default()
    });

    let alpha_rule = rule("alpha", "client-a", SPAN_A_HOST, 1111, &["*"]);
    let config = spanning_upstream_config(
        &[(SPAN_A_HOST, 8080), (SPAN_B_HOST, 8080)],
        vec![alpha_rule, beta_rule],
    );

    let error = prepare_gateway_config_for_mesh(config, &alpha_subscriber_runtime())
        .expect_err("two destinations with different winning rules cannot share one upstream");
    let message = error.to_string();
    assert!(
        message.contains("mixed-u") && message.contains("cannot be represented"),
        "the refusal names the unrepresentable upstream: {message}"
    );
}

/// The refusal is ORDER-INDEPENDENT. Both rules here set the SAME two
/// upstream-wide fields, so a merge would have produced a winner chosen by the
/// `(namespace, name, host)` sort — a different service's policy depending on
/// nothing but spelling. Neither ordering of the input may produce a config,
/// and both must fail the same way.
#[test]
fn an_upstream_spanning_two_services_has_no_order_dependent_cross_service_winner() {
    // Both rules set the SAME two upstream-wide fields, so any merge would
    // have to pick a loser.
    let mut alpha_rule = rule("alpha", "z-client", SPAN_A_HOST, 1111, &["*"]);
    alpha_rule.traffic_policy = Some(MeshTrafficPolicy {
        connect_timeout_ms: Some(1111),
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
        ..MeshTrafficPolicy::default()
    });
    let mut beta_rule = rule("beta", "a-owner", SPAN_B_HOST, 4444, &["*"]);
    beta_rule.traffic_policy = Some(MeshTrafficPolicy {
        connect_timeout_ms: Some(4444),
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
        ..MeshTrafficPolicy::default()
    });

    let forward_config = spanning_upstream_config(
        &[(SPAN_A_HOST, 8080), (SPAN_B_HOST, 8080)],
        vec![alpha_rule.clone(), beta_rule.clone()],
    );
    let reversed_config = spanning_upstream_config(
        &[(SPAN_A_HOST, 8080), (SPAN_B_HOST, 8080)],
        vec![beta_rule, alpha_rule],
    );

    let forward = prepare_gateway_config_for_mesh(forward_config, &alpha_subscriber_runtime())
        .expect_err("conflicting upstream-wide fields are refused");
    let reversed = prepare_gateway_config_for_mesh(reversed_config, &alpha_subscriber_runtime())
        .expect_err("and are refused just the same in the other input order");

    assert_eq!(
        forward.to_string(),
        reversed.to_string(),
        "the outcome must not depend on which rule the producer listed first"
    );
}

/// Two targets for ONE destination — a multi-port upstream — resolve to the
/// same winning rule set, so there is nothing to arbitrate and the policy
/// applies exactly as it does for a single-target upstream.
#[test]
fn an_upstream_with_two_ports_for_one_destination_still_applies_its_rule() {
    let mut client_rule = rule("alpha", "client-a", SPAN_A_HOST, 1111, &["*"]);
    client_rule.traffic_policy = Some(MeshTrafficPolicy {
        connect_timeout_ms: Some(1111),
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
        ..MeshTrafficPolicy::default()
    });

    let config = spanning_upstream_config(
        &[(SPAN_A_HOST, 8080), (SPAN_A_HOST, 9090)],
        vec![client_rule],
    );
    let prepared = prepare_gateway_config_for_mesh(config, &alpha_subscriber_runtime())
        .expect("one destination on two ports is representable");

    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "mixed-p")
        .expect("operator proxy survives mesh preparation");
    assert_eq!(proxy.backend_connect_timeout_ms, 1111);

    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "mixed-u")
        .expect("operator upstream survives mesh preparation");
    assert_eq!(
        upstream.algorithm,
        ferrum_edge::config::types::LoadBalancerAlgorithm::LeastConnections,
        "the sole winning rule applies to the whole upstream"
    );
}

/// The boundary, pinned deliberately: a second destination with NO visible rule
/// of its own does not make the upstream unrepresentable. There is one winning
/// rule set, and refusing here would reject the ordinary "upstream carries a
/// static fallback target" shape. That target does inherit the upstream-wide
/// policy — the documented consequence of upstream-wide slots, not an
/// order-dependent contest between two services' rules.
#[test]
fn an_upstream_whose_second_destination_has_no_rule_still_applies() {
    let config = spanning_upstream_config(
        &[(SPAN_A_HOST, 8080), (SPAN_B_HOST, 8080)],
        vec![rule("alpha", "client-a", SPAN_A_HOST, 1111, &["*"])],
    );
    let prepared = prepare_gateway_config_for_mesh(config, &alpha_subscriber_runtime())
        .expect("a destination with no rule cannot disagree with one that has a rule");

    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "mixed-p")
        .expect("operator proxy survives mesh preparation");
    assert_eq!(proxy.backend_connect_timeout_ms, 1111);
}

// ── EgressGateway: a SYNTHESIZED upstream carries the owner's policy ─────
//
// The upstream namespace is not ownership evidence for a machine-synthesized
// egress upstream: `build_egress_upstream` stamps the GATEWAY's namespace,
// which no operator can choose, and an external host pins no namespace in its
// own syntax either. The declaring ServiceEntry is the ONLY evidence left, so
// the data-plane tier pass has to read it from the same index slice admission
// used. Otherwise every rule the control plane admits at the service tier for
// an external host is refused before materialization and the owner's whole
// trafficPolicy — TLS origination included — is silently discarded.
//
// The operator-authored shape is already covered above
// (`materialized_external_connect_timeout` deliberately places the upstream in
// the owning namespace); these cases cover the shape whose namespace is chosen
// by the materializer.

const EGRESS_GATEWAY_NAMESPACE: &str = "istio-egress";
const EXTERNAL_HOST_OWNER: &str = "payments";

/// The owner's policy for [`EXTERNAL_HOST`], carrying one knob per projection
/// path so a PARTIAL application is visible instead of passing: backend TLS
/// origination, outlier-detection thresholds, and the connect timeout.
fn external_owner_policy_rule(namespace: &str) -> MeshDestinationRule {
    let mut dr = rule(namespace, "owner-policy", EXTERNAL_HOST, 2222, &["*"]);
    dr.traffic_policy = Some(MeshTrafficPolicy {
        connect_timeout_ms: Some(2222),
        outlier_detection: Some(MeshOutlierDetection {
            consecutive_errors: Some(7),
            interval_seconds: Some(11),
            base_ejection_seconds: Some(13),
            max_ejection_percent: Some(42),
        }),
        tls: Some(MeshTrafficPolicyTls {
            mode: MtlsMode::Simple,
            sni: Some(EXTERNAL_HOST.to_string()),
            subject_alt_names: vec![EXTERNAL_HOST.to_string()],
            ..MeshTrafficPolicyTls::default()
        }),
        ..MeshTrafficPolicy::default()
    });
    dr
}

/// An EgressGateway mesh: one external `ServiceEntry` declared in
/// `owner_namespace`, an importing Sidecar in the gateway's own namespace, and
/// whatever DestinationRules the case under test supplies.
fn egress_gateway_mesh(owner_namespace: &str, rules: Vec<MeshDestinationRule>) -> MeshConfig {
    let mut entry = external_service_entry(owner_namespace, "external-api", EXTERNAL_HOST);
    entry.ports[0].protocol = AppProtocol::Http;
    MeshConfig {
        istio_root_namespace: "istio-system".to_string(),
        service_entries: vec![entry],
        workloads: vec![workload_in(EGRESS_GATEWAY_NAMESPACE, "egress-gateway")],
        destination_rules: rules,
        sidecars: vec![permissive_sidecar(EGRESS_GATEWAY_NAMESPACE)],
        ..MeshConfig::default()
    }
}

/// Materialize an EgressGateway data plane for a subscriber in
/// [`EGRESS_GATEWAY_NAMESPACE`], end to end through slice narrowing AND
/// `apply_destination_rules`.
fn prepare_egress_gateway(mesh: MeshConfig) -> GatewayConfig {
    let runtime = MeshRuntimeConfig {
        namespace: EGRESS_GATEWAY_NAMESPACE.to_string(),
        topology: MeshTopology::EgressGateway,
        sidecar_enforced: true,
        ..default_mesh_runtime()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds")
}

/// The materialized egress upstream for [`EXTERNAL_HOST`], plus the effective
/// connect timeout of the proxy that references it.
fn egress_upstream_for_external_host(prepared: &GatewayConfig) -> (&Upstream, u64) {
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.targets.iter().any(|t| t.host == EXTERNAL_HOST))
        .expect("the egress gateway materializes an upstream for the ServiceEntry host");
    let connect_timeout_ms = prepared
        .proxies
        .iter()
        .find(|p| p.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("the materialized egress upstream has a referencing proxy")
        .backend_connect_timeout_ms;
    (upstream, connect_timeout_ms)
}

#[test]
fn a_synthesized_egress_upstream_carries_the_service_entry_owners_traffic_policy() {
    let owner = vec![external_owner_policy_rule(EXTERNAL_HOST_OWNER)];
    let prepared = prepare_egress_gateway(egress_gateway_mesh(EXTERNAL_HOST_OWNER, owner));
    let (upstream, connect_timeout_ms) = egress_upstream_for_external_host(&prepared);

    // The premise of the case: the gateway's namespace is stamped on the
    // upstream, so it cannot stand in for the ServiceEntry's owner.
    assert_eq!(
        upstream.namespace, EGRESS_GATEWAY_NAMESPACE,
        "a ServiceEntry-derived egress upstream carries the GATEWAY's namespace"
    );
    assert_ne!(
        upstream.namespace, EXTERNAL_HOST_OWNER,
        "and the operator cannot move it into the owning namespace"
    );

    assert_eq!(
        connect_timeout_ms, 2222,
        "the owner's connectTimeout must reach the egress proxy"
    );
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some(EXTERNAL_HOST),
        "the owner's TLS origination must reach the egress upstream — dropping \
         it leaves the external connection on whatever posture the upstream \
         defaults to, which is weaker than what the host's owner configured"
    );
    assert_eq!(
        upstream.backend_tls_san_allow_list,
        vec![EXTERNAL_HOST.to_string()],
        "and so must the SAN allow-list that constrains it"
    );

    let passive = upstream
        .health_checks
        .as_ref()
        .and_then(|checks| checks.passive.as_ref())
        .expect("the egress upstream carries a passive health check");
    // The owner's outlierDetection thresholds must reach the egress upstream.
    assert_eq!(passive.unhealthy_threshold, 7);
    assert_eq!(passive.unhealthy_window_seconds, 11);
    assert_eq!(passive.healthy_after_seconds, 13);
    assert_eq!(passive.max_ejection_percent, Some(42));
}

/// The guard the repair must not trade away. Reading ownership from the
/// ServiceEntry index WIDENS the data-plane tier pass, so an unrelated
/// namespace's rule for the same external host must still be refused — the
/// index names one owner, and it is not the claimant.
#[test]
fn an_unrelated_namespace_rule_never_reaches_the_synthesized_egress_upstream() {
    let unpoliced = prepare_egress_gateway(egress_gateway_mesh(EXTERNAL_HOST_OWNER, Vec::new()));
    let (baseline_upstream, baseline_timeout) = egress_upstream_for_external_host(&unpoliced);
    let baseline_sni = baseline_upstream.backend_tls_sni.clone();

    let claimant = vec![external_owner_policy_rule("evil")];
    let prepared = prepare_egress_gateway(egress_gateway_mesh(EXTERNAL_HOST_OWNER, claimant));
    let (upstream, connect_timeout_ms) = egress_upstream_for_external_host(&prepared);
    assert_eq!(
        connect_timeout_ms, baseline_timeout,
        "`evil` is neither the client, the ServiceEntry's owner, nor the root"
    );
    assert_eq!(
        upstream.backend_tls_sni, baseline_sni,
        "and it must not originate TLS on the owner's behalf either"
    );
}
