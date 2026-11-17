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
//!   `destination_rule_host_specificity` in a direction that invents a tier.
//! * CP/DP agreement on that ownership for a MACHINE-SYNTHESIZED upstream: an
//!   EgressGateway upstream is stamped with the gateway's own namespace, so the
//!   materialization tier pass must resolve the external host's owner from the
//!   ServiceEntry index rather than from the upstream — and must still refuse a
//!   claimant that does not own it.

use std::collections::HashMap;

use ferrum_edge::config::types::{BackendScheme, GatewayConfig, Upstream, UpstreamTarget};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshDestinationRule, MeshEndpoint, MeshLoadBalancer,
    MeshOutlierDetection, MeshService, MeshSidecar, MeshSidecarEgress, MeshSimpleLb,
    MeshTrafficPolicy, MeshTrafficPolicyTls, MtlsMode, Resolution, ServiceEntry,
    ServiceEntryLocation, ServicePort, Workload, WorkloadRef,
    destination_rule_exported_to_namespace,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, prepare_gateway_config_via_mesh_slice_with_fixtures,
};
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
        allow_path_parameters: false,
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
    let prepared = prepare_gateway_config_via_mesh_slice_with_fixtures(config, &runtime)
        .expect("mesh preparation succeeds");
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
    let prepared = prepare_gateway_config_via_mesh_slice_with_fixtures(config, &runtime)
        .expect("mesh preparation succeeds");

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
    let prepared = prepare_gateway_config_via_mesh_slice_with_fixtures(config, &runtime)
        .expect("mesh preparation succeeds");
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

/// `destination_rule_host_specificity` treats a two-label rule host as Kubernetes
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
        let prepared = prepare_gateway_config_via_mesh_slice_with_fixtures(config, &runtime)
            .expect("mesh preparation succeeds");
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

/// A wildcard host owns nothing itself (issue #7395): it reaches the service
/// tier only for destinations its namespace owns, and `evil` owns none here,
/// so only the client's own wildcard stands.
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

    let error =
        prepare_gateway_config_via_mesh_slice_with_fixtures(config, &alpha_subscriber_runtime())
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

    let forward = prepare_gateway_config_via_mesh_slice_with_fixtures(
        forward_config,
        &alpha_subscriber_runtime(),
    )
    .expect_err("conflicting upstream-wide fields are refused");
    let reversed = prepare_gateway_config_via_mesh_slice_with_fixtures(
        reversed_config,
        &alpha_subscriber_runtime(),
    )
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
    let prepared =
        prepare_gateway_config_via_mesh_slice_with_fixtures(config, &alpha_subscriber_runtime())
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
    let prepared =
        prepare_gateway_config_via_mesh_slice_with_fixtures(config, &alpha_subscriber_runtime())
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
    prepare_gateway_config_via_mesh_slice_with_fixtures(config, &runtime)
        .expect("mesh preparation succeeds")
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

// ── EgressGateway: the DestinationRule drives the backend scheme ─────────
//
// Issue #7236, Istio semantics: an external `HTTP`, `HTTP2` or `GRPC`
// ServiceEntry port is plaintext (gRPC dials h2c) unless a DestinationRule
// `tls.mode` of `SIMPLE`, `MUTUAL` or `ISTIO_MUTUAL` asks the gateway to
// originate TLS. `DISABLE` or no `tls` keeps it plaintext. A `TLS` port stays a
// terminate-and-re-originate port whatever the rule says.

/// The owner's DestinationRule for [`EXTERNAL_HOST`] with only a top-level
/// `tls.mode`.
fn external_tls_mode_rule(mode: MtlsMode) -> MeshDestinationRule {
    let mut dr = rule(
        EXTERNAL_HOST_OWNER,
        "owner-tls",
        EXTERNAL_HOST,
        2222,
        &["*"],
    );
    dr.traffic_policy = Some(MeshTrafficPolicy {
        tls: Some(MeshTrafficPolicyTls {
            mode,
            ..MeshTrafficPolicyTls::default()
        }),
        ..MeshTrafficPolicy::default()
    });
    dr
}

/// The backend scheme of the egress proxy materialized for [`EXTERNAL_HOST`]
/// when its ServiceEntry port declares `protocol`, under `rules`.
fn egress_scheme_for(protocol: AppProtocol, rules: Vec<MeshDestinationRule>) -> BackendScheme {
    let mut mesh = egress_gateway_mesh(EXTERNAL_HOST_OWNER, rules);
    mesh.service_entries[0].ports[0].protocol = protocol;
    let prepared = prepare_egress_gateway(mesh);
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.targets.iter().any(|t| t.host == EXTERNAL_HOST))
        .expect("the egress gateway materializes an upstream for the ServiceEntry host");
    prepared
        .proxies
        .iter()
        .find(|p| p.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("the materialized egress upstream has a referencing proxy")
        .backend_scheme
        .expect("an HTTP-family egress proxy carries a backend scheme")
}

#[test]
fn egress_gateway_http2_and_grpc_ports_are_plaintext_without_a_destination_rule() {
    for protocol in [AppProtocol::Http, AppProtocol::Http2, AppProtocol::Grpc] {
        assert_eq!(
            egress_scheme_for(protocol, Vec::new()),
            BackendScheme::Http,
            "{protocol:?}: an external port with no DestinationRule is plaintext (h2c for gRPC)"
        );
    }
}

#[test]
fn egress_gateway_destination_rule_tls_mode_originates_tls() {
    for protocol in [AppProtocol::Http, AppProtocol::Http2, AppProtocol::Grpc] {
        assert_eq!(
            egress_scheme_for(protocol, vec![external_tls_mode_rule(MtlsMode::Simple)]),
            BackendScheme::Https,
            "{protocol:?}: tls.mode SIMPLE originates TLS to the external backend"
        );
        assert_eq!(
            egress_scheme_for(protocol, vec![external_tls_mode_rule(MtlsMode::Disable)]),
            BackendScheme::Http,
            "{protocol:?}: tls.mode DISABLE keeps the external port plaintext"
        );
    }
}

#[test]
fn egress_gateway_port_level_tls_mode_overrides_the_top_level_mode() {
    let port = 443;
    let with_port_mode = |top: MtlsMode, per_port: MtlsMode| {
        let mut dr = external_tls_mode_rule(top);
        dr.port_level_settings.insert(
            port,
            MeshTrafficPolicy {
                tls: Some(MeshTrafficPolicyTls {
                    mode: per_port,
                    ..MeshTrafficPolicyTls::default()
                }),
                ..MeshTrafficPolicy::default()
            },
        );
        egress_scheme_for(AppProtocol::Grpc, vec![dr])
    };
    assert_eq!(
        with_port_mode(MtlsMode::Disable, MtlsMode::Simple),
        BackendScheme::Https,
        "a SIMPLE portLevelSettings entry for the ServiceEntry port originates TLS"
    );
    assert_eq!(
        with_port_mode(MtlsMode::Simple, MtlsMode::Disable),
        BackendScheme::Http,
        "a DISABLE portLevelSettings entry keeps that port plaintext"
    );
}

#[test]
fn egress_gateway_unrelated_namespace_rule_cannot_turn_on_tls_origination() {
    let mut claimant = external_tls_mode_rule(MtlsMode::Simple);
    claimant.namespace = "evil".to_string();
    assert_eq!(
        egress_scheme_for(AppProtocol::Grpc, vec![claimant]),
        BackendScheme::Http,
        "only a rule the lookup path admits for the host can change its scheme"
    );
}

#[test]
fn egress_gateway_tls_port_always_originates_tls() {
    assert_eq!(
        egress_scheme_for(AppProtocol::Tls, Vec::new()),
        BackendScheme::Https
    );
    assert_eq!(
        egress_scheme_for(
            AppProtocol::Tls,
            vec![external_tls_mode_rule(MtlsMode::Disable)]
        ),
        BackendScheme::Https,
        "a TLS port is a terminate-and-re-originate port; DISABLE does not downgrade it"
    );
}

// ── EgressGateway: a STATIC ServiceEntry is still matched by its host ────
//
// Under `resolution: STATIC` the egress upstream's targets are the declared
// endpoint addresses, not the ServiceEntry host. A DestinationRule names the
// host, so the upstream must carry that host as a match candidate or the rule
// (its TLS origination included) never reaches the endpoints and an HTTP2/GRPC
// port silently stays plaintext.

const STATIC_ENDPOINT: &str = "192.0.2.10";

/// [`egress_gateway_mesh`] with the ServiceEntry switched to `resolution:
/// STATIC` and one IP endpoint carrying the named port.
fn static_egress_gateway_mesh(
    protocol: AppProtocol,
    rules: Vec<MeshDestinationRule>,
) -> MeshConfig {
    let mut mesh = egress_gateway_mesh(EXTERNAL_HOST_OWNER, rules);
    let entry = &mut mesh.service_entries[0];
    entry.resolution = Resolution::Static;
    entry.ports[0].protocol = protocol;
    entry.endpoints = vec![MeshEndpoint {
        address: STATIC_ENDPOINT.to_string(),
        ports: HashMap::from([("https".to_string(), 8443)]),
        labels: HashMap::new(),
        network: None,
    }];
    mesh
}

/// The upstream and proxy materialized for the STATIC endpoint.
fn static_egress_pair(prepared: &GatewayConfig) -> (&Upstream, BackendScheme, u64) {
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.targets.iter().any(|t| t.host == STATIC_ENDPOINT))
        .expect("the egress gateway materializes an upstream for the STATIC endpoint");
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("the materialized egress upstream has a referencing proxy");
    (
        upstream,
        proxy
            .backend_scheme
            .expect("an HTTP-family egress proxy carries a backend scheme"),
        proxy.backend_connect_timeout_ms,
    )
}

#[test]
fn a_static_service_entry_host_rule_originates_tls_to_its_endpoints() {
    for protocol in [AppProtocol::Http, AppProtocol::Http2, AppProtocol::Grpc] {
        let prepared = prepare_egress_gateway(static_egress_gateway_mesh(
            protocol,
            vec![external_owner_policy_rule(EXTERNAL_HOST_OWNER)],
        ));
        let (upstream, scheme, connect_timeout_ms) = static_egress_pair(&prepared);
        assert!(
            upstream
                .targets
                .iter()
                .all(|target| target.host == STATIC_ENDPOINT && target.port == 8443),
            "{protocol:?}: the premise — STATIC dials the declared endpoint, not the host"
        );
        assert_eq!(
            scheme,
            BackendScheme::Https,
            "{protocol:?}: the owner's tls.mode SIMPLE for the ServiceEntry host must \
             originate TLS to its STATIC endpoints"
        );
        assert_eq!(
            upstream.backend_tls_sni.as_deref(),
            Some(EXTERNAL_HOST),
            "{protocol:?}: and the rule's TLS settings must reach the upstream"
        );
        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec![EXTERNAL_HOST.to_string()],
            "{protocol:?}: including its SAN allow-list"
        );
        assert_eq!(
            connect_timeout_ms, 2222,
            "{protocol:?}: the rest of the rule's trafficPolicy applies too"
        );
    }
}

#[test]
fn a_static_service_entry_without_a_rule_stays_plaintext_and_a_claimant_cannot_change_it() {
    let unpoliced =
        prepare_egress_gateway(static_egress_gateway_mesh(AppProtocol::Grpc, Vec::new()));
    let (_, scheme, _) = static_egress_pair(&unpoliced);
    assert_eq!(
        scheme,
        BackendScheme::Http,
        "no DestinationRule: plaintext h2c"
    );

    let mut claimant = external_owner_policy_rule("evil");
    claimant.name = "claimant".to_string();
    let prepared = prepare_egress_gateway(static_egress_gateway_mesh(
        AppProtocol::Grpc,
        vec![claimant],
    ));
    let (upstream, scheme, _) = static_egress_pair(&prepared);
    assert_eq!(
        scheme,
        BackendScheme::Http,
        "matching the ServiceEntry host must not let a non-owner's rule reach it"
    );
    assert_eq!(upstream.backend_tls_sni, None);
}

// ── Wildcard hosts: Istio semantics on every topology (issue #7395) ──────
//
// A wildcard rule host (`*.example.com`, `*`) is applied like an exact one.
// Per destination host the winner is the most specific lookup tier first, then
// the most specific host within it (exact or Service alias over any wildcard,
// a longer wildcard suffix over a shorter one). A wildcard owns nothing itself:
// it reaches the service tier only for destinations its own namespace owns.

const EXTERNAL_WILDCARD: &str = "*.example.com";

/// Client tier beats service tier beats root tier even when the more
/// privileged tier only has a wildcard; within one tier, exact beats wildcard
/// and the longer wildcard suffix beats the shorter one.
#[test]
fn wildcard_rules_resolve_by_tier_then_host_specificity() {
    let entries = vec![external_service_entry(
        "beta",
        "external-api",
        EXTERNAL_HOST,
    )];
    let effective = |rules: Vec<MeshDestinationRule>| {
        materialized_external_connect_timeout(
            external_host_mesh(entries.clone(), rules),
            "alpha",
            "beta",
        )
        .0
    };
    let owner_exact = rule("beta", "owner-exact", EXTERNAL_HOST, 2222, &["*"]);

    assert_eq!(
        effective(vec![
            owner_exact.clone(),
            rule("alpha", "client-wildcard", EXTERNAL_WILDCARD, 1111, &["*"]),
        ]),
        1111,
        "the client tier wins outright, even with only a wildcard"
    );
    assert_eq!(
        effective(vec![
            owner_exact.clone(),
            rule(
                "istio-system",
                "root-wildcard",
                EXTERNAL_WILDCARD,
                3333,
                &["*"]
            ),
        ]),
        2222,
        "the owner's exact rule beats the root namespace's wildcard default"
    );
    assert_eq!(
        effective(vec![rule(
            "istio-system",
            "root-wildcard",
            EXTERNAL_WILDCARD,
            3333,
            &["*"]
        )]),
        3333,
        "a root wildcard alone governs the host (it used to be ignored)"
    );
    assert_eq!(
        effective(vec![
            rule("alpha", "client-wildcard", EXTERNAL_WILDCARD, 4444, &["*"]),
            rule("alpha", "client-exact", EXTERNAL_HOST, 1111, &["*"]),
        ]),
        1111,
        "within the client tier the exact host beats the wildcard"
    );
    assert_eq!(
        effective(vec![
            rule("alpha", "client-catch-all", "*", 5555, &["*"]),
            rule("alpha", "client-tld", "*.com", 6666, &["*"]),
            rule("alpha", "client-wildcard", EXTERNAL_WILDCARD, 4444, &["*"]),
        ]),
        4444,
        "within the client tier the longest wildcard suffix wins"
    );
}

/// The service tier for a wildcard is per destination (issue #7395): a
/// wildcard declared by the namespace whose ServiceEntry owns a matching host
/// is admitted and applied there; the same wildcard from an unrelated
/// namespace owns nothing and is refused at admission and on the data plane.
#[test]
fn a_wildcard_reaches_the_service_tier_only_for_destinations_its_namespace_owns() {
    let entries = vec![external_service_entry(
        "beta",
        "external-api",
        EXTERNAL_HOST,
    )];
    let mesh = external_host_mesh(
        entries.clone(),
        vec![
            rule("beta", "owner-wildcard", EXTERNAL_WILDCARD, 2222, &["*"]),
            rule("evil", "hijack-wildcard", EXTERNAL_WILDCARD, 6666, &["*"]),
        ],
    );
    assert_eq!(
        admitted_rule_names(&mesh, "alpha"),
        vec!["owner-wildcard".to_string()],
        "the ServiceEntry owner's wildcard is a service-tier rule for the host it owns"
    );
    let (effective, _) = materialized_external_connect_timeout(mesh, "alpha", "beta");
    assert_eq!(
        effective, 2222,
        "and it governs that host on the data plane"
    );

    // A wildcard naming no destination its namespace owns is refused, whatever
    // the upstream's own namespace says.
    let (effective, baseline) = materialized_external_connect_timeout(
        external_host_mesh(
            Vec::new(),
            vec![rule(
                "evil",
                "hijack-wildcard",
                EXTERNAL_WILDCARD,
                6666,
                &["*"],
            )],
        ),
        "alpha",
        "evil",
    );
    assert_eq!(
        effective, baseline,
        "ownership of a wildcard is never inferred from a namespace alone"
    );
}

/// Requirement 2's shape through slice construction AND TLS-scheme
/// projection: a ServiceEntry owner in another namespace than the
/// EgressGateway authors a wildcard that originates TLS; the gateway dials the
/// owned host over TLS. An unrelated namespace's identical wildcard leaves it
/// plaintext.
#[test]
fn a_cross_namespace_service_entry_owners_wildcard_originates_tls_on_the_egress_gateway() {
    let wildcard_tls = |namespace: &str| {
        let mut dr = external_tls_mode_rule(MtlsMode::Simple);
        dr.namespace = namespace.to_string();
        dr.host = EXTERNAL_WILDCARD.to_string();
        dr
    };
    assert_eq!(
        egress_scheme_for(AppProtocol::Http, vec![wildcard_tls(EXTERNAL_HOST_OWNER)]),
        BackendScheme::Https,
        "the owner's wildcard tls.mode SIMPLE originates TLS to its external host"
    );
    assert_eq!(
        egress_scheme_for(AppProtocol::Http, vec![wildcard_tls("evil")]),
        BackendScheme::Http,
        "an unrelated namespace's wildcard owns nothing and changes nothing"
    );
}

/// The backend scheme an EgressGateway running in `gateway_namespace` dials
/// [`EXTERNAL_HOST`] with (HTTP ServiceEntry port), under `rules`.
fn egress_scheme_in_namespace(
    gateway_namespace: &str,
    rules: Vec<MeshDestinationRule>,
) -> BackendScheme {
    let mut mesh = egress_gateway_mesh(EXTERNAL_HOST_OWNER, rules);
    mesh.workloads = vec![workload_in(gateway_namespace, "egress-gateway")];
    mesh.sidecars = vec![permissive_sidecar(gateway_namespace)];
    let runtime = MeshRuntimeConfig {
        namespace: gateway_namespace.to_string(),
        topology: MeshTopology::EgressGateway,
        sidecar_enforced: true,
        ..default_mesh_runtime()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let prepared = prepare_gateway_config_via_mesh_slice_with_fixtures(config, &runtime)
        .expect("mesh preparation succeeds");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.targets.iter().any(|t| t.host == EXTERNAL_HOST))
        .expect("the egress gateway materializes an upstream for the ServiceEntry host");
    prepared
        .proxies
        .iter()
        .find(|p| p.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("the materialized egress upstream has a referencing proxy")
        .backend_scheme
        .expect("an HTTP-family egress proxy carries a backend scheme")
}

/// Istio's root-namespace exception (issue #7395 requirement 1): for a client
/// that itself runs in the root namespace, only the root namespace's PRIVATE
/// rules are its client tier; its exported rules stay the mesh-wide default
/// behind the destination owner's rules. Otherwise an exported root wildcard
/// `DISABLE` would override the owner's exact TLS rule for every gateway in
/// `istio-system`.
#[test]
fn a_root_namespace_egress_gateway_keeps_exported_root_rules_behind_the_owner() {
    let owner_tls = external_tls_mode_rule(MtlsMode::Simple);
    let root_disable = |name: &str, host: &str, export_to: &[&str]| {
        let mut dr = external_tls_mode_rule(MtlsMode::Disable);
        dr.namespace = "istio-system".to_string();
        dr.name = name.to_string();
        dr.host = host.to_string();
        dr.export_to = export_to.iter().map(|e| (*e).to_string()).collect();
        dr
    };

    assert_eq!(
        egress_scheme_in_namespace(
            "istio-system",
            vec![
                owner_tls.clone(),
                root_disable("mesh-default", EXTERNAL_WILDCARD, &["*"]),
            ],
        ),
        BackendScheme::Https,
        "an exported root wildcard is the root tier, behind the owner's exact rule"
    );
    assert_eq!(
        egress_scheme_in_namespace(
            "istio-system",
            vec![
                owner_tls.clone(),
                root_disable("mesh-default", EXTERNAL_HOST, &["*"]),
            ],
        ),
        BackendScheme::Https,
        "so is an exported root exact rule"
    );
    assert_eq!(
        egress_scheme_in_namespace(
            "istio-system",
            vec![
                owner_tls.clone(),
                root_disable("gateway-local", EXTERNAL_WILDCARD, &["."]),
            ],
        ),
        BackendScheme::Http,
        "a root-namespace PRIVATE rule is the root-namespace client's own tier"
    );
    assert_eq!(
        egress_scheme_in_namespace(
            EGRESS_GATEWAY_NAMESPACE,
            vec![
                owner_tls,
                root_disable("gateway-local", EXTERNAL_WILDCARD, &["."]),
            ],
        ),
        BackendScheme::Https,
        "outside the root namespace a private root rule is invisible"
    );
}

/// A materialized Service upstream is arbitrated on its LOGICAL Service host
/// (issue #7395 requirement 3). Its targets are east-west gateway endpoints and
/// opaque cross-cluster HBONE transport identities; a catch-all rule must not
/// win one of those while the exact rule wins the Service name, which would
/// refuse the whole slice. The genuine multi-destination refusal stays: an
/// operator upstream that really dials both hosts is still refused.
#[test]
fn a_materialized_service_upstream_is_arbitrated_on_its_logical_service_host() {
    use ferrum_edge::_test_support::apply_destination_rules_with_tenant_roots_for_test as apply;

    const SERVICE_FQDN: &str = "reviews.beta.svc.cluster.local";
    let slice = |rules: Vec<MeshDestinationRule>| MeshSlice {
        namespace: "alpha".to_string(),
        istio_root_namespace: "istio-system".to_string(),
        services: vec![service_in("beta", "reviews")],
        destination_rules: rules,
        ..MeshSlice::default()
    };
    let upstream_with_remote_targets = |id: &str| {
        let mut upstream = http_upstream(id, "10.1.0.3", 8080);
        upstream.namespace = "beta".to_string();
        upstream.name = Some(SERVICE_FQDN.to_string());
        for host in [
            "mesh-xc-hbone|eastwest.remote.example.com|15443|10.1.0.4",
            "eastwest.remote.example.com",
        ] {
            upstream.targets.push(UpstreamTarget {
                host: host.to_string(),
                port: 15443,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: None,
                path: None,
            });
        }
        upstream
    };
    let exact = || {
        let mut dr = rule("beta", "owner-exact", SERVICE_FQDN, 2222, &["*"]);
        dr.traffic_policy = Some(MeshTrafficPolicy {
            load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
            ..MeshTrafficPolicy::default()
        });
        dr
    };
    let catch_all = || {
        let mut dr = rule("istio-system", "mesh-default", "*", 3333, &["*"]);
        dr.traffic_policy = Some(MeshTrafficPolicy {
            load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
            ..MeshTrafficPolicy::default()
        });
        dr
    };
    let runtime = alpha_subscriber_runtime();
    let applied = |id: &str, rules: Vec<MeshDestinationRule>| {
        let mut config = GatewayConfig {
            upstreams: vec![upstream_with_remote_targets(id)],
            ..GatewayConfig::default()
        };
        apply(&mut config, &runtime, &slice(rules), &[]).map(|()| config.upstreams[0].clone())
    };

    let materialized = "__mesh-out-upstream-beta-reviews-8080";
    let exact_only = applied(materialized, vec![exact()]).expect("the exact rule applies");
    let catch_all_only =
        applied(materialized, vec![catch_all()]).expect("the catch-all applies alone");
    assert_ne!(
        exact_only.algorithm, catch_all_only.algorithm,
        "the premise: the two rules project different load balancers"
    );
    let both = applied(materialized, vec![exact(), catch_all()])
        .expect("a materialized Service upstream has one logical destination");
    assert_eq!(
        both.algorithm, exact_only.algorithm,
        "the exact owner rule wins the logical Service host over the root catch-all"
    );

    let error = applied("operator-u", vec![exact(), catch_all()])
        .expect_err("an operator upstream really dialing two hosts with different winners");
    assert!(
        error.to_string().contains("cannot be represented"),
        "the genuine multi-destination refusal is kept: {error}"
    );
}

// ── Review round (sol F1–F4, dsf F2) ─────────────────────────────────────

/// The scheme and the materialized egress upstream for the first upstream
/// whose target host or name is `host`, on an EgressGateway in
/// [`EGRESS_GATEWAY_NAMESPACE`] built from `mesh`.
fn egress_scheme_for_mesh(mesh: MeshConfig, host: &str) -> BackendScheme {
    let prepared = prepare_egress_gateway(mesh);
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.name.as_deref() == Some(host) || u.targets.iter().any(|t| t.host == host))
        .expect("the egress gateway materializes an upstream for the ServiceEntry host");
    prepared
        .proxies
        .iter()
        .find(|p| p.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("the materialized egress upstream has a referencing proxy")
        .backend_scheme
        .expect("an HTTP-family egress proxy carries a backend scheme")
}

/// A `tls.mode` DestinationRule in `namespace` for `host`.
fn tls_rule(namespace: &str, name: &str, host: &str, mode: MtlsMode) -> MeshDestinationRule {
    let mut dr = rule(namespace, name, host, 2222, &["*"]);
    dr.traffic_policy = Some(MeshTrafficPolicy {
        tls: Some(MeshTrafficPolicyTls {
            mode,
            ..MeshTrafficPolicyTls::default()
        }),
        ..MeshTrafficPolicy::default()
    });
    dr
}

/// sol F1: a client- or root-tier wildcard is judged by the Sidecar egress
/// scope against the destinations it covers, not against its own namespace
/// and literal host. A gateway importing only `payments/*` keeps a root
/// `*.example.com` TLS rule for `payments`' ServiceEntry host.
#[test]
fn a_root_wildcard_survives_a_sidecar_scope_that_imports_only_the_destination_namespace() {
    let mut mesh = egress_gateway_mesh(
        EXTERNAL_HOST_OWNER,
        vec![tls_rule(
            "istio-system",
            "mesh-default",
            EXTERNAL_WILDCARD,
            MtlsMode::Simple,
        )],
    );
    mesh.sidecars = vec![sidecar_admitting(
        EGRESS_GATEWAY_NAMESPACE,
        &[format!("{EXTERNAL_HOST_OWNER}/*").as_str()],
    )];
    assert_eq!(
        egress_scheme_for_mesh(mesh.clone(), EXTERNAL_HOST),
        BackendScheme::Https,
        "the root wildcard covers an imported destination, so the scope admits it"
    );

    // A scope that imports nothing the wildcard covers still drops it.
    mesh.sidecars = vec![sidecar_admitting(
        EGRESS_GATEWAY_NAMESPACE,
        &[
            format!("{EXTERNAL_HOST_OWNER}/{EXTERNAL_HOST}").as_str(),
            "other/*",
        ],
    )];
    mesh.destination_rules = vec![tls_rule(
        "istio-system",
        "mesh-default",
        "*.unrelated.example",
        MtlsMode::Simple,
    )];
    assert_eq!(
        egress_scheme_for_mesh(mesh, EXTERNAL_HOST),
        BackendScheme::Http,
        "a wildcard covering no admitted destination changes nothing"
    );
}

/// sol F2: a wildcard ServiceEntry host is owned by the single namespace
/// that declares it, at admission and on the data plane, so the owner's rule
/// for the identical host, or for a broader wildcard, governs it from another
/// namespace's EgressGateway; an unrelated namespace's rule does not.
#[test]
fn a_wildcard_service_entry_host_is_governed_by_its_owners_rules() {
    let wildcard_host = "*.wild.example.com";
    let mesh_with = |rules: Vec<MeshDestinationRule>| {
        let mut mesh = egress_gateway_mesh(EXTERNAL_HOST_OWNER, rules);
        mesh.service_entries[0].hosts = vec![wildcard_host.to_string()];
        mesh
    };
    for host in [wildcard_host, "*.example.com", "*"] {
        assert_eq!(
            egress_scheme_for_mesh(
                mesh_with(vec![tls_rule(
                    EXTERNAL_HOST_OWNER,
                    "owner-tls",
                    host,
                    MtlsMode::Simple
                )]),
                wildcard_host,
            ),
            BackendScheme::Https,
            "the owner's {host} rule governs its wildcard ServiceEntry host"
        );
        assert_eq!(
            egress_scheme_for_mesh(
                mesh_with(vec![tls_rule("evil", "hijack", host, MtlsMode::Simple)]),
                wildcard_host,
            ),
            BackendScheme::Http,
            "an unrelated namespace's {host} rule owns nothing"
        );
    }
}

/// sol F3: a STATIC ServiceEntry's DNS endpoint is a transport endpoint of
/// the one logical destination, not a second destination. A root `*` default
/// and the owner's exact rule do not make the EgressGateway upstream
/// unrepresentable; the owner's rule wins the ServiceEntry host.
#[test]
fn a_static_service_entrys_dns_endpoint_does_not_enter_rule_arbitration() {
    let mut mesh = egress_gateway_mesh(
        EXTERNAL_HOST_OWNER,
        vec![
            tls_rule(
                EXTERNAL_HOST_OWNER,
                "owner-tls",
                EXTERNAL_HOST,
                MtlsMode::Simple,
            ),
            tls_rule("istio-system", "mesh-default", "*", MtlsMode::Disable),
        ],
    );
    let entry = &mut mesh.service_entries[0];
    entry.resolution = Resolution::Static;
    entry.endpoints = vec![MeshEndpoint {
        address: "backend.vendor.net".to_string(),
        ports: HashMap::from([("https".to_string(), 8443)]),
        labels: HashMap::new(),
        network: None,
    }];
    assert_eq!(
        egress_scheme_for_mesh(mesh, "backend.vendor.net"),
        BackendScheme::Https,
        "the ServiceEntry host is the one destination; its owner's exact rule wins"
    );
}

/// sol F4 (narrowed): an upstream id, or a name that only repeats it, is never
/// a wildcard candidate, so a catch-all cannot latch onto a synthetic dotted
/// identifier such as an east-west Service upstream's; an exact rule still
/// matches an id as before.
#[test]
fn a_wildcard_never_names_an_upstream_id() {
    use ferrum_edge::_test_support::apply_destination_rules_with_tenant_roots_for_test as apply;

    const SYNTHETIC: &str = "__mesh-ew-upstream-beta-reviews.p8080";
    let slice = MeshSlice {
        namespace: "alpha".to_string(),
        istio_root_namespace: "istio-system".to_string(),
        destination_rules: vec![rule("alpha", "catch-all", "*", 3333, &["*"])],
        ..MeshSlice::default()
    };
    let mut upstream = http_upstream(SYNTHETIC, "10.1.0.3", 8080);
    upstream.namespace = "alpha".to_string();
    upstream.name = Some(SYNTHETIC.to_string());
    let mut proxy = http_proxy("ew-p", "10.1.0.3", 8080);
    proxy.namespace = "alpha".to_string();
    proxy.upstream_id = Some(SYNTHETIC.to_string());
    let baseline = proxy.backend_connect_timeout_ms;
    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    apply(&mut config, &alpha_subscriber_runtime(), &slice, &[]).expect("applies");
    assert_eq!(
        config.proxies[0].backend_connect_timeout_ms, baseline,
        "the catch-all must not match a synthetic id"
    );
}

/// dsf F2: a rule spelled exactly like a wildcard destination host is an
/// exact match for ranking, but without a ServiceEntry owner it never borrows
/// the upstream's namespace for the service tier (admission refuses it the
/// same way); with the owner's ServiceEntry visible it applies.
#[test]
fn an_identically_spelled_wildcard_rule_takes_no_upstream_namespace_fallback() {
    use ferrum_edge::_test_support::apply_destination_rules_with_tenant_roots_for_test as apply;

    const WILD: &str = "*.api.external.com";
    let applied = |service_entries: Vec<ServiceEntry>| {
        let slice = MeshSlice {
            namespace: "alpha".to_string(),
            istio_root_namespace: "istio-system".to_string(),
            service_entries,
            destination_rules: vec![rule("beta", "beta-wild", WILD, 4444, &["*"])],
            ..MeshSlice::default()
        };
        let mut upstream = http_upstream("beta-u", WILD, 443);
        upstream.namespace = "beta".to_string();
        let mut proxy = http_proxy("beta-p", WILD, 443);
        proxy.namespace = "beta".to_string();
        proxy.upstream_id = Some("beta-u".to_string());
        let mut config = GatewayConfig {
            proxies: vec![proxy],
            upstreams: vec![upstream],
            ..GatewayConfig::default()
        };
        apply(&mut config, &alpha_subscriber_runtime(), &slice, &[]).expect("applies");
        config.proxies[0].backend_connect_timeout_ms
    };
    assert_ne!(
        applied(Vec::new()),
        4444,
        "no owner: the wildcard rule must not take the service tier from the upstream"
    );
    assert_eq!(
        applied(vec![external_service_entry("beta", "wild", WILD)]),
        4444,
        "the declaring ServiceEntry makes `beta` the owner of the wildcard host"
    );
}

// ── Review round 2 (sol F1, F2) ──────────────────────────────────────────

/// sol F2 (Istio `pilot/pkg/model/push_context.go`,
/// `getExportedDestinationRuleFromNamespace`): in the target service's
/// namespace Istio picks the most specific host among the EXPORTED rules first
/// and only then checks the client may see it; a hidden match falls through to
/// the root namespace instead of retrying the broader wildcard. So `payments`'
/// exact rule exported only to another namespace hides `payments`' public
/// wildcard from the gateway for that host and the root exact TLS rule
/// applies. The control plane resolves this and sends only the outcome.
///
/// A namespace-private rule (`exportTo: ["."]`) is not in Istio's exported
/// index (`SetDestinationRules` adds only non-private rules to
/// `exportedDestRulesByNamespace`), so it shadows nothing for other
/// namespaces and the owner's wildcard wins the service tier.
#[test]
fn a_hidden_exported_exact_rule_shadows_its_namespaces_wildcard_like_istio() {
    const HIDDEN_EXPORT: &str = "hidden-tenant-ns";
    let rules = |hidden_export: &str| {
        let mut public_wildcard = rule(
            EXTERNAL_HOST_OWNER,
            "owner-wildcard",
            EXTERNAL_WILDCARD,
            4444,
            &["*"],
        );
        public_wildcard.traffic_policy = Some(MeshTrafficPolicy {
            connect_timeout_ms: Some(4444),
            ..MeshTrafficPolicy::default()
        });
        let mut hidden_exact = tls_rule(
            EXTERNAL_HOST_OWNER,
            "owner-exact-hidden",
            EXTERNAL_HOST,
            MtlsMode::Disable,
        );
        hidden_exact.export_to = vec![hidden_export.to_string()];
        let mut hidden_unrelated = rule(
            EXTERNAL_HOST_OWNER,
            "owner-unrelated-hidden",
            "*.payments-internal.example.com",
            5555,
            &[],
        );
        hidden_unrelated.export_to = vec![hidden_export.to_string()];
        vec![
            public_wildcard,
            hidden_exact,
            hidden_unrelated,
            tls_rule("istio-system", "mesh-tls", EXTERNAL_HOST, MtlsMode::Simple),
        ]
    };

    let mesh = egress_gateway_mesh(EXTERNAL_HOST_OWNER, rules(HIDDEN_EXPORT));
    let slice = slice_for(&mesh, EGRESS_GATEWAY_NAMESPACE);
    assert_eq!(
        slice
            .destination_rule_host_exclusions
            .iter()
            .map(|exclusion| (
                exclusion.namespace.as_str(),
                exclusion.name.as_str(),
                exclusion.rule_host.as_str(),
                exclusion.host.as_str()
            ))
            .collect::<Vec<_>>(),
        vec![(
            EXTERNAL_HOST_OWNER,
            "owner-wildcard",
            EXTERNAL_WILDCARD,
            EXTERNAL_HOST
        )],
        "only the outcome rides the slice: the visible wildcard does not apply to that host"
    );
    // Nothing about a rule outside its export scope reaches the subscriber.
    let wire = serde_json::to_string(&slice).expect("slice serializes");
    for hidden in [
        "owner-exact-hidden",
        "owner-unrelated-hidden",
        "payments-internal",
        HIDDEN_EXPORT,
    ] {
        assert!(
            !wire.contains(hidden),
            "hidden-rule metadata {hidden:?} must not appear in another namespace's slice"
        );
    }
    assert_eq!(
        egress_scheme_for_mesh(mesh, EXTERNAL_HOST),
        BackendScheme::Https,
        "the hidden exact match shadows the owner's wildcard; the root TLS rule applies"
    );

    let private = egress_gateway_mesh(EXTERNAL_HOST_OWNER, rules("."));
    assert!(
        slice_for(&private, EGRESS_GATEWAY_NAMESPACE)
            .destination_rule_host_exclusions
            .is_empty(),
        "a namespace-private rule is not in the exported index and excludes nothing"
    );
    assert_eq!(
        egress_scheme_for_mesh(private, EXTERNAL_HOST),
        BackendScheme::Http,
        "the owner's wildcard wins the service tier over the root TLS rule"
    );
}

/// sol F1: a concrete external host belongs to the most specific registered
/// wildcard ServiceEntry covering it, so the declaring namespace's wildcard
/// rule reaches the service tier on an upstream dialing that concrete host
/// (as a NodeWaypoint split residual does), ahead of a root default.
#[test]
fn a_concrete_host_under_a_wildcard_service_entry_takes_its_owners_rule() {
    let concrete = "api.one.wild.example.com";
    let entries = vec![external_service_entry(
        "beta",
        "wild-api",
        "*.wild.example.com",
    )];
    let effective = |rules: Vec<MeshDestinationRule>| {
        let mut upstream = http_upstream("ext-u", concrete, 443);
        upstream.namespace = "alpha".to_string();
        let mut proxy = http_proxy("ext-p", concrete, 443);
        proxy.namespace = "alpha".to_string();
        proxy.upstream_id = Some("ext-u".to_string());
        let config = GatewayConfig {
            proxies: vec![proxy],
            upstreams: vec![upstream],
            mesh: Some(Box::new(external_host_mesh(entries.clone(), rules))),
            ..GatewayConfig::default()
        };
        let prepared = prepare_gateway_config_via_mesh_slice_with_fixtures(
            config,
            &alpha_subscriber_runtime(),
        )
        .expect("mesh preparation succeeds");
        prepared
            .proxies
            .iter()
            .find(|p| p.id == "ext-p")
            .expect("operator proxy survives")
            .backend_connect_timeout_ms
    };
    assert_eq!(
        effective(vec![
            rule("beta", "owner-wildcard", "*.wild.example.com", 2222, &["*"]),
            rule("istio-system", "mesh-default", "*", 3333, &["*"]),
        ]),
        2222,
        "the wildcard ServiceEntry's owner is the service tier for its concrete hosts"
    );
    assert_eq!(
        effective(vec![
            rule("evil", "hijack", "*.wild.example.com", 6666, &["*"]),
            rule("istio-system", "mesh-default", "*", 3333, &["*"]),
        ]),
        3333,
        "an unrelated namespace still owns nothing; the root default applies"
    );
}

// ── Review round 3 (sol F1) ──────────────────────────────────────────────

/// sol F1: an exclusion names the visible rule by namespace, name AND its own
/// host pattern. Native/file configs may repeat one `(namespace, name)` for
/// distinct hosts, so excluding by name alone would also suppress a sibling
/// exact rule that outranks the hidden wildcard. Here `payments/shared`
/// exists twice (a broad wildcard without TLS and an exact TLS rule); a hidden
/// `*.one.example.com` shadows only the broad wildcard, and the exact TLS
/// rule still wins, as in Istio (the exact host is the most specific exported
/// match).
#[test]
fn an_exclusion_never_suppresses_a_same_named_sibling_rule() {
    const CONCRETE: &str = "api.one.example.com";
    let mut mesh = egress_gateway_mesh(
        EXTERNAL_HOST_OWNER,
        vec![
            rule(
                EXTERNAL_HOST_OWNER,
                "shared",
                EXTERNAL_WILDCARD,
                4444,
                &["*"],
            ),
            tls_rule(EXTERNAL_HOST_OWNER, "shared", CONCRETE, MtlsMode::Simple),
            {
                let mut hidden = rule(
                    EXTERNAL_HOST_OWNER,
                    "hidden-narrow",
                    "*.one.example.com",
                    5555,
                    &[],
                );
                hidden.export_to = vec!["hidden-tenant-ns".to_string()];
                hidden
            },
        ],
    );
    mesh.service_entries[0].hosts = vec![CONCRETE.to_string()];

    let slice = slice_for(&mesh, EGRESS_GATEWAY_NAMESPACE);
    assert_eq!(
        slice
            .destination_rule_host_exclusions
            .iter()
            .map(|exclusion| (exclusion.rule_host.as_str(), exclusion.host.as_str()))
            .collect::<Vec<_>>(),
        vec![(EXTERNAL_WILDCARD, CONCRETE)],
        "only the shadowed broad wildcard is excluded, identified by its host pattern"
    );
    assert_eq!(
        egress_scheme_for_mesh(mesh, CONCRETE),
        BackendScheme::Https,
        "the same-named exact TLS rule is not excluded and wins the host"
    );
}
