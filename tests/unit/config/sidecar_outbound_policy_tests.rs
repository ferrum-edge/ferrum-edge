//! Issue #3262 — Istio `Sidecar.outboundTrafficPolicy` translation, selection,
//! propagation, and effective-policy resolution.
//!
//! Scope of this file (no mesh runtime, no sockets):
//!   - **Translation**: the supported `ALLOW_ANY` / `REGISTRY_ONLY` modes, and
//!     the documented `ALLOW_ANY` default for an omitted/null `mode`, and every
//!     fail-closed variant (unknown / non-string `mode`, non-object block,
//!     unsupported `egressProxy`). A degraded variant must
//!     still leave the `Sidecar` — and therefore its `egress` narrowing — in the
//!     translation, because dropping it would WIDEN the slice.
//!   - **Selection**: which `Sidecar` supplies the policy for a workload, and
//!     that an omitted block inherits rather than walking to a less-specific
//!     `Sidecar`.
//!   - **Ambiguous labels (security)**: when several workloads share one SPIFFE
//!     id with divergent labels the slice carries only their intersection, so
//!     resolution folds every candidate strictest-wins and can never relax a
//!     stricter possibly-applicable workload policy. The Sidecar egress scope
//!     folds the same candidates (GHSA-mhm9-gp97-237q): a destination rides the
//!     slice only when every candidate's scope admits it.
//!   - **Gate**: the policy applies only under
//!     `enforce_sidecar_egress && !sidecar_egress_dry_run`.
//!   - **Effective precedence**: Sidecar → mesh-wide → runtime default.
//!   - **Serialization parity**: native JSON round-trip and the xDS ECDS
//!     carrier round-trip agree with the natively built slice.
//!   - **Update / delete**: editing only the mode, or deleting the `Sidecar`,
//!     changes the slice AND is visible to `content_eq` (so MeshSubscribe
//!     dedupe cannot keep a stale gate live).
//!   - **Canonical docs parity**: `docs/configuration.md` and `ferrum.conf`
//!     describe every application `FERRUM_MESH_SIDECAR_ENFORCED` now gates,
//!     including a workload-scoped `ALLOW_ANY` overriding a stricter default.
//!
//! Live request-path enforcement is covered by
//! `tests/integration/mesh_sidecar_e2e_tests.rs`; CRD status reporting by
//! `tests/integration/k8s_controller_istio_status_tests.rs`.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MeshSidecar, MeshSidecarEgress, OutboundTrafficPolicy,
    ServicePort, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::modes::mesh::config_consumer::xds_client::{
    XdsClientConfig, reverse_translate_xds_snapshot,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::xds::carrier::{MeshSliceCarrier, build_slice_carriers};
use ferrum_edge::xds::translate_mesh_slice_to_snapshot;

/// Rebuild `slice` through the DP's production xDS path (SotW accumulator and
/// reverse translation) as the workload that requested it.
fn rebuild_over_xds(slice: &MeshSlice) -> MeshSlice {
    let config = XdsClientConfig {
        cp_urls: Vec::new(),
        node_id: slice.node_id.clone(),
        cluster: String::new(),
        namespace: slice.namespace.clone(),
        workload_spiffe_id: slice.workload_spiffe_id.clone(),
        waypoint_name: slice.waypoint_name.clone(),
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
        stream_channel_capacity: 1,
        primary_retry_secs: 0,
        connect_timeout_seconds: 0,
        labels: slice.labels.clone(),
    };
    reverse_translate_xds_snapshot(&translate_mesh_slice_to_snapshot(slice), &config)
        .expect("the DP rebuilds the xDS-carried slice")
}
use serde_json::{Value, json};

// ── Kubernetes translation fixtures ───────────────────────────────────────

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn sidecar_object(name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "Sidecar".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
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

/// Translate one `Sidecar` object and return the translated `MeshSidecar`.
/// Panics when the resource was rejected — every case in this file must be
/// ACCEPTED, which is itself the fail-closed property under test.
fn translate_one(spec: Value) -> MeshSidecar {
    let translation =
        translate_k8s_objects(&[sidecar_object("sc", spec)], options()).expect("translation");
    let mesh = translation
        .config
        .mesh
        .as_deref()
        .expect("mesh block")
        .clone();
    assert_eq!(
        mesh.sidecars.len(),
        1,
        "the Sidecar must survive translation; dropping it would also drop its \
         egress narrowing and widen the slice"
    );
    mesh.sidecars.into_iter().next().expect("sidecar")
}

/// A `spec` whose `egress` scope is meaningful, so a test can prove the scope
/// survived alongside a degraded `outboundTrafficPolicy`.
fn spec_with_egress_and_policy(policy: Option<Value>) -> Value {
    let mut spec = json!({
        "egress": [{ "hosts": ["./reviews"] }],
    });
    if let Some(policy) = policy {
        spec["outboundTrafficPolicy"] = policy;
    }
    spec
}

// ── Translation: supported modes ──────────────────────────────────────────

#[test]
fn omitted_outbound_traffic_policy_translates_to_inherit() {
    let sidecar = translate_one(spec_with_egress_and_policy(None));
    assert_eq!(
        sidecar.outbound_traffic_policy, None,
        "an omitted block must inherit the mesh-wide policy, not pin one"
    );
}

#[test]
fn allow_any_mode_translates_to_allow_any() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(
        json!({ "mode": "ALLOW_ANY" }),
    )));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::AllowAny)
    );
}

#[test]
fn registry_only_mode_translates_to_registry_only() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(
        json!({ "mode": "REGISTRY_ONLY" }),
    )));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );
}

#[test]
fn present_policy_with_omitted_or_null_mode_uses_istio_allow_any_default() {
    for policy in [
        json!({}),
        json!({ "mode": null }),
        json!({ "egressProxy": null }),
    ] {
        let sidecar = translate_one(spec_with_egress_and_policy(Some(policy)));
        assert_eq!(
            sidecar.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::AllowAny),
            "a present Sidecar outboundTrafficPolicy object with no concrete mode uses Istio's documented ALLOW_ANY default"
        );
    }
}

// ── Translation: fail-closed variants ─────────────────────────────────────

/// Every unrepresentable-but-present variant must resolve to the restrictive
/// mode AND leave the resource (with its egress scope) intact.
#[test]
fn unrepresentable_outbound_policy_variants_fail_closed_without_dropping_the_sidecar() {
    let cases: Vec<(&str, Value)> = vec![
        (
            "egressProxy with no mode",
            json!({ "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" } }),
        ),
        ("unknown mode token", json!({ "mode": "ALOW_ANY" })),
        ("lowercase mode token", json!({ "mode": "allow_any" })),
        ("numeric proto form", json!({ "mode": 1 })),
        (
            "egressProxy alongside an explicit ALLOW_ANY",
            json!({
                "mode": "ALLOW_ANY",
                "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" },
            }),
        ),
    ];
    for (label, policy) in cases {
        let sidecar = translate_one(spec_with_egress_and_policy(Some(policy)));
        assert_eq!(
            sidecar.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "{label} must fail closed to REGISTRY_ONLY"
        );
        assert_eq!(
            sidecar.egress.len(),
            1,
            "{label} must not cost the Sidecar its egress narrowing"
        );
    }
}

#[test]
fn non_object_outbound_traffic_policy_fails_closed() {
    for policy in [json!("REGISTRY_ONLY"), json!(["REGISTRY_ONLY"]), json!(7)] {
        let sidecar = translate_one(spec_with_egress_and_policy(Some(policy.clone())));
        assert_eq!(
            sidecar.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "a non-object outboundTrafficPolicy ({policy}) must fail closed"
        );
    }
}

#[test]
fn surrounding_whitespace_on_allow_any_fails_closed() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(
        json!({ "mode": "  ALLOW_ANY  " }),
    )));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "a padded ALLOW_ANY token is not an exact Istio enum and must fail closed"
    );
}

/// An explicit `egressProxy: null` is proto-JSON for "unset" and gets the same
/// null-is-absent normalization `mode: null` gets — so it must NOT force
/// REGISTRY_ONLY onto an operator who declared no egress proxy.
#[test]
fn explicit_null_egress_proxy_is_treated_as_absent() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(json!({
        "mode": "ALLOW_ANY",
        "egressProxy": null,
    }))));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::AllowAny),
        "egressProxy: null is unset, so the declared mode must be honored"
    );

    let sidecar = translate_one(spec_with_egress_and_policy(Some(json!({
        "mode": "REGISTRY_ONLY",
        "egressProxy": null,
    }))));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );

    // With no concrete mode and no egress proxy, Istio's documented Sidecar
    // API default applies.
    let sidecar = translate_one(spec_with_egress_and_policy(Some(
        json!({ "egressProxy": null }),
    )));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::AllowAny),
        "an omitted mode resolves to the documented ALLOW_ANY API default"
    );
}

/// A NON-null `egressProxy` still wins over an explicit `ALLOW_ANY`; the null
/// normalization above must not become a bypass.
#[test]
fn non_null_egress_proxy_still_overrides_an_explicit_allow_any() {
    for proxy in [
        json!({ "host": "istio-egressgateway.istio-system.svc.cluster.local" }),
        json!({}),
        json!("istio-egressgateway"),
    ] {
        let sidecar = translate_one(spec_with_egress_and_policy(Some(json!({
            "mode": "ALLOW_ANY",
            "egressProxy": proxy,
        }))));
        assert_eq!(
            sidecar.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "a present, non-null egressProxy must keep the registry gate armed"
        );
    }
}

/// The TOP-LEVEL block is deliberately NOT null-normalized: it is what decides
/// whether a workload-scoped policy exists at all, so an explicit `null` there
/// fails closed rather than silently inheriting a possibly-laxer mesh-wide
/// value.
#[test]
fn explicit_null_outbound_traffic_policy_block_still_fails_closed() {
    let sidecar = translate_one(spec_with_egress_and_policy(Some(Value::Null)));
    assert_eq!(
        sidecar.outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "an explicit top-level null must not be read as 'inherit'"
    );
}

// ── Slice fixtures ────────────────────────────────────────────────────────

fn sidecar(
    name: &str,
    namespace: &str,
    selector: Option<WorkloadSelector>,
    policy: Option<OutboundTrafficPolicy>,
) -> MeshSidecar {
    MeshSidecar {
        name: name.to_string(),
        namespace: namespace.to_string(),
        workload_selector: selector,
        egress_inherits_defaults: false,
        egress: vec![MeshSidecarEgress {
            hosts: vec!["*/*".to_string()],
            port: None,
        }],
        ingress_declared: false,
        ingress: Vec::new(),
        outbound_traffic_policy: policy,
    }
}

fn selector_for(app: &str, namespace: &str) -> WorkloadSelector {
    WorkloadSelector {
        labels: HashMap::from([("app".to_string(), app.to_string())]),
        namespace: Some(namespace.to_string()),
    }
}

fn config_with_sidecars(sidecars: Vec<MeshSidecar>) -> GatewayConfig {
    config_with_mesh(MeshConfig {
        sidecars,
        ..MeshConfig::default()
    })
}

fn config_with_mesh(mesh: MeshConfig) -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

/// Slice request for an `app=reviews` workload in `default`, with Sidecar
/// enforcement on and dry-run off (the gate the policy needs).
fn enforced_request() -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        labels: [("app".to_string(), "reviews".to_string())]
            .into_iter()
            .collect(),
        enforce_sidecar_egress: true,
        ..MeshSliceRequest::default()
    }
}

fn slice_for(config: &GatewayConfig, request: MeshSliceRequest) -> MeshSlice {
    MeshSlice::from_gateway_config(config, request)
}

// ── Selection ─────────────────────────────────────────────────────────────

#[test]
fn workload_scoped_sidecar_policy_wins_over_the_namespace_default() {
    let config = config_with_sidecars(vec![
        sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        ),
        sidecar(
            "reviews",
            "default",
            Some(selector_for("reviews", "default")),
            Some(OutboundTrafficPolicy::RegistryOnly),
        ),
    ]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "the most specific applicable Sidecar supplies the policy"
    );
}

#[test]
fn non_matching_workload_selector_does_not_supply_a_policy() {
    let config = config_with_sidecars(vec![sidecar(
        "ratings",
        "default",
        Some(selector_for("ratings", "default")),
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "a Sidecar that does not select this workload must not gate its egress"
    );
}

#[test]
fn namespace_default_supplies_the_policy_when_no_workload_scoped_sidecar_matches() {
    let config = config_with_sidecars(vec![sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );
}

#[test]
fn selected_sidecar_omitting_the_policy_inherits_instead_of_walking_to_a_less_specific_one() {
    // Istio resolves exactly ONE Sidecar per workload. The workload-scoped one
    // wins; because it omits `outboundTrafficPolicy`, the workload inherits the
    // mesh-wide value — it must NOT fall through to the namespace default's
    // REGISTRY_ONLY (that would be an `egress`-only inheritance rule applied
    // where Istio has none).
    let config = config_with_sidecars(vec![
        sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        ),
        sidecar(
            "reviews",
            "default",
            Some(selector_for("reviews", "default")),
            None,
        ),
    ]);
    let slice = slice_for(&config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "an omitted block on the selected Sidecar inherits the mesh-wide policy"
    );
}

#[test]
fn same_tier_sidecars_resolve_deterministically_by_ascii_smallest_name() {
    let sidecars = vec![
        sidecar(
            "zzz-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        ),
        sidecar(
            "aaa-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        ),
    ];
    let forward = slice_for(&config_with_sidecars(sidecars.clone()), enforced_request());
    let reversed_input: Vec<MeshSidecar> = sidecars.into_iter().rev().collect();
    let reversed = slice_for(&config_with_sidecars(reversed_input), enforced_request());
    assert_eq!(
        forward.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "the ASCII-smallest name wins within a tier"
    );
    assert_eq!(
        forward.sidecar_outbound_traffic_policy, reversed.sidecar_outbound_traffic_policy,
        "resolution must not depend on translator emission order"
    );
}

// ── Enforcement gate ──────────────────────────────────────────────────────

#[test]
fn sidecar_policy_is_not_applied_when_enforcement_is_off() {
    let config = config_with_sidecars(vec![sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(
        &config,
        MeshSliceRequest {
            enforce_sidecar_egress: false,
            ..enforced_request()
        },
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "FERRUM_MESH_SIDECAR_ENFORCED gates the workload-scoped policy"
    );
}

#[test]
fn sidecar_policy_is_not_applied_under_dry_run() {
    // Dry-run reports the egress scope that WOULD apply and changes nothing;
    // arming the registry gate is a live behavior change.
    let config = config_with_sidecars(vec![sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    )]);
    let slice = slice_for(
        &config,
        MeshSliceRequest {
            sidecar_egress_dry_run: true,
            ..enforced_request()
        },
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "dry-run must not arm the outbound registry gate"
    );
    assert!(
        slice.sidecar_egress_scope.is_some(),
        "dry-run still reports the egress scope"
    );
}

// ── Effective precedence ──────────────────────────────────────────────────

#[test]
fn effective_policy_prefers_sidecar_then_mesh_wide_then_runtime_default() {
    let mesh_wide = MeshSlice {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        ..MeshSlice::default()
    };
    let sidecar_relaxes = MeshSlice {
        sidecar_outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
        ..mesh_wide.clone()
    };
    let sidecar_tightens = MeshSlice {
        sidecar_outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
        ..MeshSlice::default()
    };
    let inherits_runtime = MeshSlice::default();

    assert_eq!(
        mesh_wide.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "the mesh-wide policy overrides the runtime default"
    );
    assert_eq!(
        sidecar_relaxes.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny,
        "a Sidecar ALLOW_ANY relaxes a mesh-wide REGISTRY_ONLY (Istio semantics)"
    );
    assert_eq!(
        sidecar_tightens.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "a Sidecar REGISTRY_ONLY tightens an otherwise-permissive mesh"
    );
    assert_eq!(
        inherits_runtime.effective_outbound_traffic_policy(OutboundTrafficPolicy::RegistryOnly),
        OutboundTrafficPolicy::RegistryOnly,
        "with neither tier set, FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY decides"
    );
    assert_eq!(
        inherits_runtime.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny,
        "the shipped default stays AllowAny"
    );
}

// ── Update / delete ───────────────────────────────────────────────────────

#[test]
fn editing_only_the_mode_changes_the_slice_and_is_visible_to_content_eq() {
    let registry_only = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )]),
        enforced_request(),
    );
    let allow_any = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        )]),
        enforced_request(),
    );
    assert_ne!(
        registry_only.sidecar_outbound_traffic_policy, allow_any.sidecar_outbound_traffic_policy,
        "the edit must reach the slice"
    );
    assert!(
        !registry_only.content_eq(&allow_any),
        "content_eq must see a mode-only edit, or MeshSubscribe dedupe keeps the stale gate live"
    );
}

#[test]
fn deleting_the_sidecar_falls_back_to_the_mesh_wide_policy() {
    let before = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )]),
        enforced_request(),
    );
    let after = slice_for(&config_with_sidecars(Vec::new()), enforced_request());

    assert_eq!(
        before.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );
    assert_eq!(
        after.sidecar_outbound_traffic_policy, None,
        "deleting the Sidecar withdraws its override"
    );
    assert!(
        !before.content_eq(&after),
        "the withdrawal must not be deduped away"
    );
    assert_eq!(
        after.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny,
        "after deletion the workload falls back to the mesh-wide/runtime policy"
    );
}

#[test]
fn withdrawing_a_relaxing_sidecar_restores_the_mesh_wide_registry_gate() {
    // The security-relevant direction: a Sidecar ALLOW_ANY was masking a
    // mesh-wide REGISTRY_ONLY. Deleting it must re-arm the gate.
    let mesh_with_sidecar = MeshConfig {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        sidecars: vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        )],
        ..MeshConfig::default()
    };
    let mesh_without_sidecar = MeshConfig {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
        ..MeshConfig::default()
    };
    let before = slice_for(&config_with_mesh(mesh_with_sidecar), enforced_request());
    let after = slice_for(&config_with_mesh(mesh_without_sidecar), enforced_request());

    assert_eq!(
        before.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::AllowAny
    );
    assert_eq!(
        after.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "withdrawing the relaxing Sidecar must re-arm the mesh-wide gate"
    );
    assert!(!before.content_eq(&after));
}

// ── Serialization parity ──────────────────────────────────────────────────

#[test]
fn mesh_sidecar_outbound_policy_round_trips_through_native_json() {
    let original = sidecar(
        "ns-default",
        "default",
        None,
        Some(OutboundTrafficPolicy::RegistryOnly),
    );
    let encoded = serde_json::to_string(&original).expect("encode");
    assert!(
        encoded.contains("\"outbound_traffic_policy\":\"registry_only\""),
        "native/file encoding uses the snake_case enum: {encoded}"
    );
    let decoded: MeshSidecar = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, original);

    // An omitted field is the inherit case and must stay omitted on the wire.
    let inheriting = sidecar("ns-default", "default", None, None);
    let encoded = serde_json::to_string(&inheriting).expect("encode");
    assert!(
        !encoded.contains("outbound_traffic_policy"),
        "the inherit case must not serialize a value: {encoded}"
    );
    let decoded: MeshSidecar = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded.outbound_traffic_policy, None);
}

#[test]
fn native_source_rejects_an_unknown_outbound_policy_value() {
    let malformed = json!({
        "name": "ns-default",
        "namespace": "default",
        "outbound_traffic_policy": "registry_onlyy",
    });
    let decoded: Result<MeshSidecar, _> = serde_json::from_value(malformed);
    assert!(
        decoded.is_err(),
        "the native/file source must fail closed on an unknown enum value rather \
         than silently defaulting"
    );
}

#[test]
fn slice_round_trips_the_sidecar_policy_through_the_xds_carriers() {
    let native = slice_for(
        &config_with_sidecars(vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )]),
        enforced_request(),
    );
    assert_eq!(
        native.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );

    let carriers = build_slice_carriers(&native);
    let policy_carrier = carriers
        .iter()
        .find(|c| matches!(c, MeshSliceCarrier::SidecarOutboundTrafficPolicy(_)))
        .expect("sidecar outbound policy carrier is emitted");
    assert_eq!(
        policy_carrier.resource_name(),
        "ferrum-mesh-carrier/sidecar-outbound-traffic-policy",
        "the reserved ECDS resource name is part of the DP's decode binding"
    );

    // Rebuild through the DP's production xDS path.
    let recovered = rebuild_over_xds(&native);
    assert_eq!(
        recovered.sidecar_outbound_traffic_policy, native.sidecar_outbound_traffic_policy,
        "an xDS-built slice must resolve the same workload-scoped policy"
    );
    assert_eq!(
        recovered.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        native.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        "xDS and native slices must agree on the EFFECTIVE policy"
    );
}

#[test]
fn absent_sidecar_policy_carrier_is_the_wire_form_of_inherit() {
    // The DP rebuilds `RecoveredMeshSlice` per ECDS response, so a CP that stops
    // emitting the carrier (Sidecar deleted, or gate turned off) leaves the DP
    // with `None` and it falls back to the mesh-wide value. Nothing has to
    // publish an explicit "cleared" sentinel.
    let inheriting = slice_for(&config_with_sidecars(Vec::new()), enforced_request());
    let carriers = build_slice_carriers(&inheriting);
    assert!(
        !carriers
            .iter()
            .any(|c| matches!(c, MeshSliceCarrier::SidecarOutboundTrafficPolicy(_))),
        "no carrier is emitted when there is no workload-scoped override"
    );

    let recovered = rebuild_over_xds(&inheriting);
    assert_eq!(recovered.sidecar_outbound_traffic_policy, None);
}

#[test]
fn sidecar_and_mesh_wide_policies_ride_distinct_carriers() {
    // Collapsing the two tiers onto one carrier would make a Sidecar ALLOW_ANY
    // indistinguishable from a mesh-wide ALLOW_ANY and break the
    // delete-falls-back-to-mesh-wide path.
    let mesh = MeshConfig {
        outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
        sidecars: vec![sidecar(
            "ns-default",
            "default",
            None,
            Some(OutboundTrafficPolicy::RegistryOnly),
        )],
        ..MeshConfig::default()
    };
    let slice = slice_for(&config_with_mesh(mesh), enforced_request());
    let carriers = build_slice_carriers(&slice);

    let mesh_wide = carriers
        .iter()
        .find(|c| matches!(c, MeshSliceCarrier::OutboundTrafficPolicy(_)))
        .expect("mesh-wide carrier");
    let workload_scoped = carriers
        .iter()
        .find(|c| matches!(c, MeshSliceCarrier::SidecarOutboundTrafficPolicy(_)))
        .expect("workload-scoped carrier");
    assert_ne!(
        mesh_wide.type_url(),
        workload_scoped.type_url(),
        "the two precedence tiers must not share an inner type URL"
    );
    assert_ne!(
        mesh_wide.resource_name(),
        workload_scoped.resource_name(),
        "the two precedence tiers must not share an ECDS resource name"
    );
}

// ── End-to-end through the Kubernetes translator ──────────────────────────

#[test]
fn kubernetes_translated_sidecar_policy_reaches_the_slice() {
    let object = K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: "Sidecar".to_string(),
        metadata: K8sMetadata {
            name: "reviews".to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({
            "workloadSelector": { "labels": { "app": "reviews" } },
            "egress": [{ "hosts": ["*/*"] }],
            "outboundTrafficPolicy": { "mode": "REGISTRY_ONLY" },
        }),
        status: Value::Object(serde_json::Map::new()),
    };
    let translation = translate_k8s_objects(&[object], options()).expect("translation");
    let slice = slice_for(&translation.config, enforced_request());
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "the Kubernetes translation must reach the workload's slice"
    );
    assert_eq!(
        slice.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "and override an otherwise-permissive runtime default"
    );
}

// ── Ambiguous workload labels must not relax the gate ─────────────────────
//
// When several workloads share one SPIFFE id with DIVERGENT label sets and the
// request carries no explicit labels, the slice's labels are only their
// INTERSECTION. A `workloadSelector` Sidecar that genuinely selects one of those
// workloads can miss that intersection, so selection would fall through to a
// less-specific — possibly `ALLOW_ANY` — tier and silently disarm the outbound
// registry gate. Resolution therefore folds every candidate label set,
// strictest-wins (`REGISTRY_ONLY` > inherit > `ALLOW_ANY`).

const SHARED_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/shared";

fn shared_spiffe_workload(service: &str, labels: &[(&str, &str)]) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(SHARED_SPIFFE).expect("spiffe"),
        selector: WorkloadSelector {
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            namespace: Some("default".to_string()),
        },
        service_name: service.to_string(),
        service_namespace: None,
        addresses: vec!["10.0.0.1".to_string()],
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: "default".to_string(),
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

/// A request with NO explicit labels, pinned to the shared SPIFFE id — the shape
/// that makes the slice `labels_ambiguous` when the candidates diverge.
fn ambiguous_request() -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        workload_spiffe_id: Some(SHARED_SPIFFE.to_string()),
        enforce_sidecar_egress: true,
        ..MeshSliceRequest::default()
    }
}

fn ambiguous_slice(sidecars: Vec<MeshSidecar>, workloads: Vec<Workload>) -> MeshSlice {
    let config = config_with_mesh(MeshConfig {
        sidecars,
        workloads,
        ..MeshConfig::default()
    });
    let slice = slice_for(&config, ambiguous_request());
    assert!(
        slice.labels_ambiguous,
        "the fixture must actually produce an ambiguous slice, or the fold is not under test"
    );
    slice
}

/// The finding's exact scenario: the label intersection matches only a
/// permissive namespace default, while a real candidate is selected by a
/// stricter `workloadSelector` Sidecar. The strict policy must win.
#[test]
fn ambiguous_labels_do_not_relax_a_stricter_workload_scoped_policy() {
    let slice = ambiguous_slice(
        vec![
            sidecar(
                "ns-default-open",
                "default",
                None,
                Some(OutboundTrafficPolicy::AllowAny),
            ),
            sidecar(
                "reviews-strict",
                "default",
                Some(selector_for("reviews", "default")),
                Some(OutboundTrafficPolicy::RegistryOnly),
            ),
        ],
        vec![
            shared_spiffe_workload("reviews", &[("app", "reviews")]),
            shared_spiffe_workload("ratings", &[("app", "ratings")]),
        ],
    );
    assert!(
        slice.labels.is_empty(),
        "the two candidates share no labels, so the intersection is empty and \
         would select only the permissive namespace default"
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "a stricter possibly-applicable workload policy must not be relaxed by ambiguity"
    );
    assert_eq!(
        slice.effective_outbound_traffic_policy(OutboundTrafficPolicy::AllowAny),
        OutboundTrafficPolicy::RegistryOnly,
        "and the registry gate stays armed end to end"
    );
}

/// A non-empty intersection is just as unsafe: it can match a BROAD permissive
/// selector while a narrower, stricter selector applies to one real candidate.
/// The per-tier ASCII-smallest-name tiebreak still resolves each candidate.
#[test]
fn ambiguous_labels_do_not_relax_when_the_intersection_matches_a_broad_open_sidecar() {
    let slice = ambiguous_slice(
        vec![
            // Same tier as the broad Sidecar below; the ASCII-smaller name wins
            // for the canary candidate that matches both.
            MeshSidecar {
                workload_selector: Some(WorkloadSelector {
                    labels: HashMap::from([
                        ("app".to_string(), "reviews".to_string()),
                        ("tier".to_string(), "canary".to_string()),
                    ]),
                    namespace: Some("default".to_string()),
                }),
                ..sidecar(
                    "a-canary-strict",
                    "default",
                    None,
                    Some(OutboundTrafficPolicy::RegistryOnly),
                )
            },
            sidecar(
                "z-reviews-open",
                "default",
                Some(selector_for("reviews", "default")),
                Some(OutboundTrafficPolicy::AllowAny),
            ),
        ],
        vec![
            shared_spiffe_workload("reviews", &[("app", "reviews"), ("tier", "web")]),
            shared_spiffe_workload("reviews-canary", &[("app", "reviews"), ("tier", "canary")]),
        ],
    );
    assert_eq!(
        slice.labels.get("app"),
        Some(&"reviews".to_string()),
        "the intersection keeps app=reviews and therefore matches the OPEN selector"
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly),
        "the canary candidate's stricter selector must win over the broad ALLOW_ANY"
    );
}

/// Inherit outranks `ALLOW_ANY`: a candidate with no applicable Sidecar defers
/// to the mesh-wide tier, which may itself be `REGISTRY_ONLY`, so the fold must
/// not adopt another candidate's `ALLOW_ANY`.
#[test]
fn ambiguous_labels_prefer_inherit_over_a_candidate_allow_any() {
    let slice = ambiguous_slice(
        vec![sidecar(
            "reviews-open",
            "default",
            Some(selector_for("reviews", "default")),
            Some(OutboundTrafficPolicy::AllowAny),
        )],
        vec![
            shared_spiffe_workload("reviews", &[("app", "reviews")]),
            shared_spiffe_workload("ratings", &[("app", "ratings")]),
        ],
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "the ratings candidate has no applicable Sidecar, so the workload tier \
         must defer to the mesh-wide policy rather than adopting ALLOW_ANY"
    );
    assert_eq!(
        slice.effective_outbound_traffic_policy(OutboundTrafficPolicy::RegistryOnly),
        OutboundTrafficPolicy::RegistryOnly,
        "so a strict mesh-wide/runtime default stays in force"
    );
}

/// The fold must not OVER-tighten either: when every candidate resolves to the
/// same permissive policy, that policy is honored.
#[test]
fn ambiguous_labels_keep_allow_any_when_every_candidate_agrees() {
    let slice = ambiguous_slice(
        vec![sidecar(
            "ns-default-open",
            "default",
            None,
            Some(OutboundTrafficPolicy::AllowAny),
        )],
        vec![
            shared_spiffe_workload("reviews", &[("app", "reviews")]),
            shared_spiffe_workload("ratings", &[("app", "ratings")]),
        ],
    );
    assert_eq!(
        slice.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::AllowAny),
        "unanimous candidates must not be tightened; the fold keeps precedence honest"
    );
}

/// The fold is order-independent, so precedence stays deterministic across
/// pods, reconciles, and translator emission order.
#[test]
fn ambiguous_label_resolution_is_order_independent() {
    let sidecars = || {
        vec![
            sidecar(
                "ns-default-open",
                "default",
                None,
                Some(OutboundTrafficPolicy::AllowAny),
            ),
            sidecar(
                "reviews-strict",
                "default",
                Some(selector_for("reviews", "default")),
                Some(OutboundTrafficPolicy::RegistryOnly),
            ),
        ]
    };
    let workloads = || {
        vec![
            shared_spiffe_workload("reviews", &[("app", "reviews")]),
            shared_spiffe_workload("ratings", &[("app", "ratings")]),
        ]
    };
    let forward = ambiguous_slice(sidecars(), workloads());
    let mut reversed_sidecars = sidecars();
    reversed_sidecars.reverse();
    let mut reversed_workloads = workloads();
    reversed_workloads.reverse();
    let reversed = ambiguous_slice(reversed_sidecars, reversed_workloads);
    assert_eq!(
        forward.sidecar_outbound_traffic_policy,
        reversed.sidecar_outbound_traffic_policy
    );
    assert_eq!(
        forward.sidecar_outbound_traffic_policy,
        Some(OutboundTrafficPolicy::RegistryOnly)
    );
}

/// Ambiguity does not bypass the rollout gate: with enforcement off, the
/// workload tier stays absent and the mesh-wide policy remains in force.
#[test]
fn ambiguous_labels_still_respect_the_enforcement_gate() {
    let config = config_with_mesh(MeshConfig {
        sidecars: vec![sidecar(
            "reviews-strict",
            "default",
            Some(selector_for("reviews", "default")),
            Some(OutboundTrafficPolicy::RegistryOnly),
        )],
        workloads: vec![
            shared_spiffe_workload("reviews", &[("app", "reviews")]),
            shared_spiffe_workload("ratings", &[("app", "ratings")]),
        ],
        ..MeshConfig::default()
    });
    let request = MeshSliceRequest {
        enforce_sidecar_egress: false,
        ..ambiguous_request()
    };
    let slice = slice_for(&config, request);
    assert!(slice.labels_ambiguous);
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "the workload-scoped tier is gated by FERRUM_MESH_SIDECAR_ENFORCED"
    );

    let dry_run = MeshSliceRequest {
        sidecar_egress_dry_run: true,
        ..ambiguous_request()
    };
    let slice = slice_for(&config, dry_run);
    assert_eq!(
        slice.sidecar_outbound_traffic_policy, None,
        "dry-run reports but never arms or disarms the registry gate"
    );
}

// ── Ambiguous labels: Sidecar egress scope (GHSA-mhm9-gp97-237q) ──────────
//
// The egress scope applies the same rule #3262 settled for the outbound
// policy: resolve every candidate label set and keep the strictest outcome,
// which for egress scope is the INTERSECTION of the admitted views.

fn mesh_service(namespace: &str, name: &str) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
        uid: None,
        allow_path_parameters: false,
    }
}

/// `default/*`: admits only services in the workload's own namespace.
fn namespace_local_egress_sidecar(name: &str, selector: Option<WorkloadSelector>) -> MeshSidecar {
    MeshSidecar {
        egress: vec![MeshSidecarEgress {
            hosts: vec!["default/*".to_string()],
            port: None,
        }],
        ..sidecar(name, "default", selector, None)
    }
}

fn egress_services() -> Vec<MeshService> {
    vec![
        mesh_service("default", "reviews"),
        mesh_service("default", "ratings"),
        mesh_service("billing", "payments"),
    ]
}

fn shared_spiffe_candidates() -> Vec<Workload> {
    vec![
        shared_spiffe_workload("reviews", &[("app", "reviews")]),
        shared_spiffe_workload("ratings", &[("app", "ratings")]),
    ]
}

fn slice_service_names(slice: &MeshSlice) -> Vec<String> {
    let mut names: Vec<String> = slice
        .services
        .iter()
        .map(|service| format!("{}/{}", service.namespace, service.name))
        .collect();
    names.sort();
    names
}

fn ambiguous_egress_slice(sidecars: Vec<MeshSidecar>) -> MeshSlice {
    let config = config_with_mesh(MeshConfig {
        sidecars,
        workloads: shared_spiffe_candidates(),
        services: egress_services(),
        ..MeshConfig::default()
    });
    let slice = slice_for(&config, ambiguous_request());
    assert!(
        slice.labels_ambiguous,
        "the fixture must actually produce an ambiguous slice, or the fold is not under test"
    );
    slice
}

/// The advisory's scenario: the empty label intersection matches only a wide
/// namespace default, while a real candidate is selected by a narrower
/// `workloadSelector` Sidecar. The narrow scope must still apply.
#[test]
fn ambiguous_labels_do_not_widen_a_workload_scoped_sidecar_egress_scope() {
    let slice = ambiguous_egress_slice(vec![
        sidecar("ns-default-wide", "default", None, None),
        namespace_local_egress_sidecar("reviews-narrow", Some(selector_for("reviews", "default"))),
    ]);
    assert!(slice.labels.is_empty(), "the candidates share no labels");
    assert_eq!(
        slice_service_names(&slice),
        vec!["default/ratings".to_string(), "default/reviews".to_string()],
        "a destination the reviews Sidecar excludes must not ride the slice because the \
         label intersection only matched the wider namespace default"
    );
}

/// A candidate no Sidecar selects contributes no narrowing; it must not cancel
/// the scope another candidate's Sidecar imposes.
#[test]
fn ambiguous_labels_keep_a_candidate_scope_when_another_candidate_has_none() {
    let slice = ambiguous_egress_slice(vec![namespace_local_egress_sidecar(
        "reviews-narrow",
        Some(selector_for("reviews", "default")),
    )]);
    assert_eq!(
        slice_service_names(&slice),
        vec!["default/ratings".to_string(), "default/reviews".to_string()],
        "the reviews candidate's egress scope still applies"
    );
}

/// The fold must not over-tighten: candidates that resolve the same wide
/// scope keep it, and explicit labels resolve exactly.
#[test]
fn egress_scope_fold_does_not_narrow_when_candidates_agree_or_labels_are_explicit() {
    let slice = ambiguous_egress_slice(vec![sidecar("ns-default-wide", "default", None, None)]);
    assert_eq!(
        slice_service_names(&slice),
        vec![
            "billing/payments".to_string(),
            "default/ratings".to_string(),
            "default/reviews".to_string()
        ]
    );

    let config = config_with_mesh(MeshConfig {
        sidecars: vec![
            sidecar("ns-default-wide", "default", None, None),
            namespace_local_egress_sidecar(
                "reviews-narrow",
                Some(selector_for("reviews", "default")),
            ),
        ],
        workloads: shared_spiffe_candidates(),
        services: egress_services(),
        ..MeshConfig::default()
    });
    let explicit = MeshSliceRequest {
        labels: [("app".to_string(), "ratings".to_string())]
            .into_iter()
            .collect(),
        ..ambiguous_request()
    };
    let slice = slice_for(&config, explicit);
    assert!(!slice.labels_ambiguous);
    assert_eq!(
        slice_service_names(&slice).len(),
        3,
        "explicit ratings labels select only the wide namespace default"
    );
}

/// Admission under the fold is order-independent.
#[test]
fn ambiguous_egress_scope_resolution_is_order_independent() {
    let sidecars = || {
        vec![
            sidecar("ns-default-wide", "default", None, None),
            namespace_local_egress_sidecar(
                "reviews-narrow",
                Some(selector_for("reviews", "default")),
            ),
        ]
    };
    let forward = ambiguous_egress_slice(sidecars());
    let mut reversed_sidecars = sidecars();
    reversed_sidecars.reverse();
    let mut workloads = shared_spiffe_candidates();
    workloads.reverse();
    let config = config_with_mesh(MeshConfig {
        sidecars: reversed_sidecars,
        workloads,
        services: egress_services(),
        ..MeshConfig::default()
    });
    let reversed = slice_for(&config, ambiguous_request());
    assert_eq!(
        slice_service_names(&forward),
        slice_service_names(&reversed)
    );
}

// ── Canonical env docs / template parity ──────────────────────────────────

const CONFIGURATION_MD: &str = include_str!("../../../docs/configuration.md");
const FERRUM_CONF: &str = include_str!("../../../ferrum.conf");

/// The pre-#3262 wording that presented the flag as narrowing-only.
const STALE_NARROWING_ONLY_CLAIM: &str = "only gates the slice-";

/// The canonical `docs/configuration.md` table row for a `FERRUM_*` setting.
fn configuration_md_row(key: &str) -> &'static str {
    let prefix = format!("| `{key}` |");
    CONFIGURATION_MD
        .lines()
        .find(|line| line.starts_with(prefix.as_str()))
        .unwrap_or_else(|| panic!("docs/configuration.md must document {key}"))
}

/// The `ferrum.conf` comment block immediately above a setting's commented
/// assignment, plus the assignment line itself.
fn ferrum_conf_block(key: &str) -> String {
    let assignment = format!("# {key} = ");
    let lines: Vec<&str> = FERRUM_CONF.lines().collect();
    let idx = lines
        .iter()
        .position(|line| line.starts_with(assignment.as_str()))
        .unwrap_or_else(|| panic!("ferrum.conf must template {key}"));
    let mut start = idx;
    while start > 0 && lines[start - 1].starts_with('#') {
        start -= 1;
    }
    lines[start..=idx].join("\n")
}

/// `FERRUM_MESH_SIDECAR_ENFORCED` no longer gates slice narrowing alone: it also
/// gates `ingress[]` materialization and the workload-scoped
/// `outboundTrafficPolicy`, where an operator- or tenant-authored `ALLOW_ANY`
/// can override a stricter mesh-wide / env default. The canonical docs and the
/// template must say so, or operators enable the flag without seeing that
/// consequence.
#[test]
fn sidecar_enforced_docs_describe_every_gated_application() {
    let row = configuration_md_row("FERRUM_MESH_SIDECAR_ENFORCED");
    let conf = ferrum_conf_block("FERRUM_MESH_SIDECAR_ENFORCED");
    for (surface, block) in [
        ("docs/configuration.md", row),
        ("ferrum.conf", conf.as_str()),
    ] {
        for needle in [
            "outboundTrafficPolicy",
            "ingress[]",
            "ALLOW_ANY",
            "registry_only",
            "dry-run",
        ] {
            assert!(
                block.contains(needle),
                "{surface} FERRUM_MESH_SIDECAR_ENFORCED docs must mention {needle:?}"
            );
        }
    }
    assert!(
        !CONFIGURATION_MD.contains(STALE_NARROWING_ONLY_CLAIM),
        "docs/configuration.md must not retain the stale slice-narrowing-only claim"
    );
    assert!(
        !FERRUM_CONF.contains(STALE_NARROWING_ONLY_CLAIM),
        "ferrum.conf must not retain the stale slice-narrowing-only claim"
    );
}

/// Dry-run deliberately does NOT apply the workload-scoped policy (arming or
/// disarming the registry gate is a live behavior change), so both canonical
/// surfaces must say so next to the flag operators actually set.
#[test]
fn sidecar_dry_run_docs_disclaim_the_workload_scoped_policy() {
    let row = configuration_md_row("FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN");
    let conf = ferrum_conf_block("FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN");
    for (surface, block) in [
        ("docs/configuration.md", row),
        ("ferrum.conf", conf.as_str()),
    ] {
        assert!(
            block.contains("outboundTrafficPolicy"),
            "{surface} dry-run docs must name the workload-scoped policy it skips"
        );
        assert!(
            block.contains("ingress[]"),
            "{surface} dry-run docs must name the ingress[] materialization it skips"
        );
    }
}
