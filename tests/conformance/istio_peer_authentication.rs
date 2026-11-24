//! Istio PeerAuthentication conformance.
//!
//! Covers the single-winner precedence (WorkloadSelector > Namespace > MeshWide),
//! `mtls.mode` translation, and `UNSET` / omitted-mode inheritance from the
//! next-higher tier. CLAUDE.md "PolicyScope filtering" calls out that
//! precedence is single-winner only where the runtime resolves one effective
//! setting — PeerAuthentication is one of those surfaces.

use std::collections::{BTreeMap, HashMap};

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MtlsMode, PeerAuthentication, PolicyScope};
use ferrum_edge::modes::mesh::slice::{MeshSlice, resolve_effective_mtls_mode};
use serde_json::{Value, json};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "istio_peer_authentication";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn peer_auth(name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "security.istio.io/v1beta1".to_string(),
        kind: "PeerAuthentication".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

/// Translate with the source-namespace filter off, so root-namespace
/// (`istio-system`, mesh-wide) policies are kept alongside `default` ones.
fn translate_all(objects: &[K8sObject]) -> Vec<PeerAuthentication> {
    let options = options().with_source_namespaces(Vec::new());
    let result = translate_k8s_objects(objects, options);
    let mesh = result.expect("translation succeeds").config.mesh;
    let peer_auths = mesh.expect("mesh config").peer_authentications;
    assert_eq!(peer_auths.len(), objects.len(), "every policy translates");
    peer_auths
}

fn translate_one(spec: Value) -> ferrum_edge::modes::mesh::config::PeerAuthentication {
    let result = translate_k8s_objects(&[peer_auth("pa-under-test", "default", spec)], options())
        .expect("translation succeeds");
    let mesh = result.config.mesh.expect("mesh config");
    mesh.peer_authentications
        .into_iter()
        .next()
        .expect("one peer auth emitted")
}

/// `mtls.mode = STRICT` projects onto the workload's MtlsMode.
#[test]
fn peer_auth_strict_mode() {
    register_feature!(
        category = CATEGORY,
        feature = "mtls.mode = STRICT",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Maps to MtlsMode::Strict; frontend client cert verification required. Live-gated \
                 by sidecar.peer_auth.{strict_mtls_authenticated,strict_mtls_plaintext_rejected} \
                 in the mesh-e2e-sidecar suite.",
    );
    let pa = translate_one(json!({"mtls": {"mode": "STRICT"}}));
    assert_eq!(pa.mtls_mode, MtlsMode::Strict);
}

/// `mtls.mode = PERMISSIVE` projects onto the workload's MtlsMode.
#[test]
fn peer_auth_permissive_mode() {
    register_feature!(
        category = CATEGORY,
        feature = "mtls.mode = PERMISSIVE",
        status = Status::Supported,
        notes = "Maps to MtlsMode::Permissive; Ferrum's default when no PA matches.",
    );
    let pa = translate_one(json!({"mtls": {"mode": "PERMISSIVE"}}));
    assert_eq!(pa.mtls_mode, MtlsMode::Permissive);
}

/// `mtls.mode = DISABLE` projects onto the workload's MtlsMode (translation
/// layer accepts). The mesh apply path later rejects `Disable` for Ambient,
/// NodeWaypoint, and EgressGateway topologies per CLAUDE.md — covered by the
/// `mesh_topology_matrix` module / integration suite.
#[test]
fn peer_auth_disable_mode() {
    register_feature!(
        category = CATEGORY,
        feature = "mtls.mode = DISABLE",
        status = Status::Supported,
        notes = "Translation accepts DISABLE; mesh apply rejects it for Ambient/NodeWaypoint/EgressGateway (keeps last good).",
    );
    let pa = translate_one(json!({"mtls": {"mode": "DISABLE"}}));
    assert_eq!(pa.mtls_mode, MtlsMode::Disable);
}

/// An unrecognized `mtls.mode` (e.g. a typo) is rejected at translation rather
/// than silently downgraded to `PERMISSIVE`. Otherwise a malformed
/// PeerAuthentication would quietly weaken a workload's intended inbound mTLS
/// posture; the rejection instead surfaces as `FerrumAccepted=False`.
#[test]
fn peer_auth_unknown_mode_fails_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "mtls.mode unknown value fails closed",
        status = Status::Supported,
        notes = "Unrecognized mode strings are rejected (FerrumAccepted=False) instead of silently mapping to PERMISSIVE.",
    );
    let err = translate_k8s_objects(
        &[peer_auth(
            "pa-typo",
            "default",
            json!({"mtls": {"mode": "STICT"}}),
        )],
        options(),
    )
    .expect_err("unknown mtls.mode should reject the policy");
    let message = err.to_string();
    assert!(
        message.contains("mtls.mode") && message.contains("STICT") && message.contains("STRICT"),
        "error should identify the bad mode and the valid set, got: {message}"
    );
}

/// A typo'd `portLevelMtls.<port>.mode` is likewise rejected rather than
/// silently downgraded to `PERMISSIVE`.
#[test]
fn peer_auth_unknown_port_level_mode_fails_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "portLevelMtls.<port>.mode unknown value fails closed",
        status = Status::Supported,
        notes =
            "Per-port override with an unrecognized mode is rejected, not mapped to PERMISSIVE.",
    );
    let err = translate_k8s_objects(
        &[peer_auth(
            "pa-port-typo",
            "default",
            json!({"mtls": {"mode": "STRICT"}, "portLevelMtls": {"8080": {"mode": "PREMISSIVE"}}}),
        )],
        options(),
    )
    .expect_err("unknown portLevelMtls mode should reject the policy");
    let message = err.to_string();
    assert!(
        message.contains("portLevelMtls[\"8080\"].mode") && message.contains("PREMISSIVE"),
        "error should identify the bad port-level mode, got: {message}"
    );
}

/// `selector.matchLabels` → `WorkloadSelector` scope at translation.
#[test]
fn peer_auth_workload_selector_scope() {
    register_feature!(
        category = CATEGORY,
        feature = "selector.matchLabels → WorkloadSelector scope",
        status = Status::Supported,
        notes = "WorkloadSelector is the most-specific tier in single-winner precedence.",
    );
    let pa = translate_one(json!({
        "selector": {"matchLabels": {"app": "api"}},
        "mtls": {"mode": "STRICT"}
    }));
    match pa.scope {
        PolicyScope::WorkloadSelector { selector } => {
            assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
        }
        other => panic!("expected WorkloadSelector scope, got {other:?}"),
    }
}

/// A mixed-mode policy resolves independently per app port, which is the input
/// used by the pre-handshake `SO_ORIGINAL_DST` TLS-config selector.
#[test]
fn peer_auth_port_level_mtls_override() {
    register_feature!(
        category = CATEGORY,
        feature = "portLevelMtls.<port>.mode",
        status = Status::Supported,
        notes = "Mixed STRICT/PERMISSIVE app ports resolve independently for pre-handshake ServerConfig selection.",
    );
    let pa = translate_one(json!({
        "selector": {"matchLabels": {"app": "api"}},
        "mtls": {"mode": "PERMISSIVE"},
        "portLevelMtls": {
            "8080": {"mode": "STRICT"},
            "9090": {"mode": "PERMISSIVE"}
        }
    }));
    assert_eq!(pa.mtls_mode, MtlsMode::Permissive);
    assert_eq!(
        pa.port_overrides.get(&8080).copied(),
        Some(MtlsMode::Strict)
    );
    assert_eq!(
        pa.port_overrides.get(&9090).copied(),
        Some(MtlsMode::Permissive)
    );
    let labels = HashMap::from([("app".to_string(), "api".to_string())]);
    assert_eq!(
        resolve_effective_mtls_mode(std::slice::from_ref(&pa), "default", &labels, 8080),
        MtlsMode::Strict
    );
    assert_eq!(
        resolve_effective_mtls_mode(std::slice::from_ref(&pa), "default", &labels, 9090),
        MtlsMode::Permissive
    );
}

/// Istio only applies `portLevelMtls` when the policy has a workload selector.
#[test]
fn peer_auth_port_level_mtls_requires_selector() {
    register_feature!(
        category = CATEGORY,
        feature = "portLevelMtls requires workload selector",
        status = Status::Supported,
        notes = "Omitted, null, and empty-matchLabels portLevelMtls entries are carried but ignored during effective-mode resolution.",
    );
    let labels = HashMap::<String, String>::new();
    for selector in [Value::Null, json!({"matchLabels": {}})] {
        let pa = translate_one(json!({
            "selector": selector,
            "mtls": {"mode": "STRICT"},
            "portLevelMtls": {
                "8080": {"mode": "DISABLE"}
            }
        }));

        assert_eq!(
            resolve_effective_mtls_mode(std::slice::from_ref(&pa), "default", &labels, 8080),
            MtlsMode::Strict,
            "null/empty-selector portLevelMtls must not override the workload-level mode"
        );
    }
}

/// Single-winner precedence: a WorkloadSelector-scoped PA beats a Namespace-
/// scoped PA in the same namespace on a matching workload.
#[test]
fn peer_auth_workload_selector_beats_namespace() {
    register_feature!(
        category = CATEGORY,
        feature = "WorkloadSelector > Namespace precedence",
        status = Status::Supported,
        notes = "CLAUDE.md invariant: most-specific scope wins for PeerAuthentication.",
    );
    let result = translate_k8s_objects(
        &[
            peer_auth(
                "ns-default",
                "default",
                json!({"mtls": {"mode": "PERMISSIVE"}}),
            ),
            peer_auth(
                "wl-override",
                "default",
                json!({"selector": {"matchLabels": {"app": "api"}}, "mtls": {"mode": "STRICT"}}),
            ),
        ],
        options(),
    )
    .expect("translation succeeds");

    let mesh = result.config.mesh.expect("mesh config");
    let pas = &mesh.peer_authentications;
    assert_eq!(pas.len(), 2);

    let mut labels = HashMap::new();
    labels.insert("app".to_string(), "api".to_string());
    let effective = resolve_effective_mtls_mode(pas, "default", &labels, 8080);
    assert_eq!(
        effective,
        MtlsMode::Strict,
        "WorkloadSelector-scoped STRICT must beat Namespace-scoped PERMISSIVE on matching workload"
    );
}

/// Namespace-scoped PA wins over MeshWide PA on a matching workload.
#[test]
fn peer_auth_namespace_beats_mesh_wide() {
    register_feature!(
        category = CATEGORY,
        feature = "Namespace > MeshWide precedence",
        status = Status::Supported,
        notes = "CLAUDE.md invariant: a namespace-scoped PA beats a root-namespace mesh-wide PA.",
    );
    let result = translate_k8s_objects(
        &[
            peer_auth(
                "mesh-wide",
                "istio-system",
                json!({"mtls": {"mode": "PERMISSIVE"}}),
            ),
            peer_auth("ns-strict", "default", json!({"mtls": {"mode": "STRICT"}})),
        ],
        options(),
    )
    .expect("translation succeeds");

    let mesh = result.config.mesh.expect("mesh config");
    let pas = &mesh.peer_authentications;
    let effective: MtlsMode = resolve_effective_mtls_mode(pas, "default", &HashMap::new(), 8080);
    assert_eq!(effective, MtlsMode::Strict);
}

/// PERMISSIVE is the default mode when no PA matches.
#[test]
fn peer_auth_default_is_permissive_when_no_match() {
    register_feature!(
        category = CATEGORY,
        feature = "default mtls mode = PERMISSIVE when no PA matches",
        status = Status::Supported,
        notes = "resolve_effective_mtls_mode returns Permissive when no PA targets the workload.",
    );
    let effective = resolve_effective_mtls_mode(&[], "default", &HashMap::new(), 8080);
    assert_eq!(effective, MtlsMode::Permissive);
}

/// Istio `UNSET`, and a `mode` / `mtls` block that is omitted (which decodes to
/// `UNSET`), inherit from the next-higher tier: workload port override ->
/// workload mode -> namespace -> mesh-wide -> the `PERMISSIVE` default. A
/// workload policy that only sets `portLevelMtls` (Istio's documented
/// "inherit STRICT, except port X" pattern) must leave every other port at the
/// inherited `STRICT`, and a namespace policy with an empty `mtls` block must
/// not override a mesh-wide `STRICT`. The listener fallback
/// (`resolve_inbound_workload_mtls_mode_fail_closed`) and the per-app-port
/// table (`resolve_inbound_mtls_mode_fail_closed`) resolve the same way.
#[test]
fn peer_auth_unset_and_omitted_modes_inherit_higher_tier() {
    register_feature!(
        category = CATEGORY,
        feature = "mtls.mode UNSET/omitted inherits the next-higher tier",
        status = Status::Supported,
        notes = "UNSET and omitted workload/port/namespace modes inherit (port override -> \
                 workload -> namespace -> mesh-wide -> PERMISSIVE); they never override an \
                 inherited STRICT. Applies to the listener fallback and per-app-port table.",
    );
    let labels = HashMap::from([("app".to_string(), "finance".to_string())]);
    let finance_variants = [
        (
            "UNSET",
            json!({
                "selector": {"matchLabels": {"app": "finance"}},
                "mtls": {"mode": "UNSET"},
                "portLevelMtls": {"8080": {"mode": "DISABLE"}}
            }),
        ),
        (
            "omitted",
            json!({
                "selector": {"matchLabels": {"app": "finance"}},
                "portLevelMtls": {"8080": {"mode": "DISABLE"}}
            }),
        ),
        (
            "empty mtls block",
            json!({
                "selector": {"matchLabels": {"app": "finance"}},
                "mtls": {},
                "portLevelMtls": {"8080": {"mode": "DISABLE"}}
            }),
        ),
    ];
    for (case, finance) in finance_variants {
        let pas = translate_all(&[
            peer_auth("ns-strict", "default", json!({"mtls": {"mode": "STRICT"}})),
            peer_auth("finance", "default", finance),
        ]);
        let translated = pas
            .iter()
            .find(|pa| pa.name == "finance")
            .expect("finance policy translated");
        assert_eq!(
            translated.mtls_mode,
            MtlsMode::Unset,
            "{case}: workload mode must translate to the inherit marker, not PERMISSIVE"
        );
        assert_eq!(
            resolve_effective_mtls_mode(&pas, "default", &labels, 9090),
            MtlsMode::Strict,
            "{case}: a port without an override must inherit the namespace STRICT"
        );
        assert_eq!(
            resolve_effective_mtls_mode(&pas, "default", &labels, 8080),
            MtlsMode::Disable,
            "{case}: the explicit port override still applies"
        );

        let slice = MeshSlice {
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "finance".to_string())]),
            peer_authentications: pas,
            ..MeshSlice::default()
        };
        assert_eq!(
            slice.resolve_inbound_workload_mtls_mode_fail_closed(),
            MtlsMode::Strict,
            "{case}: the inbound listener fallback must inherit the namespace STRICT"
        );
        assert_eq!(
            slice.resolve_inbound_mtls_mode_fail_closed(9090),
            MtlsMode::Strict,
            "{case}: per-app-port resolution must inherit the namespace STRICT"
        );
        assert_eq!(
            slice.resolve_inbound_mtls_mode_fail_closed(8080),
            MtlsMode::Disable,
            "{case}: per-app-port table keeps the explicit override"
        );
    }

    // Namespace policy with no mode under a mesh-wide (root namespace) STRICT.
    for (case, namespace_spec) in [
        ("empty mtls block", json!({"mtls": {}})),
        ("explicit UNSET", json!({"mtls": {"mode": "UNSET"}})),
        ("no mtls block", json!({})),
    ] {
        let pas = translate_all(&[
            peer_auth(
                "mesh-strict",
                "istio-system",
                json!({"mtls": {"mode": "STRICT"}}),
            ),
            peer_auth("ns-unset", "default", namespace_spec),
        ]);
        assert_eq!(
            resolve_effective_mtls_mode(&pas, "default", &HashMap::new(), 9090),
            MtlsMode::Strict,
            "{case}: a namespace policy without a mode must not override mesh-wide STRICT"
        );
        let slice = MeshSlice {
            namespace: "default".to_string(),
            peer_authentications: pas,
            ..MeshSlice::default()
        };
        assert_eq!(
            slice.resolve_inbound_workload_mtls_mode_fail_closed(),
            MtlsMode::Strict,
            "{case}: the inbound listener fallback must inherit mesh-wide STRICT"
        );
    }

    // Port-level UNSET / omitted inherits the policy's own workload mode, and
    // through it the namespace mode when the workload mode is itself unset.
    let pas = translate_all(&[
        peer_auth("ns-strict", "default", json!({"mtls": {"mode": "STRICT"}})),
        peer_auth(
            "finance-permissive",
            "default",
            json!({
                "selector": {"matchLabels": {"app": "finance"}},
                "mtls": {"mode": "PERMISSIVE"},
                "portLevelMtls": {"8080": {"mode": "UNSET"}, "8081": {}}
            }),
        ),
    ]);
    for port in [8080, 8081] {
        assert_eq!(
            resolve_effective_mtls_mode(&pas, "default", &labels, port),
            MtlsMode::Permissive,
            "port {port}: an unset port override inherits the workload's explicit mode"
        );
    }
    let pas = translate_all(&[
        peer_auth("ns-strict", "default", json!({"mtls": {"mode": "STRICT"}})),
        peer_auth(
            "finance-port-unset",
            "default",
            json!({
                "selector": {"matchLabels": {"app": "finance"}},
                "portLevelMtls": {"8080": {"mode": "UNSET"}}
            }),
        ),
    ]);
    assert_eq!(
        resolve_effective_mtls_mode(&pas, "default", &labels, 8080),
        MtlsMode::Strict,
        "an unset port override under an unset workload mode inherits the namespace STRICT"
    );
}

/// Inheritance does not change explicit precedence: an explicit lower-tier mode
/// still overrides a higher tier, an unset chain with nothing above it falls
/// back to the `PERMISSIVE` default, and an inherited mode can be `DISABLE`.
#[test]
fn peer_auth_explicit_lower_tier_mode_still_overrides_inherited_mode() {
    register_feature!(
        category = CATEGORY,
        feature = "explicit lower-tier mtls.mode overrides the inherited mode",
        status = Status::Supported,
        notes = "Only UNSET/omitted modes inherit; an explicit workload or namespace mode \
                 still wins over the tiers above it.",
    );
    let labels = HashMap::from([("app".to_string(), "finance".to_string())]);

    let pas = translate_all(&[
        peer_auth("ns-strict", "default", json!({"mtls": {"mode": "STRICT"}})),
        peer_auth(
            "finance",
            "default",
            json!({
                "selector": {"matchLabels": {"app": "finance"}},
                "mtls": {"mode": "PERMISSIVE"}
            }),
        ),
    ]);
    assert_eq!(
        resolve_effective_mtls_mode(&pas, "default", &labels, 9090),
        MtlsMode::Permissive,
        "an explicit workload PERMISSIVE overrides the namespace STRICT"
    );

    let pas = translate_all(&[
        peer_auth(
            "mesh-strict",
            "istio-system",
            json!({"mtls": {"mode": "STRICT"}}),
        ),
        peer_auth(
            "ns-permissive",
            "default",
            json!({"mtls": {"mode": "PERMISSIVE"}}),
        ),
    ]);
    assert_eq!(
        resolve_effective_mtls_mode(&pas, "default", &HashMap::new(), 9090),
        MtlsMode::Permissive,
        "an explicit namespace PERMISSIVE overrides the mesh-wide STRICT"
    );

    let pas = translate_all(&[
        peer_auth("ns-unset", "default", json!({"mtls": {}})),
        peer_auth(
            "finance",
            "default",
            json!({"selector": {"matchLabels": {"app": "finance"}}}),
        ),
    ]);
    assert_eq!(
        resolve_effective_mtls_mode(&pas, "default", &labels, 9090),
        MtlsMode::Permissive,
        "an unset chain with no concrete tier falls back to the PERMISSIVE default"
    );

    let pas = translate_all(&[
        peer_auth(
            "ns-disable",
            "default",
            json!({"mtls": {"mode": "DISABLE"}}),
        ),
        peer_auth(
            "finance",
            "default",
            json!({"selector": {"matchLabels": {"app": "finance"}}, "mtls": {}}),
        ),
    ]);
    assert_eq!(
        resolve_effective_mtls_mode(&pas, "default", &labels, 9090),
        MtlsMode::Disable,
        "an unset workload mode inherits the namespace DISABLE"
    );
}

/// Same-tier ties stay fail-secure when one of the tied policies inherits: the
/// `UNSET` policy counts at the mode it inherits, and the more restrictive
/// mode wins. The ambiguous shared-SPIFFE escalation likewise counts an
/// `UNSET` candidate-only selector policy at its inherited mode.
#[test]
fn peer_auth_unset_same_tier_tie_and_ambiguous_escalation_fail_secure() {
    register_feature!(
        category = CATEGORY,
        feature = "UNSET same-tier tie and ambiguous-label escalation fail secure",
        status = Status::Supported,
        notes = "An UNSET policy is ranked at its inherited mode in the same-tier \
                 most-restrictive tie-break and in the ambiguous-label fail-closed escalation.",
    );
    let pas = translate_all(&[
        peer_auth(
            "mesh-strict",
            "istio-system",
            json!({"mtls": {"mode": "STRICT"}}),
        ),
        peer_auth(
            "a-ns-permissive",
            "default",
            json!({"mtls": {"mode": "PERMISSIVE"}}),
        ),
        peer_auth("b-ns-unset", "default", json!({"mtls": {}})),
    ]);
    assert_eq!(
        resolve_effective_mtls_mode(&pas, "default", &HashMap::new(), 9090),
        MtlsMode::Strict,
        "a same-tier UNSET inheriting mesh-wide STRICT beats a same-tier PERMISSIVE"
    );

    let pas = translate_all(&[
        peer_auth("ns-strict", "default", json!({"mtls": {"mode": "STRICT"}})),
        peer_auth(
            "shared-permissive",
            "default",
            json!({
                "selector": {"matchLabels": {"app": "shared"}},
                "mtls": {"mode": "PERMISSIVE"}
            }),
        ),
        peer_auth(
            "api-unset",
            "default",
            json!({
                "selector": {"matchLabels": {"role": "api"}},
                "portLevelMtls": {"8080": {"mode": "DISABLE"}}
            }),
        ),
    ]);
    let slice = MeshSlice {
        namespace: "default".to_string(),
        labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
        labels_ambiguous: true,
        peer_authentications: pas,
        ..MeshSlice::default()
    };
    assert_eq!(
        slice.resolve_inbound_workload_mtls_mode_fail_closed(),
        MtlsMode::Strict,
        "a candidate-only UNSET selector policy escalates to the STRICT it would inherit"
    );
}
