//! Istio PeerAuthentication conformance.
//!
//! Covers the single-winner precedence (WorkloadSelector > Namespace > MeshWide)
//! and `mtls.mode` translation. CLAUDE.md "PolicyScope filtering" calls out
//! that precedence is single-winner only where the runtime resolves one
//! effective setting — PeerAuthentication is one of those surfaces.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MtlsMode, PolicyScope};
use ferrum_edge::modes::mesh::slice::resolve_effective_mtls_mode;
use serde_json::{Value, json};

use crate::conformance::registry::Status;

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
        notes = "Maps to MtlsMode::Strict; frontend client cert verification required.",
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
    let scope = pa.scope.expect("scope emitted");
    match scope {
        PolicyScope::WorkloadSelector { selector } => {
            assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
        }
        other => panic!("expected WorkloadSelector scope, got {other:?}"),
    }
}

/// `portLevelMtls.<port>.mode` overrides the workload-level mode for the
/// specified port. `resolve_effective_mtls_mode` looks up the override.
#[test]
fn peer_auth_port_level_mtls_override() {
    register_feature!(
        category = CATEGORY,
        feature = "portLevelMtls.<port>.mode",
        status = Status::Supported,
        notes = "Per-port override within the winning policy; resolve_effective_mtls_mode reads port_overrides[port].",
    );
    let pa = translate_one(json!({
        "mtls": {"mode": "STRICT"},
        "portLevelMtls": {"8080": {"mode": "PERMISSIVE"}}
    }));
    assert_eq!(pa.mtls_mode, MtlsMode::Strict);
    assert_eq!(
        pa.port_overrides.get(&8080).copied(),
        Some(MtlsMode::Permissive)
    );
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
