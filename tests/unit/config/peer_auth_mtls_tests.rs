//! Tests for PeerAuthentication mTLS mode resolution via the public API.
//!
//! Inline tests in `src/modes/mesh/slice.rs` cover the private helpers
//! (`classify_peer_auth_scope`, `peer_auth_applies_to_workload`) and the
//! core resolution scenarios. This file exercises the public
//! `resolve_effective_mtls_mode` and `MeshSlice::resolve_effective_mtls_mode`
//! surface with scenarios that benefit from the external-crate perspective.

use ferrum_edge::modes::mesh::config::{
    MtlsMode, PeerAuthentication, PolicyScope, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::{
    MeshSlice, node_waypoint_destination_peer_authentications, resolve_effective_mtls_mode,
};
use std::collections::{BTreeMap, HashMap};

fn peer_auth(
    name: &str,
    namespace: &str,
    selector: Option<WorkloadSelector>,
    mode: MtlsMode,
    port_overrides: HashMap<u16, MtlsMode>,
) -> PeerAuthentication {
    // The namespace default without a selector, otherwise those labels in
    // `namespace` (or the selector's own namespace when it names one).
    let scope = match selector {
        Some(selector) => PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                namespace: selector.namespace.or_else(|| Some(namespace.to_string())),
                labels: selector.labels,
            },
        },
        None => PolicyScope::Namespace {
            namespace: namespace.to_string(),
        },
    };
    PeerAuthentication {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope,
        mtls_mode: mode,
        port_overrides,
    }
}

fn peer_auth_with_scope(
    name: &str,
    namespace: &str,
    scope: PolicyScope,
    mode: MtlsMode,
) -> PeerAuthentication {
    PeerAuthentication {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope,
        mtls_mode: mode,
        port_overrides: HashMap::new(),
    }
}

// ── Scope precedence (public API path) ──────────────────────────────────

#[test]
fn workload_selector_with_non_matching_labels_falls_through() {
    let policies = vec![
        peer_auth(
            "ns-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        ),
        peer_auth(
            "wl-disable",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "backend".into())]),
                namespace: None,
            }),
            MtlsMode::Disable,
            HashMap::new(),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "frontend".to_string())]);
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    assert_eq!(mode, MtlsMode::Strict);
}

// ── Port-level override does not leak from lower scope ──────────────────

#[test]
fn port_override_from_lower_scope_does_not_leak() {
    let policies = vec![
        peer_auth(
            "ns-policy",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::from([(8080, MtlsMode::Disable)]),
        ),
        peer_auth(
            "wl-policy",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "web".into())]),
                namespace: None,
            }),
            MtlsMode::Permissive,
            HashMap::new(),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "web".to_string())]);
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 8080),
        MtlsMode::Permissive,
    );
}

// ── MeshSlice convenience method ────────────────────────────────────────

#[test]
fn mesh_slice_resolve_method_integration() {
    let slice = MeshSlice {
        namespace: "prod".to_string(),
        labels: BTreeMap::from([
            ("app".to_string(), "api".to_string()),
            ("version".to_string(), "v2".to_string()),
        ]),
        peer_authentications: vec![
            peer_auth(
                "mesh-permissive",
                "prod",
                None,
                MtlsMode::Permissive,
                HashMap::new(),
            ),
            peer_auth(
                "api-strict",
                "prod",
                Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: None,
                }),
                MtlsMode::Strict,
                HashMap::from([(15006, MtlsMode::Permissive)]),
            ),
        ],
        ..MeshSlice::default()
    };

    assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict);
    assert_eq!(
        slice.resolve_effective_mtls_mode(15006),
        MtlsMode::Permissive
    );
}

// ── Same-scope tie-breaking (fail-secure: more-restrictive mode wins) ─────

#[test]
fn same_scope_tie_resolves_fail_secure_to_strict_regardless_of_name() {
    // Two WorkloadSelector-tier PeerAuthentications match the same workload
    // with conflicting modes. The tie resolves FAIL-SECURE to the more-
    // restrictive mode, so a tenant cannot silently downgrade inbound mTLS by
    // giving a Disable policy a low-sorting name. (Two conflicting same-tier
    // PeerAuthentications are an operator misconfiguration; the contract here is
    // fail-secure determinism, not policy-name order.)
    let strict = peer_auth(
        "wl-strict",
        "default",
        Some(WorkloadSelector {
            labels: HashMap::from([("app".into(), "api".into())]),
            namespace: None,
        }),
        MtlsMode::Strict,
        HashMap::new(),
    );
    let disable = peer_auth(
        "wl-disable",
        "default",
        Some(WorkloadSelector {
            labels: HashMap::from([("app".into(), "api".into())]),
            namespace: None,
        }),
        MtlsMode::Disable,
        HashMap::new(),
    );
    let labels = HashMap::from([("app".to_string(), "api".to_string())]);

    // `wl-disable` sorts before `wl-strict`: before this fix it won the tie and
    // silently downgraded mTLS to DISABLE. Fail-secure must pick Strict.
    let forward = vec![disable.clone(), strict.clone()];
    assert_eq!(
        resolve_effective_mtls_mode(&forward, "default", &labels, 8080),
        MtlsMode::Strict,
        "Strict must win over a lower-sorting Disable (no silent downgrade)"
    );

    let reversed = vec![strict, disable];
    assert_eq!(
        resolve_effective_mtls_mode(&reversed, "default", &labels, 8080),
        MtlsMode::Strict,
        "reversed slice order resolves to the same fail-secure winner"
    );
}

#[test]
fn same_scope_tie_resolves_fail_secure_regardless_of_namespace_order() {
    // Mesh-wide policies in different namespaces both apply. The more-
    // restrictive mode wins even when its namespace sorts AFTER the conflicting
    // policy's namespace, so namespace lexical order — including a customized
    // root namespace that sorts after tenants — cannot downgrade inbound mTLS.
    let strict = peer_auth_with_scope(
        "mesh-default",
        "zzz-root",
        PolicyScope::MeshWide,
        MtlsMode::Strict,
    );
    let permissive = peer_auth_with_scope(
        "mesh-default",
        "aaa-root",
        PolicyScope::MeshWide,
        MtlsMode::Permissive,
    );
    let labels = HashMap::<String, String>::new();

    let forward = vec![permissive.clone(), strict.clone()];
    assert_eq!(
        resolve_effective_mtls_mode(&forward, "default", &labels, 8080),
        MtlsMode::Strict,
        "Strict in zzz-root must beat Permissive in aaa-root"
    );

    let reversed = vec![strict, permissive];
    assert_eq!(
        resolve_effective_mtls_mode(&reversed, "default", &labels, 8080),
        MtlsMode::Strict,
        "reversed slice order resolves to the same winner"
    );
}

#[test]
fn same_scope_tie_equal_modes_resolve_deterministically() {
    // When both same-tier policies carry the SAME mode, fail-secure does not
    // fabricate a stricter mode: the operator's intended mode is returned, and
    // the (namespace, name) tiebreak only picks a canonical winner, never the
    // mode — so the result is identical regardless of slice order.
    let a = peer_auth_with_scope(
        "zz-policy",
        "aaa-root",
        PolicyScope::MeshWide,
        MtlsMode::Disable,
    );
    let b = peer_auth_with_scope(
        "aa-policy",
        "zzz-root",
        PolicyScope::MeshWide,
        MtlsMode::Disable,
    );
    let labels = HashMap::<String, String>::new();

    let forward = vec![a.clone(), b.clone()];
    assert_eq!(
        resolve_effective_mtls_mode(&forward, "default", &labels, 8080),
        MtlsMode::Disable,
        "equal-mode same-tier policies resolve to that mode"
    );

    let reversed = vec![b, a];
    assert_eq!(
        resolve_effective_mtls_mode(&reversed, "default", &labels, 8080),
        MtlsMode::Disable,
        "reversed slice order resolves to the same mode"
    );
}

#[test]
fn root_strict_selector_never_overridden_by_tenant_disable_regardless_of_namespace_sort() {
    // A trusted root global-selector STRICT policy must never be downgraded by a
    // tenant DISABLE policy in the same (WorkloadSelector) tier, no matter how
    // the two namespaces sort lexically. Before the fail-secure tiebreak, any
    // tenant namespace that sorted before the root namespace — or a customized
    // root namespace that sorted after tenant namespaces — flipped the resolved
    // mode to DISABLE, silently downgrading inbound mTLS.
    let assert_strict_wins = |root_ns: &str, tenant_ns: &str| {
        let trusted_root = peer_auth_with_scope(
            "zz-root-strict",
            root_ns,
            PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    // Root/global selector: applies across namespaces.
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: None,
                },
            },
            MtlsMode::Strict,
        );
        let tenant_disable = peer_auth_with_scope(
            "00-disable",
            tenant_ns,
            PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: Some(tenant_ns.to_string()),
                },
            },
            MtlsMode::Disable,
        );
        let labels = HashMap::from([("app".to_string(), "api".to_string())]);

        for policies in [
            [trusted_root.clone(), tenant_disable.clone()],
            [tenant_disable.clone(), trusted_root.clone()],
        ] {
            assert_eq!(
                resolve_effective_mtls_mode(&policies, tenant_ns, &labels, 8080),
                MtlsMode::Strict,
                "root STRICT must win over tenant DISABLE (root_ns={root_ns}, tenant_ns={tenant_ns})"
            );
        }
    };

    // Root namespace sorts before the tenant (the only ordering the prior
    // name/namespace tiebreak happened to resolve safely).
    assert_strict_wins("istio-system", "tenant-a");
    // Tenant namespace sorts before the root namespace (previously a bypass).
    assert_strict_wins("istio-system", "backend");
    // Customized root namespace sorts after the tenant namespace (previously a
    // bypass via FERRUM_K8S_ISTIO_ROOT_NAMESPACE).
    assert_strict_wins("zz-root", "tenant-a");
}

// ── Empty selector labels ───────────────────────────────────────────────

#[test]
fn empty_selector_labels_is_namespace_scope() {
    let policies = vec![
        peer_auth(
            "empty-selector",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::new(),
                namespace: None,
            }),
            MtlsMode::Disable,
            HashMap::new(),
        ),
        peer_auth(
            "real-selector",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "web".into())]),
                namespace: None,
            }),
            MtlsMode::Strict,
            HashMap::new(),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "web".to_string())]);
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    assert_eq!(mode, MtlsMode::Strict);
}

/// Namespace-wide STRICT (TCP/HBONE default) plus a selector-scoped
/// `portLevelMtls` PERMISSIVE overlay on one UDP/DTLS port: that port must
/// resolve PERMISSIVE so a NodeWaypoint can start a server-only DTLS listener
/// without a client CA, while other ports stay STRICT.
#[test]
fn workload_port_level_permissive_overrides_namespace_strict_on_that_port() {
    let policies = vec![
        peer_auth("default", "default", None, MtlsMode::Strict, HashMap::new()),
        peer_auth(
            "dtls-echo",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "dtls-echo".into())]),
                namespace: None,
            }),
            MtlsMode::Strict,
            HashMap::from([(15354, MtlsMode::Permissive)]),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "dtls-echo".to_string())]);
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 15354),
        MtlsMode::Permissive,
        "dtls-echo:15354 must be PERMISSIVE so live DTLS probes need no client CA"
    );
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 8080),
        MtlsMode::Strict,
        "other ports on the same workload keep namespace STRICT"
    );
    let other = HashMap::from([("app".to_string(), "udp-echo".to_string())]);
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &other, 15354),
        MtlsMode::Strict,
        "a workload the overlay does not select stays STRICT on every port"
    );
}

/// Hosted live failure (PR #3799 / run 31772379258): the NodeWaypoint's own
/// inbound `peer_authentications` view keeps only policies that match the
/// waypoint pod, so the destination `dtls-echo` `portLevelMtls` PERMISSIVE
/// overlay is stripped. Resolving DTLS client-cert demand against that view
/// alone forces STRICT (empty application-data reply after a completed
/// handshake). The destination capture inventory still carries the overlay;
/// the owner-scoped union must use it.
#[test]
fn node_waypoint_destination_peer_auths_keep_selector_port_overlay() {
    let namespace_strict = peer_auth("default", "default", None, MtlsMode::Strict, HashMap::new());
    let dtls_overlay = peer_auth(
        "dtls-echo",
        "default",
        Some(WorkloadSelector {
            labels: HashMap::from([("app".into(), "dtls-echo".into())]),
            namespace: None,
        }),
        MtlsMode::Strict,
        HashMap::from([(15354, MtlsMode::Permissive)]),
    );
    let slice = MeshSlice {
        namespace: "default".into(),
        labels: BTreeMap::from([("app".to_string(), "ferrum-mesh".to_string())]),
        peer_authentications: vec![namespace_strict.clone()],
        node_waypoint_capture_peer_authentications: vec![
            namespace_strict.clone(),
            dtls_overlay.clone(),
        ],
        ..MeshSlice::default()
    };
    let dtls_labels = HashMap::from([("app".to_string(), "dtls-echo".to_string())]);
    assert_eq!(
        resolve_effective_mtls_mode(&slice.peer_authentications, "default", &dtls_labels, 15354),
        MtlsMode::Strict,
        "the waypoint's own inbound view must not see the destination overlay"
    );
    let destination_auths = node_waypoint_destination_peer_authentications(&slice);
    assert_eq!(
        resolve_effective_mtls_mode(&destination_auths, "default", &dtls_labels, 15354),
        MtlsMode::Permissive,
        "generated DTLS must honour the destination portLevelMtls overlay"
    );
    assert_eq!(
        resolve_effective_mtls_mode(&destination_auths, "default", &dtls_labels, 8080),
        MtlsMode::Strict,
        "other ports on the destination stay STRICT"
    );
    let waypoint_labels = HashMap::from([("app".to_string(), "ferrum-mesh".to_string())]);
    assert_eq!(
        resolve_effective_mtls_mode(&destination_auths, "default", &waypoint_labels, 15354),
        MtlsMode::Strict,
        "the NodeWaypoint's own inbound identity is unchanged by the destination overlay"
    );
}
