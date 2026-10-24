//! Node-waypoint per-pod policy scoping on the TCP stream accept path.
//!
//! Finding #3 (re-scoped): PR #1358 plumbed `node_waypoint_policy_scope` onto
//! `StreamConnectionContext` and made `mesh_authz::on_stream_connect` read it,
//! but the TCP/UDP accept loops still hard-passed `None`, so scoped
//! (Namespace/WorkloadSelector) DENY/ALLOW mesh policies were inert on stream
//! traffic in node-waypoint topology. This suite proves the TCP stream accept
//! path now resolves the connection's source pod identity from its socket
//! cookie and stamps the per-pod `PolicyScopeCache`, mirroring the HTTP/HBONE
//! admit path in `src/proxy/mod.rs`.
//!
//! Coverage:
//!   - The exact production chain the accept loop uses — `resolve_stream`
//!     against a *real accepted TCP socket*, then `policy_scope_for_pod` — maps
//!     a connection to its source pod's scope (Linux-only: `SO_COOKIE`).
//!   - A Namespace-scoped and a WorkloadSelector-scoped policy each apply to the
//!     matching source pod and NOT to an unrelated pod (the per-pod filter
//!     `PolicyScopeCache::policy_applies` that `mesh_authz` consumes).
//!   - An unresolved connection (cookie not enrolled) yields no scope, so
//!     `mesh_authz` retains mesh-wide-only policies — the documented
//!     fail-closed-soft default. The plugin-side `mesh_authz.scope_missing`
//!     stamping for `None` scope is covered in
//!     `tests/unit/plugins/mesh_plugins_tests.rs`.
//!   - Non-node-waypoint stream proxies are unchanged: with no resolver
//!     installed the accept path stamps `None` and no per-pod scope is consulted.
//!
//! UDP/DTLS stream scoping is intentionally out of scope: node-waypoint capture
//! is keyed by the per-connection TCP socket cookie (`connect4`/`connect6`
//! cgroup hooks), and a shared UDP frontend socket has no per-source-pod
//! cookie. See `docs/mesh.md` and the comments in `src/proxy/udp_proxy.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_ebpf_common::OrigDst4;
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, WorkloadSelector,
};
use ferrum_edge::modes::mesh::node_waypoint::{
    NodeWaypointIdentity, NodeWaypointIdentityResolver, parse_pod_uid,
};

const POD_A: &str = "11111111-1111-1111-1111-111111111111";
const POD_B: &str = "22222222-2222-2222-2222-222222222222";
const SPIFFE_A: &str = "spiffe://cluster.local/ns/team-a/sa/api";
const SPIFFE_B: &str = "spiffe://cluster.local/ns/team-b/sa/api";

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw).expect("valid test SPIFFE ID")
}

fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn policy_with_scope(name: &str, scope: PolicyScope, action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "team-a".to_string(),
        scope,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action,
        }],
    }
}

/// Enroll pod A (ns `team-a`, labels `app=api,tier=web`) and pod B (ns
/// `team-b`, labels `app=api`) into a fresh resolver, mapping `cookie_a`→A and
/// `cookie_b`→B, and install per-pod policy scopes derived from their
/// workload metadata.
fn resolver_with_two_pods(cookie_a: u64, cookie_b: u64) -> Arc<NodeWaypointIdentityResolver> {
    let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
    let pod_a = parse_pod_uid(POD_A).unwrap();
    let pod_b = parse_pod_uid(POD_B).unwrap();
    let id_a = NodeWaypointIdentity::new(pod_a, spiffe(SPIFFE_A));
    let id_b = NodeWaypointIdentity::new(pod_b, spiffe(SPIFFE_B));
    let hash_a = id_a.workload_spiffe_hash;
    let hash_b = id_b.workload_spiffe_hash;
    resolver.upsert_identity(id_a);
    resolver.upsert_identity(id_b);
    resolver.record_orig_dst4(
        cookie_a,
        OrigDst4 {
            addr: 0x0a00_0001,
            port: 8080,
            pod_uid: pod_a,
            workload_spiffe_hash: hash_a,
        },
    );
    resolver.record_orig_dst4(
        cookie_b,
        OrigDst4 {
            addr: 0x0a00_0002,
            port: 8081,
            pod_uid: pod_b,
            workload_spiffe_hash: hash_b,
        },
    );

    // Install per-pod scopes the way slice apply does: publish one slice
    // generation built from the workload set. Pod A is in team-a with labels
    // app=api,tier=web; pod B is in team-b with app=api. `policy_scope_for_pod`
    // looks each pod up by the exact UID the eBPF stamps (its workload's
    // `metadata.uid`), so the two pods are scoped independently.
    resolver.install_policy_scopes_from_workloads(&[
        workload(
            SPIFFE_A,
            "team-a",
            "api",
            labels(&[("app", "api"), ("tier", "web")]),
            POD_A,
        ),
        workload(SPIFFE_B, "team-b", "api", labels(&[("app", "api")]), POD_B),
    ]);
    resolver
}

/// Build a minimal `Workload` for the slice-driven scope install. `pod_uid` must
/// match the captured pod's `metadata.uid` so the per-pod-UID scope index
/// (`scopes_by_pod_uid`) keys to the exact UID the eBPF stamps.
fn workload(
    spiffe_id: &str,
    namespace: &str,
    service_name: &str,
    labels: HashMap<String, String>,
    pod_uid: &str,
) -> ferrum_edge::modes::mesh::config::Workload {
    use ferrum_edge::identity::TrustDomain;
    use ferrum_edge::modes::mesh::config::{Workload, WorkloadSelector};
    Workload {
        spiffe_id: spiffe(spiffe_id),
        selector: WorkloadSelector {
            labels,
            namespace: Some(namespace.to_string()),
        },
        service_name: service_name.to_string(),
        service_namespace: None,
        addresses: Vec::new(),
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("valid trust domain"),
        namespace: namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: Some(pod_uid.to_string()),
        node_waypoint: None,
        remote_provenance: false,
    }
}

/// A Namespace-scoped policy resolves through the per-pod scope to apply to the
/// pod in that namespace and NOT to a pod in a different namespace. This is the
/// `PolicyScopeCache::policy_applies` filter that `mesh_authz` runs once the
/// accept loop stamps `node_waypoint_policy_scope`.
#[test]
fn namespace_scoped_policy_applies_only_to_matching_pod() {
    let resolver = resolver_with_two_pods(11, 12);
    let pod_a = parse_pod_uid(POD_A).unwrap();
    let pod_b = parse_pod_uid(POD_B).unwrap();

    let team_a_deny = policy_with_scope(
        "team-a-deny",
        PolicyScope::Namespace {
            namespace: "team-a".to_string(),
        },
        PolicyAction::Deny,
    );

    let scope_a = resolver
        .policy_scope_for_pod(&pod_a)
        .expect("pod A scope installed");
    let scope_b = resolver
        .policy_scope_for_pod(&pod_b)
        .expect("pod B scope installed");

    assert!(
        scope_a.policy_applies(&team_a_deny),
        "team-a namespace DENY must apply to a pod in team-a"
    );
    assert!(
        !scope_b.policy_applies(&team_a_deny),
        "team-a namespace DENY must NOT apply to a pod in team-b — \
         pre-fix the stream path treated every connection as mesh-wide and \
         this scoped policy was silently skipped"
    );
}

/// A WorkloadSelector-scoped policy resolves through the per-pod scope to apply
/// only to the pod whose labels match the selector.
#[test]
fn workload_selector_scoped_policy_applies_only_to_matching_pod() {
    let resolver = resolver_with_two_pods(21, 22);
    let pod_a = parse_pod_uid(POD_A).unwrap();
    let pod_b = parse_pod_uid(POD_B).unwrap();

    // Selector requires tier=web; only pod A carries it.
    let tier_web_deny = policy_with_scope(
        "tier-web-deny",
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: labels(&[("tier", "web")]),
                namespace: Some("team-a".to_string()),
            },
        },
        PolicyAction::Deny,
    );

    let scope_a = resolver.policy_scope_for_pod(&pod_a).unwrap();
    let scope_b = resolver.policy_scope_for_pod(&pod_b).unwrap();

    assert!(
        scope_a.policy_applies(&tier_web_deny),
        "tier=web selector DENY must apply to pod A (tier=web)"
    );
    assert!(
        !scope_b.policy_applies(&tier_web_deny),
        "tier=web selector DENY must NOT apply to pod B (no tier label)"
    );
}

/// A MeshWide policy applies to any pod regardless of the per-pod scope — it is
/// never filtered out, matching the mesh-wide-only fallback semantics.
#[test]
fn mesh_wide_policy_applies_to_every_pod() {
    let resolver = resolver_with_two_pods(31, 32);
    let pod_a = parse_pod_uid(POD_A).unwrap();
    let pod_b = parse_pod_uid(POD_B).unwrap();

    let mesh_wide_deny =
        policy_with_scope("mesh-wide-deny", PolicyScope::MeshWide, PolicyAction::Deny);

    let scope_a = resolver.policy_scope_for_pod(&pod_a).unwrap();
    let scope_b = resolver.policy_scope_for_pod(&pod_b).unwrap();

    assert!(scope_a.policy_applies(&mesh_wide_deny));
    assert!(scope_b.policy_applies(&mesh_wide_deny));
}

/// An unenrolled cookie fails closed: `resolve_cookie` errors, so the accept
/// loop stamps no scope. `mesh_authz` then retains mesh-wide-only policies and
/// stamps `mesh_authz.scope_missing` (plugin behavior covered in unit tests).
#[test]
fn unresolved_cookie_yields_no_scope() {
    let resolver = resolver_with_two_pods(41, 42);

    let unknown = resolver.resolve_cookie(999);
    assert!(
        unknown.is_err(),
        "an unenrolled cookie must fail closed so the accept path stamps no \
         per-pod scope (mesh-wide-only fallback)"
    );
}

/// An enrolled identity whose workload is absent from the current slice fails
/// closed on resolve. Enrollment is now slice-driven (lazy hash-join), so an
/// identity outlives its workload only when the control plane removed it;
/// `resolve_record` re-validates the cached identity against the live slice
/// index (`workload_identities_by_hash`) and fails closed rather than resolving
/// to a now-orphaned identity. The stream accept loop then stamps no per-pod
/// scope (mesh-wide-only fallback, see `resolve_node_waypoint_stream_scope`);
/// the HBONE accept loop drops the connection. (Pre-fix this surfaced as
/// "resolves but no scope", which slice-coupled enrollment made unreachable: a
/// vouched workload always contributes both its hash and its scope.)
#[test]
fn enrolled_pod_whose_workload_is_absent_from_slice_fails_closed() {
    let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
    let pod_a = parse_pod_uid(POD_A).unwrap();
    let id_a = NodeWaypointIdentity::new(pod_a, spiffe(SPIFFE_A));
    let hash_a = id_a.workload_spiffe_hash;
    resolver.upsert_identity(id_a);
    resolver.record_orig_dst4(
        7,
        OrigDst4 {
            addr: 0x0a00_0001,
            port: 8080,
            pod_uid: pod_a,
            workload_spiffe_hash: hash_a,
        },
    );
    // No workload in the current slice vouches for this identity's hash (the
    // index is empty), so resolution fails closed even though the identity is
    // cached in `identities_by_pod_uid`.
    assert!(
        resolver.resolve_cookie(7).is_err(),
        "an identity whose workload is not in the current slice must fail \
         closed, not resolve to a stale identity"
    );
    assert!(
        resolver.policy_scope_for_pod(&pod_a).is_none(),
        "and with no installed scope the per-pod lookup stays None"
    );
}

/// End-to-end production chain on a REAL accepted TCP socket: read the
/// accepted server-side socket's `SO_COOKIE`, register an orig-dst record under
/// exactly that cookie (what the GAP-2M accept-side bridge would do), then run
/// the precise resolution the TCP accept loop runs —
/// `resolve_stream(&accepted_stream)` followed by `policy_scope_for_pod`. This
/// pins the wiring: the accept loop maps a live connection to its source pod's
/// scope. Linux-only because `SO_COOKIE` is a Linux socket option; on other
/// platforms node-waypoint resolution fails closed by design.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn resolve_stream_against_real_accepted_socket_maps_to_pod_scope() {
    use crate::scaffolding::port_registry::TestSocket;
    use ferrum_edge::identity::TrustDomain;
    use ferrum_edge::modes::mesh::config::Workload;
    use tokio::net::{TcpListener, TcpStream};

    let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
    let pod_a = parse_pod_uid(POD_A).unwrap();
    let id_a = NodeWaypointIdentity::new(pod_a, spiffe(SPIFFE_A));
    let hash_a = id_a.workload_spiffe_hash;
    resolver.upsert_identity(id_a);

    let listener = TcpListener::bind_test(("127.0.0.1", 0))
        .await
        .expect("bind ephemeral listener");
    let addr = listener.local_addr().expect("listener addr");

    // Connect a client and accept the server-side stream — this is the socket
    // the production accept loop holds and reads `SO_COOKIE` from.
    let connect = tokio::spawn(async move { TcpStream::connect(addr).await });
    let (accepted, _peer) = listener.accept().await.expect("accept connection");
    let _client = connect
        .await
        .expect("join connect")
        .expect("client connect");

    // Read the accepted socket's actual cookie and register the orig-dst record
    // under it, mirroring the accept-side registrar contract.
    let cookie = ferrum_edge::socket_opts::socket_cookie(&accepted).expect("SO_COOKIE on Linux");
    resolver.record_orig_dst4(
        cookie,
        OrigDst4 {
            addr: u32::from_ne_bytes([10, 0, 0, 1]),
            port: 8080,
            pod_uid: pod_a,
            workload_spiffe_hash: hash_a,
        },
    );
    // Install the pod's scope the production way — from the slice's workload
    // set — which also seeds the `workload_spiffe_hash` gate so `resolve_record`'s
    // current-slice re-validation passes for the resolved identity. The workload
    // carries this pod's `metadata.uid` so the per-pod-UID scope index keys to the
    // captured pod.
    let workload = Workload {
        spiffe_id: spiffe(SPIFFE_A),
        selector: WorkloadSelector {
            labels: labels(&[("app", "api"), ("tier", "web")]),
            namespace: Some("team-a".to_string()),
        },
        service_name: "api".to_string(),
        service_namespace: None,
        addresses: Vec::new(),
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("valid trust domain"),
        namespace: "team-a".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: Some(POD_A.to_string()),
        node_waypoint: None,
        remote_provenance: false,
    };
    resolver.install_policy_scopes_from_workloads(&[workload]);

    // The exact chain the TCP accept loop now runs: `resolve_stream` returns
    // the identity, per-pod scope, and original destination from one consistent
    // slice load.
    let resolved = resolver
        .resolve_stream(&accepted)
        .expect("accepted socket resolves to enrolled pod identity");
    assert_eq!(resolved.identity.pod_uid, pod_a);
    assert_eq!(resolved.identity.spiffe_id.as_str(), SPIFFE_A);
    assert_eq!(resolved.orig_dst, "10.0.0.1:8080".parse().unwrap());

    // The scope returned by resolve and the scope re-queried per request must
    // agree (same generation), and both must be present for this vouched pod.
    let scope = resolved
        .policy_scope
        .expect("resolve must return the resolved pod's scope");
    let requeried = resolver
        .policy_scope_for_pod(&resolved.identity.pod_uid)
        .expect("resolved pod has an installed policy scope");
    assert_eq!(scope.namespace, requeried.namespace);

    let team_a_deny = policy_with_scope(
        "team-a-deny",
        PolicyScope::Namespace {
            namespace: "team-a".to_string(),
        },
        PolicyAction::Deny,
    );
    assert!(
        scope.policy_applies(&team_a_deny),
        "the scope resolved from the live connection must apply the team-a \
         namespace policy to the source pod"
    );
}

// ── NodeWaypoint transparent-inbound-capture destination inventory (#3287) ──
//
// A NodeWaypoint serves every ENROLLED pod on its node, and those pods routinely
// live in namespaces other than the NodeWaypoint's own. The capture listener
// terminates unauthenticated direct plaintext, so the destination's own
// PeerAuthentication posture is the only gate — and the ordinary
// subscription-namespace `peer_authentications` view cannot express it.
//
// These cases pin the TRANSPORT: that the cross-namespace destination and its
// STRICT policy actually reach the DP over each config protocol (native/file
// slice projection, and the xDS ECDS carriers), and that an unauthorized or
// foreign-node destination is absent. The resolver-side enforcement is pinned in
// `src/proxy/node_waypoint_ingress_capture.rs`, which can reach the crate-private
// resolver directly.
mod node_waypoint_capture_inventory {
    use std::collections::HashMap;

    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::identity::spiffe::TrustDomain;
    use ferrum_edge::modes::mesh::config::{
        AppProtocol, MeshConfig, MeshPolicy, MeshRule, MtlsMode, NodeWaypointEndpoint,
        PeerAuthentication, PolicyAction, PolicyScope, Workload, WorkloadPort, WorkloadSelector,
    };
    use ferrum_edge::modes::mesh::slice::{
        MeshSlice, MeshSliceRequest, node_waypoint_destination_peer_authentications,
        resolve_effective_mtls_mode,
    };
    use ferrum_edge::xds::carrier::MeshSliceCarrier;

    const THIS_WAYPOINT: &str = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-a";
    const OTHER_WAYPOINT: &str = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-b";
    const APP_PORT: u16 = 8080;

    fn workload(namespace: &str, name: &str, waypoint: &str, address: &str) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
        Workload {
            spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/{namespace}/sa/{name}"))
                .expect("workload SPIFFE ID"),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), name.to_string())]),
                namespace: Some(namespace.to_string()),
            },
            service_name: name.to_string(),
            service_namespace: None,
            addresses: vec![address.to_string()],
            ports: vec![WorkloadPort {
                port: APP_PORT,
                protocol: AppProtocol::Http,
                name: None,
            }],
            trust_domain,
            namespace: namespace.to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some(name.to_string()),
            pod_uid: None,
            node_waypoint: Some(NodeWaypointEndpoint {
                address: "10.0.0.1".to_string(),
                hbone_port: 15008,
                spiffe_id: SpiffeId::new(waypoint).expect("node waypoint SPIFFE ID"),
                node_name: None,
                node_uid: None,
                network: None,
                cluster: None,
            }),
            remote_provenance: false,
        }
    }

    fn namespace_peer_auth(namespace: &str, mode: MtlsMode) -> PeerAuthentication {
        PeerAuthentication {
            name: format!("{namespace}-default"),
            namespace: namespace.to_string(),
            scope: Some(PolicyScope::Namespace {
                namespace: namespace.to_string(),
            }),
            selector: None,
            mtls_mode: mode,
            port_overrides: HashMap::new(),
        }
    }

    /// The local document a `FERRUM_MESH_CONFIG_PROTOCOL=file` NodeWaypoint
    /// loads, or the CP-authorized view a native subscriber receives.
    fn config_with_workloads() -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![
                    workload("payments", "ledger", THIS_WAYPOINT, "10.244.1.7"),
                    workload("payments", "reports", OTHER_WAYPOINT, "10.244.1.8"),
                ],
                peer_authentications: vec![
                    namespace_peer_auth("payments", MtlsMode::Strict),
                    namespace_peer_auth("ferrum", MtlsMode::Permissive),
                ],
                mesh_policies: capture_fixture_policies(),
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        }
    }

    fn policy(namespace: &str, name: &str, scope: PolicyScope, action: PolicyAction) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: namespace.to_string(),
            scope,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: Vec::new(),
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action,
            }],
        }
    }

    fn app_selector(namespace: &str, app: &str) -> PolicyScope {
        PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), app.to_string())]),
                namespace: Some(namespace.to_string()),
            },
        }
    }

    /// AuthorizationPolicy fixture for the capture inventory:
    ///
    /// * `payments-deny-all` — namespace-wide DENY in the captured pod's own
    ///   namespace: must ride the inventory.
    /// * `ledger-deny` — selector DENY matching the captured `ledger` pod: must
    ///   ride.
    /// * `reports-deny` — selector DENY matching only `reports`, which is
    ///   enrolled on ANOTHER node's NodeWaypoint: must NOT ride.
    /// * `inventory-deny` — a namespace with no captured destination at all:
    ///   must NOT ride.
    /// * `mesh-wide-audit` — root-namespace mesh-wide policy: applies to every
    ///   destination, so it rides (and is also in the waypoint's own view).
    /// * `ferrum-deny` — the waypoint's own namespace: stays in the ordinary
    ///   view and is not applicable to any captured destination.
    fn capture_fixture_policies() -> Vec<MeshPolicy> {
        vec![
            policy(
                "payments",
                "payments-deny-all",
                PolicyScope::Namespace {
                    namespace: "payments".to_string(),
                },
                PolicyAction::Deny,
            ),
            policy(
                "payments",
                "ledger-deny",
                app_selector("payments", "ledger"),
                PolicyAction::Deny,
            ),
            policy(
                "payments",
                "reports-deny",
                app_selector("payments", "reports"),
                PolicyAction::Deny,
            ),
            policy(
                "inventory",
                "inventory-deny",
                PolicyScope::Namespace {
                    namespace: "inventory".to_string(),
                },
                PolicyAction::Deny,
            ),
            policy(
                "istio-system",
                "mesh-wide-audit",
                PolicyScope::MeshWide,
                PolicyAction::Audit,
            ),
            policy(
                "ferrum",
                "ferrum-deny",
                PolicyScope::Namespace {
                    namespace: "ferrum".to_string(),
                },
                PolicyAction::Deny,
            ),
        ]
    }

    fn policy_names(policies: &[MeshPolicy]) -> Vec<&str> {
        let mut names: Vec<&str> = policies.iter().map(|policy| policy.name.as_str()).collect();
        names.sort_unstable();
        names
    }

    fn node_waypoint_request() -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            workload_spiffe_id: Some(THIS_WAYPOINT.to_string()),
            node_waypoint_capture_scoping: true,
            ..MeshSliceRequest::default()
        }
    }

    /// File/local slicing derives the inventory DP-side from the same document.
    /// The `payments` STRICT policy must ride the capture fields even though the
    /// NodeWaypoint's own namespace is `ferrum`, and the pod enrolled on another
    /// node's NodeWaypoint must be absent.
    #[test]
    fn local_slicing_carries_the_cross_namespace_capture_destination_and_policy() {
        let slice =
            MeshSlice::from_gateway_config(&config_with_workloads(), node_waypoint_request());

        assert_eq!(
            slice
                .node_waypoint_capture_destinations
                .iter()
                .map(|workload| workload.service_name.as_str())
                .collect::<Vec<_>>(),
            vec!["ledger"],
            "only pods enrolled on THIS NodeWaypoint may be captured for"
        );
        assert_eq!(
            slice
                .node_waypoint_capture_peer_authentications
                .iter()
                .map(|policy| policy.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["payments"],
            "the captured pod's OWN namespace STRICT policy must be carried; the NodeWaypoint's \
             own `ferrum` policy is not applicable to it and must not be"
        );
        assert_eq!(
            slice.node_waypoint_capture_peer_authentications[0].mtls_mode,
            MtlsMode::Strict
        );

        // Routing visibility is untouched: the cross-namespace pod does not
        // appear in `workloads`, and the capture policy does not leak into the
        // proxy's own `peer_authentications` posture view.
        assert!(
            slice
                .workloads
                .iter()
                .all(|workload| workload.namespace == "ferrum"),
            "the capture inventory must not widen the routing workload view"
        );
        assert!(
            slice
                .peer_authentications
                .iter()
                .all(|policy| policy.namespace == "ferrum"),
            "the capture inventory must not widen the proxy's own PeerAuthentication view"
        );
    }

    /// Same-namespace selector-scoped `portLevelMtls` overlays are stripped from
    /// the NodeWaypoint's own inbound view (they do not match the waypoint pod)
    /// but must still ride the capture inventory so generated DTLS listeners
    /// can start PERMISSIVE without a client certificate.
    #[test]
    fn local_slicing_carries_same_namespace_dtls_port_overlay_on_the_capture_inventory() {
        const DTLS_PORT: u16 = 15354;
        let dtls_overlay = PeerAuthentication {
            name: "dtls-echo".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: Some(WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dtls-echo".to_string())]),
                namespace: None,
            }),
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::from([(DTLS_PORT, MtlsMode::Permissive)]),
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![workload(
                    "ferrum",
                    "dtls-echo",
                    THIS_WAYPOINT,
                    "10.244.1.11",
                )],
                peer_authentications: vec![
                    namespace_peer_auth("ferrum", MtlsMode::Strict),
                    dtls_overlay,
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let slice = MeshSlice::from_gateway_config(&config, node_waypoint_request());

        assert!(
            slice
                .peer_authentications
                .iter()
                .all(|policy| policy.name != "dtls-echo"),
            "the destination overlay must not leak into the waypoint's own inbound view"
        );
        assert!(
            slice
                .node_waypoint_capture_peer_authentications
                .iter()
                .any(|policy| policy.name == "dtls-echo"),
            "the capture inventory must carry the destination portLevelMtls overlay"
        );

        let dtls_labels = HashMap::from([("app".to_string(), "dtls-echo".to_string())]);
        let destination_auths = node_waypoint_destination_peer_authentications(&slice);
        assert_eq!(
            resolve_effective_mtls_mode(&destination_auths, "ferrum", &dtls_labels, DTLS_PORT),
            MtlsMode::Permissive,
            "generated DTLS on the overlaid port must be PERMISSIVE"
        );
        assert_eq!(
            resolve_effective_mtls_mode(&destination_auths, "ferrum", &dtls_labels, APP_PORT),
            MtlsMode::Strict,
            "other ports on the same destination stay STRICT"
        );
    }

    /// A non-NodeWaypoint subscriber (the flag absent) receives no inventory at
    /// all — the capture path is the only consumer, and carrying it elsewhere
    /// would be a gratuitous cross-namespace disclosure.
    #[test]
    fn a_non_node_waypoint_subscription_receives_no_capture_inventory() {
        let mut request = node_waypoint_request();
        request.node_waypoint_capture_scoping = false;
        let slice = MeshSlice::from_gateway_config(&config_with_workloads(), request);
        assert!(slice.node_waypoint_capture_destinations.is_empty());
        assert!(slice.node_waypoint_capture_peer_authentications.is_empty());
    }

    /// A NodeWaypoint whose own identity is unknown cannot be matched against
    /// `Workload.node_waypoint.spiffe_id`, so there is no least-privilege answer
    /// and the inventory is empty (the capture path then refuses every
    /// connection rather than resolving one with the wrong policy).
    #[test]
    fn an_identity_less_node_waypoint_subscription_fails_closed() {
        let mut request = node_waypoint_request();
        request.workload_spiffe_id = None;
        let slice = MeshSlice::from_gateway_config(&config_with_workloads(), request);
        assert!(slice.node_waypoint_capture_destinations.is_empty());
        assert!(slice.node_waypoint_capture_peer_authentications.is_empty());
    }

    /// xDS parity: the inventory rides its OWN ECDS carriers, so an xDS-built
    /// slice reaches the same capture posture a native-built one does. Without
    /// this the xDS DP would silently hold an empty inventory.
    #[test]
    fn the_capture_inventory_round_trips_over_the_xds_ecds_carriers() {
        let slice =
            MeshSlice::from_gateway_config(&config_with_workloads(), node_waypoint_request());
        let resources = ferrum_edge::xds::translator::translate_mesh_slice_carriers(&slice);

        let mut rebuilt = MeshSlice::default();
        let mut saw_destinations = false;
        let mut saw_peer_authentications = false;
        let mut saw_mesh_policies = false;
        for resource in &resources {
            // The ECDS resource body is an encoded `TypedExtensionConfig`; the
            // Ferrum carrier is its inner `Any`, exactly as the DP recovers it.
            let typed_extension =
                <ferrum_edge::xds::proto::TypedExtensionConfig as prost::Message>::decode(
                    resource.value.as_slice(),
                )
                .expect("ECDS resource decodes as TypedExtensionConfig");
            let Some(inner) = typed_extension.typed_config.as_ref() else {
                continue;
            };
            let Some(carrier) =
                MeshSliceCarrier::decode(&inner.type_url, &inner.value).expect("carrier decodes")
            else {
                continue;
            };
            saw_destinations |= matches!(
                carrier,
                MeshSliceCarrier::NodeWaypointCaptureDestinations(_)
            );
            saw_peer_authentications |= matches!(
                carrier,
                MeshSliceCarrier::NodeWaypointCapturePeerAuthentications(_)
            );
            saw_mesh_policies |= matches!(
                carrier,
                MeshSliceCarrier::NodeWaypointCaptureMeshPolicies(_)
            );
            ferrum_edge::xds::carrier::apply_carrier(&mut rebuilt, carrier);
        }

        assert!(
            saw_destinations && saw_peer_authentications,
            "both capture carriers must be emitted when the inventory is non-empty"
        );
        assert_eq!(
            rebuilt.node_waypoint_capture_destinations,
            slice.node_waypoint_capture_destinations
        );
        assert_eq!(
            rebuilt.node_waypoint_capture_peer_authentications,
            slice.node_waypoint_capture_peer_authentications
        );
        assert!(
            saw_mesh_policies,
            "the capture AuthorizationPolicy carrier must be emitted when the inventory is \
             non-empty"
        );
        assert!(
            !slice.node_waypoint_capture_mesh_policies.is_empty(),
            "the fixture must exercise a non-empty destination policy inventory"
        );
        assert_eq!(
            rebuilt.node_waypoint_capture_mesh_policies,
            slice.node_waypoint_capture_mesh_policies
        );
    }

    /// `content_eq` backs CP-side update dedupe. The capture inventory moves
    /// independently of every other field (a pod in another namespace enrolling,
    /// or that namespace flipping to STRICT), so omitting it would keep serving
    /// a stale — and more permissive — capture posture.
    #[test]
    fn content_eq_observes_the_capture_inventory() {
        let strict =
            MeshSlice::from_gateway_config(&config_with_workloads(), node_waypoint_request());

        let mut permissive_config = config_with_workloads();
        permissive_config
            .mesh
            .as_deref_mut()
            .expect("mesh")
            .peer_authentications[0] = namespace_peer_auth("payments", MtlsMode::Permissive);
        let permissive =
            MeshSlice::from_gateway_config(&permissive_config, node_waypoint_request());

        assert!(
            !strict.content_eq(&permissive),
            "a captured destination's PeerAuthentication flipping STRICT→PERMISSIVE must not be \
             deduped away"
        );

        let mut dropped = strict.clone();
        dropped.node_waypoint_capture_destinations.clear();
        assert!(
            !strict.content_eq(&dropped),
            "a captured destination leaving the inventory must not be deduped away"
        );
    }

    /// File/local slicing carries the captured destination's own
    /// AuthorizationPolicy set — namespace-wide, selector, and root mesh-wide —
    /// on the dedicated capture field, and nothing else: a selector for a pod on
    /// another node, a namespace with no captured destination, and the waypoint's
    /// own namespace policy are all absent. The ordinary `mesh_policies` view is
    /// not widened.
    #[test]
    fn local_slicing_carries_only_the_capture_destinations_authorization_policies() {
        let slice =
            MeshSlice::from_gateway_config(&config_with_workloads(), node_waypoint_request());

        assert_eq!(
            policy_names(&slice.node_waypoint_capture_mesh_policies),
            vec!["ledger-deny", "mesh-wide-audit", "payments-deny-all"],
            "exactly the policies the scoped evaluator applies to the captured `ledger` pod"
        );
        assert!(
            slice
                .mesh_policies
                .iter()
                .all(|policy| policy.namespace != "payments" && policy.namespace != "inventory"),
            "the capture inventory must not widen the waypoint's own AuthorizationPolicy view"
        );
    }

    /// A non-NodeWaypoint subscriber and an identity-less NodeWaypoint receive no
    /// destination AuthorizationPolicy inventory (no destination, no policy).
    #[test]
    fn capture_authorization_inventory_is_absent_without_capture_scoping_or_identity() {
        let mut unflagged = node_waypoint_request();
        unflagged.node_waypoint_capture_scoping = false;
        let slice = MeshSlice::from_gateway_config(&config_with_workloads(), unflagged);
        assert!(slice.node_waypoint_capture_mesh_policies.is_empty());

        let mut identity_less = node_waypoint_request();
        identity_less.workload_spiffe_id = None;
        let slice = MeshSlice::from_gateway_config(&config_with_workloads(), identity_less);
        assert!(slice.node_waypoint_capture_mesh_policies.is_empty());
    }

    /// A DENY added in the captured pod's namespace changes only the capture
    /// inventory, so slice dedupe must observe it.
    #[test]
    fn content_eq_observes_the_capture_authorization_inventory() {
        let mut without_deny_config = config_with_workloads();
        without_deny_config
            .mesh
            .as_deref_mut()
            .expect("mesh")
            .mesh_policies
            .retain(|policy| policy.namespace != "payments");
        let without_deny =
            MeshSlice::from_gateway_config(&without_deny_config, node_waypoint_request());
        let with_deny =
            MeshSlice::from_gateway_config(&config_with_workloads(), node_waypoint_request());

        assert_eq!(
            without_deny.mesh_policies, with_deny.mesh_policies,
            "the waypoint's own view is identical in both slices"
        );
        assert!(
            !with_deny.content_eq(&without_deny),
            "a captured destination gaining a DENY must not be deduped away"
        );
    }

    /// End to end over the local slice: the plugin config the mesh runtime
    /// injects (`mesh_slice` + `per_pod_policy_scoping`) must refuse a captured
    /// connection to `ledger` because its own namespace DENYs it — the stream
    /// context carries exactly the destination scope the capture relay stamps.
    /// A connection scoped to a waypoint-namespace pod is judged by its own
    /// namespace's policy, not by the foreign one.
    #[tokio::test]
    async fn the_scoped_evaluator_enforces_the_captured_destinations_deny() {
        use std::sync::Arc;

        use ferrum_edge::ConsumerIndex;
        use ferrum_edge::config::types::BackendScheme;
        use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
        use ferrum_edge::plugins::mesh::authz::MeshAuthz;
        use ferrum_edge::plugins::{Plugin, PluginResult, StreamConnectionContext};

        let mut config = config_with_workloads();
        // Keep only the destination's DENY plus the root audit so the waypoint
        // namespace carries nothing that could refuse on its own.
        config
            .mesh
            .as_deref_mut()
            .expect("mesh")
            .mesh_policies
            .retain(|policy| {
                matches!(
                    policy.name.as_str(),
                    "payments-deny-all" | "mesh-wide-audit"
                )
            });
        let slice = MeshSlice::from_gateway_config(&config, node_waypoint_request());
        let ledger = slice
            .node_waypoint_capture_destinations
            .iter()
            .find(|workload| workload.service_name == "ledger")
            .cloned()
            .expect("ledger is a capture destination");
        assert!(
            slice
                .mesh_policies
                .iter()
                .all(|policy| policy.name != "payments-deny-all"),
            "precondition: the destination DENY is absent from the ordinary view"
        );

        let plugin = MeshAuthz::new(&serde_json::json!({
            "mesh_slice": slice,
            "per_pod_policy_scoping": true,
        }))
        .expect("mesh_authz builds from the NodeWaypoint slice");

        let stream_context = || {
            StreamConnectionContext::new(
                "10.244.9.9".to_string(),
                "10.244.9.9".to_string(),
                "__mesh-nw-capture".to_string(),
                None,
                15006,
                BackendScheme::Tcp,
                Arc::new(ConsumerIndex::new(&[])),
            )
        };

        let mut captured = stream_context();
        captured.node_waypoint_policy_scope =
            Some(Arc::new(PolicyScopeCache::from_workload(&ledger)));
        let result = plugin.on_stream_connect(&mut captured).await;
        assert!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 403,
                    ..
                }
            ),
            "the captured destination's own namespace DENY must refuse the connection, got \
             {result:?}"
        );
        assert_eq!(
            captured
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("mesh_authz.deny_policy"))
                .map(String::as_str),
            Some("payments-deny-all")
        );

        let waypoint_pod = workload("ferrum", "local-app", THIS_WAYPOINT, "10.244.1.20");
        let mut local = stream_context();
        local.node_waypoint_policy_scope =
            Some(Arc::new(PolicyScopeCache::from_workload(&waypoint_pod)));
        let result = plugin.on_stream_connect(&mut local).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "a foreign destination's policy must not reach a pod it does not select, got \
             {result:?}"
        );
    }

    fn node_waypoint_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
        super::super::mesh_test_support::runtime_for_topology(
            ferrum_edge::modes::mesh::MeshTopology::NodeWaypoint,
        )
    }

    fn prepare(slice: &MeshSlice) -> Result<GatewayConfig, String> {
        ferrum_edge::modes::mesh::prepare_gateway_config_from_mesh_slice(
            slice,
            &node_waypoint_runtime(),
        )
        .map_err(|error| error.to_string())
    }

    /// A capture-scoped producer that resolves NO applicable destination policy
    /// still proves it resolved the inventory: the slice is marked complete,
    /// the (empty) xDS carrier is still emitted, and the slice is served.
    #[test]
    fn an_empty_capture_authorization_inventory_is_explicitly_complete() {
        let mut config = config_with_workloads();
        config
            .mesh
            .as_deref_mut()
            .expect("mesh")
            .mesh_policies
            .clear();
        let slice = MeshSlice::from_gateway_config(&config, node_waypoint_request());
        assert!(!slice.node_waypoint_capture_destinations.is_empty());
        assert!(slice.node_waypoint_capture_mesh_policies.is_empty());
        assert!(slice.node_waypoint_capture_mesh_policies_resolved);
        slice
            .validate_node_waypoint_capture_inventory()
            .expect("an explicitly complete empty inventory is valid");
        prepare(&slice).expect("a complete empty inventory is served");

        let mut rebuilt = MeshSlice::default();
        let mut saw_empty_carrier = false;
        for resource in ferrum_edge::xds::translator::translate_mesh_slice_carriers(&slice) {
            let typed_extension =
                <ferrum_edge::xds::proto::TypedExtensionConfig as prost::Message>::decode(
                    resource.value.as_slice(),
                )
                .expect("ECDS resource decodes as TypedExtensionConfig");
            let Some(inner) = typed_extension.typed_config.as_ref() else {
                continue;
            };
            let Some(carrier) =
                MeshSliceCarrier::decode(&inner.type_url, &inner.value).expect("carrier decodes")
            else {
                continue;
            };
            if let MeshSliceCarrier::NodeWaypointCaptureMeshPolicies(policies) = &carrier {
                saw_empty_carrier = policies.is_empty();
            }
            ferrum_edge::xds::carrier::apply_carrier(&mut rebuilt, carrier);
        }
        assert!(
            saw_empty_carrier,
            "the AuthorizationPolicy carrier is the completeness evidence and must be emitted \
             even when empty"
        );
        assert!(rebuilt.node_waypoint_capture_mesh_policies_resolved);
        rebuilt
            .validate_node_waypoint_capture_inventory()
            .expect("the recovered empty inventory is complete");
    }

    /// The shape an older producer sends — capture destinations and their
    /// PeerAuthentication, but no destination AuthorizationPolicy evidence —
    /// is refused at conversion, which is what both the initial-config path
    /// and slice reload run. On reload the previously accepted complete
    /// generation is left untouched.
    #[test]
    fn capture_destinations_without_policy_evidence_are_refused_at_startup_and_reload() {
        let complete =
            MeshSlice::from_gateway_config(&config_with_workloads(), node_waypoint_request());
        assert!(complete.node_waypoint_capture_mesh_policies_resolved);

        let mut missing_evidence = complete.clone();
        missing_evidence.node_waypoint_capture_mesh_policies.clear();
        missing_evidence.node_waypoint_capture_mesh_policies_resolved = false;
        assert!(
            !missing_evidence
                .node_waypoint_capture_destinations
                .is_empty()
        );

        // Startup: nothing to fall back to, so no capture-serving generation.
        let error = prepare(&missing_evidence)
            .expect_err("capture destinations without policy evidence must be refused");
        assert!(
            error.contains("node_waypoint_capture_mesh_policies_resolved"),
            "diagnostic must name the missing evidence: {error}"
        );

        // Reload: the accepted generation keeps its destination policies; the
        // incomplete candidate is refused rather than replacing it.
        let accepted = prepare(&complete).expect("complete generation is served");
        assert!(
            accepted
                .mesh
                .as_deref()
                .expect("mesh")
                .node_waypoint_capture_mesh_policies
                .iter()
                .any(|policy| policy.name == "payments-deny-all")
        );
        assert!(prepare(&missing_evidence).is_err());

        // xDS: the older shape emits no AuthorizationPolicy carrier, so the
        // recovered slice carries no evidence and is refused the same way.
        let mut recovered = MeshSlice::default();
        for resource in
            ferrum_edge::xds::translator::translate_mesh_slice_carriers(&missing_evidence)
        {
            let typed_extension =
                <ferrum_edge::xds::proto::TypedExtensionConfig as prost::Message>::decode(
                    resource.value.as_slice(),
                )
                .expect("ECDS resource decodes as TypedExtensionConfig");
            let Some(inner) = typed_extension.typed_config.as_ref() else {
                continue;
            };
            if let Some(carrier) =
                MeshSliceCarrier::decode(&inner.type_url, &inner.value).expect("carrier decodes")
            {
                assert!(
                    !matches!(
                        carrier,
                        MeshSliceCarrier::NodeWaypointCaptureMeshPolicies(_)
                    ),
                    "an unresolved inventory must not emit completeness evidence"
                );
                ferrum_edge::xds::carrier::apply_carrier(&mut recovered, carrier);
            }
        }
        assert!(!recovered.node_waypoint_capture_destinations.is_empty());
        assert!(
            recovered
                .validate_node_waypoint_capture_inventory()
                .is_err()
        );

        // Policies without evidence are incoherent and refused too.
        let mut policies_without_evidence = complete;
        policies_without_evidence
            .node_waypoint_capture_destinations
            .clear();
        policies_without_evidence.node_waypoint_capture_mesh_policies_resolved = false;
        assert!(
            policies_without_evidence
                .validate_node_waypoint_capture_inventory()
                .is_err()
        );

        // A slice with no capture inventory at all (any other topology) needs
        // no evidence.
        MeshSlice::default()
            .validate_node_waypoint_capture_inventory()
            .expect("no capture inventory, nothing to prove");
    }

    /// When the destination leaves this NodeWaypoint, its AuthorizationPolicy
    /// leaves with it on the next generation, and the prepared config's
    /// back-projection is replaced rather than merged.
    #[test]
    fn destination_policies_are_withdrawn_with_the_destination() {
        let generation_one =
            MeshSlice::from_gateway_config(&config_with_workloads(), node_waypoint_request());
        let prepared_one = prepare(&generation_one).expect("generation one");
        assert!(
            !prepared_one
                .mesh
                .as_deref()
                .expect("mesh")
                .node_waypoint_capture_mesh_policies
                .is_empty()
        );

        // `ledger` is now enrolled on another node's NodeWaypoint.
        let mut config = config_with_workloads();
        config.mesh.as_deref_mut().expect("mesh").workloads[0] =
            workload("payments", "ledger", OTHER_WAYPOINT, "10.244.1.7");
        let generation_two = MeshSlice::from_gateway_config(&config, node_waypoint_request());
        assert!(generation_two.node_waypoint_capture_destinations.is_empty());
        assert!(
            generation_two
                .node_waypoint_capture_mesh_policies
                .is_empty()
        );
        assert!(generation_two.node_waypoint_capture_mesh_policies_resolved);
        assert!(!generation_one.content_eq(&generation_two));

        let prepared_two = prepare(&generation_two).expect("generation two");
        let mesh = prepared_two.mesh.as_deref().expect("mesh");
        assert!(mesh.node_waypoint_capture_destinations.is_empty());
        assert!(
            mesh.node_waypoint_capture_mesh_policies.is_empty(),
            "a withdrawn destination's policies must not survive in the prepared config"
        );
    }

    /// A CUSTOM policy that only the capture inventory carries still brings its
    /// extension provider onto the slice; otherwise the delegation could never
    /// bind and every captured connection to that destination would be denied.
    #[test]
    fn a_capture_only_custom_policy_carries_its_extension_provider() {
        let mut config = config_with_workloads();
        let mesh = config.mesh.as_deref_mut().expect("mesh");
        mesh.ext_authz_providers = vec![
            serde_json::from_value(serde_json::json!({
                "name": "payments-authz",
                "service": "authz.payments.svc.cluster.local",
                "port": 9000,
                "tls": true,
                "timeout_ms": 1000,
                "status_on_error": 403,
            }))
            .expect("provider"),
        ];
        mesh.mesh_policies = vec![policy(
            "payments",
            "payments-custom",
            PolicyScope::Namespace {
                namespace: "payments".to_string(),
            },
            PolicyAction::Custom {
                provider: "payments-authz".to_string(),
            },
        )];
        let slice = MeshSlice::from_gateway_config(&config, node_waypoint_request());

        assert_eq!(
            policy_names(&slice.node_waypoint_capture_mesh_policies),
            vec!["payments-custom"]
        );
        assert!(
            slice.mesh_policies.is_empty(),
            "the waypoint's own view carries no CUSTOM policy"
        );
        assert_eq!(
            slice
                .ext_authz_providers
                .iter()
                .map(|provider| provider.name.as_str())
                .collect::<Vec<_>>(),
            vec!["payments-authz"],
            "a provider referenced only by the capture inventory must ride the slice"
        );
    }

    /// CP-driven slicing: the CP hands the slice builder a namespace-level
    /// candidate inventory (owner = a captured destination's namespace or the
    /// root namespace) beside an already-narrowed `mesh_policies`. The builder
    /// keeps exactly the candidates that select a captured destination — a
    /// selector for a pod on another node never leaves the CP — and leaves the
    /// waypoint's own view alone.
    #[test]
    fn cp_resolved_candidates_are_narrowed_to_the_exact_destination_set() {
        let app = |namespace: &str, app: &str| app_selector(namespace, app);
        let namespace = |namespace: &str| PolicyScope::Namespace {
            namespace: namespace.to_string(),
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                // What the CP filter leaves for a `ferrum` subscriber.
                mesh_policies: vec![policy(
                    "istio-system",
                    "root-deny",
                    PolicyScope::MeshWide,
                    PolicyAction::Deny,
                )],
                node_waypoint_capture_destinations: vec![
                    workload("payments", "ledger", THIS_WAYPOINT, "10.244.1.7"),
                    workload("secrets", "vault", THIS_WAYPOINT, "10.244.1.9"),
                ],
                node_waypoint_capture_mesh_policies: vec![
                    policy(
                        "payments",
                        "payments-deny",
                        namespace("payments"),
                        PolicyAction::Deny,
                    ),
                    policy(
                        "payments",
                        "ledger-deny",
                        app("payments", "ledger"),
                        PolicyAction::Deny,
                    ),
                    policy(
                        "payments",
                        "reports-deny",
                        app("payments", "reports"),
                        PolicyAction::Deny,
                    ),
                    policy(
                        "istio-system",
                        "root-deny",
                        PolicyScope::MeshWide,
                        PolicyAction::Deny,
                    ),
                    policy(
                        "secrets",
                        "secrets-deny",
                        namespace("secrets"),
                        PolicyAction::Deny,
                    ),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let slice = MeshSlice::from_gateway_config(&config, node_waypoint_request());

        assert_eq!(
            policy_names(&slice.node_waypoint_capture_mesh_policies),
            vec!["ledger-deny", "payments-deny", "root-deny", "secrets-deny"]
        );
        assert_eq!(policy_names(&slice.mesh_policies), vec!["root-deny"]);
        assert!(slice.node_waypoint_capture_mesh_policies_resolved);
    }
}
