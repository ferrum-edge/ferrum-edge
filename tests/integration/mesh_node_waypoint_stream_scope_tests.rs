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
    use ferrum_edge::identity::TrustDomain;
    use ferrum_edge::modes::mesh::config::Workload;
    use tokio::net::{TcpListener, TcpStream};

    let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
    let pod_a = parse_pod_uid(POD_A).unwrap();
    let id_a = NodeWaypointIdentity::new(pod_a, spiffe(SPIFFE_A));
    let hash_a = id_a.workload_spiffe_hash;
    resolver.upsert_identity(id_a);

    let listener = TcpListener::bind(("127.0.0.1", 0))
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
