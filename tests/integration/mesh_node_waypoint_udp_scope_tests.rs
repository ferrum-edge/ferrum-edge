//! NodeWaypoint UDP/DTLS scoped `AuthorizationPolicy` end to end (issue #3286).
//!
//! The TCP path scopes a stream's source pod through the socket-cookie bridge;
//! UDP/DTLS cannot (one shared frontend socket, one cookie, no UDP capture
//! hooks). This suite covers the replacement channel and the slice-preparation
//! change that depends on it:
//!
//!   - the reconcile loop turning the node-agent registry + resolved host-side
//!     interfaces into a published attribution generation, across add / update /
//!     delete;
//!   - `NodeWaypointUdpSourceScoping::resolve` joining an attributed pod to the
//!     LIVE slice's per-pod `PolicyScopeCache`, including the fail-closed case
//!     where the workload has left the slice;
//!   - a policy CHANGE (a new slice generation) taking effect for already-
//!     attributed pods;
//!   - and the per-pod policy filter `mesh_authz` runs, so a namespace-scoped
//!     DENY applies to the source pod it names and not to its neighbour.
//!
//! The matching slice-preparation change — NodeWaypoint no longer strips
//! UDP/DTLS service ports, proxies, upstreams, or DNS visibility where this
//! channel exists — is pinned beside that code in `src/modes/mesh/mod.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, Workload, WorkloadSelector,
};
use ferrum_edge::modes::mesh::hbone::UdpSourceIdentity;
use ferrum_edge::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;
use ferrum_edge::proxy::host_udp_capture::ResolvedInterface;
use ferrum_edge::proxy::netns_capture::{PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget};
use ferrum_edge::proxy::node_waypoint_udp_identity::{
    NodeWaypointUdpDatagramVerdict, NodeWaypointUdpInterfaceResolver, NodeWaypointUdpSourceIndex,
    NodeWaypointUdpSourceIndexManager, NodeWaypointUdpSourceRefusal, NodeWaypointUdpSourceScoping,
};
use ferrum_edge::proxy::node_waypoint_udp_steering::{
    NodeWaypointUdpSteerBackend, NodeWaypointUdpSteering,
};

const POD_A: &str = "11111111-1111-1111-1111-111111111111";
const POD_B: &str = "22222222-2222-2222-2222-222222222222";
const SPIFFE_A: &str = "spiffe://cluster.local/ns/team-a/sa/api";
const SPIFFE_B: &str = "spiffe://cluster.local/ns/team-b/sa/api";
const IP_A: &str = "10.244.1.7";
const IP_B: &str = "10.244.1.8";
const IFINDEX_A: u32 = 71;
const IFINDEX_B: u32 = 82;

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw).expect("valid test SPIFFE ID")
}

fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn workload(
    spiffe_id: &str,
    namespace: &str,
    labels: HashMap<String, String>,
    pod_uid: &str,
) -> Workload {
    Workload {
        spiffe_id: spiffe(spiffe_id),
        selector: WorkloadSelector {
            labels,
            namespace: Some(namespace.to_string()),
        },
        service_name: "api".to_string(),
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

fn registry_target(pod_uid: &str, spiffe_id: &str, ipv4: &str) -> PodCaptureTarget {
    PodCaptureTarget {
        pod_uid: pod_uid.to_string(),
        cgroup_path: format!("/sys/fs/cgroup/kubepods/pod{pod_uid}"),
        source_identity: UdpSourceIdentity::new(spiffe(spiffe_id), pod_uid.to_string()),
        source_ips: PodCaptureSourceIps {
            ipv4: Some(ipv4.parse().expect("valid v4")),
            ipv6: None,
        },
    }
}

/// In-memory stand-in for the node-agent-published registry directory.
#[derive(Default)]
struct FakeRegistry {
    targets: std::sync::Mutex<Vec<PodCaptureTarget>>,
}

impl FakeRegistry {
    fn set(&self, targets: Vec<PodCaptureTarget>) {
        *self.targets.lock().expect("registry lock") = targets;
    }
}

impl PodCaptureSource for FakeRegistry {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        self.targets.lock().expect("registry lock").clone()
    }
}

/// Stand-in for host-side veth resolution. Production reads the pod netns view
/// and the host route table; the reconcile logic under test is independent of
/// how a name/index was obtained.
#[derive(Default)]
struct FakeInterfaces {
    by_pod: std::sync::Mutex<HashMap<String, ResolvedInterface>>,
}

impl FakeInterfaces {
    fn set(&self, entries: &[(&str, &str, u32)]) {
        let mut map = self.by_pod.lock().expect("interface lock");
        map.clear();
        for (pod_uid, name, ifindex) in entries {
            map.insert(
                (*pod_uid).to_string(),
                ResolvedInterface {
                    name: (*name).to_string(),
                    ifindex: *ifindex,
                },
            );
        }
    }
}

/// Local newtype so the resolver trait is implemented on a type this crate
/// owns (the orphan rule forbids `impl ForeignTrait for Arc<Local>`).
struct FakeInterfaceResolver(Arc<FakeInterfaces>);

impl NodeWaypointUdpInterfaceResolver for FakeInterfaceResolver {
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        self.0
            .by_pod
            .lock()
            .expect("interface lock")
            .get(&target.pod_uid)
            .cloned()
            .ok_or_else(|| "unresolved".to_string())
    }
}

struct Fixture {
    registry: Arc<FakeRegistry>,
    interfaces: Arc<FakeInterfaces>,
    index: Arc<NodeWaypointUdpSourceIndex>,
    resolver: Arc<NodeWaypointIdentityResolver>,
    manager: NodeWaypointUdpSourceIndexManager<FakeInterfaceResolver>,
}

impl Fixture {
    /// Both pods enrolled on their own interfaces, both present in the slice.
    fn new() -> Self {
        let registry = Arc::new(FakeRegistry::default());
        registry.set(vec![
            registry_target(POD_A, SPIFFE_A, IP_A),
            registry_target(POD_B, SPIFFE_B, IP_B),
        ]);
        let interfaces = Arc::new(FakeInterfaces::default());
        interfaces.set(&[(POD_A, "vethA", IFINDEX_A), (POD_B, "vethB", IFINDEX_B)]);

        let index = Arc::new(NodeWaypointUdpSourceIndex::new());
        let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
        resolver.install_policy_scopes_from_workloads(&[
            workload(SPIFFE_A, "team-a", labels(&[("app", "api")]), POD_A),
            workload(SPIFFE_B, "team-b", labels(&[("app", "api")]), POD_B),
        ]);

        let manager = NodeWaypointUdpSourceIndexManager::new(
            registry.clone(),
            FakeInterfaceResolver(interfaces.clone()),
            index.clone(),
            std::time::Duration::from_secs(2),
        );
        Self {
            registry,
            interfaces,
            index,
            resolver,
            manager,
        }
    }

    fn scoping(&self) -> NodeWaypointUdpSourceScoping {
        NodeWaypointUdpSourceScoping {
            index: self.index.clone(),
            resolver: self.resolver.clone(),
        }
    }
}

fn ip(addr: &str) -> std::net::IpAddr {
    addr.parse().expect("valid address")
}

fn namespace_deny(name: &str, namespace: &str) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::Namespace {
            namespace: namespace.to_string(),
        },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

/// The whole chain a UDP session runs at admission: attribute the datagram to a
/// pod from its ingress interface + source address, then resolve THAT pod's
/// per-pod scope out of the live slice.
#[test]
fn a_reconciled_registry_scopes_each_pods_datagrams_to_its_own_policy_scope() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();

    let a = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's datagram resolves");
    assert_eq!(a.scope.namespace, "team-a");
    assert_eq!(a.binding.principal, spiffe(SPIFFE_A));

    let b = scoping
        .resolve(Some(IFINDEX_B), ip(IP_B))
        .expect("pod B's datagram resolves");
    assert_eq!(b.scope.namespace, "team-b");
    assert_eq!(b.binding.principal, spiffe(SPIFFE_B));
}

/// The per-pod filter `mesh_authz` applies once the session carries a scope: a
/// namespace-scoped DENY must bind to the source pod it names and leave its
/// neighbour alone. Without the attribution above, both sessions would carry no
/// scope and be denied wholesale.
#[test]
fn a_namespace_scoped_deny_binds_to_the_attributed_source_pod_only() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let deny_team_a = namespace_deny("team-a-deny", "team-a");

    let a = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A resolves");
    let b = scoping
        .resolve(Some(IFINDEX_B), ip(IP_B))
        .expect("pod B resolves");

    assert!(
        a.scope.policy_applies(&deny_team_a),
        "the DENY names team-a, and pod A's session is attributed to a team-a workload"
    );
    assert!(
        !b.scope.policy_applies(&deny_team_a),
        "pod B is in team-b; a team-a-scoped DENY must not suppress its UDP session"
    );
}

/// A spoofed source address does not become another tenant's scope: the
/// interface it arrived on is the anchor, and that interface's pod does not own
/// the forged address.
#[test]
fn one_pod_cannot_obtain_another_pods_scope_by_forging_its_source_address() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();

    let refusal = scoping
        .resolve(Some(IFINDEX_B), ip(IP_A))
        .err()
        .expect("pod B forging pod A's address must not resolve");
    assert_eq!(refusal, NodeWaypointUdpSourceRefusal::SourceAddressMismatch);
}

/// A pod that is attributable but whose workload has left the live slice has no
/// per-pod scope. That is a fail-closed outcome, not a fall-through: the caller
/// leaves the session unscoped and `mesh_authz` denies it while scoped policies
/// exist.
#[test]
fn a_pod_that_left_the_live_slice_resolves_no_scope() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();

    // A new slice generation that no longer carries pod B's workload.
    fixture
        .resolver
        .install_policy_scopes_from_workloads(&[workload(
            SPIFFE_A,
            "team-a",
            labels(&[("app", "api")]),
            POD_A,
        )]);

    let scoping = fixture.scoping();
    assert!(
        scoping.resolve(Some(IFINDEX_A), ip(IP_A)).is_ok(),
        "the workload still in the slice keeps resolving"
    );
    assert_eq!(
        scoping
            .resolve(Some(IFINDEX_B), ip(IP_B))
            .err()
            .expect("a removed workload must not resolve a stale scope"),
        NodeWaypointUdpSourceRefusal::PodNotInSlice
    );
}

/// A registry generation and a slice generation are independent publications.
/// If the slice re-attests the same pod UID under a new SPIFFE identity before
/// the registry catches up, the stale registry principal must not be paired
/// with the new workload's scope.
#[test]
fn a_stale_registry_principal_cannot_borrow_a_re_attested_pods_scope() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let pinned = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("initial registry and slice generations agree")
        .binding;

    fixture
        .resolver
        .install_policy_scopes_from_workloads(&[workload(
            SPIFFE_B,
            "team-a",
            labels(&[("app", "api")]),
            POD_A,
        )]);

    let scoping = fixture.scoping();
    assert_eq!(
        scoping
            .resolve(Some(IFINDEX_A), ip(IP_A))
            .err()
            .expect("a stale principal must fail admission"),
        NodeWaypointUdpSourceRefusal::PodNotInSlice
    );
    assert_eq!(
        scoping
            .revalidate(&pinned, Some(IFINDEX_A), ip(IP_A))
            .expect_err("a live session must fail when the slice re-attests its pod"),
        NodeWaypointUdpSourceRefusal::PodNotInSlice
    );
}

/// Reload/update, not just first construction: a workload whose labels change
/// in a new slice generation must be scoped by the NEW labels for sessions
/// admitted after the change.
#[test]
fn a_policy_relevant_label_change_takes_effect_on_the_next_admission() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let selector_deny = MeshPolicy {
        name: "canary-deny".to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: labels(&[("release", "canary")]),
                namespace: Some("team-a".to_string()),
            },
        },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    };

    let before = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A resolves");
    assert!(
        !before.scope.policy_applies(&selector_deny),
        "pod A is not labelled release=canary yet"
    );

    fixture
        .resolver
        .install_policy_scopes_from_workloads(&[workload(
            SPIFFE_A,
            "team-a",
            labels(&[("app", "api"), ("release", "canary")]),
            POD_A,
        )]);

    let after = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A still resolves");
    assert!(
        after.scope.policy_applies(&selector_deny),
        "the selector-scoped DENY must apply once the new slice generation labels the workload"
    );
}

/// Established UDP/DTLS sessions carry the plugin chain and workload scope
/// from admission. Even an accepted slice whose workload projection is
/// unchanged may add or revoke AuthorizationPolicy, so the coherent slice
/// generation must fence that old authorization lifetime.
#[test]
fn an_attributed_session_stops_revalidating_after_any_accepted_slice_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let admitted = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A resolves in the admitted generation");

    fixture.resolver.install_policy_scopes_from_workloads(&[
        workload(SPIFFE_A, "team-a", labels(&[("app", "api")]), POD_A),
        workload(SPIFFE_B, "team-b", labels(&[("app", "api")]), POD_B),
    ]);

    assert_eq!(
        scoping
            .revalidate_at_policy_generation(
                &admitted.binding,
                admitted.policy_generation,
                Some(IFINDEX_A),
                ip(IP_A),
            )
            .expect_err("the old stream-admission generation must be retired"),
        NodeWaypointUdpSourceRefusal::PolicyGenerationChanged
    );
}

/// A mesh-wide-only generation may admit an unattributable source, but that
/// miss must still be pinned. Otherwise adding the first scoped policy would
/// leave the established session on the old plugin generation forever because
/// it has no workload binding to revalidate.
#[test]
fn an_unattributable_session_is_also_fenced_by_policy_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let (policy_generation, admission) = scoping.resolve_observed(Some(999), ip("192.0.2.10"));
    let refusal = admission
        .err()
        .expect("off-node interface is not attributable");
    assert_eq!(refusal, NodeWaypointUdpSourceRefusal::UnenrolledInterface);

    fixture.resolver.install_policy_scopes_from_workloads(&[
        workload(SPIFFE_A, "team-a", labels(&[("app", "api")]), POD_A),
        workload(SPIFFE_B, "team-b", labels(&[("app", "api")]), POD_B),
    ]);

    assert_eq!(
        scoping
            .revalidate_unattributed(policy_generation, refusal, Some(999), ip("192.0.2.10"),)
            .expect_err("the old mesh-wide-only admission must be retired"),
        NodeWaypointUdpSourceRefusal::PolicyGenerationChanged
    );
}

/// Delete: a pod removed from the registry stops being attributable on the very
/// next reconcile, and sessions pinned to its old binding stop revalidating.
#[test]
fn deleting_a_pod_from_the_registry_retracts_its_attribution() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let pinned = fixture
        .index
        .authorize(Some(IFINDEX_B), ip(IP_B))
        .expect("pod B admitted");

    fixture
        .registry
        .set(vec![registry_target(POD_A, SPIFFE_A, IP_A)]);
    fixture.manager.reconcile_once();

    assert!(
        fixture.index.authorize(Some(IFINDEX_B), ip(IP_B)).is_err(),
        "a removed pod must not keep admitting new sessions"
    );
    assert_eq!(
        fixture
            .index
            .revalidate(&pinned, Some(IFINDEX_B), ip(IP_B))
            .expect_err("its live session must stop too"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
    assert!(
        fixture.index.authorize(Some(IFINDEX_A), ip(IP_A)).is_ok(),
        "the surviving pod is undisturbed by its neighbour's removal"
    );
}

/// Update: the same pod moving to a new veth (a restart under the same UID)
/// republishes on the new index and stops answering on the old one.
#[test]
fn a_pod_moving_to_a_new_interface_is_attributed_on_the_new_one_only() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();

    fixture
        .interfaces
        .set(&[(POD_A, "vethA2", 91), (POD_B, "vethB", IFINDEX_B)]);
    fixture.manager.reconcile_once();

    assert!(
        fixture.index.authorize(Some(91), ip(IP_A)).is_ok(),
        "the pod is attributable on its new host-side interface"
    );
    assert_eq!(
        fixture
            .index
            .authorize(Some(IFINDEX_A), ip(IP_A))
            .expect_err("the stale interface must attribute nothing"),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
}

/// Unresolvable source: an enrolled pod whose host-side interface cannot be
/// resolved this pass is refused rather than admitted unattributed, and its
/// neighbour is unaffected.
#[test]
fn an_unresolvable_pod_interface_refuses_only_that_pod() {
    let fixture = Fixture::new();
    fixture.interfaces.set(&[(POD_B, "vethB", IFINDEX_B)]);

    let published = fixture.manager.reconcile_once();

    assert_eq!(published.len(), 1);
    assert_eq!(published[0].pod_uid, POD_B);
    assert!(
        fixture.index.authorize(Some(IFINDEX_A), ip(IP_A)).is_err(),
        "an unresolvable pod is never attributable"
    );
    assert!(
        fixture.scoping().resolve(Some(IFINDEX_B), ip(IP_B)).is_ok(),
        "its neighbour keeps working"
    );
}

/// A shared interface (bridge CNI, or a stale registry entry pointing at a
/// recycled veth) refuses BOTH claimants. Attribution under a guessed identity
/// is precisely the cross-tenant confusion this channel must not have.
#[test]
fn a_shared_interface_refuses_every_claimant() {
    let fixture = Fixture::new();
    fixture
        .interfaces
        .set(&[(POD_A, "cni0", 5), (POD_B, "cni0", 5)]);

    let published = fixture.manager.reconcile_once();

    assert!(published.is_empty());
    assert!(fixture.index.authorize(Some(5), ip(IP_A)).is_err());
    assert!(fixture.index.authorize(Some(5), ip(IP_B)).is_err());
}

/// A UDP session is keyed by a source address and port that anything able to
/// put a packet on the wire can forge — a neighbouring pod with `CAP_NET_RAW`,
/// or an off-node sender. Such a datagram must be REFUSED (never forwarded),
/// but it must not be able to tear down the session it names: the interface it
/// actually arrived on proves it is somebody else's traffic, and the session's
/// own pinned evidence is untouched by it. Otherwise one pod could keep killing
/// a neighbour's UDP sessions at will.
#[test]
fn a_forged_datagram_from_another_interface_is_dropped_without_ending_the_session() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let scoping = fixture.scoping();
    let pinned = scoping
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's session is admitted")
        .binding;

    // Pod B forges pod A's source address, naming pod A's session.
    assert_eq!(
        scoping
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_B), ip(IP_A))
            .expect_err("a forged datagram must never be forwarded"),
        NodeWaypointUdpDatagramVerdict::DropDatagram(
            NodeWaypointUdpSourceRefusal::SourceAddressMismatch,
        ),
        "the forged datagram is dropped; pod A's session keeps its own still-vouched-for evidence"
    );

    // Off-node traffic on the node uplink, and a datagram that carried no
    // ingress-interface cmsg at all, are the same shape.
    assert_eq!(
        scoping
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(9_999), ip(IP_A))
            .expect_err("an unenrolled interface must never be forwarded"),
        NodeWaypointUdpDatagramVerdict::DropDatagram(
            NodeWaypointUdpSourceRefusal::UnenrolledInterface,
        )
    );
    assert_eq!(
        scoping
            .revalidate_datagram(&pinned, Some(IFINDEX_A), None, ip(IP_A))
            .expect_err("an unattributable datagram must never be forwarded"),
        NodeWaypointUdpDatagramVerdict::DropDatagram(
            NodeWaypointUdpSourceRefusal::NoIngressInterface,
        )
    );

    // And the session itself is still serving.
    scoping
        .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's own datagrams keep flowing");
}

/// The other half of the same split: when the refusal is a property of the
/// SESSION rather than of one datagram, the session must end. Both directions
/// are pinned here so a future change cannot collapse them back together.
#[test]
fn an_attribution_change_on_the_sessions_own_interface_ends_the_session() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let pinned = fixture
        .scoping()
        .resolve(Some(IFINDEX_A), ip(IP_A))
        .expect("pod A's session is admitted")
        .binding;

    // ABA: pod B reuses pod A's interface and address.
    fixture
        .registry
        .set(vec![registry_target(POD_B, SPIFFE_B, IP_A)]);
    fixture.interfaces.set(&[(POD_B, "vethA", IFINDEX_A)]);
    fixture.manager.reconcile_once();

    assert_eq!(
        fixture
            .scoping()
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_A), ip(IP_A))
            .expect_err("the replacement pod must not inherit the session"),
        NodeWaypointUdpDatagramVerdict::CloseSession(
            NodeWaypointUdpSourceRefusal::AttributionChanged,
        )
    );

    // Registry removal is the same verdict, and stays so even when the datagram
    // that observes it arrived on a different interface — the pinned evidence
    // is gone either way, so there is nothing left to keep serving.
    fixture.registry.set(Vec::new());
    fixture.interfaces.set(&[]);
    fixture.manager.reconcile_once();

    assert_eq!(
        fixture
            .scoping()
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_A), ip(IP_A))
            .expect_err("a removed pod's session must stop")
            .refusal(),
        NodeWaypointUdpSourceRefusal::UnenrolledInterface
    );
    assert!(
        fixture
            .scoping()
            .revalidate_datagram(&pinned, Some(IFINDEX_A), Some(IFINDEX_B), ip(IP_A))
            .expect_err("a removed pod's session must stop")
            .closes_session(),
        "a datagram-specific mismatch must not mask the pinned evidence being gone"
    );
}

/// Cleanup: shutting the manager down retracts the generation, so a listener
/// still draining its socket cannot attribute a late datagram to a pod nobody
/// is tracking any more.
#[tokio::test]
async fn manager_shutdown_retracts_the_published_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    assert!(fixture.index.authorize(Some(IFINDEX_A), ip(IP_A)).is_ok());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let index = fixture.index.clone();
    let handle = tokio::spawn(async move { fixture.manager.run(shutdown_rx).await });
    shutdown_tx.send(true).expect("signal shutdown");
    handle.await.expect("manager task completes");

    assert_eq!(
        index
            .authorize(Some(IFINDEX_A), ip(IP_A))
            .expect_err("a retracted index attributes nothing"),
        NodeWaypointUdpSourceRefusal::IndexUnavailable
    );
}

/// The manager is security-critical background state, not merely a cache
/// warmer. If its task is aborted (the same future-drop path a panic takes),
/// the last published identity generation must become unavailable immediately
/// instead of remaining trusted forever.
#[tokio::test]
async fn manager_task_abort_retracts_the_published_generation() {
    let fixture = Fixture::new();
    fixture.manager.reconcile_once();
    let before_run = fixture.index.generation();
    let index = fixture.index.clone();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move { fixture.manager.run(shutdown_rx).await });

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while index.generation() == before_run {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager should enter its reconcile loop");

    handle.abort();
    assert!(
        handle
            .await
            .expect_err("aborted manager must not complete")
            .is_cancelled(),
        "the test must exercise future-drop retraction"
    );
    assert_eq!(
        index
            .authorize(Some(IFINDEX_A), ip(IP_A))
            .expect_err("an aborted manager must leave no trusted attribution"),
        NodeWaypointUdpSourceRefusal::IndexUnavailable
    );
}

#[derive(Default)]
struct ManagerSteeringBackend {
    scripts: std::sync::Mutex<Vec<String>>,
}

impl NodeWaypointUdpSteerBackend for ManagerSteeringBackend {
    fn run_script(&self, script: &str) -> Result<(), String> {
        self.scripts
            .lock()
            .expect("steering script log")
            .push(script.to_string());
        Ok(())
    }
}

/// `StreamListenerManager` retains its own `Arc` to steering, so aborting the
/// source-index manager cannot rely on the steering object's `Drop`. The
/// manager-future guard must explicitly shut it down as well as clearing the
/// attribution index.
#[tokio::test]
async fn manager_task_abort_retracts_retained_steering_too() {
    let fixture = Fixture::new();
    let backend = Arc::new(ManagerSteeringBackend::default());
    let steering = Arc::new(NodeWaypointUdpSteering::new(backend.clone()));
    let retained_by_listener_manager = steering.clone();
    let destination = NodeWaypointUdpSteerDestination {
        ip: "10.96.0.10".parse().expect("ClusterIP"),
        port: 5300,
    };
    steering.set_bound_destinations(vec![destination], None, true);

    let manager = NodeWaypointUdpSourceIndexManager::new(
        fixture.registry.clone(),
        FakeInterfaceResolver(fixture.interfaces.clone()),
        fixture.index.clone(),
        std::time::Duration::from_secs(2),
    )
    .with_steering(steering.clone());
    let before_run = fixture.index.generation();
    let index = fixture.index.clone();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move { manager.run(shutdown_rx).await });

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while index.generation() == before_run
            || !backend
                .scripts
                .lock()
                .expect("steering script log")
                .iter()
                .any(|script| script.contains("--set-xmark"))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager should publish attribution and install steering");

    handle.abort();
    assert!(
        handle
            .await
            .expect_err("aborted manager must not complete")
            .is_cancelled()
    );
    assert_eq!(
        index
            .authorize(Some(IFINDEX_A), ip(IP_A))
            .expect_err("abort retracts attribution"),
        NodeWaypointUdpSourceRefusal::IndexUnavailable
    );
    assert!(
        retained_by_listener_manager.bound_destinations().is_empty(),
        "the retained steering owner must hold no serving plan after manager exit"
    );
    let scripts = backend.scripts.lock().expect("steering script log");
    assert!(
        scripts
            .last()
            .is_some_and(|script| script.contains("ferrum_delete_xtables_rule")),
        "future drop must run exact-name steering shutdown even while another Arc survives"
    );
}

// ── NodeWaypoint UDP/DTLS listener materialization (issue #3286) ──────────
//
// The attribution channel above is only reachable if a NodeWaypoint can
// actually CREATE a UDP/DTLS listener. `materialize_node_waypoint_udp_listeners`
// is that surface: it turns each in-mesh service's UDP-family port into a real
// stream listener proxy + upstream in the prepared `GatewayConfig`, which is
// exactly what `StreamListenerManager` binds and what
// `NodeWaypointUdpSourceScoping` then scopes. These tests pin first
// construction, reload/update/withdrawal, the fail-closed refusals, and the
// UDP-vs-DTLS split.

use ferrum_edge::config::types::{DispatchKind, GatewayConfig};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshService, NodeWaypointEndpoint, ServicePort, WorkloadRef,
};
use ferrum_edge::modes::mesh::{
    MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX, MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX,
    MeshRuntimeConfig, MeshTopology, node_waypoint_udp_proxy_id, node_waypoint_udp_upstream_id,
    prepare_gateway_config_for_mesh, prepare_gateway_config_from_mesh_slice,
};

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, gateway_config_with_mesh, mesh_config_with, mesh_slice_with,
    runtime_for_topology, workload_for,
};

const UDP_LISTENERS_ENV: &str = "FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED";
const K8S_NODE_NAME_ENV: &str = "FERRUM_K8S_NODE_NAME";
const LOCAL_NODE_NAME: &str = "worker-a";

/// Serializes the listener-switch and node-name environment mutations in this
/// test binary and restores their previous values on drop.
static UDP_LISTENER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct UdpListenerEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved_enabled: Option<String>,
    saved_node_name: Option<String>,
}

impl UdpListenerEnvGuard {
    fn set(value: Option<&str>) -> Self {
        Self::set_with_node(value, Some(LOCAL_NODE_NAME))
    }

    fn set_with_node(value: Option<&str>, node_name: Option<&str>) -> Self {
        let lock = UDP_LISTENER_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved_enabled = std::env::var(UDP_LISTENERS_ENV).ok();
        let saved_node_name = std::env::var(K8S_NODE_NAME_ENV).ok();
        // SAFETY: `_lock` serializes every mutation of both variables in this
        // test binary, and the guard restores both snapshots on drop.
        unsafe {
            match value {
                Some(value) => std::env::set_var(UDP_LISTENERS_ENV, value),
                None => std::env::remove_var(UDP_LISTENERS_ENV),
            }
            match node_name {
                Some(node_name) => std::env::set_var(K8S_NODE_NAME_ENV, node_name),
                None => std::env::remove_var(K8S_NODE_NAME_ENV),
            }
        }
        Self {
            _lock: lock,
            saved_enabled,
            saved_node_name,
        }
    }
}

impl Drop for UdpListenerEnvGuard {
    fn drop(&mut self) {
        // SAFETY: the guard still holds `UDP_LISTENER_ENV_LOCK`.
        unsafe {
            match self.saved_enabled.as_deref() {
                Some(value) => std::env::set_var(UDP_LISTENERS_ENV, value),
                None => std::env::remove_var(UDP_LISTENERS_ENV),
            }
            match self.saved_node_name.as_deref() {
                Some(value) => std::env::set_var(K8S_NODE_NAME_ENV, value),
                None => std::env::remove_var(K8S_NODE_NAME_ENV),
            }
        }
    }
}

fn udp_service(
    name: &str,
    port: u16,
    protocol: AppProtocol,
    workloads: &[&Workload],
) -> MeshService {
    udp_service_in(DEFAULT_NAMESPACE, name, port, protocol, workloads)
}

fn udp_service_in(
    namespace: &str,
    name: &str,
    port: u16,
    protocol: AppProtocol,
    workloads: &[&Workload],
) -> MeshService {
    MeshService {
        cluster_ips: vec!["10.96.0.10".to_string()],
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port,
            protocol,
            name: Some(name.to_string()),
            target_port: None,
        }],
        workloads: workloads
            .iter()
            .map(|w| WorkloadRef {
                spiffe_id: w.spiffe_id.clone(),
            })
            .collect(),
        protocol_overrides: HashMap::new(),
        uid: None,
        allow_path_parameters: false,
    }
}

fn nw_udp_proxy_id(namespace: &str, name: &str, port: u16) -> String {
    node_waypoint_udp_proxy_id(namespace, name, port)
        .expect("test identities are admitted Kubernetes namespace/service names")
}

fn nw_udp_upstream_id(namespace: &str, name: &str, port: u16) -> String {
    node_waypoint_udp_upstream_id(namespace, name, port)
        .expect("test identities are admitted Kubernetes namespace/service names")
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    runtime_for_topology(MeshTopology::NodeWaypoint)
}

fn attach_local_node_waypoint(workloads: &mut [Workload]) {
    for workload in workloads {
        if workload.node_waypoint.is_none() {
            workload.node_waypoint = Some(NodeWaypointEndpoint {
                address: "192.0.2.10".to_string(),
                hbone_port: 15008,
                spiffe_id: workload.spiffe_id.clone(),
                node_name: Some(LOCAL_NODE_NAME.to_string()),
                node_uid: None,
                network: None,
                cluster: None,
            });
        }
    }
}

fn prepare(
    runtime: &MeshRuntimeConfig,
    services: Vec<MeshService>,
    mut workloads: Vec<Workload>,
) -> GatewayConfig {
    attach_local_node_waypoint(&mut workloads);
    let mesh = mesh_config_with(workloads, services, Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    prepare_gateway_config_for_mesh(config, runtime).expect("mesh config preparation must succeed")
}

/// File-mode `prepare_gateway_config_for_mesh` filters `MeshSlice` to
/// `runtime.namespace`, so Services whose Kubernetes namespace is not the
/// NodeWaypoint subscription namespace never reach the UDP materializer.
/// This helper drives the CP-driven path with the caller-supplied inventory
/// already on the serving slice — the same materializers, without that filter.
fn prepare_serving_slice(
    runtime: &MeshRuntimeConfig,
    services: Vec<MeshService>,
    mut workloads: Vec<Workload>,
) -> GatewayConfig {
    attach_local_node_waypoint(&mut workloads);
    let slice = mesh_slice_with(runtime, workloads, services, Vec::new());
    prepare_gateway_config_from_mesh_slice(&slice, runtime)
        .expect("mesh slice preparation must succeed")
}

fn udp_listeners(config: &GatewayConfig) -> Vec<&ferrum_edge::config::types::Proxy> {
    config
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with(MESH_NODE_WAYPOINT_UDP_PROXY_ID_PREFIX))
        .collect()
}

#[test]
fn a_udp_service_port_materializes_a_node_waypoint_datagram_listener() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );

    let listeners = udp_listeners(&config);
    assert_eq!(
        listeners.len(),
        1,
        "exactly one NodeWaypoint UDP listener must materialize"
    );
    let proxy = listeners[0];
    assert_eq!(proxy.id, nw_udp_proxy_id(DEFAULT_NAMESPACE, "dns", 5353));
    assert_eq!(proxy.listen_port, Some(5353));
    assert_eq!(
        proxy.dispatch_kind,
        DispatchKind::UdpRaw,
        "a `udp` service port relays opaque datagrams"
    );
    assert!(
        !proxy.frontend_tls,
        "a `udp` port must not terminate frontend DTLS"
    );
    assert!(
        !proxy.passthrough,
        "the listener must run the on_stream_connect chain so mesh_authz evaluates the \
         attributed source pod"
    );
    assert!(
        proxy.hosts.is_empty() && proxy.stream_match.is_none(),
        "a datagram listener carries neither SNI hosts nor an L4 matcher"
    );

    let upstream_id = nw_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    assert_eq!(proxy.upstream_id.as_deref(), Some(upstream_id.as_str()));
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("the listener's upstream must be materialized");
    assert!(
        upstream
            .id
            .starts_with(MESH_NODE_WAYPOINT_UDP_UPSTREAM_ID_PREFIX)
    );
    assert_eq!(
        upstream
            .targets
            .iter()
            .map(|target| (target.host.as_str(), target.port))
            .collect::<Vec<_>>(),
        vec![("10.244.3.11", 5353)],
        "the listener forwards to the service's backing pod on its resolved target port"
    );

    // The whole point of the surface: the prepared config passes the same
    // stream-proxy validation the runtime applies before binding.
    config
        .validate_stream_proxies()
        .expect("a materialized NodeWaypoint UDP listener must be a valid stream proxy");
}

#[test]
fn a_dtls_service_port_materializes_a_frontend_dtls_terminating_listener() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("coap", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.12"]);
    let config = prepare(
        &runtime,
        vec![udp_service("coap", 5684, AppProtocol::Dtls, &[&backend])],
        vec![backend],
    );

    let listeners = udp_listeners(&config);
    assert_eq!(listeners.len(), 1);
    let proxy = listeners[0];
    assert_eq!(proxy.listen_port, Some(5684));
    assert!(
        proxy.frontend_tls,
        "a `dtls` service port must terminate frontend DTLS on the listener"
    );
    assert_eq!(
        proxy.dispatch_kind,
        DispatchKind::UdpRaw,
        "the BACKEND leg stays plaintext UDP; only the frontend terminates DTLS"
    );
    config
        .validate_stream_proxies()
        .expect("a DTLS listener must also be a valid stream proxy");
}

#[test]
fn node_waypoint_udp_listeners_are_off_by_default() {
    let _env = UdpListenerEnvGuard::set(None);
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        udp_listeners(&config).is_empty(),
        "a NodeWaypoint runs on the host network, so claiming node-wide UDP ports is opt-in"
    );
}

#[test]
fn a_malformed_listener_switch_is_rejected_rather_than_silently_disabling_listeners() {
    let _env = UdpListenerEnvGuard::set(Some("yes-please"));
    let runtime = node_waypoint_runtime();
    assert!(
        runtime
            .validate_node_waypoint_udp_listener_settings()
            .is_err(),
        "an unparseable switch must abort mesh startup instead of serving no listeners"
    );
    // Non-NodeWaypoint topologies never consume the switch, so a stray value
    // there is inert rather than a startup error.
    assert!(
        runtime_for_topology(MeshTopology::Ambient)
            .validate_node_waypoint_udp_listener_settings()
            .is_ok()
    );
}

#[test]
fn enabled_listener_surface_requires_the_current_node_name() {
    let _env = UdpListenerEnvGuard::set_with_node(Some("true"), None);
    let runtime = node_waypoint_runtime();
    assert!(
        runtime
            .validate_node_waypoint_udp_listener_settings()
            .is_err(),
        "serving must fail closed when same-node target ownership cannot be established"
    );

    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        udp_listeners(&config).is_empty(),
        "infallible read-only preparation must not widen to every cluster endpoint"
    );
}

#[test]
fn node_waypoint_udp_targets_are_restricted_to_this_exact_node() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let local = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let mut remote = local.clone();
    remote.addresses = vec!["10.244.4.12".to_string()];
    remote.node_waypoint = Some(NodeWaypointEndpoint {
        address: "192.0.2.11".to_string(),
        hbone_port: 15008,
        spiffe_id: remote.spiffe_id.clone(),
        node_name: Some("worker-b".to_string()),
        node_uid: None,
        network: None,
        cluster: None,
    });
    let mut unowned = local.clone();
    unowned.addresses = vec!["10.244.5.13".to_string()];
    unowned.node_waypoint = Some(NodeWaypointEndpoint {
        address: "192.0.2.12".to_string(),
        hbone_port: 15008,
        spiffe_id: unowned.spiffe_id.clone(),
        node_name: None,
        node_uid: None,
        network: None,
        cluster: None,
    });
    let config = prepare(
        &runtime,
        vec![udp_service(
            "dns",
            5353,
            AppProtocol::Udp,
            &[&local, &remote, &unowned],
        )],
        vec![local, remote, unowned],
    );

    let upstream_id = nw_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("the same-node endpoint keeps the listener reachable");
    assert_eq!(
        upstream
            .targets
            .iter()
            .map(|target| target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["10.244.3.11"],
        "another node's pod or a pod with missing node ownership must not be selected by a \
         node-local marked UDP socket"
    );
}

#[test]
fn only_the_node_waypoint_topology_materializes_udp_listeners() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    for topology in [
        MeshTopology::Ambient,
        MeshTopology::Sidecar,
        MeshTopology::ServiceWaypoint,
    ] {
        let runtime = runtime_for_topology(topology);
        let config = prepare(
            &runtime,
            vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
            vec![backend.clone()],
        );
        assert!(
            udp_listeners(&config).is_empty(),
            "{topology:?} has no per-datagram source-attribution channel and must not bind \
             a NodeWaypoint UDP listener"
        );
    }
}

/// Issue #3861: two plain-UDP Services with distinct ClusterIPs on ONE port
/// both materialize and both publish an exact destination route. A `hostNetwork`
/// NodeWaypoint binds the port once, but the steering rules rewrite nothing, so
/// every datagram still carries the ClusterIP its sender addressed and selects
/// exactly one Service.
#[test]
fn two_plain_udp_services_sharing_one_port_both_materialize_exact_routes() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let a = workload_for(
        "dns-a",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.11"],
    );
    let b = workload_for(
        "dns-b",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.12"],
    );
    let mut service_a = udp_service("dns-a", 5353, AppProtocol::Udp, &[&a]);
    service_a.cluster_ips = vec!["10.96.0.10".to_string()];
    let mut service_b = udp_service("dns-b", 5353, AppProtocol::Udp, &[&b]);
    service_b.cluster_ips = vec!["10.96.0.11".to_string()];
    let config = prepare(&runtime, vec![service_a, service_b], vec![a, b]);

    let listeners = udp_listeners(&config);
    assert_eq!(
        listeners.len(),
        2,
        "both compatible same-port claimants must serve; one Service entering the slice must \
         never withdraw the other"
    );
    assert!(
        listeners
            .iter()
            .all(|proxy| proxy.listen_port == Some(5353)),
        "both routes share the one bound port"
    );

    let mut routes: Vec<(String, String)> = config
        .node_waypoint_udp_destination_routes
        .iter()
        .map(|route| (route.destination.to_string(), route.proxy.id.clone()))
        .collect();
    routes.sort();
    assert_eq!(routes.len(), 2, "one exact route per Service ClusterIP");
    assert_eq!(routes[0].0, "10.96.0.10");
    assert_eq!(routes[1].0, "10.96.0.11");
    assert_ne!(
        routes[0].1, routes[1].1,
        "each destination must be owned by its OWN Service listener proxy — the owner decides \
         upstream, policy scope, plugins, accounting and reply source"
    );
    assert!(
        config
            .node_waypoint_udp_destination_routes
            .iter()
            .all(|route| route.listen_port == 5353 && !route.terminates_dtls)
    );

    // Backend isolation: each generated upstream carries only its own Service's
    // same-node endpoint.
    for (destination, proxy_id) in &routes {
        let proxy = listeners
            .iter()
            .find(|proxy| &proxy.id == proxy_id)
            .expect("route owner is materialized");
        let upstream_id = proxy.upstream_id.as_deref().expect("listener upstream");
        let upstream = config
            .upstreams
            .iter()
            .find(|upstream| upstream.id == upstream_id)
            .expect("upstream materialized");
        let hosts: Vec<&str> = upstream
            .targets
            .iter()
            .map(|target| target.host.as_str())
            .collect();
        let expected = if destination == "10.96.0.10" {
            "10.244.3.11"
        } else {
            "10.244.3.12"
        };
        assert_eq!(
            hosts,
            vec![expected],
            "destination {destination} must reach only its own Service's backend"
        );
    }
}

/// Issue #3286/#3861: the lossy `{namespace}-{name}-{port}` join collapsed
/// distinct Kubernetes identities `a-b/c` and `a/b-c` onto one proxy id and one
/// upstream id. Generated listeners share the NodeWaypoint runtime namespace, so
/// that collision overwrote one Service's ClusterIP route, backends, and policy
/// ownership with the other's.
///
/// File-mode slice construction drops both Services (namespaces `a-b` and `a`
/// are not `runtime.namespace`), which is why this proof drives the serving
/// slice directly rather than `prepare()`. Ordinary routing views stay
/// namespace-narrow; this does not widen that filter.
#[test]
fn hyphenated_namespace_name_pairs_keep_distinct_same_port_resources() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let a = workload_for("c", "a-b", [("app", "udp")], ["10.244.3.11"]);
    let b = workload_for("b-c", "a", [("app", "udp")], ["10.244.3.12"]);
    let mut service_a = udp_service_in("a-b", "c", 5353, AppProtocol::Udp, &[&a]);
    service_a.cluster_ips = vec!["10.96.0.10".to_string()];
    service_a.uid = Some("uid-ns-a-b-svc-c".to_string());
    let mut service_b = udp_service_in("a", "b-c", 5353, AppProtocol::Udp, &[&b]);
    service_b.cluster_ips = vec!["10.96.0.11".to_string()];
    service_b.uid = Some("uid-ns-a-svc-b-c".to_string());
    let config = prepare_serving_slice(&runtime, vec![service_a, service_b], vec![a, b]);

    let proxy_a = nw_udp_proxy_id("a-b", "c", 5353);
    let proxy_b = nw_udp_proxy_id("a", "b-c", 5353);
    let upstream_a = nw_udp_upstream_id("a-b", "c", 5353);
    let upstream_b = nw_udp_upstream_id("a", "b-c", 5353);
    assert_ne!(
        proxy_a, proxy_b,
        "lossy hyphen join must not collide proxy ids"
    );
    assert_ne!(
        upstream_a, upstream_b,
        "lossy hyphen join must not collide upstream ids"
    );

    let listeners = udp_listeners(&config);
    assert_eq!(
        listeners.len(),
        2,
        "both hyphen-ambiguous Services must keep their own listener proxy"
    );
    let listener_ids: Vec<&str> = listeners.iter().map(|proxy| proxy.id.as_str()).collect();
    assert!(listener_ids.contains(&proxy_a.as_str()));
    assert!(listener_ids.contains(&proxy_b.as_str()));

    let mut routes: Vec<(String, String, String)> = config
        .node_waypoint_udp_destination_routes
        .iter()
        .map(|route| {
            (
                route.destination.to_string(),
                route.proxy.id.clone(),
                config
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == route.proxy.id)
                    .and_then(|proxy| proxy.upstream_id.clone())
                    .unwrap_or_default(),
            )
        })
        .collect();
    routes.sort();
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].0, "10.96.0.10");
    assert_eq!(routes[0].1, proxy_a);
    assert_eq!(routes[0].2, upstream_a);
    assert_eq!(routes[1].0, "10.96.0.11");
    assert_eq!(routes[1].1, proxy_b);
    assert_eq!(routes[1].2, upstream_b);

    let owned = |upstream_id: &str, backend: &str, uid: &str| {
        let upstream = config
            .upstreams
            .iter()
            .find(|upstream| upstream.id == upstream_id)
            .expect("owning upstream must be materialized");
        assert_eq!(
            upstream
                .targets
                .iter()
                .map(|target| target.host.as_str())
                .collect::<Vec<_>>(),
            vec![backend],
            "each hyphen-ambiguous Service must keep its own backend"
        );
        assert_eq!(
            upstream.k8s_service_uid.as_deref(),
            Some(uid),
            "each hyphen-ambiguous Service must keep its own policy ownership uid"
        );
    };
    owned(&upstream_a, "10.244.3.11", "uid-ns-a-b-svc-c");
    owned(&upstream_b, "10.244.3.12", "uid-ns-a-svc-b-c");
}

/// Adding a second compatible claimant must not withdraw the first, and removing
/// one must retract only that one's route.
#[test]
fn same_port_claimants_are_added_and_removed_independently() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let a = workload_for(
        "dns-a",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.11"],
    );
    let b = workload_for(
        "dns-b",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.12"],
    );
    let mut service_a = udp_service("dns-a", 5353, AppProtocol::Udp, &[&a]);
    service_a.cluster_ips = vec!["10.96.0.10".to_string()];
    let mut service_b = udp_service("dns-b", 5353, AppProtocol::Udp, &[&b]);
    service_b.cluster_ips = vec!["10.96.0.11".to_string()];

    let only_a = prepare(&runtime, vec![service_a.clone()], vec![a.clone()]);
    assert_eq!(udp_listeners(&only_a).len(), 1);
    assert_eq!(only_a.node_waypoint_udp_destination_routes.len(), 1);

    let both = prepare(
        &runtime,
        vec![service_a.clone(), service_b.clone()],
        vec![a.clone(), b.clone()],
    );
    assert_eq!(
        udp_listeners(&both).len(),
        2,
        "adding a second same-port Service must not withdraw the first"
    );

    let only_b = prepare(&runtime, vec![service_b], vec![b]);
    assert_eq!(udp_listeners(&only_b).len(), 1);
    let remaining: Vec<&str> = only_b
        .node_waypoint_udp_destination_routes
        .iter()
        .map(|route| route.proxy.id.as_str())
        .collect();
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0],
        nw_udp_proxy_id(DEFAULT_NAMESPACE, "dns-b", 5353),
        "removing Service A retracts only A's route; B keeps serving"
    );
}

/// Two Services publishing the SAME exact ClusterIP on one port are ambiguous:
/// a received datagram's local destination cannot name one owner, so BOTH are
/// refused. An unrelated third claimant on the same port keeps serving.
#[test]
fn duplicate_exact_destination_claims_refuse_every_ambiguous_claimant() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let a = workload_for(
        "dns-a",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.11"],
    );
    let b = workload_for(
        "dns-b",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.12"],
    );
    let c = workload_for(
        "dns-c",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.13"],
    );
    let mut service_a = udp_service("dns-a", 5353, AppProtocol::Udp, &[&a]);
    service_a.cluster_ips = vec!["10.96.0.10".to_string()];
    let mut service_b = udp_service("dns-b", 5353, AppProtocol::Udp, &[&b]);
    service_b.cluster_ips = vec!["10.96.0.10".to_string()];
    let mut service_c = udp_service("dns-c", 5353, AppProtocol::Udp, &[&c]);
    service_c.cluster_ips = vec!["10.96.0.12".to_string()];

    let config = prepare(
        &runtime,
        vec![service_a, service_b, service_c],
        vec![a, b, c],
    );
    let ids: Vec<&str> = udp_listeners(&config)
        .iter()
        .map(|proxy| proxy.id.as_str())
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "both claimants of the duplicated exact destination are refused: {ids:?}"
    );
    assert_eq!(
        ids[0],
        nw_udp_proxy_id(DEFAULT_NAMESPACE, "dns-c", 5353),
        "the unrelated claimant of a distinct ClusterIP keeps serving"
    );
    assert_eq!(
        config
            .node_waypoint_udp_destination_routes
            .iter()
            .map(|route| route.destination.to_string())
            .collect::<Vec<_>>(),
        vec!["10.96.0.12".to_string()]
    );
}

/// A headless (ClusterIP-less) Service has no exact destination to demultiplex
/// on. It stays reachable over the direct-node-address boundary ONLY while the
/// port has a single claimant; on a shared port it is refused and the
/// VIP-bearing claimants keep serving.
#[test]
fn headless_service_is_unique_port_only_and_never_withdraws_its_neighbours() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let headless_backend = workload_for(
        "syslog",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.21"],
    );
    let mut headless = udp_service("syslog", 5140, AppProtocol::Udp, &[&headless_backend]);
    headless.cluster_ips = Vec::new();

    // Sole claimant: served, with no steerable destination.
    let alone = prepare(
        &runtime,
        vec![headless.clone()],
        vec![headless_backend.clone()],
    );
    assert_eq!(
        udp_listeners(&alone).len(),
        1,
        "a headless Service on a unique port keeps the direct-node-address lane"
    );
    assert!(
        alone.node_waypoint_udp_destination_routes.is_empty(),
        "a headless Service publishes no exact destination route"
    );

    // Shared port: refused, and the VIP-bearing claimant is untouched.
    let vip_backend = workload_for("logs", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.22"]);
    let mut vip = udp_service("logs", 5140, AppProtocol::Udp, &[&vip_backend]);
    vip.cluster_ips = vec!["10.96.0.20".to_string()];
    let shared = prepare(
        &runtime,
        vec![headless, vip],
        vec![headless_backend, vip_backend],
    );
    let ids: Vec<&str> = udp_listeners(&shared)
        .iter()
        .map(|proxy| proxy.id.as_str())
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "expected only the VIP-bearing claimant: {ids:?}"
    );
    assert_eq!(
        ids[0],
        nw_udp_proxy_id(DEFAULT_NAMESPACE, "logs", 5140),
        "the VIP-bearing claimant keeps serving on the shared port"
    );
}

/// A port whose claimants disagree on frontend posture (plain `udp` beside
/// terminating `dtls`) has no representable answer: one bound socket speaks one
/// protocol, chosen before any datagram's destination can select a route. EVERY
/// claimant on that port is refused, deterministically and order-independently;
/// compatible claimants on other ports are untouched.
#[test]
fn a_port_mixing_udp_and_dtls_refuses_every_claimant() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let plain = workload_for(
        "plain",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.31"],
    );
    let secure = workload_for(
        "secure",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.32"],
    );
    let elsewhere = workload_for(
        "other",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.33"],
    );
    let mut plain_service = udp_service("plain", 5353, AppProtocol::Udp, &[&plain]);
    plain_service.cluster_ips = vec!["10.96.0.10".to_string()];
    let mut secure_service = udp_service("secure", 5353, AppProtocol::Dtls, &[&secure]);
    secure_service.cluster_ips = vec!["10.96.0.11".to_string()];
    let mut other_service = udp_service("other", 5354, AppProtocol::Udp, &[&elsewhere]);
    other_service.cluster_ips = vec!["10.96.0.12".to_string()];

    // Both materialization orders must produce the same refusal.
    for services in [
        vec![
            plain_service.clone(),
            secure_service.clone(),
            other_service.clone(),
        ],
        vec![
            secure_service.clone(),
            plain_service.clone(),
            other_service.clone(),
        ],
    ] {
        let config = prepare(
            &runtime,
            services,
            vec![plain.clone(), secure.clone(), elsewhere.clone()],
        );
        let ids: Vec<&str> = udp_listeners(&config)
            .iter()
            .map(|proxy| proxy.id.as_str())
            .collect();
        assert_eq!(
            ids.len(),
            1,
            "the mixed-posture port refuses both claimants; the unrelated port keeps serving: \
             {ids:?}"
        );
        assert_eq!(
            ids[0],
            nw_udp_proxy_id(DEFAULT_NAMESPACE, "other", 5354),
            "compatible claimants on other ports are untouched"
        );
    }
}

/// More than one terminating-DTLS claimant on one port is likewise
/// unrepresentable: a `DtlsServer` owns its socket and carries exactly one
/// frontend identity + client verifier, chosen before any handshake state
/// exists. Every claimant is refused.
#[test]
fn a_port_with_two_dtls_services_refuses_every_claimant() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let a = workload_for(
        "dtls-a",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.41"],
    );
    let b = workload_for(
        "dtls-b",
        DEFAULT_NAMESPACE,
        [("app", "udp")],
        ["10.244.3.42"],
    );
    let mut service_a = udp_service("dtls-a", 6000, AppProtocol::Dtls, &[&a]);
    service_a.cluster_ips = vec!["10.96.0.30".to_string()];
    let mut service_b = udp_service("dtls-b", 6000, AppProtocol::Dtls, &[&b]);
    service_b.cluster_ips = vec!["10.96.0.31".to_string()];

    let config = prepare(&runtime, vec![service_a, service_b], vec![a, b]);
    assert!(
        udp_listeners(&config).is_empty(),
        "one DTLS server cannot carry two Services' postures, so both are refused"
    );
    assert!(config.node_waypoint_udp_destination_routes.is_empty());
}

/// IPv6 and dual-stack ClusterIPs are canonical exact destinations too, and an
/// IPv4-mapped spelling folds onto its IPv4 form so a dual-stack bind and a
/// dedicated v4 bind cannot disagree.
#[test]
fn same_port_destination_routes_cover_ipv4_ipv6_and_dual_stack() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let a = workload_for("v4", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.51"]);
    let b = workload_for("v6", DEFAULT_NAMESPACE, [("app", "udp")], ["fd00::51"]);
    let mut service_a = udp_service("v4", 5353, AppProtocol::Udp, &[&a]);
    service_a.cluster_ips = vec!["10.96.0.40".to_string(), "fd00:96::40".to_string()];
    let mut service_b = udp_service("v6", 5353, AppProtocol::Udp, &[&b]);
    service_b.cluster_ips = vec!["::ffff:10.96.0.41".to_string()];

    let config = prepare(&runtime, vec![service_a, service_b], vec![a, b]);
    assert_eq!(udp_listeners(&config).len(), 2);
    let mut destinations: Vec<String> = config
        .node_waypoint_udp_destination_routes
        .iter()
        .map(|route| route.destination.to_string())
        .collect();
    destinations.sort();
    assert_eq!(
        destinations,
        vec![
            "10.96.0.40".to_string(),
            "10.96.0.41".to_string(),
            "fd00:96::40".to_string(),
        ],
        "a dual-stack Service publishes both families, and an IPv4-mapped ClusterIP is \
         canonicalized onto its IPv4 form"
    );
}

#[test]
fn a_udp_service_port_with_no_reachable_endpoint_materializes_no_listener() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let orphan = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    // The service references the workload, but the slice carries no workloads.
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&orphan])],
        Vec::new(),
    );
    assert!(
        udp_listeners(&config).is_empty(),
        "a listener with no backend would be a black hole; refuse it instead"
    );
}

#[test]
fn inadmissible_cluster_ips_materialize_no_listener_or_steering() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let mut service = udp_service("dns", 5353, AppProtocol::Udp, &[&backend]);
    service.cluster_ips = vec![
        "0.0.0.0".to_string(),
        "127.0.0.1".to_string(),
        "224.0.0.1".to_string(),
        "255.255.255.255".to_string(),
        "::".to_string(),
        "::1".to_string(),
        "ff02::1".to_string(),
    ];

    let config = prepare(&runtime, vec![service], vec![backend]);

    assert!(
        udp_listeners(&config).is_empty(),
        "an explicitly inadmissible ClusterIP must refuse the listener instead of becoming the \
         unique-port headless/direct-address surface"
    );
    assert!(
        config.node_waypoint_udp_steer_destinations.is_empty()
            && config.node_waypoint_udp_destination_routes.is_empty(),
        "an inadmissible Service destination must authorize and steer nothing"
    );
}

#[test]
fn ipv6_workload_addresses_materialize_listener_targets() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["fd00::1234"]);
    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    let upstream_id = nw_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("an IPv6-only service must still materialize its upstream");
    assert_eq!(
        upstream
            .targets
            .iter()
            .map(|target| target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["fd00::1234"]
    );
}

#[test]
fn a_reload_updates_endpoints_and_withdraws_a_removed_service() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();

    let first_backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let first = prepare(
        &runtime,
        vec![udp_service(
            "dns",
            5353,
            AppProtocol::Udp,
            &[&first_backend],
        )],
        vec![first_backend],
    );
    assert_eq!(udp_listeners(&first).len(), 1);

    // Source pod recreation / endpoint change: same service, new pod address.
    let replaced_backend =
        workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.99"]);
    let updated = prepare(
        &runtime,
        vec![udp_service(
            "dns",
            5353,
            AppProtocol::Udp,
            &[&replaced_backend],
        )],
        vec![replaced_backend],
    );
    let upstream_id = nw_udp_upstream_id(DEFAULT_NAMESPACE, "dns", 5353);
    assert_eq!(
        updated
            .upstreams
            .iter()
            .find(|upstream| upstream.id == upstream_id)
            .expect("upstream")
            .targets
            .iter()
            .map(|target| target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["10.244.3.99"],
        "an endpoint change must be reflected in the next prepared generation"
    );

    // Withdrawal: the service leaves the slice entirely.
    let withdrawn = prepare(&runtime, Vec::new(), Vec::new());
    assert!(
        udp_listeners(&withdrawn).is_empty(),
        "withdrawing the service must withdraw its listener"
    );
    assert!(
        !withdrawn
            .upstreams
            .iter()
            .any(|upstream| upstream.id == upstream_id),
        "withdrawing the service must withdraw its upstream too"
    );
}

#[test]
fn a_udp_port_already_claimed_by_a_stream_proxy_is_refused() {
    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);

    // An operator TCP stream proxy already owns 5353 in this generation.
    let mut existing = super::mesh_test_support::http_proxy("operator-tcp", "example.test", 9000);
    existing.backend_scheme = Some(ferrum_edge::config::types::BackendScheme::Tcp);
    existing.hosts = Vec::new();
    existing.listen_path = None;
    existing.listen_port = Some(5353);

    let mesh = mesh_config_with(
        vec![backend.clone()],
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        Vec::new(),
    );
    let config = gateway_config_with_mesh(vec![existing], Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime)
        .expect("mesh config preparation must succeed");

    assert!(
        udp_listeners(&prepared).is_empty(),
        "a port already claimed by a stream proxy must not be re-claimed by a datagram listener"
    );
}

#[test]
fn preparation_attaches_desired_steering_metadata_without_publishing_the_live_plan() {
    use ferrum_edge::proxy::node_waypoint_udp_steering::{
        NodeWaypointUdpSteerBackend, NodeWaypointUdpSteering, published_plan,
    };

    struct NoopBackend;
    impl NodeWaypointUdpSteerBackend for NoopBackend {
        fn run_script(&self, _script: &str) -> Result<(), String> {
            Ok(())
        }
    }

    let _env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);

    let serving = NodeWaypointUdpSteering::new(std::sync::Arc::new(NoopBackend));
    let prior = vec![ferrum_edge::capture::NodeWaypointUdpSteerDestination {
        ip: "10.96.0.99".parse().expect("ip"),
        port: 9999,
    }];
    serving.set_bound_destinations(prior.clone(), Some(&["veth0".to_string()]), true);
    let before_global = published_plan();

    let config = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );

    assert_eq!(
        config.node_waypoint_udp_steer_destinations,
        vec![ferrum_edge::capture::NodeWaypointUdpSteerDestination {
            ip: "10.96.0.10".parse().expect("cluster ip"),
            port: 5353,
        }],
        "preparation must carry desired destinations on the candidate"
    );
    assert_eq!(
        serving.bound_destinations(),
        prior,
        "a rejected or merely inspected candidate must leave the serving plan untouched"
    );
    assert_eq!(
        published_plan().as_ref(),
        before_global.as_ref(),
        "read-only preparation must not mutate the process-global diagnostic plan"
    );
    std::mem::forget(serving);
}

#[test]
fn a_withdrawn_or_disabled_generation_clears_desired_steering_metadata() {
    let enabled_env = UdpListenerEnvGuard::set(Some("true"));
    let runtime = node_waypoint_runtime();
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let prepared = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        !prepared.node_waypoint_udp_steer_destinations.is_empty(),
        "a materialized ClusterIP listener must carry desired steering metadata"
    );

    let withdrawn = prepare(&runtime, Vec::new(), Vec::new());
    assert!(
        withdrawn.node_waypoint_udp_steer_destinations.is_empty(),
        "withdrawing every UDP service must clear desired steering metadata"
    );

    // Release the enabled guard BEFORE taking the disabled one.
    // `UdpListenerEnvGuard` holds `UDP_LISTENER_ENV_LOCK`, a non-reentrant
    // `std::sync::Mutex`, for its whole lifetime, so two overlapping guards on
    // one thread deadlock the test outright.
    drop(enabled_env);
    let _off = UdpListenerEnvGuard::set(None);
    let backend = workload_for("dns", DEFAULT_NAMESPACE, [("app", "udp")], ["10.244.3.11"]);
    let disabled = prepare(
        &runtime,
        vec![udp_service("dns", 5353, AppProtocol::Udp, &[&backend])],
        vec![backend],
    );
    assert!(
        disabled.node_waypoint_udp_steer_destinations.is_empty(),
        "disabling the listener switch must clear desired steering metadata"
    );
}

// ── Reply-source authorization reconciliation (issue #3286) ────────────────
//
// The materialized listener's reply is source-PINNED to the address the client
// addressed. On the Service path that is the Service ClusterIP, which is never
// a configured node IP, so `tc_inbound`'s enrolled-destination guard dropped
// every steered reply — the datapath the live gate's
// `node_waypoint.udp.service_path_allow_attributed_source` exercises.
//
// The repair is an exact, lifecycle-bound authorization with a PROOF: the
// serving proxy publishes one atomically renamed generation into the pod
// registry directory, and the node-agent — still the sole writer of every BPF
// map, because the proxy's bpffs mount is deliberately read-only — applies it
// to `FERRUM_UDP_REPLY_SOURCES` / `FERRUM_UDP_REPLY_SOURCES6` and only then
// acknowledges THAT generation. Publishing a claim is not evidence that a map
// holds it; the acknowledgement is what the proxy gates its steering rules on,
// so a generation this agent refused, narrowed, or could not apply must never
// carry one. These tests pin the node-agent half of that contract end to end,
// against the real publisher.

use dashmap::DashMap;
use ferrum_edge::capture::{CaptureConfig, CaptureMode, NodeWaypointUdpSteerDestination};
#[cfg(unix)]
use ferrum_edge::ebpf::cgroup::{CGROUP_TREE_MAX_DEPTH, CGROUP_TREE_MAX_INODES};
use ferrum_edge::ebpf::{
    BPF_MAP_UDP_REPLY_SOURCE_GATE, CaptureContract, EbpfBackend, FallbackMode, MockEbpfBackend,
    NodeAgentProxyMode, PodAttachmentState,
};
use ferrum_edge::modes::node_agent::{
    NodeAgentConfig, NodeWaypointUdpReplySourceState,
    node_waypoint_udp_reply_source_reconcile_enabled, reconcile_node_waypoint_udp_reply_sources,
};
use ferrum_edge::proxy::node_waypoint_udp_reply_source::{
    NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE, NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE,
    NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR, NodeWaypointUdpReplySourcePublisher,
    RegistryDirReplySourcePublisher, ReplySourceGeneration, read_acknowledgement,
    read_desired_generation,
};

/// The publishing NodeWaypoint proxy's own pod identity. The node-agent
/// resolves it host-side into the relay cgroup set that makes a UDP relay
/// datagram provable (issues #3956, #3957).
const RELAY_POD_UID: &str = "11111111-2222-3333-4444-555555555555";

fn reply_source(ip: &str, port: u16) -> NodeWaypointUdpSteerDestination {
    NodeWaypointUdpSteerDestination {
        ip: ip.parse().expect("reply source address"),
        port,
    }
}

/// A real cgroup-v2 tree for [`RELAY_POD_UID`].
///
/// The node-agent deliberately does NOT trust a published cgroup id — it
/// resolves the relay pod's ids from this node's own hierarchy — so a test that
/// wants a generation applied has to give it a hierarchy to resolve against.
/// Process-lived so every reconcile in this file resolves the same inode set,
/// exactly as a live node would across the node-agent's poll loop.
fn relay_cgroup_root() -> &'static std::path::Path {
    static ROOT: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().expect("relay cgroup root");
        std::fs::create_dir_all(dir.path().join(format!(
            "kubepods/pod{RELAY_POD_UID}/cri-containerd-relay.scope"
        )))
        .expect("relay cgroup tree");
        dir
    })
    .path()
}

/// The exact ids `relay_cgroup_root` should resolve to: the pod slice plus its
/// one container leaf. `bpf_skb_cgroup_id` reports the LEAF, so a set missing it
/// would authorize nothing; the pod slice rides along because the walk enrolls
/// the whole subtree.
#[cfg(unix)]
fn relay_cgroup_ids() -> Vec<u64> {
    use std::os::unix::fs::MetadataExt as _;

    let pod = relay_cgroup_root().join(format!("kubepods/pod{RELAY_POD_UID}"));
    let mut ids = vec![
        std::fs::metadata(&pod).expect("pod cgroup").ino(),
        std::fs::metadata(pod.join("cri-containerd-relay.scope"))
            .expect("container cgroup")
            .ino(),
    ];
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn node_waypoint_config(registry_dir: Option<&std::path::Path>) -> NodeAgentConfig {
    node_waypoint_config_with_cgroup_root(registry_dir, relay_cgroup_root())
}

fn node_waypoint_config_with_cgroup_root(
    registry_dir: Option<&std::path::Path>,
    cgroup_root: &std::path::Path,
) -> NodeAgentConfig {
    let mut capture_config = CaptureConfig::explicit(15006, 15001);
    capture_config.mode = CaptureMode::Ebpf;
    let mut capture_contract = CaptureContract::local_pod_defaults();
    capture_contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;
    NodeAgentConfig {
        node_name: "node-a".to_string(),
        capture_config,
        cgroup_root: cgroup_root.to_string_lossy().into_owned(),
        bpf_fs_path: "/nonexistent".to_string(),
        fallback_mode: FallbackMode::Fail,
        excluded_namespaces: std::collections::HashSet::new(),
        capture_contract,
        trust_domain: "cluster.local".to_string(),
        node_waypoint_pod_registry_dir: registry_dir.map(|dir| dir.to_path_buf()),
    }
}

#[cfg(unix)]
fn relay_pod_cgroup(cgroup_root: &std::path::Path) -> std::path::PathBuf {
    let pod = cgroup_root.join(format!("kubepods/pod{RELAY_POD_UID}"));
    std::fs::create_dir_all(&pod).expect("relay pod cgroup");
    pod
}

#[cfg(unix)]
fn assert_generation_refused_whole(backend: &MockEbpfBackend, registry: &std::path::Path) {
    assert!(
        backend.udp_relay_cgroups.is_empty() && backend.udp_reply_sources.is_empty(),
        "an incomplete relay cgroup walk must authorize neither half of the conjunction"
    );
    assert!(
        !backend.udp_reply_sources_enabled,
        "an incomplete walk must close the shared authorization gate"
    );
    assert_eq!(acknowledgement(registry), None);
}

fn enrolled_pod(uid: &str, pod_ip: &str) -> PodAttachmentState {
    PodAttachmentState {
        pod_uid: uid.to_string(),
        pod_name: "enrolled".to_string(),
        namespace: "team-a".to_string(),
        pod_ip: Some(pod_ip.parse().expect("pod ip")),
        pod_ip6: None,
        cgroup_path: None,
        veth_iface: Some("veth-mock".to_string()),
        attached: true,
        include_ports_cgroup_ids: Vec::new(),
        include_ports_policy: None,
        workload_identity_cgroup_ids: Vec::new(),
        node_probe_ports: Vec::new(),
        inbound_redirect_ports: Vec::new(),
    }
}

fn authorized(backend: &MockEbpfBackend) -> Vec<(std::net::IpAddr, u16)> {
    let mut sources: Vec<(std::net::IpAddr, u16)> =
        backend.udp_reply_sources.iter().copied().collect();
    sources.sort();
    sources
}

/// What the tc UDP arms would actually admit for `source`.
///
/// The gate, the SENDER proof, and the source proof — all three, because the
/// classifier evaluates a conjunction and any two of them without the third is
/// precisely one of the two bypasses this channel closes (issues #3956, #3957).
fn effectively_authorized(backend: &MockEbpfBackend, source: (std::net::IpAddr, u16)) -> bool {
    backend.udp_reply_sources_enabled
        && !backend.udp_relay_cgroups.is_empty()
        && backend.udp_reply_sources.contains(&source)
}

/// The generation the proxy is currently asking for, as the node-agent reads it.
fn desired_generation(registry: &std::path::Path) -> ReplySourceGeneration {
    read_desired_generation(registry)
        .expect("read desired generation")
        .expect("a generation is published")
        .generation
}

fn acknowledgement(registry: &std::path::Path) -> Option<ReplySourceGeneration> {
    read_acknowledgement(registry).expect("read acknowledgement")
}

/// The reconciliation the live Service path depends on: what the serving proxy
/// published is exactly what becomes authorized, on BOTH families — and the
/// generation is acknowledged only once that is true.
#[test]
fn a_published_generation_is_applied_then_acknowledged() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let v4 = reply_source("10.96.0.10", 5300);
    let v6 = reply_source("fd00:10:96::a", 5300);
    let generation = publisher.publish(&[v4, v6], true).expect("publication");
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "nothing is acknowledged until the node-agent has run"
    );

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    let mut expected = vec![(v4.ip, v4.port), (v6.ip, v6.port)];
    expected.sort();
    assert_eq!(authorized(&backend), expected);
    assert!(
        backend.udp_reply_sources_enabled,
        "the shared classifier gate opens only for the complete generation"
    );
    assert_eq!(
        backend.operations,
        vec![
            "set_udp_reply_sources_enabled:false".to_string(),
            "replace_udp_relay_cgroups:2".to_string(),
            "replace_udp_reply_sources:2".to_string(),
            "set_udp_reply_sources_enabled:true".to_string(),
        ],
        "every map — sender proof included — mutates only inside the shared closed-gate window, \
         and the sender proof is written before any source tuple"
    );
    assert_eq!(
        acknowledgement(registry.path()),
        Some(generation),
        "the acknowledgement names exactly the generation whose whole set is live"
    );
}

/// The whole point of the manifest: the node-agent applies a coherent SET. A
/// generation observed mid-rewrite as a partial set would be acknowledged as
/// complete, which is exactly the steered black hole this channel closes.
#[test]
fn a_partially_rewritten_generation_is_never_acknowledged() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let kept = reply_source("10.96.0.11", 5301);
    publisher
        .publish(&[reply_source("10.96.0.10", 5300), kept], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(authorized(&backend).len(), 2);

    // Simulate a torn write: a manifest whose declared count exceeds its body.
    // A per-file claim directory could not even detect this; here it refuses
    // the WHOLE generation.
    let desired = registry
        .path()
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE);
    let body = std::fs::read_to_string(&desired).expect("manifest");
    let mut lines: Vec<&str> = body.lines().collect();
    lines.pop();
    let torn = format!("{}\n", lines.join("\n"));
    std::fs::write(&desired, torn.as_bytes()).expect("torn manifest");

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        authorized(&backend).is_empty(),
        "a torn generation authorizes nothing rather than a silently narrowed subset"
    );
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "and it is never acknowledged"
    );
}

/// Retraction is the security-relevant half. A listener that stopped serving
/// must lose its authorization; retaining it would leave a ClusterIP admissible
/// to enrolled pods with no socket behind it. Each step must also be
/// acknowledged under its OWN generation.
#[test]
fn withdrawing_a_source_revokes_its_authorization_under_a_new_generation() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let kept = reply_source("10.96.0.11", 5301);
    let first = publisher
        .publish(&[reply_source("10.96.0.10", 5300), kept], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(authorized(&backend).len(), 2);
    assert_eq!(acknowledgement(registry.path()), Some(first.clone()));

    let second = publisher.publish(&[kept], true).expect("withdrawal");
    assert_ne!(first, second);
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(
        authorized(&backend),
        vec![(kept.ip, kept.port)],
        "a withdrawn reply source must lose its authorization"
    );
    assert_eq!(acknowledgement(registry.path()), Some(second));

    let empty = publisher.publish(&[], false).expect("full retraction");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        authorized(&backend).is_empty(),
        "a full retraction must leave nothing authorized"
    );
    assert!(
        !backend.udp_reply_sources_enabled,
        "an inactive retraction must leave the shared classifier gate closed"
    );
    assert_eq!(
        acknowledgement(registry.path()),
        Some(empty),
        "the empty generation is acknowledged too, so the proxy can prove the withdrawal"
    );
}

/// Containment: the relay may authorize a Service address, never a workload's
/// own. Otherwise a compromised or buggy proxy could authorize itself to answer
/// enrolled pods AS one of the pods this guard exists to protect. The refusal is
/// of the WHOLE generation — publishing the narrowed remainder and
/// acknowledging it would tell the proxy a set it never asked for is live.
#[test]
fn a_generation_naming_an_enrolled_pod_address_is_refused_whole() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let service = reply_source("10.96.0.10", 5300);
    let pod_address = reply_source("10.244.1.7", 5300);
    publisher
        .publish(&[service, pod_address], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    pods.insert(POD_A.to_string(), enrolled_pod(POD_A, "10.244.1.7"));
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert!(
        authorized(&backend).is_empty(),
        "an enrolled pod address must never become an authorized reply source, and the \
         remainder must not be authorized in its place"
    );
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "a refused generation must not be acknowledged"
    );
}

/// An over-bound generation is refused entirely rather than truncated, and — as
/// with every refusal — carries no acknowledgement.
#[test]
fn an_over_bound_generation_is_refused_and_unacknowledged() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(authorized(&backend).len(), 1);
    assert_eq!(acknowledgement(registry.path()), Some(generation));

    // A manifest declaring more sources than the BPF map can hold. The
    // publisher refuses to write one, so this is the hostile/corrupt shape the
    // node-agent must still refuse on its own.
    let desired = registry
        .path()
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE);
    let owner = desired_generation(registry.path());
    let mut body = format!(
        "ferrum-udp-reply-src v3 {} {} active 200 {RELAY_POD_UID}\n",
        owner.owner(),
        owner.sequence() + 1
    );
    for index in 0..200u16 {
        body.push_str(&format!("4-0a60000a-{}\n", 5300 + index));
    }
    std::fs::write(&desired, body.as_bytes()).expect("over-bound manifest");

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        authorized(&backend).is_empty(),
        "an over-bound generation must be refused entirely, never truncated"
    );
    assert_eq!(acknowledgement(registry.path()), None);
    assert!(
        !backend.udp_reply_sources_enabled,
        "an over-bound refusal must close the shared authorization gate"
    );
}

/// The node-agent resolves the SENDER proof host-side and applies it in the
/// same fenced generation as the source proof (issues #3956, #3957).
///
/// The published manifest names a POD; what reaches `FERRUM_UDP_RELAY_CGROUPS`
/// is this node's own resolution of that pod's cgroup subtree — including the
/// container LEAF, which is the id `bpf_skb_cgroup_id` actually reports.
#[cfg(unix)]
#[test]
fn a_generation_authorizes_the_relays_resolved_cgroup_subtree() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let source = reply_source("10.96.0.10", 5300);
    let generation = publisher.publish(&[source], true).expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    let mut applied: Vec<u64> = backend.udp_relay_cgroups.iter().copied().collect();
    applied.sort_unstable();
    assert_eq!(
        applied,
        relay_cgroup_ids(),
        "the authorized sender set must be this node's resolution of the relay pod's cgroup tree"
    );
    assert_eq!(acknowledgement(registry.path()), Some(generation));
    assert!(
        effectively_authorized(&backend, (source.ip, source.port)),
        "gate, sender proof, and source proof must all be live together"
    );

    // Withdrawal revokes the sender proof as well: leaving a dead relay's
    // cgroup behind would let a LATER generation open the gate over a stale
    // sender set.
    publisher.publish(&[], false).expect("withdrawal");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        backend.udp_relay_cgroups.is_empty() && backend.udp_reply_sources.is_empty(),
        "an inactive generation must revoke the sender proof, not merely fence it"
    );
}

/// An ACTIVE generation with zero ClusterIP sources still resolves and applies
/// the complete relay cgroup set, opens the shared gate, and is acknowledged.
/// That is the bound headless/VIP-less listener: the direct-node lane stays
/// usable without authorizing any ClusterIP tuple.
#[cfg(unix)]
#[test]
fn an_active_empty_generation_applies_the_relay_cgroup_set_and_opens_the_gate() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher.publish(&[], true).expect("active-empty");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    let mut applied: Vec<u64> = backend.udp_relay_cgroups.iter().copied().collect();
    applied.sort_unstable();
    assert_eq!(
        applied,
        relay_cgroup_ids(),
        "active-empty must still enroll the relay cgroup subtree"
    );
    assert!(
        backend.udp_reply_sources.is_empty(),
        "active-empty authorizes no ClusterIP tuple"
    );
    assert!(
        backend.udp_reply_sources_enabled,
        "the shared gate must open so the node-source lane can use the sender proof"
    );
    assert_eq!(acknowledgement(registry.path()), Some(generation.clone()));

    let with_vip = publisher
        .publish(
            &[
                reply_source("10.96.0.10", 5300),
                reply_source("fd00:10:96::a", 5300),
            ],
            true,
        )
        .expect("ClusterIP");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(authorized(&backend).len(), 2);
    assert_eq!(acknowledgement(registry.path()), Some(with_vip));
    assert!(backend.udp_reply_sources_enabled);

    let headless_again = publisher.publish(&[], true).expect("back to headless");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(backend.udp_reply_sources.is_empty());
    let mut applied: Vec<u64> = backend.udp_relay_cgroups.iter().copied().collect();
    applied.sort_unstable();
    assert_eq!(applied, relay_cgroup_ids());
    assert!(backend.udp_reply_sources_enabled);
    assert_eq!(acknowledgement(registry.path()), Some(headless_again));

    publisher.publish(&[], false).expect("last listener gone");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        backend.udp_relay_cgroups.is_empty()
            && backend.udp_reply_sources.is_empty()
            && !backend.udp_reply_sources_enabled,
        "inactive withdrawal must close the gate and clear both maps"
    );
}

/// A generation naming an ENROLLED pod as the relay is refused WHOLE.
///
/// The mirror of the enrolled-pod-ADDRESS refusal, and the reason a pod UID on
/// this channel is a name rather than an authorization: the relay may answer
/// for a Service address, but never as one of the workloads this guard protects.
#[test]
fn a_generation_naming_an_enrolled_pod_as_the_relay_is_refused() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    pods.insert(
        RELAY_POD_UID.to_string(),
        enrolled_pod(RELAY_POD_UID, "10.244.0.7"),
    );
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert!(
        backend.udp_relay_cgroups.is_empty() && backend.udp_reply_sources.is_empty(),
        "a relay identity naming an enrolled workload must authorize nothing"
    );
    assert!(!backend.udp_reply_sources_enabled);
    assert_eq!(acknowledgement(registry.path()), None);
}

/// A relay identity this node cannot resolve to a live cgroup authorizes
/// nothing. An inability to prove the sender is not evidence about it.
#[test]
fn an_unresolvable_relay_identity_authorizes_nothing() {
    let registry = tempfile::tempdir().expect("registry dir");
    // A well-formed pod UID that simply has no cgroup on this node.
    let publisher = RegistryDirReplySourcePublisher::new(
        registry.path(),
        Some("99999999-8888-7777-6666-555555555555"),
    );
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert!(
        backend.udp_reply_sources.is_empty() && backend.udp_relay_cgroups.is_empty(),
        "an unresolvable relay identity must leave both halves of the proof empty"
    );
    assert!(!backend.udp_reply_sources_enabled);
    assert_eq!(acknowledgement(registry.path()), None);
}

/// A relay pod whose cgroup tree is larger than the map must be refused WHOLE.
/// Silently truncating would omit an arbitrary container leaf — including the
/// one `bpf_skb_cgroup_id` reports for the active relay container.
#[cfg(unix)]
#[test]
fn an_over_bound_relay_cgroup_tree_is_refused_whole() {
    let cgroup_root = tempfile::tempdir().expect("cgroup root");
    let pod = relay_pod_cgroup(cgroup_root.path());
    for index in 0..CGROUP_TREE_MAX_INODES {
        std::fs::create_dir(pod.join(format!("cri-containerd-{index:03}.scope")))
            .expect("container cgroup");
    }

    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config_with_cgroup_root(Some(registry.path()), cgroup_root.path());
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert_generation_refused_whole(&backend, registry.path());
}

/// A relay pod nested past the walk's depth bound is refused WHOLE. The count
/// may look small; the missing deeper leaf is still a truncated sender proof.
#[cfg(unix)]
#[test]
fn a_too_deep_relay_cgroup_tree_is_refused_whole() {
    let cgroup_root = tempfile::tempdir().expect("cgroup root");
    let mut path = relay_pod_cgroup(cgroup_root.path());
    for index in 0..=CGROUP_TREE_MAX_DEPTH {
        path.push(format!("n{index}"));
        std::fs::create_dir(&path).expect("depth chain");
    }

    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config_with_cgroup_root(Some(registry.path()), cgroup_root.path());
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert_generation_refused_whole(&backend, registry.path());
}

/// A descendant that cannot be enumerated is not a complete sender-proof set.
/// Publishing the readable prefix would omit the unreadable container leaf.
#[cfg(unix)]
#[test]
fn an_incompletely_enumerated_relay_cgroup_tree_is_refused_whole() {
    use std::os::unix::fs::PermissionsExt as _;

    // SAFETY: `geteuid` is a pure read of this process's credentials.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let cgroup_root = tempfile::tempdir().expect("cgroup root");
    let pod = relay_pod_cgroup(cgroup_root.path());
    let hidden = pod.join("cri-containerd-hidden.scope");
    std::fs::create_dir(&hidden).expect("hidden container");
    std::fs::create_dir(hidden.join("nested-leaf")).expect("nested leaf");
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    struct RestoreMode<'a>(&'a std::path::Path);
    impl Drop for RestoreMode<'_> {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    let _restore = RestoreMode(&hidden);

    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config_with_cgroup_root(Some(registry.path()), cgroup_root.path());
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert_generation_refused_whole(&backend, registry.path());
}

/// A generation whose SENDER proof cannot be written is never acknowledged, and
/// never leaves the source proof authorized on its own.
///
/// This is the failure mode the ordering exists for: sources live in the maps
/// with no relay cgroup beside them is exactly the #3957 replay, so the
/// relay-cgroup write happens FIRST and its failure returns before any source
/// tuple is written.
#[test]
fn a_generation_whose_sender_proof_fails_is_never_acknowledged() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend {
        fail_replace_udp_relay_cgroups: true,
        ..MockEbpfBackend::default()
    };
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert!(
        backend.udp_reply_sources.is_empty(),
        "no source tuple may reach the maps once the sender proof has failed"
    );
    assert!(
        !backend.udp_reply_sources_enabled,
        "the shared gate must stay closed"
    );
    assert_eq!(acknowledgement(registry.path()), None);
}

/// Nothing published means nothing authorized — and a channel that has never
/// existed is exactly that, not an error that would make the agent retain a
/// previous generation. The acknowledgement goes with it.
#[test]
fn an_absent_channel_authorizes_nothing() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(authorized(&backend).len(), 1);
    assert!(acknowledgement(registry.path()).is_some());

    // The proxy's whole channel disappears (a restart wiping its scratch state,
    // a remount). Authorization must not survive it, and neither may the proof.
    std::fs::remove_dir_all(registry.path().join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR))
        .expect("remove channel dir");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        authorized(&backend).is_empty(),
        "authorization must not outlive the generation that justified it"
    );
    assert_eq!(acknowledgement(registry.path()), None);
    assert!(
        !backend.udp_reply_sources_enabled,
        "an absent channel must close the shared authorization gate"
    );
}

/// A map write that failed is not evidence of anything, so the reconcile must
/// not record it as converged and must NOT acknowledge — the next pass has to
/// rewrite from scratch, and until it succeeds the proxy keeps the Service path
/// unsteered.
#[test]
fn a_failed_map_write_is_never_acknowledged_and_is_retried() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let service = reply_source("10.96.0.10", 5300);
    let generation = publisher.publish(&[service], true).expect("publication");

    let mut backend = MockEbpfBackend {
        fail_replace_udp_reply_sources: true,
        ..MockEbpfBackend::default()
    };
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(authorized(&backend).is_empty());
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "a generation that could not be applied must not be acknowledged"
    );

    backend.fail_replace_udp_reply_sources = false;
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(
        authorized(&backend),
        vec![(service.ip, service.port)],
        "a failed write must be retried rather than recorded as applied"
    );
    assert_eq!(acknowledgement(registry.path()), Some(generation));
}

/// Success in one address family is not success for the generation. The
/// acknowledgement appears only after the retry has completed both IPv4 and
/// IPv6, never while the maps hold a partial family result.
#[test]
fn a_partial_family_failure_is_never_acknowledged() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let v4 = reply_source("10.96.0.10", 5300);
    let v6 = reply_source("fd00:10:96::a", 5300);
    let generation = publisher.publish(&[v4, v6], true).expect("publication");

    let stale_v6 = ("fd00:10:96::dead".parse().expect("stale IPv6"), 5353);
    let mut backend = MockEbpfBackend {
        fail_replace_udp_reply_sources_after_ipv4: true,
        udp_reply_sources: std::collections::HashSet::from([stale_v6]),
        udp_reply_sources_enabled: true,
        ..MockEbpfBackend::default()
    };
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert!(
        backend.udp_reply_sources.contains(&(v4.ip, v4.port))
            && backend.udp_reply_sources.contains(&stale_v6),
        "the injected backend must retain stale IPv6 storage after IPv4 succeeded"
    );
    assert!(
        !backend.udp_reply_sources_enabled
            && !effectively_authorized(&backend, stale_v6)
            && !effectively_authorized(&backend, (v4.ip, v4.port)),
        "one shared closed gate must make both partial IPv4 and stale IPv6 entries inert"
    );
    assert_eq!(backend.udp_reply_source_gate_updates.last(), Some(&false));
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "a partial family result must prove nothing"
    );

    backend.fail_replace_udp_reply_sources_after_ipv4 = false;
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    let mut expected = vec![(v4.ip, v4.port), (v6.ip, v6.port)];
    expected.sort();
    assert_eq!(authorized(&backend), expected);
    assert!(backend.udp_reply_sources_enabled);
    assert_eq!(acknowledgement(registry.path()), Some(generation));
}

/// Readiness must reject an ELF that has both family maps but lacks their
/// shared coherence gate. Starting without it would make partial-family map
/// contents live again.
#[test]
fn a_missing_reply_source_gate_fails_node_waypoint_startup_readiness() {
    let mut contract = CaptureContract::local_pod_defaults();
    contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;
    let backend = MockEbpfBackend {
        programs_loaded: true,
        capture_config: Some(contract.bpf_capture_config()),
        sock_ops_attached_cgroup_root: Some("/sys/fs/cgroup".to_string()),
        udp_reply_source_gate_absent: true,
        ..MockEbpfBackend::default()
    };

    let error = backend
        .validate_startup_ready(true)
        .expect_err("a missing shared gate must fail readiness");
    assert!(
        error.contains(BPF_MAP_UDP_REPLY_SOURCE_GATE),
        "the readiness diagnostic must name the missing ABI map: {error}"
    );
}

#[test]
fn backend_cleanup_closes_and_clears_reply_source_authorization() {
    let source = ("10.96.0.10".parse().expect("source address"), 5300);
    let mut backend = MockEbpfBackend {
        udp_reply_sources: std::collections::HashSet::from([source]),
        udp_reply_sources_enabled: true,
        ..MockEbpfBackend::default()
    };

    backend.cleanup_all().expect("cleanup");

    assert!(!backend.udp_reply_sources_enabled);
    assert!(backend.udp_reply_sources.is_empty());
}

/// A map that is absent from the loaded program cannot authorize its family, so
/// the whole generation stays unapplied and unacknowledged — a dual-stack
/// waypoint that acknowledged a v4-only apply would black-hole every v6 reply.
#[test]
fn an_absent_required_map_never_produces_an_acknowledgement() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend {
        udp_reply_source_maps_absent: true,
        ..MockEbpfBackend::default()
    };
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert!(authorized(&backend).is_empty());
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "an ELF without the reply-source maps must never look converged"
    );

    publisher
        .publish(&[], false)
        .expect("empty withdrawal generation");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "even an inactive withdrawal is unproven when either family map is absent"
    );
}

/// A successor can replace `desired` while the node-agent is applying the
/// predecessor's maps. The agent must re-read the exact manifest before writing
/// `applied`; otherwise the predecessor receives a late proof after the
/// successor is already current and can briefly reinstall stale steering.
#[test]
fn a_generation_superseded_during_map_apply_is_never_acknowledged() {
    let registry = tempfile::tempdir().expect("registry dir");
    let predecessor = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    predecessor
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("predecessor generation");

    let successor_registry = tempfile::tempdir().expect("successor registry");
    let successor =
        RegistryDirReplySourcePublisher::new(successor_registry.path(), Some(RELAY_POD_UID));
    let successor_source = reply_source("10.96.0.11", 5301);
    let successor_generation = successor
        .publish(&[successor_source], true)
        .expect("successor generation");
    let successor_manifest = std::fs::read(
        successor_registry
            .path()
            .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
            .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE),
    )
    .expect("successor manifest");

    let desired_path = registry
        .path()
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE);
    let mut backend = MockEbpfBackend {
        udp_reply_source_desired_replacement: Some((desired_path, successor_manifest)),
        ..MockEbpfBackend::default()
    };
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        authorized(&backend).is_empty(),
        "the superseded set must be revoked rather than left live without exact proof"
    );
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "a predecessor superseded during apply must receive no late acknowledgement"
    );

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(
        authorized(&backend),
        vec![(successor_source.ip, successor_source.port)]
    );
    assert_eq!(
        acknowledgement(registry.path()),
        Some(successor_generation),
        "the next ordinary poll applies and acknowledges only the successor"
    );
}

/// A stale acknowledgement is retracted BEFORE the maps are touched, so the
/// proxy cannot read an old proof as covering the generation currently being
/// applied. This is what makes a crash mid-apply fail closed.
#[test]
fn a_new_generation_retracts_the_previous_acknowledgement_before_applying() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let first = publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("first");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(acknowledgement(registry.path()), Some(first.clone()));

    // A new generation the agent cannot apply. The old acknowledgement must be
    // gone even though the new one is never written.
    publisher
        .publish(
            &[
                reply_source("10.96.0.10", 5300),
                reply_source("10.96.0.11", 5301),
            ],
            true,
        )
        .expect("second");
    backend.fail_replace_udp_reply_sources = true;
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(
        acknowledgement(registry.path()),
        None,
        "the previous generation's acknowledgement must not survive an unapplied change"
    );
}

/// A failed unlink must not preserve BPF authorization. The successor remains
/// unapplied, the old map contents stay inert behind the closed gate, and the
/// ordinary next poll retries after the filesystem fault clears.
#[test]
fn successor_acknowledgement_unlink_failure_closes_the_gate_and_retries() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let old_source = reply_source("10.96.0.10", 5300);
    publisher.publish(&[old_source], true).expect("first");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(backend.udp_reply_sources_enabled);

    let successor = reply_source("10.96.0.11", 5301);
    let generation = publisher.publish(&[successor], true).expect("successor");
    let applied = registry
        .path()
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);
    std::fs::remove_file(&applied).expect("remove old acknowledgement");
    std::fs::create_dir(&applied).expect("inject unlink failure");

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        !backend.udp_reply_sources_enabled
            && !effectively_authorized(&backend, (old_source.ip, old_source.port)),
        "unlink failure must close authorization even while old map storage remains"
    );
    assert!(
        !backend
            .udp_reply_sources
            .contains(&(successor.ip, successor.port)),
        "a generation whose acknowledgement could not be retracted must not be mutated in"
    );

    std::fs::remove_dir(&applied).expect("clear injected fault");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(backend.udp_reply_sources_enabled);
    assert_eq!(authorized(&backend), vec![(successor.ip, successor.port)]);
    assert_eq!(acknowledgement(registry.path()), Some(generation));
}

/// Refusal uses the same ordering as replacement. Even when the stale
/// acknowledgement path cannot be unlinked, an unreadable desired manifest
/// immediately closes the shared authorization lane and is retried.
#[test]
fn refusal_acknowledgement_unlink_failure_closes_the_gate_and_retries() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let source = reply_source("10.96.0.10", 5300);
    publisher.publish(&[source], true).expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    let channel_dir = registry.path().join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    let desired = channel_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE);
    std::fs::write(&desired, b"malformed\n").expect("corrupt desired manifest");
    let applied = channel_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);
    std::fs::remove_file(&applied).expect("remove old acknowledgement");
    std::fs::create_dir(&applied).expect("inject unlink failure");

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(
        !backend.udp_reply_sources_enabled
            && !effectively_authorized(&backend, (source.ip, source.port)),
        "refusal must close the BPF lane regardless of acknowledgement unlink failure"
    );

    std::fs::remove_dir(&applied).expect("clear injected fault");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(authorized(&backend).is_empty());
    assert!(!backend.udp_reply_sources_enabled);
    assert_eq!(acknowledgement(registry.path()), None);
}

/// If the shared gate itself cannot be closed, the node-agent must surface the
/// hard residual and stop before mutating or acknowledging a successor.
#[test]
fn gate_disable_failure_never_mutates_or_acknowledges_a_successor() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let old_source = reply_source("10.96.0.10", 5300);
    publisher.publish(&[old_source], true).expect("first");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    let replacements = backend.udp_reply_source_updates.len();

    let successor = reply_source("10.96.0.11", 5301);
    publisher.publish(&[successor], true).expect("successor");
    backend.fail_disable_udp_reply_sources = true;
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert_eq!(backend.udp_reply_source_updates.len(), replacements);
    assert_eq!(authorized(&backend), vec![(old_source.ip, old_source.port)]);
    assert_eq!(acknowledgement(registry.path()), None);

    backend.fail_disable_udp_reply_sources = false;
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert!(backend.udp_reply_sources_enabled);
    assert_eq!(authorized(&backend), vec![(successor.ip, successor.port)]);
}

/// An acknowledgement that vanishes underneath a converged agent is rewritten,
/// so a wiped scratch directory cannot strand the proxy waiting forever for a
/// proof the agent believes it already gave.
#[test]
fn a_lost_acknowledgement_is_rewritten_on_the_next_pass() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(acknowledgement(registry.path()), Some(generation.clone()));

    let applied = registry
        .path()
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);
    std::fs::remove_file(&applied).expect("remove acknowledgement");

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(acknowledgement(registry.path()), Some(generation));
}

/// A successor process publishes under its OWN owner, so the predecessor's
/// acknowledgement never covers it: the agent must apply and re-acknowledge.
#[test]
fn a_successor_generation_gets_its_own_acknowledgement() {
    let registry = tempfile::tempdir().expect("registry dir");
    let destinations = [reply_source("10.96.0.10", 5300)];
    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();

    let predecessor = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let old = predecessor
        .publish(&destinations, true)
        .expect("predecessor");
    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    assert_eq!(acknowledgement(registry.path()), Some(old.clone()));
    assert_eq!(backend.udp_reply_source_updates.len(), 1);

    let successor = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let new = successor.publish(&destinations, true).expect("successor");
    assert_ne!(old, new);

    reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);

    assert_eq!(
        acknowledgement(registry.path()),
        Some(new),
        "the successor's generation must be acknowledged under its own owner"
    );
    assert_eq!(
        backend.udp_reply_source_updates.len(),
        2,
        "even an identical set under a new owner must be freshly applied to both families"
    );
}

/// The reconcile runs on a 250 ms poll, so an unchanged, already-acknowledged
/// generation must issue no map calls at all.
#[test]
fn a_quiet_poll_issues_no_map_write() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(&[reply_source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut backend = MockEbpfBackend::default();
    let pods = DashMap::new();
    let config = node_waypoint_config(Some(registry.path()));
    let mut state = NodeWaypointUdpReplySourceState::default();
    for _ in 0..4 {
        reconcile_node_waypoint_udp_reply_sources(&mut backend, &config, &pods, &mut state);
    }
    assert_eq!(
        backend.udp_reply_source_updates.len(),
        1,
        "only the first pass may write; the rest are already converged"
    );
}

/// The channel exists for one topology. A local-pod node-agent has no
/// NodeWaypoint UDP/DTLS relay whose replies could need authorizing, and
/// without a registry directory there is no channel to read.
#[test]
fn the_reconcile_is_node_waypoint_and_registry_scoped() {
    let registry = tempfile::tempdir().expect("registry dir");
    assert!(node_waypoint_udp_reply_source_reconcile_enabled(
        &node_waypoint_config(Some(registry.path()))
    ));
    assert!(!node_waypoint_udp_reply_source_reconcile_enabled(
        &node_waypoint_config(None)
    ));

    let mut local_pod = node_waypoint_config(Some(registry.path()));
    local_pod.capture_contract.proxy_mode = NodeAgentProxyMode::LocalPod;
    assert!(!node_waypoint_udp_reply_source_reconcile_enabled(
        &local_pod
    ));
}
