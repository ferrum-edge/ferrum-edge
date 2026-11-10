//! Host-network UDP capture reconciliation and per-datagram attribution
//! (issue #3288).
//!
//! The capture socket in this placement is shared by every enrolled pod on the
//! node, so two things carry the entire security argument and are pinned here:
//!
//! * **Attribution** — a datagram is relayed under a workload identity only when
//!   its ingress interface maps to exactly one enrolled pod AND its source
//!   address is one that pod is registered to use. Anything else is dropped.
//! * **Lifecycle** — every failure keeps the datapath either on the previous
//!   correct ruleset or behind a fail-closed DROP guard; a pod is never marked
//!   ready before its capture is genuinely live, its rules survive until the
//!   node-agent acknowledges closing its BPF gate, and a capture loop that dies
//!   is restarted instead of black-holing the node.
//! * **Process boundary** — readiness is durable and shared with the node-agent,
//!   so a new generation discharges the previous one's close handshake BEFORE it
//!   reaps that generation's rules or applies its own. Reaping first is the one
//!   way this path can produce a plaintext window.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_edge::identity::spiffe::SpiffeId;
use ferrum_edge::modes::mesh::hbone::UdpSourceIdentity;
use ferrum_edge::proxy::host_udp_capture::{
    HostUdpCaptureBackend, HostUdpCaptureManager, HostUdpDatagramRefusal, HostUdpIdentityIndex,
    HostUdpListenerHandle, HostUdpPodBinding, HostUdpRefusal, HostUdpStaleGenerationRecovery,
    ResolvedInterface, plan_host_udp_bindings, recover_and_reap_stale_host_udp_state,
};
use ferrum_edge::proxy::netns_capture::{PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget};

const POD_A_UID: &str = "11111111-1111-4111-8111-111111111111";
const POD_B_UID: &str = "22222222-2222-4222-8222-222222222222";
const POD_C_UID: &str = "33333333-3333-4333-8333-333333333333";

fn identity(uid: &str, sa: &str) -> UdpSourceIdentity {
    let principal =
        SpiffeId::new(format!("spiffe://cluster.local/ns/team/sa/{sa}")).expect("valid SPIFFE id");
    UdpSourceIdentity::new(principal, uid).expect("valid source identity")
}

fn target(uid: &str, sa: &str, ipv4: Option<&str>) -> PodCaptureTarget {
    PodCaptureTarget {
        pod_uid: uid.to_string(),
        cgroup_path: format!("/sys/fs/cgroup/kubepods/pod{uid}"),
        source_identity: Some(identity(uid, sa)),
        source_ips: PodCaptureSourceIps {
            ipv4: ipv4.map(|ip| ip.parse().expect("valid ipv4")),
            ipv6: None,
        },
    }
}

fn iface(name: &str, ifindex: u32) -> ResolvedInterface {
    ResolvedInterface {
        name: name.to_string(),
        ifindex,
    }
}

fn binding(uid: &str, sa: &str, name: &str, ifindex: u32, ipv4: &str) -> HostUdpPodBinding {
    HostUdpPodBinding {
        pod_uid: uid.to_string(),
        iface: name.to_string(),
        ifindex,
        ipv4: Some(ipv4.parse().expect("valid ipv4")),
        ipv6: None,
        identity: identity(uid, sa),
    }
}

// ── Attribution ────────────────────────────────────────────────────────────

#[test]
fn identity_index_attributes_a_datagram_by_ingress_interface_and_source_address() {
    let index = HostUdpIdentityIndex::new();
    index.publish(&[
        binding(POD_A_UID, "a", "vetha", 11, "10.244.1.5"),
        binding(POD_B_UID, "b", "vethb", 12, "10.244.1.6"),
    ]);

    let a: IpAddr = "10.244.1.5".parse().unwrap();
    let b: IpAddr = "10.244.1.6".parse().unwrap();
    assert!(index.authorize(Some(11), a).is_ok());
    assert!(index.authorize(Some(12), b).is_ok());

    let resolved = index
        .identity_for(Some(11), a)
        .expect("pod A resolves to its own identity");
    assert_eq!(resolved.pod_uid, POD_A_UID);
    assert!(resolved.principal.as_str().ends_with("/sa/a"));
    let resolved = index
        .identity_for(Some(12), b)
        .expect("pod B resolves to its own identity");
    assert!(resolved.principal.as_str().ends_with("/sa/b"));
}

#[test]
fn identity_index_refuses_a_pod_spoofing_a_neighbours_source_address() {
    let index = HostUdpIdentityIndex::new();
    index.publish(&[
        binding(POD_A_UID, "a", "vetha", 11, "10.244.1.5"),
        binding(POD_B_UID, "b", "vethb", 12, "10.244.1.6"),
    ]);

    // Pod A forges pod B's address. The forgery does not change which interface
    // the datagram entered on, so attribution fails and the datagram is dropped —
    // it is NEVER relayed under either pod's identity.
    let forged: IpAddr = "10.244.1.6".parse().unwrap();
    assert_eq!(
        index.authorize(Some(11), forged),
        Err(HostUdpDatagramRefusal::SourceAddressMismatch)
    );
    assert!(index.identity_for(Some(11), forged).is_none());
}

#[test]
fn identity_index_refuses_unattributable_datagrams() {
    let index = HostUdpIdentityIndex::new();
    index.publish(&[binding(POD_A_UID, "a", "vetha", 11, "10.244.1.5")]);
    let a: IpAddr = "10.244.1.5".parse().unwrap();

    // No ingress-interface cmsg at all, and the kernel's "unspecified" index.
    assert_eq!(
        index.authorize(None, a),
        Err(HostUdpDatagramRefusal::NoIngressInterface)
    );
    assert_eq!(
        index.authorize(Some(0), a),
        Err(HostUdpDatagramRefusal::NoIngressInterface)
    );
    // A non-enrolled interface: the node uplink, another CNI's device, or a pod
    // that is not part of the mesh.
    assert_eq!(
        index.authorize(Some(99), a),
        Err(HostUdpDatagramRefusal::UnenrolledInterface)
    );
    // A different address family the pod never registered.
    let v6: IpAddr = "fd00::5".parse().unwrap();
    assert_eq!(
        index.authorize(Some(11), v6),
        Err(HostUdpDatagramRefusal::SourceAddressMismatch)
    );
}

#[test]
fn identity_index_clear_stops_attributing_late_datagrams() {
    let index = HostUdpIdentityIndex::new();
    index.publish(&[binding(POD_A_UID, "a", "vetha", 11, "10.244.1.5")]);
    let a: IpAddr = "10.244.1.5".parse().unwrap();
    assert!(index.authorize(Some(11), a).is_ok());

    index.clear();
    assert_eq!(
        index.authorize(Some(11), a),
        Err(HostUdpDatagramRefusal::UnenrolledInterface),
        "a socket still draining after capture stops must not attribute a late datagram"
    );
}

#[test]
fn identity_index_publishes_whole_generations() {
    let index = HostUdpIdentityIndex::new();
    index.publish(&[binding(POD_A_UID, "a", "vetha", 11, "10.244.1.5")]);
    // A pod recycled onto the same interface index with a new identity: the whole
    // mapping is replaced, so no reader can see the old identity behind the new
    // address (or vice versa).
    index.publish(&[binding(POD_B_UID, "b", "vetha", 11, "10.244.1.9")]);

    let old: IpAddr = "10.244.1.5".parse().unwrap();
    let new: IpAddr = "10.244.1.9".parse().unwrap();
    assert_eq!(
        index.authorize(Some(11), old),
        Err(HostUdpDatagramRefusal::SourceAddressMismatch)
    );
    assert_eq!(
        index
            .identity_for(Some(11), new)
            .expect("new binding")
            .pod_uid,
        POD_B_UID
    );
}

// ── Planning ───────────────────────────────────────────────────────────────

#[test]
fn planner_refuses_pods_that_cannot_be_attributed() {
    let mut unattested = target(POD_A_UID, "a", Some("10.244.1.5"));
    unattested.source_identity = None;
    let mut addressless = target(POD_B_UID, "b", None);
    addressless.source_ips = PodCaptureSourceIps::default();
    let unresolved = target(
        "33333333-3333-4333-8333-333333333333",
        "c",
        Some("10.244.1.7"),
    );

    let mut resolved = HashMap::new();
    resolved.insert(unattested.pod_uid.clone(), iface("vetha", 11));
    resolved.insert(addressless.pod_uid.clone(), iface("vethb", 12));

    let state = plan_host_udp_bindings(&[unattested, addressless, unresolved], &resolved);
    assert!(
        state.bindings.is_empty(),
        "none of these pods can be attributed: {:#?}",
        state.bindings
    );
    let reasons: Vec<HostUdpRefusal> = state.refused.iter().map(|(_, reason)| *reason).collect();
    assert!(
        reasons.contains(&HostUdpRefusal::MissingIdentity),
        "{reasons:?}"
    );
    assert!(
        reasons.contains(&HostUdpRefusal::MissingPodAddress),
        "{reasons:?}"
    );
    assert!(
        reasons.contains(&HostUdpRefusal::UnresolvedInterface),
        "{reasons:?}"
    );
}

#[test]
fn planner_refuses_both_pods_that_share_one_interface() {
    // A bridge CNI (or a stale registry entry pointing at a recycled veth) makes
    // per-datagram attribution impossible. Capturing either pod would relay it
    // under a guessed identity, so BOTH are refused — first-wins would be a
    // cross-tenant identity bug.
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    let b = target(POD_B_UID, "b", Some("10.244.1.6"));
    let mut resolved = HashMap::new();
    resolved.insert(a.pod_uid.clone(), iface("cni0", 7));
    resolved.insert(b.pod_uid.clone(), iface("cni0", 7));

    let state = plan_host_udp_bindings(&[a, b], &resolved);
    assert!(state.bindings.is_empty(), "{:#?}", state.bindings);
    assert_eq!(state.refused.len(), 2);
    for (_, reason) in &state.refused {
        assert_eq!(*reason, HostUdpRefusal::AmbiguousInterface);
    }
}

#[test]
fn planner_refuses_a_hostile_interface_name() {
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    let mut resolved = HashMap::new();
    // A prefix wildcard would silently widen capture to every `veth*` device.
    resolved.insert(a.pod_uid.clone(), iface("veth+", 11));

    let state = plan_host_udp_bindings(std::slice::from_ref(&a), &resolved);
    assert!(state.bindings.is_empty());
    assert_eq!(state.refused[0].1, HostUdpRefusal::InvalidInterface);

    // Interface index 0 is the kernel's "unspecified" value and cannot key
    // attribution.
    let mut resolved = HashMap::new();
    resolved.insert(a.pod_uid.clone(), iface("vetha", 0));
    let state = plan_host_udp_bindings(&[a], &resolved);
    assert_eq!(state.refused[0].1, HostUdpRefusal::InvalidInterface);
}

#[test]
fn planner_orders_rules_deterministically_and_detects_attribution_changes() {
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    let b = target(POD_B_UID, "b", Some("10.244.1.6"));
    let mut resolved = HashMap::new();
    resolved.insert(a.pod_uid.clone(), iface("vethz", 12));
    resolved.insert(b.pod_uid.clone(), iface("vetha", 11));

    let state = plan_host_udp_bindings(&[a.clone(), b.clone()], &resolved);
    assert_eq!(
        state.ifaces(),
        vec!["vetha".to_string(), "vethz".to_string()],
        "rule order must not depend on registry enumeration order, or every poll would \
         rewrite the chain"
    );

    // Re-planning the same inputs is neither a rule change nor an attribution
    // change, so reconciliation is a no-op.
    let same = plan_host_udp_bindings(&[b.clone(), a.clone()], &resolved);
    assert!(!same.rules_differ_from(&state));
    assert!(!same.requires_listener_restart_from(&state));

    // A pod recycled onto the same interface IS an attribution change: sessions
    // admitted under the old evidence must not keep relaying.
    let mut recycled = HashMap::new();
    recycled.insert(a.pod_uid.clone(), iface("vethz", 12));
    recycled.insert(b.pod_uid.clone(), iface("vetha", 11));
    let mut renamed_b = b.clone();
    renamed_b.source_ips.ipv4 = Some("10.244.1.99".parse().unwrap());
    let changed = plan_host_udp_bindings(&[a.clone(), renamed_b], &recycled);
    assert!(!changed.rules_differ_from(&state), "same interface set");
    assert!(
        changed.requires_listener_restart_from(&state),
        "a changed source-address set behind the same interface must restart the listener"
    );

    // Withdrawing a binding must restart the listener too: per-datagram
    // authorization stops new traffic, but a session admitted earlier still
    // holds the removed pod's identity and its transparent reply socket, so a
    // one-way return stream could keep reaching a removed (or recycled) address.
    let removed = plan_host_udp_bindings(std::slice::from_ref(&a), &resolved);
    assert!(
        removed.requires_listener_restart_from(&state),
        "removing a captured pod must cancel the sessions admitted under its evidence"
    );
    let refused = plan_host_udp_bindings(&[a.clone(), b.clone()], &HashMap::new());
    assert!(
        refused.requires_listener_restart_from(&state),
        "a pod that became refused is a withdrawal, not an unchanged binding"
    );

    // A pure addition is not: the pods that stayed keep exactly the evidence
    // they were admitted under, so their live sessions must not be disturbed.
    let c = target(POD_C_UID, "c", Some("10.244.1.7"));
    let mut grown = resolved.clone();
    grown.insert(c.pod_uid.clone(), iface("vethm", 13));
    let added = plan_host_udp_bindings(&[a, b, c], &grown);
    assert!(added.rules_differ_from(&state), "the ruleset does change");
    assert!(
        !added.requires_listener_restart_from(&state),
        "adding a pod must not tear down every other pod's live sessions"
    );
}

// ── Reconciliation ─────────────────────────────────────────────────────────

#[derive(Default)]
struct FakeSource {
    targets: Mutex<Vec<PodCaptureTarget>>,
}

impl FakeSource {
    fn set(&self, targets: Vec<PodCaptureTarget>) {
        *self.targets.lock().unwrap() = targets;
    }
}

impl PodCaptureSource for FakeSource {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        self.targets.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct FakeBackendState {
    calls: Vec<String>,
    interfaces: HashMap<String, ResolvedInterface>,
    fail_install_guard: bool,
    fail_install_capture: bool,
    fail_release_guard: bool,
    fail_teardown_all: bool,
    /// The next `start_listener` hands back a capture loop that returns on its
    /// own, standing in for a socket error or a panicked task.
    listener_exits: bool,
    listeners: usize,
    listener_stops: usize,
    /// Thread each blocking datapath effect (guard / capture / teardown /
    /// release script) ran on.
    effect_threads: Vec<std::thread::ThreadId>,
}

#[derive(Clone, Default)]
struct FakeBackend {
    inner: Arc<Mutex<FakeBackendState>>,
}

impl FakeBackend {
    fn record(&self, call: &str) {
        self.inner.lock().unwrap().calls.push(call.to_string());
    }

    fn record_effect(&self, call: &str) {
        let mut state = self.inner.lock().unwrap();
        state.calls.push(call.to_string());
        state.effect_threads.push(std::thread::current().id());
    }

    fn effect_threads(&self) -> Vec<std::thread::ThreadId> {
        self.inner.lock().unwrap().effect_threads.clone()
    }

    fn calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().calls.clone()
    }

    fn reset_calls(&self) {
        self.inner.lock().unwrap().calls.clear();
    }

    fn set_interface(&self, pod_uid: &str, name: &str, ifindex: u32) {
        self.inner
            .lock()
            .unwrap()
            .interfaces
            .insert(pod_uid.to_string(), iface(name, ifindex));
    }

    fn listeners(&self) -> usize {
        self.inner.lock().unwrap().listeners
    }

    fn listener_stops(&self) -> usize {
        self.inner.lock().unwrap().listener_stops
    }

    fn set_listener_exits(&self, exits: bool) {
        self.inner.lock().unwrap().listener_exits = exits;
    }

    fn set_fail_install_guard(&self, fail: bool) {
        self.inner.lock().unwrap().fail_install_guard = fail;
    }

    fn set_fail_teardown_all(&self, fail: bool) {
        self.inner.lock().unwrap().fail_teardown_all = fail;
    }
}

impl HostUdpCaptureBackend for FakeBackend {
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        self.inner
            .lock()
            .unwrap()
            .interfaces
            .get(&target.pod_uid)
            .cloned()
            .ok_or_else(|| "unresolved".to_string())
    }

    fn install_guard(&self, ifaces: &[String]) -> Result<(), String> {
        self.record_effect(&format!("guard:{}", ifaces.join(",")));
        if self.inner.lock().unwrap().fail_install_guard {
            return Err("iptables guard failed".to_string());
        }
        Ok(())
    }

    fn install_capture(&self, ifaces: &[String]) -> Result<(), String> {
        self.record_effect(&format!("capture:{}", ifaces.join(",")));
        if self.inner.lock().unwrap().fail_install_capture {
            return Err("iptables failed".to_string());
        }
        Ok(())
    }

    fn teardown_capture_rules(&self) -> Result<(), String> {
        self.record_effect("teardown_capture");
        Ok(())
    }

    fn release_guard(&self) -> Result<(), String> {
        self.record_effect("release_guard");
        if self.inner.lock().unwrap().fail_release_guard {
            return Err("xtables lock timeout".to_string());
        }
        Ok(())
    }

    fn teardown_all(&self) -> Result<(), String> {
        self.record_effect("teardown_all");
        if self.inner.lock().unwrap().fail_teardown_all {
            return Err("xtables lock timeout".to_string());
        }
        Ok(())
    }

    fn start_listener(
        &self,
        _index: Arc<HostUdpIdentityIndex>,
    ) -> Result<HostUdpListenerHandle, String> {
        self.record("start_listener");
        let exits = {
            let mut state = self.inner.lock().unwrap();
            state.listeners += 1;
            state.listener_exits
        };
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let inner = Arc::clone(&self.inner);
        // A real capture loop runs until it is stopped, so the fake spawns a
        // task that does the same — otherwise the manager could never tell a
        // live loop from one that died.
        let task = tokio::spawn(async move {
            if exits {
                return;
            }
            let _ = rx.changed().await;
            inner.lock().unwrap().listener_stops += 1;
        });
        Ok(HostUdpListenerHandle::new(tx, task))
    }
}

/// Let a spawned capture-loop task reach its exit so the manager's supervision
/// can observe it. The fake's loop finishes on its first poll, so one scheduler
/// turn is enough; the bounded loop keeps the test from depending on that.
async fn settle_listener_tasks() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

fn manager(
    source: Arc<FakeSource>,
    backend: FakeBackend,
    ready_dir: Option<std::path::PathBuf>,
) -> HostUdpCaptureManager<FakeBackend> {
    HostUdpCaptureManager::new(source, backend, Duration::from_millis(10)).with_ready_dir(ready_dir)
}

#[tokio::test]
async fn reconcile_installs_the_guard_before_capture_and_releases_it_after() {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source, backend.clone(), None);

    let state = manager.reconcile_once().await;
    assert_eq!(state.bindings.len(), 1);

    assert_eq!(
        backend.calls(),
        vec![
            "guard:vetha".to_string(),
            "capture:vetha".to_string(),
            "start_listener".to_string(),
            "release_guard".to_string(),
        ],
        "enrolled UDP egress must be dropped, never plaintext, for the whole rebuild"
    );
    assert_eq!(backend.listeners(), 1);
}

/// Every iptables / routing effect blocks on a child process (seconds under
/// xtables-lock contention), so none may run on the runtime thread that drives
/// the manager (issue #7170). The current-thread test runtime makes that
/// thread observable: it is the test's own thread.
#[tokio::test]
async fn blocking_datapath_effects_never_run_on_the_runtime_thread() {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(Arc::clone(&source), backend.clone(), None);

    manager.reconcile_once().await;
    source.set(Vec::new());
    manager.reconcile_once().await;
    manager.shutdown().await;

    let runtime_thread = std::thread::current().id();
    let threads = backend.effect_threads();
    assert!(
        threads.len() >= 4,
        "the reconcile and shutdown passes must have run datapath effects: {:?}",
        backend.calls()
    );
    assert!(
        threads.iter().all(|thread| *thread != runtime_thread),
        "a blocking datapath effect ran on the runtime thread: {:?}",
        backend.calls()
    );
}

#[tokio::test]
async fn reconcile_is_a_no_op_when_nothing_changed() {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source, backend.clone(), None);

    manager.reconcile_once().await;
    backend.reset_calls();
    manager.reconcile_once().await;
    assert!(
        backend.calls().is_empty(),
        "an unchanged poll must not churn the datapath: {:?}",
        backend.calls()
    );
}

#[tokio::test]
async fn capture_install_failure_retains_the_guard_and_removes_partial_state() {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    backend.inner.lock().unwrap().fail_install_capture = true;
    let mut manager = manager(source, backend.clone(), None);

    manager.reconcile_once().await;
    assert_eq!(
        backend.calls(),
        vec![
            "guard:vetha".to_string(),
            "capture:vetha".to_string(),
            "teardown_capture".to_string(),
        ],
        "the DROP guard must survive a failed install; the guard is never released"
    );
    assert_eq!(backend.listeners(), 0, "no socket behind a failed ruleset");
}

#[tokio::test]
async fn guard_release_failure_removes_capture_rather_than_capturing_behind_a_drop() {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    backend.inner.lock().unwrap().fail_release_guard = true;
    let mut manager = manager(source, backend.clone(), None);

    manager.reconcile_once().await;
    let calls = backend.calls();
    assert!(calls.contains(&"release_guard".to_string()), "{calls:?}");
    assert_eq!(
        calls.last().map(String::as_str),
        Some("teardown_capture"),
        "dropping is a correct posture; capturing behind a live DROP is not: {calls:?}"
    );
    assert_eq!(
        backend.listener_stops(),
        1,
        "a failed generation must not leave its now-untracked sessions alive"
    );

    // The retained guard makes the next poll re-apply rather than short-circuit.
    backend.reset_calls();
    backend.inner.lock().unwrap().fail_release_guard = false;
    manager.reconcile_once().await;
    assert!(
        backend.calls().contains(&"release_guard".to_string()),
        "a retained guard must be retried, not left dropping forever: {:?}",
        backend.calls()
    );
    assert_eq!(
        backend.listeners(),
        2,
        "the retry must create a fresh listener"
    );
}

#[tokio::test]
async fn capture_rebuild_failure_stops_the_previously_applied_listener_generation() {
    let source = Arc::new(FakeSource::default());
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    let b = target(POD_B_UID, "b", Some("10.244.1.6"));
    source.set(vec![a.clone()]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    backend.set_interface(POD_B_UID, "vethb", 12);
    let mut manager = manager(source.clone(), backend.clone(), None);
    manager.reconcile_once().await;
    assert_eq!(backend.listeners(), 1);

    // A pure addition would normally preserve the listener. Once the rebuild
    // fails and clears `applied`, however, retaining it would also erase the
    // generation needed to detect a later withdrawal and restart stale sessions.
    source.set(vec![a, b]);
    backend.inner.lock().unwrap().fail_install_capture = true;
    backend.reset_calls();
    manager.reconcile_once().await;

    assert_eq!(
        backend.listener_stops(),
        1,
        "the listener must stop whenever its applied generation is discarded"
    );
    assert_eq!(
        backend.calls(),
        vec![
            "guard:vetha,vethb".to_string(),
            "capture:vetha,vethb".to_string(),
            "teardown_capture".to_string(),
        ],
        "the failed rebuild remains guarded and never releases plaintext egress"
    );
}

#[tokio::test]
async fn pod_enrollment_and_removal_rebuild_the_ruleset() {
    let source = Arc::new(FakeSource::default());
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    let b = target(POD_B_UID, "b", Some("10.244.1.6"));
    source.set(vec![a.clone()]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    backend.set_interface(POD_B_UID, "vethb", 12);
    let mut manager = manager(source.clone(), backend.clone(), None);

    manager.reconcile_once().await;
    backend.reset_calls();

    source.set(vec![a.clone(), b.clone()]);
    let state = manager.reconcile_once().await;
    assert_eq!(
        state.ifaces(),
        vec!["vetha".to_string(), "vethb".to_string()]
    );
    assert!(
        backend.calls().contains(&"capture:vetha,vethb".to_string()),
        "{:?}",
        backend.calls()
    );
    assert_eq!(
        backend.listeners(),
        1,
        "adding a pod must not restart the shared listener and drop live sessions"
    );

    backend.reset_calls();
    source.set(vec![b]);
    let state = manager.reconcile_once().await;
    assert_eq!(state.ifaces(), vec!["vethb".to_string()]);
    let calls = backend.calls();
    assert!(
        calls.contains(&"capture:vethb".to_string()),
        "the removed pod's rule must disappear from the rebuilt chain: {calls:?}"
    );
    assert_eq!(
        calls.first().map(String::as_str),
        Some("guard:vetha,vethb"),
        "the removed pod's interface must stay inside the DROP guard while its rule is \
         rebuilt away: {calls:?}"
    );
    assert_eq!(
        backend.listeners(),
        2,
        "removing a pod must restart the shared listener; a session admitted under its \
         evidence still holds its identity and its transparent reply socket"
    );
}

#[tokio::test]
async fn readiness_marker_is_published_only_after_capture_is_live_and_retracted_on_removal() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    let source = Arc::new(FakeSource::default());
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    source.set(vec![a.clone()]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source.clone(), backend.clone(), Some(ready_dir.clone()))
        .with_gate_close_timeout(Duration::from_millis(50));

    manager.reconcile_once().await;
    assert!(
        ready_dir.join(POD_A_UID).is_file(),
        "the node-agent's UDP gate opens only on this marker"
    );

    source.set(Vec::new());
    manager.reconcile_once().await;
    assert!(
        !ready_dir.join(POD_A_UID).is_file(),
        "readiness must be retracted when a pod stops being captured"
    );
    assert!(
        registry
            .path()
            .join(".udp-ack-required")
            .join(POD_A_UID)
            .is_file(),
        "retraction alone does not close the node-agent's BPF gate, so the durable handshake \
         must be requested for the pod that left"
    );

    // The acknowledgement arrives, so the pod may finally be retired.
    std::fs::create_dir_all(&ack_dir).expect("ack dir");
    std::fs::write(ack_dir.join(POD_A_UID), b"").expect("ack marker");
    backend.reset_calls();
    manager.reconcile_once().await;
    assert!(
        !registry
            .path()
            .join(".udp-ack-required")
            .join(POD_A_UID)
            .is_file(),
        "an acknowledged gate close clears its own durable requirement"
    );
    let calls = backend.calls();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("guard:vetha"),
        "the departing pod stays guarded across the transition that removes its rules: \
         {calls:?}"
    );
    assert!(
        calls.contains(&"teardown_capture".to_string())
            && calls.last().map(String::as_str) == Some("release_guard"),
        "with nothing left to capture the chain contents go and the guard is released: \
         {calls:?}"
    );
}

#[tokio::test]
async fn a_failed_readiness_marker_write_is_retried_without_rebuilding_capture() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    // A plain file where the marker directory belongs makes the first
    // publication fail after the datapath becomes live.
    std::fs::write(&ready_dir, b"").expect("blocking file");
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source, backend.clone(), Some(ready_dir.clone()));

    manager.reconcile_once().await;
    assert!(!ready_dir.join(POD_A_UID).is_file());
    std::fs::remove_file(&ready_dir).expect("remove blocker");
    backend.reset_calls();

    manager.reconcile_once().await;
    assert!(
        ready_dir.join(POD_A_UID).is_file(),
        "an otherwise-idle reconcile must retry the missing readiness marker"
    );
    assert!(
        backend.calls().is_empty(),
        "retrying a filesystem publication must not churn healthy rules or the listener: {:?}",
        backend.calls()
    );
}

#[tokio::test]
async fn a_recreated_veth_moves_the_readiness_withdrawal_scope() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source.clone(), backend.clone(), Some(ready_dir));

    manager.reconcile_once().await;
    backend.set_interface(POD_A_UID, "vethz", 12);
    manager.reconcile_once().await;
    backend.reset_calls();

    source.set(Vec::new());
    manager.reconcile_once().await;
    assert_eq!(
        backend.calls(),
        vec!["guard:vethz".to_string()],
        "a later withdrawal must guard the current veth generation, not the interface on which \
         this pod first published readiness"
    );
}

#[tokio::test]
async fn a_removed_pods_capture_rule_survives_until_its_gate_close_is_acknowledged() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    let source = Arc::new(FakeSource::default());
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    let b = target(POD_B_UID, "b", Some("10.244.1.6"));
    source.set(vec![a.clone(), b.clone()]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    backend.set_interface(POD_B_UID, "vethb", 12);
    let mut manager = manager(source.clone(), backend.clone(), Some(ready_dir.clone()))
        .with_gate_close_timeout(Duration::from_millis(50));

    manager.reconcile_once().await;
    assert!(ready_dir.join(POD_A_UID).is_file());
    backend.reset_calls();

    // Pod A leaves and the node-agent never acknowledges closing its gate. Its
    // rule must NOT be rebuilt away: the old rule plus an open BPF gate is
    // capture, while no rule plus an open BPF gate is plaintext egress.
    source.set(vec![b.clone()]);
    let state = manager.reconcile_once().await;
    assert_eq!(state.ifaces(), vec!["vethb".to_string()]);
    let calls = backend.calls();
    assert_eq!(
        calls,
        vec!["guard:vetha,vethb".to_string()],
        "an unacknowledged gate close installs the union guard and touches nothing else: \
         {calls:?}"
    );

    // Retrying keeps the same posture and must not re-issue the request, which
    // would delete an acknowledgement that has since landed.
    backend.reset_calls();
    manager.reconcile_once().await;
    assert_eq!(
        backend.calls(),
        vec!["guard:vetha,vethb".to_string()],
        "a retry stays fail-closed rather than removing the departing pod's rule"
    );

    std::fs::create_dir_all(&ack_dir).expect("ack dir");
    std::fs::write(ack_dir.join(POD_A_UID), b"").expect("ack marker");
    backend.reset_calls();
    manager.reconcile_once().await;
    let calls = backend.calls();
    assert!(
        calls.contains(&"capture:vethb".to_string()),
        "once the gate close is acknowledged the chain is rebuilt without the departed pod: \
         {calls:?}"
    );
    assert_eq!(
        calls.last().map(String::as_str),
        Some("release_guard"),
        "and only then does the guard come down: {calls:?}"
    );
}

#[tokio::test]
async fn a_pod_returning_before_its_gate_close_is_acknowledged_is_republished() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let source = Arc::new(FakeSource::default());
    let a = target(POD_A_UID, "a", Some("10.244.1.5"));
    source.set(vec![a.clone()]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source.clone(), backend.clone(), Some(ready_dir.clone()))
        .with_gate_close_timeout(Duration::from_millis(50));

    manager.reconcile_once().await;
    source.set(Vec::new());
    manager.reconcile_once().await;
    assert!(!ready_dir.join(POD_A_UID).is_file());

    // A registry flap must not wedge the node waiting for an acknowledgement the
    // node-agent has no reason to send.
    source.set(vec![a]);
    manager.reconcile_once().await;
    assert!(
        ready_dir.join(POD_A_UID).is_file(),
        "a pod that re-entered capture is readied again by the ordinary apply path"
    );
    assert!(
        !registry
            .path()
            .join(".udp-ack-required")
            .join(POD_A_UID)
            .is_file(),
        "and its abandoned handshake requirement is cancelled, not left to block later polls"
    );
}

#[tokio::test]
async fn an_unexpectedly_exited_capture_loop_is_guarded_and_restarted() {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    backend.set_listener_exits(true);
    let mut manager = manager(source, backend.clone(), None);

    manager.reconcile_once().await;
    assert_eq!(backend.listeners(), 1);
    settle_listener_tasks().await;

    // Nothing about the registry changed, so without supervision this poll would
    // short-circuit and the node would keep steering enrolled egress into a
    // socket nobody reads.
    backend.set_listener_exits(false);
    backend.reset_calls();
    manager.reconcile_once().await;
    assert_eq!(
        backend.calls(),
        vec![
            "guard:vetha".to_string(),
            "capture:vetha".to_string(),
            "start_listener".to_string(),
            "release_guard".to_string(),
        ],
        "a dead capture loop is restarted through the normal guarded apply path"
    );
    assert_eq!(backend.listeners(), 2);

    // The restarted loop is live, so the next poll is a no-op again.
    settle_listener_tasks().await;
    backend.reset_calls();
    manager.reconcile_once().await;
    assert!(
        backend.calls().is_empty(),
        "a running capture loop must not be mistaken for a dead one: {:?}",
        backend.calls()
    );
}

#[tokio::test]
async fn an_operator_requested_shutdown_is_never_turned_into_a_restart() {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let manager = manager(source, backend.clone(), None);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move { manager.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    let _ = shutdown_tx.send(true);
    handle.await.expect("manager exits");

    assert_eq!(
        backend.listeners(),
        1,
        "stopping the listener on shutdown must not look like an unexpected exit: {:?}",
        backend.calls()
    );
    assert!(
        backend.calls().contains(&"teardown_all".to_string()),
        "shutdown removes host state instead of restarting capture: {:?}",
        backend.calls()
    );
}

#[tokio::test]
async fn a_refused_pod_never_becomes_ready() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let source = Arc::new(FakeSource::default());
    let mut unattested = target(POD_A_UID, "a", Some("10.244.1.5"));
    unattested.source_identity = None;
    source.set(vec![unattested]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source, backend.clone(), Some(ready_dir.clone()));

    let state = manager.reconcile_once().await;
    assert_eq!(state.refused.len(), 1);
    assert!(
        !ready_dir.join(POD_A_UID).is_file(),
        "withholding readiness is what keeps a refused pod's UDP egress closed instead of \
         letting it bypass the mesh in plaintext"
    );
    assert_eq!(backend.listeners(), 0);
}

#[tokio::test]
async fn shutdown_without_a_gate_close_acknowledgement_stays_fail_closed() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source, backend.clone(), Some(ready_dir.clone()))
        .with_gate_close_timeout(Duration::from_millis(50));
    manager.reconcile_once().await;
    backend.reset_calls();

    // No `.udp-not-ready` marker is ever written, so the node-agent never
    // confirms its BPF gate closed.
    manager.shutdown().await;

    let calls = backend.calls();
    assert!(
        calls.contains(&"guard:vetha".to_string()),
        "an unacknowledged shutdown must leave the DROP guard installed: {calls:?}"
    );
    assert!(
        calls.contains(&"teardown_capture".to_string())
            && !calls.contains(&"teardown_all".to_string()),
        "the capture rules go, the guard stays: {calls:?}"
    );
    assert!(
        !ready_dir.join(POD_A_UID).is_file(),
        "readiness must be retracted before capture stops"
    );
}

#[tokio::test]
async fn shutdown_guard_failure_retains_capture_rules() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source, backend.clone(), Some(ready_dir))
        .with_gate_close_timeout(Duration::from_millis(50));
    manager.reconcile_once().await;
    backend.reset_calls();
    backend.set_fail_install_guard(true);

    // Without an acknowledgement, failure to install the shutdown DROP guard
    // must retain the existing TPROXY/routing path. Removing it here would let
    // a still-open node-agent gate release the pod's UDP egress as plaintext.
    manager.shutdown().await;

    let calls = backend.calls();
    assert!(calls.contains(&"guard:vetha".to_string()), "{calls:?}");
    assert!(
        !calls.contains(&"teardown_capture".to_string())
            && !calls.contains(&"teardown_all".to_string()),
        "capture and routing objects must remain fail-closed when the replacement guard fails: \
         {calls:?}"
    );
    assert_eq!(
        backend.listener_stops(),
        1,
        "the shared listener still stops during process shutdown"
    );
}

#[tokio::test]
async fn shutdown_tears_everything_down_once_the_gate_close_is_acknowledged() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    let backend = FakeBackend::default();
    backend.set_interface(POD_A_UID, "vetha", 11);
    let mut manager = manager(source, backend.clone(), Some(ready_dir))
        .with_gate_close_timeout(Duration::from_secs(5));
    manager.reconcile_once().await;
    backend.reset_calls();

    // A PRE-EXISTING acknowledgement is deliberately not enough: requesting the
    // close deletes any stale `.udp-not-ready` marker so it can never authorize a
    // new handoff. Only the node-agent republishing it after readiness was
    // retracted proves this generation's gates are shut.
    let stale_ack_dir = ack_dir.clone();
    std::fs::create_dir_all(&stale_ack_dir).expect("ack dir");
    std::fs::write(stale_ack_dir.join(POD_A_UID), b"").expect("stale ack marker");
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        std::fs::create_dir_all(&ack_dir).expect("ack dir");
        std::fs::write(ack_dir.join(POD_A_UID), b"").expect("ack marker");
    });

    manager.shutdown().await;
    assert!(
        backend.calls().contains(&"teardown_all".to_string()),
        "an acknowledged shutdown removes every Ferrum-owned host object: {:?}",
        backend.calls()
    );
    assert!(
        !registry
            .path()
            .join(".udp-ack-required")
            .join(POD_A_UID)
            .is_file(),
        "and clears the durable requirement it raised"
    );
}

#[tokio::test]
async fn startup_reaps_stale_host_state_before_the_first_apply() {
    let source = Arc::new(FakeSource::default());
    let backend = FakeBackend::default();
    let manager = manager(source, backend.clone(), None);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move { manager.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(true);
    handle.await.expect("manager exits");

    assert_eq!(
        backend.calls().first().map(String::as_str),
        Some("teardown_all"),
        "a crash-restart must reap the previous generation's rules before installing its \
         own, or a chain no socket serves keeps black-holing egress: {:?}",
        backend.calls()
    );
}

// ── Stale-generation recovery ───────────────────────────────────────────────
//
// Readiness is durable and shared with the node-agent, so a generation that dies
// leaves BOTH its host rules and an open BPF UDP gate for every pod it readied.
// Reaping the rules while those gates are open is the plaintext window; these
// pin that the reap is sequenced behind the close handshake instead.

/// One unsettled pass sleeps a poll interval, so keep the budget small.
const RECOVERY_WAIT: Duration = Duration::from_millis(20);

/// Publish one durable handshake marker, creating its directory the way the
/// producer and the node-agent both do.
fn write_marker(dir: &std::path::Path, pod_uid: &str) {
    std::fs::create_dir_all(dir).expect("marker dir");
    std::fs::write(dir.join(pod_uid), b"").expect("marker");
}

fn recovery_manager(
    backend: FakeBackend,
    ready_dir: &std::path::Path,
) -> HostUdpCaptureManager<FakeBackend> {
    let source = Arc::new(FakeSource::default());
    source.set(vec![target(POD_A_UID, "a", Some("10.244.1.5"))]);
    backend.set_interface(POD_A_UID, "vetha", 11);
    manager(source, backend, Some(ready_dir.to_path_buf())).with_gate_close_timeout(RECOVERY_WAIT)
}

#[tokio::test]
async fn startup_recovery_retracts_stale_readiness_before_reaping_host_state() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_required = registry.path().join(".udp-ack-required");
    let ack_dir = registry.path().join(".udp-not-ready");
    // A previous generation readied pod A and died. Its rules are still installed
    // and the node-agent's UDP gate for A is still open.
    write_marker(&ready_dir, POD_A_UID);
    let backend = FakeBackend::default();
    let mut manager = recovery_manager(backend.clone(), &ready_dir);

    assert!(
        !manager.recover_stale_generation_once().await,
        "the previous generation's rules may not be removed until the node-agent confirms it \
         closed the gate that readiness opened"
    );
    assert!(
        !ready_dir.join(POD_A_UID).is_file(),
        "readiness must be retracted so the node-agent starts closing the gate"
    );
    assert!(
        ack_required.join(POD_A_UID).is_file(),
        "and the durable requirement must be persisted, so a further crash still recovers"
    );
    assert!(
        backend.calls().is_empty(),
        "nothing may touch host state while a gate is possibly still open — a capture path with \
         no socket drops, removing it would release plaintext: {:?}",
        backend.calls()
    );

    write_marker(&ack_dir, POD_A_UID);
    assert!(manager.recover_stale_generation_once().await);
    assert_eq!(
        backend.calls(),
        vec!["teardown_all".to_string()],
        "only an acknowledged handoff reaps the predecessor's state"
    );
    assert!(
        !ack_required.join(POD_A_UID).is_file(),
        "an acknowledged recovery clears the requirement it raised"
    );
}

#[tokio::test]
async fn startup_recovery_adopts_a_close_request_a_previous_generation_left_unfinished() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    // Readiness was already retracted; the process died awaiting the ack. The
    // requirement alone is still evidence that a gate may be open.
    write_marker(&registry.path().join(".udp-ack-required"), POD_A_UID);
    let backend = FakeBackend::default();
    let mut manager = recovery_manager(backend.clone(), &ready_dir);

    assert!(!manager.recover_stale_generation_once().await);
    assert!(backend.calls().is_empty(), "{:?}", backend.calls());

    write_marker(&ack_dir, POD_A_UID);
    assert!(manager.recover_stale_generation_once().await);
    assert_eq!(backend.calls(), vec!["teardown_all".to_string()]);
}

#[tokio::test]
async fn a_stale_acknowledgement_cannot_authorize_the_startup_handoff() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    write_marker(&ready_dir, POD_A_UID);
    // Left over from an OLDER close; it says nothing about the gate the readiness
    // above opened.
    write_marker(&ack_dir, POD_A_UID);
    let backend = FakeBackend::default();
    let mut manager = recovery_manager(backend.clone(), &ready_dir);

    assert!(
        !manager.recover_stale_generation_once().await,
        "a pre-existing acknowledgement must not settle this handoff"
    );
    assert!(
        !ack_dir.join(POD_A_UID).is_file(),
        "the request ordering deletes it, so only a freshly published one can settle the recovery"
    );
    assert!(backend.calls().is_empty(), "{:?}", backend.calls());
}

#[tokio::test]
async fn a_handshake_that_cannot_be_persisted_never_reaps_the_previous_generation() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    write_marker(&ready_dir, POD_A_UID);
    // A plain file where the durable request directory belongs, so persisting the
    // requirement fails.
    std::fs::write(registry.path().join(".udp-ack-required"), b"").expect("blocking file");
    let backend = FakeBackend::default();
    let mut manager = recovery_manager(backend.clone(), &ready_dir);

    assert!(!manager.recover_stale_generation_once().await);
    assert!(
        ready_dir.join(POD_A_UID).is_file(),
        "readiness is retracted only AFTER the durable requirement is persisted; retracting first \
         would lose the restart insurance"
    );
    assert!(
        backend.calls().is_empty(),
        "and an unpersisted handshake never authorizes a reap: {:?}",
        backend.calls()
    );
}

#[tokio::test]
async fn an_incomplete_retraction_cannot_release_startup_to_the_incoming_producer() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    write_marker(&ready_dir, POD_A_UID);
    // Block persistence exactly as a permissions/I/O failure would. Recovery
    // must retain both the marker and the startup boundary.
    let blocker = registry.path().join(".udp-ack-required");
    std::fs::write(&blocker, b"").expect("blocking file");
    let mut recovery = HostUdpStaleGenerationRecovery::new(Some(ready_dir.clone()));

    assert!(!recovery.poll_once(RECOVERY_WAIT).await);
    assert!(ready_dir.join(POD_A_UID).is_file());
    assert!(
        !recovery.retraction_complete(),
        "the incoming producer must not start while recovery can still retract its readiness"
    );

    std::fs::remove_file(&blocker).expect("remove blocker");
    assert!(!recovery.poll_once(RECOVERY_WAIT).await);
    assert!(
        recovery.retraction_complete(),
        "once discovery is complete and every close request is durably persisted, the incoming \
         producer may start while acknowledgement continues in the background"
    );
    assert!(!ready_dir.join(POD_A_UID).is_file());
}

#[tokio::test]
async fn an_unreadable_marker_directory_keeps_the_retraction_boundary_closed() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    // A plain file makes read_dir fail. Treating that as an empty directory
    // would authorize teardown without knowing whether a gate is still open.
    std::fs::write(&ready_dir, b"").expect("blocking file");
    let mut recovery = HostUdpStaleGenerationRecovery::new(Some(ready_dir.clone()));

    assert!(!recovery.poll_once(RECOVERY_WAIT).await);
    assert!(!recovery.retraction_complete());

    std::fs::remove_file(&ready_dir).expect("remove blocker");
    assert!(recovery.poll_once(RECOVERY_WAIT).await);
    assert!(recovery.retraction_complete());
}

#[tokio::test]
async fn a_failed_stale_state_reap_is_retried_rather_than_logged_once() {
    // No durable obligation: this is about the reap itself. A failure that was
    // only logged would leave a socketless capture path black-holing the node
    // with nothing left to clean it up.
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let backend = FakeBackend::default();
    backend.set_fail_teardown_all(true);
    let mut manager = recovery_manager(backend.clone(), &ready_dir);

    assert!(!manager.recover_stale_generation_once().await);
    assert_eq!(backend.calls(), vec!["teardown_all".to_string()]);

    backend.set_fail_teardown_all(false);
    backend.reset_calls();
    assert!(manager.recover_stale_generation_once().await);
    assert_eq!(
        backend.calls(),
        vec!["teardown_all".to_string()],
        "the reap is retried on the next pass"
    );
}

#[tokio::test]
async fn a_node_agent_that_never_acknowledges_leaves_the_previous_generation_installed() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    write_marker(&ready_dir, POD_A_UID);
    let backend = FakeBackend::default();
    let manager = recovery_manager(backend.clone(), &ready_dir);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move { manager.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let _ = shutdown_tx.send(true);
    handle.await.expect("manager exits");

    assert!(
        backend.calls().is_empty(),
        "an unrecovered startup applies nothing and reaps nothing — including on the way out, \
         where the ordinary teardown would see an empty published set and conclude nothing was \
         ready: {:?}",
        backend.calls()
    );
    assert_eq!(backend.listeners(), 0);
    assert!(
        !ready_dir.join(POD_A_UID).is_file(),
        "readiness stays retracted, so the node-agent keeps closing rather than reopening the gate"
    );
}

#[tokio::test]
async fn a_closed_shutdown_channel_stops_the_host_manager() {
    let source = Arc::new(FakeSource::default());
    let backend = FakeBackend::default();
    let manager = manager(source, backend.clone(), None);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    drop(shutdown_tx);

    tokio::time::timeout(Duration::from_secs(1), manager.run(shutdown_rx))
        .await
        .expect("a closed watch channel must stop the manager instead of busy-spinning");
    assert!(
        backend.calls().is_empty(),
        "shutdown before startup recovery owns no predecessor teardown: {:?}",
        backend.calls()
    );
}

#[tokio::test]
async fn unreadable_stale_markers_defer_udp_recovery_without_blocking_mesh_startup() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    std::fs::write(&ready_dir, b"").expect("blocking file");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let recovery = tokio::time::timeout(
        Duration::from_secs(1),
        recover_and_reap_stale_host_udp_state(
            Some(ready_dir),
            Duration::from_secs(60),
            shutdown_rx,
        ),
    )
    .await
    .expect("one unreadable-directory pass must return control to mesh startup");
    assert!(
        recovery.retraction_ready.is_some(),
        "only the incoming UDP producer should wait for safe retraction"
    );
    let retry_task = recovery
        .retry_task
        .expect("recovery continues in the background");
    let _ = shutdown_tx.send(true);
    retry_task.await.expect("retry task exits on shutdown");
}

#[tokio::test]
async fn a_placement_switch_settles_when_the_incoming_producer_republishes_readiness() {
    // The disabled/switched half: no manager runs here, so the recovery is driven
    // on its own exactly as mesh startup drives it before starting the
    // per-pod-netns producer.
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_required = registry.path().join(".udp-ack-required");
    write_marker(&ready_dir, POD_A_UID);
    let mut recovery = HostUdpStaleGenerationRecovery::new(Some(ready_dir.clone()));

    assert!(!recovery.poll_once(RECOVERY_WAIT).await);
    assert_eq!(recovery.outstanding(), 1);
    assert!(!ready_dir.join(POD_A_UID).is_file());

    // The producer this node switched TO now captures pod A inside its own
    // namespace and publishes readiness again. That egress never reaches the host
    // namespace, so the stale host rules can go — and without this the two halves
    // of a placement switch would deadlock, each waiting on the other.
    write_marker(&ready_dir, POD_A_UID);
    assert!(recovery.poll_once(RECOVERY_WAIT).await);
    assert_eq!(recovery.outstanding(), 0);
    assert!(
        ready_dir.join(POD_A_UID).is_file(),
        "the incoming producer's own readiness must be left alone, not retracted again"
    );
    assert!(
        !ack_required.join(POD_A_UID).is_file(),
        "and the requirement this recovery raised is cleared"
    );
}

#[tokio::test]
async fn recovery_touches_only_ferrum_owned_marker_names() {
    let registry = tempfile::tempdir().expect("tempdir");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    write_marker(&ready_dir, POD_A_UID);
    std::fs::create_dir_all(ready_dir.join("a-directory-not-a-marker")).expect("subdir");
    let mut recovery = HostUdpStaleGenerationRecovery::new(Some(ready_dir.clone()));

    assert!(!recovery.poll_once(RECOVERY_WAIT).await);
    assert_eq!(
        recovery.outstanding(),
        1,
        "only the pod marker is adopted; a non-file entry is not a readiness marker"
    );
    assert!(
        ready_dir.join("a-directory-not-a-marker").is_dir(),
        "and nothing outside the marker convention is removed"
    );

    write_marker(&ack_dir, POD_A_UID);
    assert!(recovery.poll_once(RECOVERY_WAIT).await);
}

#[tokio::test]
async fn recovery_is_a_no_op_without_a_handshake_directory() {
    let backend = FakeBackend::default();
    let source = Arc::new(FakeSource::default());
    let mut manager = manager(source, backend.clone(), None);

    assert!(
        manager.recover_stale_generation_once().await,
        "nothing gated a pod on a readiness marker, so there is no durable obligation to discharge"
    );
    assert_eq!(backend.calls(), vec!["teardown_all".to_string()]);
}

#[test]
fn ipv6_only_pods_are_attributed_by_their_registered_v6_address() {
    let index = HostUdpIdentityIndex::new();
    index.publish(&[HostUdpPodBinding {
        pod_uid: POD_A_UID.to_string(),
        iface: "vetha".to_string(),
        ifindex: 11,
        ipv4: None,
        ipv6: Some("fd00::5".parse::<Ipv6Addr>().expect("valid ipv6")),
        identity: identity(POD_A_UID, "a"),
    }]);

    let v6: IpAddr = "fd00::5".parse().unwrap();
    assert!(index.authorize(Some(11), v6).is_ok());
    let v4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 244, 1, 5));
    assert_eq!(
        index.authorize(Some(11), v4),
        Err(HostUdpDatagramRefusal::SourceAddressMismatch),
        "a v6-only pod must not be credited for a v4 source it never registered"
    );
}
