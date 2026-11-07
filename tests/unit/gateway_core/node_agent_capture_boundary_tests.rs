//! Private node-agent entry points, compiled by the hosted library test lane.

use super::*;
use crate::ebpf::MockEbpfBackend;

fn config() -> NodeAgentConfig {
    let mut capture_config = CaptureConfig::explicit(15006, 15001);
    capture_config.mode = CaptureMode::Ebpf;
    NodeAgentConfig {
        node_name: "test-node".to_string(),
        capture_config,
        cgroup_root: "/unused-cgroup".to_string(),
        bpf_fs_path: "/unused-bpffs".to_string(),
        fallback_mode: FallbackMode::Iptables,
        excluded_namespaces: HashSet::new(),
        capture_contract: CaptureContract::local_pod_defaults(),
        trust_domain: "cluster.local".to_string(),
        node_waypoint_pod_registry_dir: None,
    }
}

#[test]
fn root_proxy_uid_is_rejected_before_loading_or_writing_bpf_state() {
    let mut config = config();
    config.capture_config.proxy_uid = Some(0);
    let mut backend = MockEbpfBackend::default();
    let metrics = NodeAgentMetrics::default();
    let error = initialize_backend(&mut backend, &config, &metrics).unwrap_err();
    assert!(error.to_string().contains("proxy UID must be non-zero"));
    assert!(!backend.programs_loaded);
    assert!(backend.bypass_uids.is_empty());
    assert!(backend.operations.is_empty());
    assert_eq!(
        metrics.snapshot().capture_state,
        NODE_AGENT_CAPTURE_STATE_UNAVAILABLE
    );
}

#[tokio::test]
async fn root_proxy_uid_is_rejected_before_any_iptables_fallback_command() {
    let mut config = config();
    config.capture_config.proxy_uid = Some(0);
    let probe = KernelProbeResult {
        kernel_release: "4.19.0".to_string(),
        meets_version_requirement: false,
        cgroup_v2_available: false,
        bpf_fs_available: false,
    };
    let metrics = NodeAgentMetrics::default();
    let (shutdown_tx, _shutdown_rx) =
        crate::overload::ShutdownSender::channel(std::time::Duration::ZERO);
    shutdown_tx.shutdown();
    let executed = AtomicBool::new(false);
    let ready = Arc::new(AtomicBool::new(false));
    let error = handle_fallback_with(
        &config,
        &probe,
        &metrics,
        &shutdown_tx,
        |_, _| {
            executed.store(true, Ordering::SeqCst);
            async { Ok(()) }
        },
        Arc::clone(&ready),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("proxy UID must be non-zero"));
    assert!(!executed.load(Ordering::SeqCst));
    assert!(!ready.load(Ordering::SeqCst));
}

#[cfg(unix)]
#[test]
fn seventeenth_port_installs_capture_all_for_pod_and_container_cgroups() {
    let cgroup_root = tempfile::tempdir().unwrap();
    std::fs::create_dir(cgroup_root.path().join("container")).unwrap();
    let ports = (1..=INCLUDE_PORTS_MAX as u16 + 1)
        .rev()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let annotations = HashMap::from([
        (
            "traffic.sidecar.istio.io/includeOutboundPorts".to_string(),
            ports,
        ),
        (
            "ferrum.io/includeOutboundPorts".to_string(),
            "17,1".to_string(),
        ),
    ]);
    let mut backend = MockEbpfBackend::default();
    let (applied, logs) = crate::modes::tests::capture_logs(|| {
        apply_include_outbound_ports(
            &mut backend,
            "test-pod",
            cgroup_root.path().to_str().unwrap(),
            &annotations,
        )
        .unwrap()
    });
    assert!(logs.contains("capturing all outbound ports subject to earlier exclusions"));
    assert!(!logs.contains("truncat"));
    assert_eq!(applied.policy, IncludePortsPolicy::all());
    assert_eq!(applied.cgroup_ids.len(), 2);
    assert_eq!(backend.include_ports.len(), 2);
    for cgroup_id in applied.cgroup_ids {
        assert_eq!(backend.include_ports[&cgroup_id], IncludePortsPolicy::all());
    }
}

/// NodeWaypoint config whose inbound tc ingress redirect is armed (IPv4-only
/// capture listener), rooted at a scratch cgroup tree.
fn redirect_config(cgroup_root: String) -> NodeAgentConfig {
    redirect_config_with_ipv6(cgroup_root, false)
}

fn redirect_config_with_ipv6(cgroup_root: String, supports_ipv6: bool) -> NodeAgentConfig {
    let mut config = config();
    config.cgroup_root = cgroup_root;
    config.capture_contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;
    config.capture_contract.ingress_redirect_ifaces = vec!["eth0".to_string()];
    config.capture_contract.node_waypoint_ingress_redirect_mark =
        NODE_WAYPOINT_INGRESS_REDIRECT_MARK;
    config.capture_contract.ingress_capture_port = 15006;
    config.capture_contract.ingress_capture_supports_ipv6 = supports_ipv6;
    assert!(config.capture_contract.ingress_redirect_enabled());
    config
}

fn redirect_scope_v4(
    backend: &MockEbpfBackend,
    ip: std::net::Ipv4Addr,
) -> std::collections::BTreeSet<u16> {
    backend
        .pod_inbound_ports
        .iter()
        .filter(|(entry_ip, _)| *entry_ip == ip)
        .map(|(_, port)| *port)
        .collect()
}

fn redirect_scope_v6(
    backend: &MockEbpfBackend,
    ip: std::net::Ipv6Addr,
) -> std::collections::BTreeSet<u16> {
    backend
        .pod_inbound_ports6
        .iter()
        .filter(|(entry_ip, _)| *entry_ip == ip)
        .map(|(_, port)| *port)
        .collect()
}

fn drive_redirect_pod(
    backend: &mut MockEbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    pod_ip: std::net::Ipv4Addr,
    inbound_redirect_ports: Vec<u16>,
) {
    drive_redirect_pod_with_ips(
        backend,
        pod_states,
        config,
        metrics,
        PodSourceIps {
            ipv4: Some(pod_ip),
            ipv6: None,
        },
        inbound_redirect_ports,
    );
}

fn drive_redirect_pod_with_ips(
    backend: &mut MockEbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    pod_source_ips: PodSourceIps,
    inbound_redirect_ports: Vec<u16>,
) {
    let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
    let annotations = HashMap::new();
    let pod_ip_str = pod_source_ips.ipv4.map(|ip| ip.to_string());
    let event = PodEvent {
        pod_uid: "pod-uid-1",
        pod_name: "test-pod",
        namespace: "default",
        service_account: None,
        labels: &labels,
        annotations: &annotations,
        pod_ip_str: pod_ip_str.as_deref(),
        pod_source_ips,
        node_probe_ports: Vec::new(),
        inbound_redirect_ports,
        veth_iface_override: Some("veth-mock"),
        host_network: false,
    };
    handle_pod_added(backend, pod_states, config, metrics, &event);
}

/// Issue #7025: a redirect rewrite that writes the widened scope and then
/// fails the pod-IP flag write leaves the BPF scope wider than the tracked
/// set. A later event whose ports EQUAL the tracked set must still rewrite the
/// scope (the withdrawn port may not stay redirect-eligible) and clear the
/// pending record once the write converges.
#[test]
fn redirect_update_failure_followed_by_reverting_event_withdraws_the_port() {
    let cgroup_root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
    let config = redirect_config(cgroup_root.path().to_string_lossy().to_string());
    let mut backend = MockEbpfBackend::default();
    backend.load_programs().unwrap();
    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
    let metrics = NodeAgentMetrics::default();
    let pod_ip: std::net::Ipv4Addr = "10.0.0.5".parse().unwrap();
    let state_key = pod_state_key(&pod_states, "pod-uid-1");
    let tracked = || {
        pod_states
            .get("pod-uid-1")
            .unwrap()
            .inbound_redirect_ports
            .clone()
    };

    drive_redirect_pod(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        pod_ip,
        vec![8080],
    );
    assert_eq!(tracked(), vec![8080]);
    assert_eq!(
        redirect_scope_v4(&backend, pod_ip),
        std::collections::BTreeSet::from([8080])
    );

    // The scope write lands, then the pod-IP flag write fails: the BPF scope
    // already admits 9090 while the tracked set stays [8080].
    backend.fail_update_pod_ip = true;
    drive_redirect_pod(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        pod_ip,
        vec![8080, 9090],
    );
    assert_eq!(tracked(), vec![8080]);
    assert!(redirect_scope_v4(&backend, pod_ip).contains(&9090));
    assert!(has_capture_failure(
        &state_key,
        &CaptureFailureOp::InboundRedirectUpdate
    ));

    // The spec reverts to the tracked set. Before #7025 this returned early
    // and 9090 stayed redirect-eligible with the record pending forever.
    backend.fail_update_pod_ip = false;
    drive_redirect_pod(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        pod_ip,
        vec![8080],
    );
    assert_eq!(
        redirect_scope_v4(&backend, pod_ip),
        std::collections::BTreeSet::from([8080]),
        "the withdrawn port must leave the BPF redirect scope"
    );
    assert!(backend.pod_ips[&pod_ip].inbound_redirect_enabled());
    assert_eq!(tracked(), vec![8080]);
    assert!(!has_capture_failure(
        &state_key,
        &CaptureFailureOp::InboundRedirectUpdate
    ));
}

/// Issue #7025: pod removal must prune every live-pod capture-failure record
/// (including the inbound redirect update the old code missed), so the node can
/// leave PARTIALLY_ATTACHED. Removal blockers are the teardown retry queue and
/// survive until their retry succeeds.
#[test]
fn pod_removal_prunes_every_live_pod_capture_failure_record() {
    let cgroup_root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
    let config = redirect_config(cgroup_root.path().to_string_lossy().to_string());
    let mut backend = MockEbpfBackend::default();
    backend.load_programs().unwrap();
    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
    let metrics = NodeAgentMetrics::default();
    let pod_ip: std::net::Ipv4Addr = "10.0.0.6".parse().unwrap();
    drive_redirect_pod(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        pod_ip,
        vec![8080],
    );
    assert!(pod_states.contains_key("pod-uid-1"));

    let state_key = pod_state_key(&pod_states, "pod-uid-1");
    // Targets of failed pod-IP moves whose redirect scope landed before the
    // pod-IP write failed: removal must retire them, not just the record.
    let abandoned_v4: std::net::Ipv4Addr = "10.0.0.77".parse().unwrap();
    let abandoned_v6: std::net::Ipv6Addr = "fd00::77".parse().unwrap();
    backend.pod_inbound_ports.insert((abandoned_v4, 8080));
    backend.pod_inbound_ports6.insert((abandoned_v6, 8080));
    let live_records = [
        CaptureFailureOp::PodIpUpdate(abandoned_v4),
        CaptureFailureOp::PodIp6Update(abandoned_v6),
        CaptureFailureOp::NodeProbePortUpdate {
            desired_ports: vec![8080],
        },
        CaptureFailureOp::UdpReadiness,
        CaptureFailureOp::InboundRedirectUpdate,
    ];
    for record in &live_records {
        assert!(!record.blocks_removal());
        remember_capture_failure(&state_key, record.clone());
    }
    // A stale address from an earlier pod-IP change whose removal failed: the
    // live pod's teardown does not own it, so it must survive pod removal.
    let stale_ip = std::net::IpAddr::from([10, 0, 0, 99]);
    let stale_removal = CaptureFailureOp::PodIpRemove(stale_ip);
    assert!(stale_removal.blocks_removal());
    remember_capture_failure(&state_key, stale_removal.clone());
    metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED);

    handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-1");

    assert!(!pod_states.contains_key("pod-uid-1"));
    assert!(redirect_scope_v4(&backend, abandoned_v4).is_empty());
    assert!(redirect_scope_v6(&backend, abandoned_v6).is_empty());
    for record in &live_records {
        assert!(
            !has_capture_failure(&state_key, record),
            "pod removal must prune {record:?}"
        );
    }
    assert!(has_capture_failure(&state_key, &stale_removal));
    assert!(has_pending_removal_blocking_failure(&state_key));
    // A genuine teardown blocker still pends, so the node honestly stays
    // degraded until it converges.
    assert_eq!(
        metrics.snapshot().capture_state,
        NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
    );

    // The removal blocker converges through its own retry, after which no
    // record remains and the node leaves PARTIALLY_ATTACHED.
    retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);
    assert!(!has_capture_failure(&state_key, &stale_removal));
    assert!(!has_pending_capture_failures(&pod_states));
    assert!(PENDING_CAPTURE_FAILURES.get(&state_key).is_none());
    assert_ne!(
        metrics.snapshot().capture_state,
        NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
    );
}

/// Issue #7025, pod-IP sibling: a move to a new IPv4 address that writes the
/// scope there and then fails the pod-IP write must not pend forever when the
/// next event reverts to the tracked address. The revert re-converges the
/// tracked address, retires the abandoned target's scope, and clears the record.
#[test]
fn pod_ip_move_failure_followed_by_reverting_event_retires_the_abandoned_target() {
    let cgroup_root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
    let config = redirect_config(cgroup_root.path().to_string_lossy().to_string());
    let mut backend = MockEbpfBackend::default();
    backend.load_programs().unwrap();
    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
    let metrics = NodeAgentMetrics::default();
    let tracked_ip: std::net::Ipv4Addr = "10.0.0.5".parse().unwrap();
    let moved_ip: std::net::Ipv4Addr = "10.0.0.7".parse().unwrap();
    let state_key = pod_state_key(&pod_states, "pod-uid-1");

    drive_redirect_pod(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        tracked_ip,
        vec![8080],
    );
    assert_eq!(
        redirect_scope_v4(&backend, tracked_ip),
        std::collections::BTreeSet::from([8080])
    );

    backend.fail_update_pod_ip = true;
    drive_redirect_pod(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        moved_ip,
        vec![8080],
    );
    assert_eq!(
        pod_states.get("pod-uid-1").unwrap().pod_ip,
        Some(tracked_ip)
    );
    assert_eq!(
        redirect_scope_v4(&backend, moved_ip),
        std::collections::BTreeSet::from([8080]),
        "the scope moved before the pod-IP write failed"
    );
    assert!(has_capture_failure(
        &state_key,
        &CaptureFailureOp::PodIpUpdate(moved_ip)
    ));

    backend.fail_update_pod_ip = false;
    drive_redirect_pod(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        tracked_ip,
        vec![8080],
    );
    assert_eq!(
        pod_states.get("pod-uid-1").unwrap().pod_ip,
        Some(tracked_ip)
    );
    assert_eq!(
        redirect_scope_v4(&backend, tracked_ip),
        std::collections::BTreeSet::from([8080])
    );
    assert!(backend.pod_ips[&tracked_ip].inbound_redirect_enabled());
    assert!(
        redirect_scope_v4(&backend, moved_ip).is_empty(),
        "the abandoned target's scope must be cleared"
    );
    assert!(!backend.pod_ips.contains_key(&moved_ip));
    assert!(!has_capture_failure(
        &state_key,
        &CaptureFailureOp::PodIpUpdate(moved_ip)
    ));
    assert!(!has_pending_capture_failures(&pod_states));
}

/// IPv6 counterpart of the pod-IP move regression (dual-stack pod with an
/// IPv6-capable capture listener; the IPv4 address never changes).
#[test]
fn pod_ip6_move_failure_followed_by_reverting_event_retires_the_abandoned_target() {
    let cgroup_root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
    let config = redirect_config_with_ipv6(cgroup_root.path().to_string_lossy().to_string(), true);
    let mut backend = MockEbpfBackend::default();
    backend.load_programs().unwrap();
    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
    let metrics = NodeAgentMetrics::default();
    let ip4: std::net::Ipv4Addr = "10.0.0.5".parse().unwrap();
    let tracked_ip6: std::net::Ipv6Addr = "fd00::5".parse().unwrap();
    let moved_ip6: std::net::Ipv6Addr = "fd00::7".parse().unwrap();
    let state_key = pod_state_key(&pod_states, "pod-uid-1");
    let ips = |ip6: std::net::Ipv6Addr| PodSourceIps {
        ipv4: Some(ip4),
        ipv6: Some(ip6),
    };

    drive_redirect_pod_with_ips(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        ips(tracked_ip6),
        vec![8080],
    );
    assert_eq!(
        redirect_scope_v6(&backend, tracked_ip6),
        std::collections::BTreeSet::from([8080])
    );

    backend.fail_update_pod_ip = true;
    drive_redirect_pod_with_ips(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        ips(moved_ip6),
        vec![8080],
    );
    assert_eq!(
        pod_states.get("pod-uid-1").unwrap().pod_ip6,
        Some(tracked_ip6)
    );
    assert_eq!(
        redirect_scope_v6(&backend, moved_ip6),
        std::collections::BTreeSet::from([8080])
    );
    assert!(has_capture_failure(
        &state_key,
        &CaptureFailureOp::PodIp6Update(moved_ip6)
    ));

    backend.fail_update_pod_ip = false;
    drive_redirect_pod_with_ips(
        &mut backend,
        &pod_states,
        &config,
        &metrics,
        ips(tracked_ip6),
        vec![8080],
    );
    assert_eq!(
        pod_states.get("pod-uid-1").unwrap().pod_ip6,
        Some(tracked_ip6)
    );
    assert_eq!(
        redirect_scope_v6(&backend, tracked_ip6),
        std::collections::BTreeSet::from([8080])
    );
    assert!(backend.pod_ips6[&tracked_ip6].inbound_redirect_enabled());
    assert!(redirect_scope_v6(&backend, moved_ip6).is_empty());
    assert!(!backend.pod_ips6.contains_key(&moved_ip6));
    assert!(!has_capture_failure(
        &state_key,
        &CaptureFailureOp::PodIp6Update(moved_ip6)
    ));
    assert!(!has_pending_capture_failures(&pod_states));
}
