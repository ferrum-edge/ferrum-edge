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
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(true);
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
