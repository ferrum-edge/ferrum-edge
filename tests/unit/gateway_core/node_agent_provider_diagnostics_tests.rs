//! Inject command results at the provider boundary; never run privileged tools.

use super::*;
use std::os::unix::process::ExitStatusExt;

fn output(code: i32) -> std::process::Output {
    std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: Vec::new(),
        stderr: b"UNREGISTERED_PROVIDER5591 at /sys/fs/cgroup/'UNREGISTERED_PATH5591".to_vec(),
    }
}

fn spawn_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "UNREGISTERED_SPAWN5591 at /sys/fs/cgroup/'UNREGISTERED_PATH5591",
    )
}

#[test]
fn routing_install_provider_failures_are_safe_in_final_rendering() {
    for spawn_failure in [false, true] {
        let mut calls = 0;
        let (error, logs) = crate::modes::tests::capture_logs(|| {
            install_ingress_redirect_routing_with(false, |args| {
                calls += 1;
                if spawn_failure {
                    Err(spawn_error())
                } else {
                    // Failed idempotence deletes remain best effort. The first
                    // install failure must stop the rest of the batch.
                    assert!(args.iter().any(|arg| arg == "del") || calls > 1);
                    Ok(output(23))
                }
            })
            .expect_err("routing must not be admitted after a provider failure")
        });
        let rendered = crate::startup::render_startup_error(
            anyhow::Error::msg(error).context("policy routing installation failed"),
            &[],
        );
        assert!(rendered.contains("`ip "), "{rendered}");
        assert!(rendered.contains("provider details withheld"), "{rendered}");
        assert!(rendered.contains("iproute2"), "{rendered}");
        assert!(rendered.contains("NET_ADMIN"), "{rendered}");
        if spawn_failure {
            assert_eq!(calls, 1);
            assert!(rendered.contains("PermissionDenied"), "{rendered}");
        } else {
            assert!(rendered.contains("exit status: 23"), "{rendered}");
            let expected = ingress_redirect_routing_commands(false)
                .iter()
                .position(|args| !args.iter().any(|arg| arg == "del"))
                .unwrap()
                + 1;
            assert_eq!(calls, expected);
        }
        assert!(!rendered.contains("UNREGISTERED"), "{rendered}");
        assert!(!logs.contains("UNREGISTERED"), "{logs}");
    }
}

#[test]
fn iptables_provider_failures_survive_cleanup_with_safe_fatal_diagnostics() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for spawn_failure in [false, true] {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let probe = KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };
        let metrics = NodeAgentMetrics::default();
        let ready = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, _shutdown_rx) =
            crate::overload::ShutdownSender::channel(std::time::Duration::from_secs(30));
        let mut phases = Vec::new();
        let setup_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (error, logs) = crate::modes::tests::capture_logs(|| {
            runtime.block_on(async {
                handle_fallback_with(
                    &config,
                    &probe,
                    &metrics,
                    &shutdown_tx,
                    |commands, phase| {
                        phases.push(phase);
                        let setup_calls = setup_calls.clone();
                        async move {
                            execute_iptables_commands_with(&commands, phase, |_| {
                                let result = if phase == "setup" {
                                    setup_calls.fetch_add(1, Ordering::Relaxed);
                                    if spawn_failure {
                                        Err(spawn_error())
                                    } else {
                                        Ok(output(23))
                                    }
                                } else {
                                    Ok(output(0))
                                };
                                std::future::ready(result)
                            })
                            .await
                        }
                    },
                    ready.clone(),
                )
                .await
                .expect_err("setup failure must survive fallback cleanup")
            })
        });
        assert_eq!(phases, ["pre-setup UDP teardown", "setup", "cleanup"]);
        assert_eq!(setup_calls.load(Ordering::Relaxed), 1);
        assert!(!ready.load(Ordering::Acquire));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_UNAVAILABLE
        );
        let rendered = crate::startup::render_startup_error(error, &[]);
        assert!(rendered.contains("iptables setup command"), "{rendered}");
        assert!(rendered.contains("provider details withheld"), "{rendered}");
        if spawn_failure {
            assert!(rendered.contains("PermissionDenied"), "{rendered}");
            assert!(rendered.contains("/bin/sh"), "{rendered}");
            assert!(rendered.contains("execution permissions"), "{rendered}");
            assert!(logs.contains("Failed to spawn iptables command"), "{logs}");
        } else {
            assert!(rendered.contains("exit status: 23"), "{rendered}");
            assert!(rendered.contains("NET_ADMIN"), "{rendered}");
            assert!(logs.contains("iptables command failed"), "{logs}");
        }
        assert!(!rendered.contains("UNREGISTERED"), "{rendered}");
        assert!(!logs.contains("UNREGISTERED"), "{logs}");
    }
}
