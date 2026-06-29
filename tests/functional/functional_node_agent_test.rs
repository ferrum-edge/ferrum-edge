//! Functional smoke coverage for node_agent metrics.

use std::env;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::scaffolding::ports::reserve_port;

fn gateway_binary_path() -> String {
    std::env::var("CARGO_BIN_EXE_ferrum-edge")
        .unwrap_or_else(|_| super::namespace_helpers::gateway_binary_path().to_string())
}

fn terminate(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn prepend_noop_shell(command: &mut Command, temp_dir: &Path) {
    let bin_dir = temp_dir.join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake shell bin dir");

    let shell_path = bin_dir.join(if cfg!(windows) { "sh.cmd" } else { "sh" });
    fs::write(
        &shell_path,
        if cfg!(windows) {
            "@echo off\r\nexit /b 0\r\n"
        } else {
            "#!/bin/sh\nexit 0\n"
        },
    )
    .expect("write fake sh");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&shell_path)
            .expect("stat fake sh")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&shell_path, permissions).expect("chmod fake sh");
    }

    let mut paths = vec![bin_dir];
    if let Some(existing_path) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing_path));
    }
    let path = env::join_paths(paths).expect("join PATH for fake sh");
    command.env("PATH", path);
}

#[ignore]
#[tokio::test]
async fn node_agent_boots_with_contract_env_and_exposes_metrics() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cgroup_root = tmp.path().join("missing-cgroup-root");
    let bpf_root = tmp.path().join("missing-bpf-root");

    let admin_port = reserve_port()
        .await
        .expect("reserve admin port")
        .drop_and_take_port();
    let mut command = Command::new(gateway_binary_path());
    prepend_noop_shell(&mut command, tmp.path());
    let mut child = command
        .env("FERRUM_MODE", "node_agent")
        .env("FERRUM_NODE_AGENT_NODE_NAME", "functional-node")
        .env("FERRUM_NODE_AGENT_PROXY_MODE", "node_waypoint")
        .env("FERRUM_NODE_AGENT_ADMIN_ENABLED", "true")
        .env("FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT", "16008")
        .env("FERRUM_NODE_AGENT_CGROUP_ROOT", &cgroup_root)
        .env("FERRUM_NODE_AGENT_BPF_FS_PATH", &bpf_root)
        .env("FERRUM_NODE_AGENT_FALLBACK_MODE", "iptables")
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
        // /metrics is gated by default; allowlist the loopback scrape (node_agent
        // generates a random admin JWT secret, so a token can't be minted here).
        .env("FERRUM_METRICS_ALLOWED_CIDRS", "127.0.0.1/32,::1")
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn node_agent");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{admin_port}/metrics");
    let mut last_body = String::new();
    for _ in 0..50 {
        if let Some(status) = child.try_wait().expect("poll node_agent") {
            terminate(child);
            panic!("node_agent exited before metrics scrape: {status}");
        }
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            last_body = response.text().await.expect("metrics body");
            if last_body.contains("ferrum_node_agent_pods_enrolled_total") {
                terminate(child);
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    terminate(child);
    if last_body.is_empty() {
        panic!("node_agent metrics endpoint did not become ready at {url}");
    }
    panic!("node_agent /metrics missing node-agent counters:\n{last_body}");
}
