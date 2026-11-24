//! Static chart contract for the node-agent bpffs mount (issue #6698).
//!
//! Ferrum pins its BPF maps at fixed `/sys/fs/bpf/ferrum/*` paths: the
//! node-agent writes them and the ambient NodeWaypoint proxy opens them by
//! path. `nodeAgent.bpfFsPath` may only relocate the *host* bpffs; both
//! containers must mount it at `/sys/fs/bpf`, and the node-agent must be told
//! that same in-container path (it refuses any other value).

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("charts/ferrum-mesh")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read charts/ferrum-mesh/{rel}: {e}"))
}

/// Lines of the `- name: bpf-fs` list item (the item line plus its deeper
/// indented continuation lines), for every occurrence in the template.
fn bpf_fs_items(template: &str) -> Vec<Vec<String>> {
    let lines: Vec<&str> = template.lines().collect();
    let mut items = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if line.trim() != "- name: bpf-fs" {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let mut item = vec![line.trim().to_string()];
        for next in &lines[idx + 1..] {
            let next_indent = next.len() - next.trim_start().len();
            if next.trim().is_empty() || next_indent <= indent {
                break;
            }
            item.push(next.trim().to_string());
        }
        items.push(item);
    }
    items
}

fn assert_bpf_fs_contract(template_rel: &str) {
    let template = read(template_rel);
    let items = bpf_fs_items(&template);
    let mounts: Vec<_> = items
        .iter()
        .filter(|item| item.iter().any(|l| l.starts_with("mountPath:")))
        .collect();
    let volumes: Vec<_> = items
        .iter()
        .filter(|item| item.iter().any(|l| l == "hostPath:"))
        .collect();
    assert_eq!(mounts.len(), 1, "{template_rel}: one bpf-fs volumeMount");
    assert_eq!(
        volumes.len(),
        1,
        "{template_rel}: one bpf-fs hostPath volume"
    );
    assert!(
        mounts[0].iter().any(|l| l == "mountPath: /sys/fs/bpf"),
        "{template_rel}: bpf-fs must mount at the fixed in-container pin root \
         /sys/fs/bpf, not a values-controlled path: {:?}",
        mounts[0]
    );
    assert!(
        volumes[0]
            .iter()
            .any(|l| l == "path: {{ .Values.nodeAgent.bpfFsPath }}"),
        "{template_rel}: nodeAgent.bpfFsPath must select the host bpffs: {:?}",
        volumes[0]
    );
}

#[test]
fn node_agent_mounts_host_bpffs_at_the_fixed_pin_root() {
    assert_bpf_fs_contract("templates/node-agent-daemonset.yaml");
}

#[test]
fn ambient_node_waypoint_mounts_host_bpffs_at_the_fixed_pin_root() {
    assert_bpf_fs_contract("templates/ambient-daemonset.yaml");
}

#[test]
fn node_agent_bpf_fs_env_names_the_in_container_mount() {
    let template = read("templates/node-agent-daemonset.yaml");
    let lines: Vec<&str> = template.lines().map(str::trim).collect();
    let idx = lines
        .iter()
        .position(|l| *l == "- name: FERRUM_NODE_AGENT_BPF_FS_PATH")
        .expect("node-agent DaemonSet must set FERRUM_NODE_AGENT_BPF_FS_PATH");
    assert_eq!(
        lines.get(idx + 1).copied(),
        Some("value: \"/sys/fs/bpf\""),
        "FERRUM_NODE_AGENT_BPF_FS_PATH must be the in-container mount, \
         not nodeAgent.bpfFsPath (the host path)"
    );
}
