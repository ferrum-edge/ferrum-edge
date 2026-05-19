#![allow(dead_code)]
//! cgroup v2 path resolution for Kubernetes pods.
//!
//! Kubernetes uses two cgroup drivers — `systemd` and `cgroupfs` — each
//! placing pod cgroups at different paths. The node agent must resolve
//! the correct path before attaching BPF programs.

use std::path::{Path, PathBuf};

/// Resolve the cgroup v2 path for a Kubernetes pod.
///
/// Tries systemd driver paths first (`kubepods.slice/...`), then falls back to
/// cgroupfs driver paths (`kubepods/pod{uid}/`).
pub fn resolve_pod_cgroup_path(cgroup_root: &str, pod_uid: &str) -> Option<PathBuf> {
    let sanitized_uid = pod_uid.replace('-', "_");

    systemd_pod_cgroup_paths(cgroup_root, &sanitized_uid)
        .into_iter()
        .chain(cgroupfs_pod_cgroup_paths(cgroup_root, pod_uid))
        .find(|path| path.exists())
}

fn systemd_pod_cgroup_paths(cgroup_root: &str, sanitized_uid: &str) -> [PathBuf; 3] {
    let root = Path::new(cgroup_root).join("kubepods.slice");
    [
        root.join(format!("kubepods-pod{sanitized_uid}.slice")),
        root.join(format!(
            "kubepods-burstable.slice/kubepods-burstable-pod{sanitized_uid}.slice"
        )),
        root.join(format!(
            "kubepods-besteffort.slice/kubepods-besteffort-pod{sanitized_uid}.slice"
        )),
    ]
}

fn cgroupfs_pod_cgroup_paths(cgroup_root: &str, pod_uid: &str) -> [PathBuf; 3] {
    let root = Path::new(cgroup_root).join("kubepods");
    [
        root.join(format!("pod{pod_uid}")),
        root.join(format!("burstable/pod{pod_uid}")),
        root.join(format!("besteffort/pod{pod_uid}")),
    ]
}

/// Build the expected cgroup path for a given QoS class (for testing/validation).
pub fn cgroup_path_for_qos(cgroup_root: &str, pod_uid: &str, qos_class: &str) -> PathBuf {
    match qos_class {
        "Guaranteed" => Path::new(cgroup_root).join(format!("kubepods/pod{pod_uid}")),
        "Burstable" => Path::new(cgroup_root).join(format!("kubepods/burstable/pod{pod_uid}")),
        "BestEffort" => Path::new(cgroup_root).join(format!("kubepods/besteffort/pod{pod_uid}")),
        _ => Path::new(cgroup_root).join(format!("kubepods/pod{pod_uid}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_path_for_qos_guaranteed() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "Guaranteed");
        assert_eq!(path, PathBuf::from("/sys/fs/cgroup/kubepods/podabc-123"));
    }

    #[test]
    fn cgroup_path_for_qos_burstable() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "Burstable");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/kubepods/burstable/podabc-123")
        );
    }

    #[test]
    fn cgroup_path_for_qos_besteffort() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "BestEffort");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/kubepods/besteffort/podabc-123")
        );
    }

    #[test]
    fn resolve_pod_cgroup_path_nonexistent() {
        assert!(resolve_pod_cgroup_path("/nonexistent/cgroup", "abc-123").is_none());
    }

    #[test]
    fn systemd_path_sanitizes_dashes_to_underscores() {
        let sanitized = "abc-def-123".replace('-', "_");
        assert_eq!(sanitized, "abc_def_123");
    }

    #[test]
    fn resolve_pod_cgroup_path_finds_systemd_burstable_pod() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc_def.slice");
        std::fs::create_dir_all(&path).unwrap();

        assert_eq!(
            resolve_pod_cgroup_path(dir.path().to_str().unwrap(), "abc-def"),
            Some(path)
        );
    }

    #[test]
    fn resolve_pod_cgroup_path_finds_systemd_besteffort_pod() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc_def.slice");
        std::fs::create_dir_all(&path).unwrap();

        assert_eq!(
            resolve_pod_cgroup_path(dir.path().to_str().unwrap(), "abc-def"),
            Some(path)
        );
    }
}
