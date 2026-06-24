#![allow(dead_code)]
//! cgroup v2 path resolution for Kubernetes pods.
//!
//! Kubernetes uses two cgroup drivers — `systemd` and `cgroupfs` — each
//! placing pod cgroups at different paths. The node agent must resolve
//! the correct path before attaching BPF programs.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// Resolve the cgroup v2 path for a Kubernetes pod.
///
/// Tries systemd driver paths first (`kubepods.slice/...`), then falls back to
/// cgroupfs driver paths (`kubepods/pod{uid}/`).
pub fn resolve_pod_cgroup_path(cgroup_root: &str, pod_uid: &str) -> Option<PathBuf> {
    let sanitized_uid = pod_uid.replace('-', "_");

    if let Some(path) = systemd_pod_cgroup_paths(cgroup_root, &sanitized_uid)
        .into_iter()
        .chain(cgroupfs_pod_cgroup_paths(cgroup_root, pod_uid))
        .find(|path| path.exists())
    {
        return Some(path);
    }

    discover_pod_cgroup_paths(cgroup_root, pod_uid, &sanitized_uid)
        .into_iter()
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

const POD_CGROUP_DISCOVERY_MAX_DEPTH: usize = 8;
const POD_CGROUP_DISCOVERY_MAX_DIRS: usize = 4096;

fn discover_pod_cgroup_paths(
    cgroup_root: &str,
    pod_uid: &str,
    sanitized_uid: &str,
) -> Vec<PathBuf> {
    let root = Path::new(cgroup_root);
    let raw_cgroupfs = format!("pod{pod_uid}");
    let systemd_suffix = format!("pod{sanitized_uid}.slice");
    let mut matches = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0usize));
    let mut scanned = 0usize;

    while let Some((dir, depth)) = queue.pop_front() {
        if scanned >= POD_CGROUP_DISCOVERY_MAX_DIRS {
            break;
        }
        scanned += 1;

        let name_matches = dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == raw_cgroupfs || name.ends_with(&systemd_suffix));
        if name_matches {
            matches.push(dir.clone());
            continue;
        }
        if depth >= POD_CGROUP_DISCOVERY_MAX_DEPTH {
            continue;
        }

        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let descend = entry.file_type().map(|t| t.is_dir()).unwrap_or(true);
            if descend {
                queue.push_back((entry.path(), depth + 1));
            }
        }
    }

    matches
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

/// Bounds for [`collect_cgroup_tree_inodes`]. Kubernetes pod cgroups nest only
/// a level or two deep (the pod slice plus a `.scope`/dir per container, plus
/// the pause container), so these are generous; they exist solely to keep a
/// pathological or adversarial cgroup tree from turning enrollment into an
/// unbounded directory walk.
const CGROUP_TREE_MAX_DEPTH: usize = 8;
const CGROUP_TREE_MAX_INODES: usize = 256;

/// Collect the inode of `pod_cgroup_path` plus every descendant cgroup
/// directory inode, breadth-first and bounded by [`CGROUP_TREE_MAX_DEPTH`] /
/// [`CGROUP_TREE_MAX_INODES`]. The pod inode is returned first.
///
/// This exists because the `connect4`/`connect6` hooks read
/// `bpf_get_current_cgroup_id()`, which returns the *leaf* cgroup the calling
/// task belongs to. On Kubernetes the connecting task is a container process
/// living in a child cgroup *below* the pod cgroup
/// (`.../kubepods-pod<uid>.slice/cri-containerd-<id>.scope`,
/// `.../pod<uid>/<container-id>`), so the pod cgroup inode alone never matches
/// the hook's lookup key — per-cgroup maps keyed only by the pod inode miss and
/// the hook falls back to its sentinel. Enrolling every descendant inode (the
/// container leaves) as well as the pod inode keys those maps with the same id
/// the hook reads. Returns an empty Vec on stat failure or on non-Unix builds;
/// the caller treats empty as "nothing enrolled".
#[cfg(unix)]
pub fn collect_cgroup_tree_inodes(pod_cgroup_path: &Path) -> Vec<u64> {
    use std::collections::VecDeque;
    use std::os::unix::fs::MetadataExt;

    let mut inodes: Vec<u64> = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((pod_cgroup_path.to_path_buf(), 0));

    while let Some((path, depth)) = queue.pop_front() {
        if inodes.len() >= CGROUP_TREE_MAX_INODES {
            break;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        // Only directories are cgroups; the files inside a cgroup dir
        // (`cgroup.procs`, `cgroup.controllers`, ...) are not.
        if !meta.is_dir() {
            continue;
        }
        let inode = meta.ino();
        if !inodes.contains(&inode) {
            inodes.push(inode);
        }
        if depth >= CGROUP_TREE_MAX_DEPTH {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                // Use the readdir `d_type` when available (cgroupfs/kernfs
                // supplies it without a stat); if it's unknown, enqueue anyway
                // and let the loop's own `is_dir` check filter it out, so a
                // child cgroup is never skipped.
                let descend = entry.file_type().map(|t| t.is_dir()).unwrap_or(true);
                if descend {
                    queue.push_back((entry.path(), depth + 1));
                }
            }
        }
    }
    inodes
}

#[cfg(not(unix))]
pub fn collect_cgroup_tree_inodes(_pod_cgroup_path: &Path) -> Vec<u64> {
    Vec::new()
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

    #[test]
    fn resolve_pod_cgroup_path_finds_kubelet_slice_systemd_pod() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(
            "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/\
             kubelet-kubepods-burstable-podabc_def.slice",
        );
        std::fs::create_dir_all(&path).unwrap();

        assert_eq!(
            resolve_pod_cgroup_path(dir.path().to_str().unwrap(), "abc-def"),
            Some(path)
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_cgroup_tree_inodes_includes_pod_and_container_leaves() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        // Simulate a systemd-driver pod slice with two container scopes below
        // it — the leaf cgroups a container process's connect() actually runs
        // in, and whose inode `bpf_get_current_cgroup_id()` returns.
        let pod = dir.path().join("kubepods-pod_abc.slice");
        let c1 = pod.join("cri-containerd-aaaa.scope");
        let c2 = pod.join("cri-containerd-bbbb.scope");
        std::fs::create_dir_all(&c1).unwrap();
        std::fs::create_dir_all(&c2).unwrap();
        // A regular file inside a cgroup dir must NOT be treated as a cgroup.
        std::fs::write(pod.join("cgroup.procs"), b"").unwrap();

        let inodes = collect_cgroup_tree_inodes(&pod);

        let pod_ino = std::fs::metadata(&pod).unwrap().ino();
        let c1_ino = std::fs::metadata(&c1).unwrap().ino();
        let c2_ino = std::fs::metadata(&c2).unwrap().ino();
        let file_ino = std::fs::metadata(pod.join("cgroup.procs")).unwrap().ino();

        // Pod inode first, both container leaves present (the ids the
        // pod-inode-only enrollment used to miss), the file excluded.
        assert_eq!(inodes.first(), Some(&pod_ino));
        assert!(inodes.contains(&c1_ino));
        assert!(inodes.contains(&c2_ino));
        assert!(
            !inodes.contains(&file_ino),
            "files inside a cgroup dir are not cgroups"
        );
        assert_eq!(inodes.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn collect_cgroup_tree_inodes_empty_for_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(collect_cgroup_tree_inodes(&dir.path().join("does-not-exist")).is_empty());
    }
}
