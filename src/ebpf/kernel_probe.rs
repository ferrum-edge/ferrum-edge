#![allow(dead_code)]
//! Runtime kernel detection for eBPF capability probing.
//!
//! The node agent checks kernel version and cgroup v2 availability before
//! attempting BPF program loading. On kernels < 5.7 (or when cgroup v2 is
//! unavailable) the agent falls back to iptables or exits, depending on
//! `FERRUM_NODE_AGENT_FALLBACK_MODE`.

use std::path::Path;

/// Kernel capability probe result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelProbeResult {
    pub kernel_release: String,
    pub meets_version_requirement: bool,
    pub cgroup_v2_available: bool,
    pub bpf_fs_available: bool,
}

impl KernelProbeResult {
    pub fn supports_ebpf(&self) -> bool {
        self.meets_version_requirement && self.cgroup_v2_available && self.bpf_fs_available
    }

    /// Return the first-failing kernel prerequisite as a stable
    /// snake_case label, or `None` when all eBPF prerequisites are met.
    ///
    /// Used as the Prometheus `reason` label on the
    /// `ferrum_mesh_node_topology_degraded` gauge so dashboards can
    /// distinguish operator remediations (kernel upgrade vs cgroup-v2
    /// remount vs bpffs mount). The label set is closed — one of
    /// `kernel_too_old`, `cgroup_v1`, `bpffs_missing` — so cardinality is
    /// bounded regardless of fleet size.
    ///
    /// Precedence is most-fundamental first: a kernel below 5.7 cannot
    /// host the BPF programs even if cgroup v2 and bpffs are present, so
    /// the kernel-version reason wins. Likewise, without cgroup v2 the
    /// cgroup_sockaddr programs have no attachment point, so cgroup_v1
    /// is reported before bpffs_missing.
    pub fn degradation_reason(&self) -> Option<&'static str> {
        if !self.meets_version_requirement {
            Some("kernel_too_old")
        } else if !self.cgroup_v2_available {
            Some("cgroup_v1")
        } else if !self.bpf_fs_available {
            Some("bpffs_missing")
        } else {
            None
        }
    }
}

/// Probe the running kernel for eBPF capture prerequisites.
pub fn probe_kernel(cgroup_root: &str, bpf_fs_path: &str) -> KernelProbeResult {
    let kernel_release = read_kernel_release();
    let meets_version_requirement = check_kernel_version(&kernel_release);
    let cgroup_v2_available = check_cgroup_v2(cgroup_root);
    let bpf_fs_available = check_bpf_fs(bpf_fs_path);

    KernelProbeResult {
        kernel_release,
        meets_version_requirement,
        cgroup_v2_available,
        bpf_fs_available,
    }
}

fn read_kernel_release() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        "non-linux".to_string()
    }
}

fn check_kernel_version(release: &str) -> bool {
    !crate::capture::should_fallback_to_iptables(release)
}

fn check_cgroup_v2(cgroup_root: &str) -> bool {
    let cgroup_type_path = Path::new(cgroup_root).join("cgroup.type");
    let cgroup_controllers_path = Path::new(cgroup_root).join("cgroup.controllers");
    cgroup_type_path.exists() || cgroup_controllers_path.exists()
}

fn check_bpf_fs(bpf_fs_path: &str) -> bool {
    Path::new(bpf_fs_path).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_check_uses_capture_module() {
        assert!(!check_kernel_version("4.19.0"));
        assert!(!check_kernel_version("5.4.0"));
        assert!(check_kernel_version("5.7.0"));
        assert!(check_kernel_version("5.15.0"));
        assert!(check_kernel_version("6.6.12"));
    }

    #[test]
    fn kernel_version_check_unparseable() {
        assert!(!check_kernel_version("unknown"));
        assert!(!check_kernel_version(""));
    }

    #[test]
    fn probe_result_supports_ebpf_all_true() {
        let result = KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: true,
            bpf_fs_available: true,
        };
        assert!(result.supports_ebpf());
    }

    #[test]
    fn probe_result_missing_cgroup_v2() {
        let result = KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: false,
            bpf_fs_available: true,
        };
        assert!(!result.supports_ebpf());
    }

    #[test]
    fn probe_result_old_kernel() {
        let result = KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: true,
            bpf_fs_available: true,
        };
        assert!(!result.supports_ebpf());
    }

    #[test]
    fn check_cgroup_v2_nonexistent_path() {
        assert!(!check_cgroup_v2("/nonexistent/cgroup/path"));
    }

    #[test]
    fn check_cgroup_v2_ignores_v1_cgroup_procs_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("cgroup.procs"), b"").expect("write cgroup.procs");
        assert!(!check_cgroup_v2(dir.path().to_str().expect("utf8 path")));
    }

    #[test]
    fn check_cgroup_v2_accepts_controllers_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("cgroup.controllers"), b"cpu io memory")
            .expect("write cgroup.controllers");
        assert!(check_cgroup_v2(dir.path().to_str().expect("utf8 path")));
    }

    #[test]
    fn check_bpf_fs_nonexistent_path() {
        assert!(!check_bpf_fs("/nonexistent/bpf/path"));
    }

    #[test]
    fn degradation_reason_returns_none_when_supported() {
        let result = KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: true,
            bpf_fs_available: true,
        };
        assert!(result.supports_ebpf());
        assert_eq!(result.degradation_reason(), None);
    }

    #[test]
    fn degradation_reason_reports_kernel_first() {
        // Kernel-too-old wins even when cgroup v2 or bpffs are also missing —
        // operators need to know to upgrade the kernel before troubleshooting
        // downstream mounts.
        let result = KernelProbeResult {
            kernel_release: "5.4.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };
        assert_eq!(result.degradation_reason(), Some("kernel_too_old"));
    }

    #[test]
    fn degradation_reason_reports_cgroup_v1_when_kernel_ok() {
        let result = KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: false,
            bpf_fs_available: true,
        };
        assert_eq!(result.degradation_reason(), Some("cgroup_v1"));
    }

    #[test]
    fn degradation_reason_reports_bpffs_missing_when_kernel_and_cgroup_ok() {
        let result = KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: true,
            bpf_fs_available: false,
        };
        assert_eq!(result.degradation_reason(), Some("bpffs_missing"));
    }
}
