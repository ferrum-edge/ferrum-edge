//! Lightweight process/system sampling for the admin runtime metrics endpoint.
//!
//! The sampler keeps OS probing off request paths. It writes one immutable
//! [`SystemSnapshot`] into [`crate::runtime_metrics::RuntimeMetrics`] at a fixed
//! interval; the admin endpoint only clones the latest `Arc`.

use serde::Serialize;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct SystemSnapshot {
    pub sampled_at_unix_ms: u64,
    pub platform: &'static str,
    pub cpu: CpuSnapshot,
    pub memory: MemorySnapshot,
    pub file_descriptors: FdSnapshot,
    pub ephemeral_ports: EphemeralPortSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuSnapshot {
    /// Per-core percentage; a multi-threaded process can exceed 100.
    pub process_percent: f32,
    /// Linux-only system-wide CPU usage over the sample interval.
    pub system_percent: Option<f32>,
    /// Process CPU usage as a percentage of the configured cgroup quota.
    pub cgroup_quota_percent: Option<f32>,
    pub cpu_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemorySnapshot {
    pub rss_bytes: u64,
    pub virtual_bytes: u64,
    pub host_percent: Option<f32>,
    pub cgroup_percent: Option<f32>,
    pub cgroup_limit_bytes: Option<u64>,
    pub jemalloc_allocated_bytes: Option<u64>,
    pub jemalloc_resident_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FdSnapshot {
    pub current: u64,
    pub max: u64,
    pub ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EphemeralPortSnapshot {
    pub range_low: Option<u16>,
    pub range_high: Option<u16>,
    pub range_size: Option<u32>,
    pub exhaustion_events: u64,
    pub active_outbound_estimate: u64,
}

impl SystemSnapshot {
    pub fn empty() -> Self {
        Self {
            sampled_at_unix_ms: unix_ms(),
            platform: platform_name(),
            cpu: CpuSnapshot {
                process_percent: 0.0,
                system_percent: None,
                cgroup_quota_percent: None,
                cpu_count: cpu_count(),
            },
            memory: MemorySnapshot {
                rss_bytes: 0,
                virtual_bytes: 0,
                host_percent: None,
                cgroup_percent: None,
                cgroup_limit_bytes: None,
                jemalloc_allocated_bytes: jemalloc_allocated_bytes(),
                jemalloc_resident_bytes: jemalloc_resident_bytes(),
            },
            file_descriptors: FdSnapshot {
                current: 0,
                max: 0,
                ratio: 0.0,
            },
            ephemeral_ports: EphemeralPortSnapshot {
                range_low: None,
                range_high: None,
                range_size: None,
                exhaustion_events: 0,
                active_outbound_estimate: 0,
            },
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn platform_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(windows)]
    {
        "windows"
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
    {
        "other"
    }
}

fn cpu_count() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

pub fn start_sampler(
    proxy_state: Option<crate::proxy::ProxyState>,
    sample_interval_ms: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let metrics = crate::runtime_metrics::global();
    tokio::spawn(async move {
        let mut sampler = SystemSampler::new();
        let interval = Duration::from_millis(sample_interval_ms.max(100));

        loop {
            let snapshot = sampler.sample(proxy_state.as_ref());
            metrics.system.store(std::sync::Arc::new(snapshot));

            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => return,
            }
        }
    })
}

struct SystemSampler {
    prev_process_cpu_us: Option<u64>,
    prev_wall: Instant,
    prev_system_cpu: Option<SystemCpuSample>,
    cpu_quota_cores: Option<f64>,
    cgroup_memory_limit_bytes: Option<u64>,
    host_memory_total_bytes: Option<u64>,
    ephemeral_range: (Option<u16>, Option<u16>, Option<u32>),
}

impl SystemSampler {
    fn new() -> Self {
        Self {
            prev_process_cpu_us: process_cpu_us(),
            prev_wall: Instant::now(),
            prev_system_cpu: system_cpu_sample(),
            cpu_quota_cores: cgroup_cpu_quota_cores(),
            cgroup_memory_limit_bytes: cgroup_memory_limit_bytes(),
            host_memory_total_bytes: host_memory_total_bytes(),
            ephemeral_range: ephemeral_port_range(),
        }
    }

    fn sample(&mut self, proxy_state: Option<&crate::proxy::ProxyState>) -> SystemSnapshot {
        let now = Instant::now();
        let wall_us = now.duration_since(self.prev_wall).as_micros() as u64;
        let process_cpu_us = process_cpu_us();
        let process_percent = match (self.prev_process_cpu_us, process_cpu_us, wall_us) {
            (Some(prev), Some(curr), wall) if wall > 0 => {
                curr.saturating_sub(prev) as f64 / wall as f64 * 100.0
            }
            _ => 0.0,
        } as f32;
        self.prev_process_cpu_us = process_cpu_us;
        self.prev_wall = now;

        let system_percent = system_cpu_sample().and_then(|curr| {
            let prev = self.prev_system_cpu.replace(curr);
            prev.and_then(|prev| system_cpu_percent(prev, curr))
        });
        let cgroup_quota_percent = self
            .cpu_quota_cores
            .filter(|quota| *quota > 0.0)
            .map(|quota| process_percent / quota as f32);

        let memory = memory_snapshot(self.host_memory_total_bytes, self.cgroup_memory_limit_bytes);
        let file_descriptors = fd_snapshot(proxy_state);
        let ephemeral_ports = ephemeral_snapshot(proxy_state, self.ephemeral_range);

        SystemSnapshot {
            sampled_at_unix_ms: unix_ms(),
            platform: platform_name(),
            cpu: CpuSnapshot {
                process_percent,
                system_percent,
                cgroup_quota_percent,
                cpu_count: cpu_count(),
            },
            memory,
            file_descriptors,
            ephemeral_ports,
        }
    }
}

fn fd_snapshot(proxy_state: Option<&crate::proxy::ProxyState>) -> FdSnapshot {
    let (current, max) = if let Some(ps) = proxy_state {
        (
            ps.overload.fd_current.load(Ordering::Relaxed),
            ps.overload.fd_max.load(Ordering::Relaxed),
        )
    } else {
        (
            crate::overload::count_open_fds(),
            crate::overload::get_fd_limit(),
        )
    };
    FdSnapshot {
        current,
        max,
        ratio: if max > 0 {
            current as f64 / max as f64
        } else {
            0.0
        },
    }
}

fn ephemeral_snapshot(
    proxy_state: Option<&crate::proxy::ProxyState>,
    range: (Option<u16>, Option<u16>, Option<u32>),
) -> EphemeralPortSnapshot {
    let (range_low, range_high, range_size) = range;
    let Some(ps) = proxy_state else {
        return EphemeralPortSnapshot {
            range_low,
            range_high,
            range_size,
            exhaustion_events: 0,
            active_outbound_estimate: 0,
        };
    };

    // Includes in-flight TCP/TLS handshakes (guard created before send()),
    // so the estimate slightly over-counts during connect bursts.
    let reqwest_backend_requests =
        crate::runtime_metrics::global_ref().reqwest_active_backend_requests();
    let stream_backend_sessions = ps.stream_listener_manager.active_backend_session_estimate();
    // Only backend/outbound pools and stream backend sessions consume ephemeral
    // client ports. The reqwest pool entry count is deliberately excluded
    // because it counts cached client objects, not sockets; active reqwest
    // backend requests are tracked while a request is in flight or a streaming
    // response body is still alive.
    let active_outbound_estimate = reqwest_backend_requests
        .saturating_add(ps.grpc_pool.pool_size() as u64)
        .saturating_add(ps.http2_pool.pool_size() as u64)
        .saturating_add(ps.h3_pool.pool_size() as u64)
        .saturating_add(ps.hbone_pool.pool_size() as u64)
        .saturating_add(ps.mesh_mtls_pool.pool_size() as u64)
        .saturating_add(stream_backend_sessions);

    EphemeralPortSnapshot {
        range_low,
        range_high,
        range_size,
        exhaustion_events: ps.overload.port_exhaustion_events.load(Ordering::Relaxed),
        active_outbound_estimate,
    }
}

#[cfg(unix)]
fn process_cpu_us() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let user = timeval_us(usage.ru_utime);
    let sys = timeval_us(usage.ru_stime);
    Some(user.saturating_add(sys))
}

#[cfg(unix)]
fn timeval_us(tv: libc::timeval) -> u64 {
    (tv.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(tv.tv_usec as u64)
}

#[cfg(not(unix))]
fn process_cpu_us() -> Option<u64> {
    None
}

#[derive(Debug, Clone, Copy)]
struct SystemCpuSample {
    idle: u64,
    total: u64,
}

#[cfg(target_os = "linux")]
fn system_cpu_sample() -> Option<SystemCpuSample> {
    let contents = std::fs::read_to_string("/proc/stat").ok()?;
    let line = contents.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let values: Vec<u64> = parts.filter_map(|p| p.parse::<u64>().ok()).collect();
    if values.len() < 4 {
        return None;
    }
    let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
    let total = values.iter().copied().sum();
    Some(SystemCpuSample { idle, total })
}

#[cfg(not(target_os = "linux"))]
fn system_cpu_sample() -> Option<SystemCpuSample> {
    None
}

fn system_cpu_percent(prev: SystemCpuSample, curr: SystemCpuSample) -> Option<f32> {
    let total_delta = curr.total.checked_sub(prev.total)?;
    if total_delta == 0 {
        return None;
    }
    let idle_delta = curr.idle.saturating_sub(prev.idle);
    Some(((total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64 * 100.0) as f32)
}

fn memory_snapshot(
    host_total_bytes: Option<u64>,
    cgroup_limit_bytes: Option<u64>,
) -> MemorySnapshot {
    let (rss_bytes, virtual_bytes) = process_memory_bytes();
    let host_percent = host_total_bytes
        .filter(|total| *total > 0)
        .map(|total| rss_bytes as f64 / total as f64 * 100.0)
        .map(|pct| pct as f32);
    let cgroup_percent = cgroup_limit_bytes
        .filter(|limit| *limit > 0)
        .map(|limit| rss_bytes as f64 / limit as f64 * 100.0)
        .map(|pct| pct as f32);

    MemorySnapshot {
        rss_bytes,
        virtual_bytes,
        host_percent,
        cgroup_percent,
        cgroup_limit_bytes,
        jemalloc_allocated_bytes: jemalloc_allocated_bytes(),
        jemalloc_resident_bytes: jemalloc_resident_bytes(),
    }
}

#[cfg(target_os = "linux")]
fn process_memory_bytes() -> (u64, u64) {
    let Some(contents) = std::fs::read_to_string("/proc/self/statm").ok() else {
        return (0, 0);
    };
    let mut parts = contents.split_whitespace();
    let pages = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    let rss_pages = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
    (
        rss_pages.saturating_mul(page_size),
        pages.saturating_mul(page_size),
    )
}

#[cfg(target_os = "macos")]
fn process_memory_bytes() -> (u64, u64) {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::uninit();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let rc = unsafe {
        libc::task_info(
            task,
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr() as libc::task_info_t,
            &mut count,
        )
    };
    if rc != libc::KERN_SUCCESS {
        return (0, 0);
    }
    let info = unsafe { info.assume_init() };
    (info.resident_size, info.virtual_size)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn process_memory_bytes() -> (u64, u64) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if rc != 0 {
        return (0, 0);
    }
    let usage = unsafe { usage.assume_init() };
    let rss = (usage.ru_maxrss as u64).saturating_mul(1024);
    (rss, 0)
}

#[cfg(not(unix))]
fn process_memory_bytes() -> (u64, u64) {
    (0, 0)
}

#[cfg(target_os = "linux")]
fn host_memory_total_bytes() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn host_memory_total_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn cgroup_memory_limit_bytes() -> Option<u64> {
    read_cgroup_memory_limit_from_paths(
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    )
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_limit_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn read_cgroup_memory_limit_from_paths(v2_path: &str, v1_path: &str) -> Option<u64> {
    if let Some(limit) = read_cgroup_limit_file(v2_path) {
        return Some(limit);
    }
    read_cgroup_limit_file(v1_path)
}

#[cfg(target_os = "linux")]
fn read_cgroup_limit_file(path: &str) -> Option<u64> {
    let value = std::fs::read_to_string(path).ok()?;
    parse_cgroup_limit(value.trim())
}

#[cfg(target_os = "linux")]
fn parse_cgroup_limit(value: &str) -> Option<u64> {
    if value == "max" {
        return None;
    }
    let parsed = value.parse::<u64>().ok()?;
    // Very large v1 values represent "unlimited" on many kernels.
    if parsed >= (1u64 << 60) {
        None
    } else {
        Some(parsed)
    }
}

#[cfg(target_os = "linux")]
fn cgroup_cpu_quota_cores() -> Option<f64> {
    if let Some(cores) = read_cgroup_v2_cpu_quota("/sys/fs/cgroup/cpu.max") {
        return Some(cores);
    }
    read_cgroup_v1_cpu_quota(
        "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
        "/sys/fs/cgroup/cpu/cpu.cfs_period_us",
    )
}

#[cfg(not(target_os = "linux"))]
fn cgroup_cpu_quota_cores() -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn read_cgroup_v2_cpu_quota(path: &str) -> Option<f64> {
    let contents = std::fs::read_to_string(path).ok()?;
    parse_cgroup_v2_cpu_quota(contents.trim())
}

#[cfg(target_os = "linux")]
fn parse_cgroup_v2_cpu_quota(value: &str) -> Option<f64> {
    let mut parts = value.split_whitespace();
    let quota = parts.next()?;
    let period = parts.next()?.parse::<u64>().ok()?;
    if quota == "max" || period == 0 {
        return None;
    }
    let quota = quota.parse::<u64>().ok()?;
    Some(quota as f64 / period as f64)
}

#[cfg(target_os = "linux")]
fn read_cgroup_v1_cpu_quota(quota_path: &str, period_path: &str) -> Option<f64> {
    let quota = std::fs::read_to_string(quota_path)
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()?;
    let period = std::fs::read_to_string(period_path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    if quota <= 0 || period == 0 {
        return None;
    }
    Some(quota as f64 / period as f64)
}

#[cfg(target_os = "linux")]
fn ephemeral_port_range() -> (Option<u16>, Option<u16>, Option<u32>) {
    let Some(contents) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()
    else {
        return (None, None, None);
    };
    parse_ephemeral_port_range(contents.trim())
}

#[cfg(not(target_os = "linux"))]
fn ephemeral_port_range() -> (Option<u16>, Option<u16>, Option<u32>) {
    (None, None, None)
}

#[cfg(target_os = "linux")]
fn parse_ephemeral_port_range(value: &str) -> (Option<u16>, Option<u16>, Option<u32>) {
    let mut parts = value.split_whitespace();
    let low = parts.next().and_then(|p| p.parse::<u16>().ok());
    let high = parts.next().and_then(|p| p.parse::<u16>().ok());
    let size = match (low, high) {
        (Some(low), Some(high)) if high >= low => Some(high as u32 - low as u32 + 1),
        _ => None,
    };
    (low, high, size)
}

#[cfg(not(windows))]
fn jemalloc_allocated_bytes() -> Option<u64> {
    let _ = tikv_jemalloc_ctl::epoch::advance();
    tikv_jemalloc_ctl::stats::allocated::read()
        .ok()
        .map(|v| v as u64)
}

#[cfg(windows)]
fn jemalloc_allocated_bytes() -> Option<u64> {
    None
}

#[cfg(not(windows))]
fn jemalloc_resident_bytes() -> Option<u64> {
    let _ = tikv_jemalloc_ctl::epoch::advance();
    tikv_jemalloc_ctl::stats::resident::read()
        .ok()
        .map(|v| v as u64)
}

#[cfg(windows)]
fn jemalloc_resident_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_cgroup_limit_handles_max_and_large_v1_values() {
        assert_eq!(super::parse_cgroup_limit("max"), None);
        assert_eq!(super::parse_cgroup_limit("1073741824"), Some(1_073_741_824));
        assert_eq!(super::parse_cgroup_limit(&(1u64 << 60).to_string()), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_cgroup_v2_cpu_quota_handles_quota_and_unlimited() {
        assert_eq!(super::parse_cgroup_v2_cpu_quota("max 100000"), None);
        assert_eq!(super::parse_cgroup_v2_cpu_quota("200000 100000"), Some(2.0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ephemeral_port_range_returns_size() {
        assert_eq!(
            super::parse_ephemeral_port_range("32768\t60999"),
            (Some(32768), Some(60999), Some(28232))
        );
    }

    #[cfg(unix)]
    #[test]
    fn sampler_without_proxy_state_reports_process_metrics() {
        let mut sampler = super::SystemSampler::new();
        let snapshot = sampler.sample(None);

        assert!(snapshot.memory.rss_bytes > 0);
        assert!(snapshot.file_descriptors.current > 0);
        assert!(snapshot.file_descriptors.max > 0);
    }

    #[tokio::test]
    async fn ephemeral_snapshot_excludes_frontend_active_connections() {
        let config = crate::config::types::GatewayConfig::default();
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig::default());
        let env_config = crate::config::EnvConfig::default();
        let (proxy_state, _handles) =
            crate::proxy::ProxyState::new(config, dns_cache, env_config, None, None)
                .expect("proxy state");

        proxy_state
            .overload
            .active_connections
            .store(500, Ordering::Relaxed);

        let snapshot =
            super::ephemeral_snapshot(Some(&proxy_state), (Some(32768), Some(60999), Some(28232)));

        assert_eq!(snapshot.active_outbound_estimate, 0);
    }
}
