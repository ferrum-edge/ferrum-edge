//! Client-owned resource snapshots at the measurement boundaries.

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ClientUsage {
    pub pid: u32,
    pub role: &'static str,
    pub complete_bracket: bool,
    pub cpu_seconds: f64,
    pub user_cpu_seconds: f64,
    pub system_cpu_seconds: f64,
    pub voluntary_ctxt_switches: i64,
    pub nonvoluntary_ctxt_switches: i64,
    pub peak_rss_bytes: u64,
    pub rss_scope: &'static str,
    pub bracket_secs: f64,
    pub boundary_slack_secs: f64,
}

pub struct Snapshot {
    cpu_seconds: f64,
    user_cpu_seconds: f64,
    system_cpu_seconds: f64,
    voluntary_ctxt_switches: i64,
    nonvoluntary_ctxt_switches: i64,
    peak_rss_bytes: u64,
}

impl Snapshot {
    #[cfg(unix)]
    pub fn capture() -> std::io::Result<Self> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage writes this correctly sized, uniquely borrowed
        // output. Only assume initialization after the successful return.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let usage = unsafe { usage.assume_init() };
        let user_cpu_seconds =
            usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
        let system_cpu_seconds =
            usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
        let cpu_seconds = user_cpu_seconds + system_cpu_seconds;
        let peak_rss_bytes = usage.ru_maxrss.max(0) as u64;
        #[cfg(not(target_os = "macos"))]
        let peak_rss_bytes = peak_rss_bytes * 1024;
        Ok(Self {
            cpu_seconds,
            user_cpu_seconds,
            system_cpu_seconds,
            voluntary_ctxt_switches: usage.ru_nvcsw,
            nonvoluntary_ctxt_switches: usage.ru_nivcsw,
            peak_rss_bytes,
        })
    }

    #[cfg(not(unix))]
    pub fn capture() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "client getrusage unavailable",
        ))
    }

    pub fn finish(self, end: Self, elapsed: f64, nominal: f64) -> ClientUsage {
        ClientUsage {
            pid: std::process::id(),
            role: "client",
            complete_bracket: end.user_cpu_seconds >= self.user_cpu_seconds
                && end.system_cpu_seconds >= self.system_cpu_seconds
                && end.voluntary_ctxt_switches >= self.voluntary_ctxt_switches
                && end.nonvoluntary_ctxt_switches >= self.nonvoluntary_ctxt_switches,
            cpu_seconds: end.cpu_seconds - self.cpu_seconds,
            user_cpu_seconds: end.user_cpu_seconds - self.user_cpu_seconds,
            system_cpu_seconds: end.system_cpu_seconds - self.system_cpu_seconds,
            voluntary_ctxt_switches: end.voluntary_ctxt_switches - self.voluntary_ctxt_switches,
            nonvoluntary_ctxt_switches: end.nonvoluntary_ctxt_switches
                - self.nonvoluntary_ctxt_switches,
            peak_rss_bytes: end.peak_rss_bytes,
            rss_scope: "process lifetime high-water mark at measurement end",
            bracket_secs: elapsed,
            boundary_slack_secs: (elapsed - nominal).max(0.0),
        }
    }
}
