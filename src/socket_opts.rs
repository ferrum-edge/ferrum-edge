//! Platform-specific socket optimizations inspired by Cloudflare Pingora.
//!
//! Provides `IP_BIND_ADDRESS_NO_PORT` (defers ephemeral port allocation to connect()),
//! `TCP_FASTOPEN` (saves 1 RTT on repeat connections), and `TCP_INFO` access for
//! kernel-level connection diagnostics. All functions are no-ops on non-Linux platforms.

#[cfg(target_os = "linux")]
use tracing::debug;

// ── IP_BIND_ADDRESS_NO_PORT ─────────────────────────────────────────────────

/// Enable `IP_BIND_ADDRESS_NO_PORT` on a socket (Linux only).
///
/// Tells the kernel to defer ephemeral source port allocation until `connect()`,
/// enabling 4-tuple (src_ip, src_port, dst_ip, dst_port) co-selection.
/// This prevents ephemeral port exhaustion under high outbound connection rates
/// because the same source port can be reused for connections to different destinations.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn set_ip_bind_address_no_port(
    fd: std::os::unix::io::RawFd,
    enable: bool,
) -> std::io::Result<()> {
    // IP_BIND_ADDRESS_NO_PORT = 24 (Linux 4.2+)
    const IP_BIND_ADDRESS_NO_PORT: libc::c_int = 24;
    let val: libc::c_int = if enable { 1 } else { 0 };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_BIND_ADDRESS_NO_PORT,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_ip_bind_address_no_port(_fd: i32, _enable: bool) -> std::io::Result<()> {
    Ok(()) // No-op on non-Linux
}

// ── TCP_FASTOPEN ────────────────────────────────────────────────────────────

/// Enable `TCP_FASTOPEN` on a server (listening) socket (Linux only).
///
/// Allows the server to accept data in the SYN packet, saving 1 RTT for repeat
/// clients that have cached a TFO cookie. The `queue_len` controls the maximum
/// pending TFO connections.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn set_tcp_fastopen_server(
    fd: std::os::unix::io::RawFd,
    queue_len: i32,
) -> std::io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &queue_len as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    debug!(
        "TCP_FASTOPEN enabled on server socket (queue_len={})",
        queue_len
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_tcp_fastopen_server(_fd: i32, _queue_len: i32) -> std::io::Result<()> {
    Ok(())
}

/// Enable `TCP_FASTOPEN_CONNECT` on a client (connecting) socket (Linux only).
///
/// Allows the client to send data in the SYN packet on repeat connections,
/// saving 1 RTT. The first connection to each peer establishes a TFO cookie;
/// subsequent connections use it.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn set_tcp_fastopen_client(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    // TCP_FASTOPEN_CONNECT = 30 (Linux 4.11+)
    const TCP_FASTOPEN_CONNECT: libc::c_int = 30;
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_FASTOPEN_CONNECT,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_tcp_fastopen_client(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

// ── TCP_INFO ────────────────────────────────────────────────────────────────

/// Kernel TCP connection metrics from `getsockopt(TCP_INFO)`.
///
/// Provides RTT, congestion window, and retransmission stats for adaptive
/// buffer sizing and connection diagnostics.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API for TCP_INFO diagnostics, used by lib consumers
pub struct TcpConnectionInfo {
    /// Smoothed RTT in microseconds.
    pub rtt_us: u32,
    /// RTT variance in microseconds.
    pub rtt_var_us: u32,
    /// Sender congestion window (in segments).
    pub snd_cwnd: u32,
    /// Sender MSS (maximum segment size) in bytes.
    pub snd_mss: u32,
    /// Total retransmitted segments.
    pub total_retrans: u32,
}

#[cfg(target_os = "linux")]
impl TcpConnectionInfo {
    /// Compute the bandwidth-delay product (BDP) in bytes.
    ///
    /// BDP = cwnd * MSS. This represents the kernel's estimate of how much
    /// data can be in flight on this connection, which is the optimal buffer
    /// size for maximizing throughput without causing congestion.
    #[allow(dead_code)]
    pub fn bdp_bytes(&self) -> usize {
        (self.snd_cwnd as usize) * (self.snd_mss as usize)
    }
}

/// Retrieve TCP connection info from the kernel via `getsockopt(TCP_INFO)`.
///
/// Returns `None` on non-Linux platforms or if the syscall fails.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn get_tcp_info(fd: std::os::unix::io::RawFd) -> Option<TcpConnectionInfo> {
    // Use MaybeUninit to avoid initializing the large tcp_info struct
    let mut info = std::mem::MaybeUninit::<libc::tcp_info>::uninit();
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some(TcpConnectionInfo {
        rtt_us: info.tcpi_rtt,
        rtt_var_us: info.tcpi_rttvar,
        snd_cwnd: info.tcpi_snd_cwnd,
        snd_mss: info.tcpi_snd_mss,
        total_retrans: info.tcpi_total_retrans,
    })
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API for TCP_INFO diagnostics, used by lib consumers
pub struct TcpConnectionInfo {
    /// Smoothed RTT in microseconds.
    pub rtt_us: u32,
    /// RTT variance in microseconds.
    pub rtt_var_us: u32,
    /// Sender congestion window (in segments).
    pub snd_cwnd: u32,
    /// Sender MSS (maximum segment size) in bytes.
    pub snd_mss: u32,
    /// Total retransmitted segments.
    pub total_retrans: u32,
}

#[cfg(not(target_os = "linux"))]
impl TcpConnectionInfo {
    /// Compute the bandwidth-delay product (BDP) in bytes.
    ///
    /// BDP = cwnd * MSS. This represents the kernel's estimate of how much
    /// data can be in flight on this connection, which is the optimal buffer
    /// size for maximizing throughput without causing congestion.
    #[allow(dead_code)]
    pub fn bdp_bytes(&self) -> usize {
        (self.snd_cwnd as usize) * (self.snd_mss as usize)
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn get_tcp_info(_fd: i32) -> Option<TcpConnectionInfo> {
    None
}
