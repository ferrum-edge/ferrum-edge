//! Platform-specific socket optimizations inspired by Cloudflare Pingora.
//!
//! Provides `IP_BIND_ADDRESS_NO_PORT` (defers ephemeral port allocation to connect()),
//! `TCP_FASTOPEN` (saves 1 RTT on repeat connections), `TCP_INFO` access for
//! kernel-level BDP-optimal buffer sizing, `SO_BUSY_POLL` for low-latency UDP,
//! `UDP_GRO`/`UDP_SEGMENT` for kernel-level
//! datagram batching, and `kTLS` for enabling splice(2) on TLS paths.
//! All functions are no-ops on non-Linux platforms.

#[cfg(target_os = "linux")]
use tracing::debug;

// ── Monotonic coarse clock ──────────────────────────────────────────────────

/// Returns monotonic milliseconds since the first call to this function.
///
/// Uses `std::time::Instant` under a `OnceLock` so the clock NEVER goes
/// backwards, regardless of NTP slew, admin clock changes, or daylight
/// savings transitions. `SystemTime::now()` (wall clock) must not be used
/// for idle-timeout tracking because `saturating_sub` would pin the
/// elapsed duration at 0 after a backwards clock jump, and the timeout
/// would never fire.
///
/// Resolution is sub-microsecond (matches `Instant`). The value has no
/// meaningful zero — it is only defined relative to prior calls within
/// the same process.
#[inline]
pub fn monotonic_now_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn set_tcp_fastopen_client(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

// ── TCP_INFO (BDP-optimal buffer sizing) ───────────────────────────────

/// Kernel-level TCP connection metrics from `getsockopt(TCP_INFO)`.
///
/// Used to compute Bandwidth-Delay Product (BDP) for optimal buffer sizing
/// on long-lived TCP stream connections. BDP = (rtt_us / 1_000_000) × cwnd × mss.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TcpConnectionInfo {
    /// Smoothed round-trip time in microseconds (SRTT).
    pub rtt_us: u32,
    /// Congestion window in segments.
    pub snd_cwnd: u32,
    /// Maximum segment size in bytes.
    pub snd_mss: u32,
}

#[allow(dead_code)]
impl TcpConnectionInfo {
    /// Compute the Bandwidth-Delay Product in bytes.
    ///
    /// BDP represents the optimal amount of data in-flight between sender and
    /// receiver. Socket buffers sized to BDP maximize throughput without waste.
    pub fn bdp_bytes(&self) -> usize {
        if self.rtt_us == 0 || self.snd_cwnd == 0 || self.snd_mss == 0 {
            return 0;
        }
        // cwnd × mss gives the current congestion window in bytes.
        // This already reflects the BDP as the kernel adjusts cwnd based on RTT.
        (self.snd_cwnd as usize).saturating_mul(self.snd_mss as usize)
    }
}

/// Retrieve TCP connection info from the kernel via `getsockopt(TCP_INFO)`.
///
/// Returns RTT, congestion window, and MSS for BDP-optimal buffer sizing.
/// Linux 2.6+ only. No-op on non-Linux (returns `None`).
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn get_tcp_info(fd: std::os::unix::io::RawFd) -> Option<TcpConnectionInfo> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut libc::tcp_info as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    Some(TcpConnectionInfo {
        rtt_us: info.tcpi_rtt,
        snd_cwnd: info.tcpi_snd_cwnd,
        snd_mss: info.tcpi_snd_mss,
    })
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn get_tcp_info(_fd: i32) -> Option<TcpConnectionInfo> {
    None
}

// ── SO_BUSY_POLL (low-latency polling) ─────────────────────────────────

/// Enable `SO_BUSY_POLL` on a socket (Linux 3.11+ only).
///
/// When set, the kernel spins for up to `busy_poll_us` microseconds waiting
/// for incoming data before sleeping. This reduces receive latency at the cost
/// of CPU. Useful for latency-sensitive UDP proxying.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn set_so_busy_poll(fd: std::os::unix::io::RawFd, busy_poll_us: u32) -> std::io::Result<()> {
    let val = busy_poll_us as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    debug!("SO_BUSY_POLL enabled ({}µs)", busy_poll_us);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_so_busy_poll(_fd: i32, _busy_poll_us: u32) -> std::io::Result<()> {
    Ok(())
}

/// Enable `SO_PREFER_BUSY_POLL` on a socket (Linux 5.11+ only).
///
/// Stronger preference for busy-polling over interrupt-driven recv.
/// Should be combined with `SO_BUSY_POLL` for maximum effect.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn set_so_prefer_busy_poll(fd: std::os::unix::io::RawFd, enable: bool) -> std::io::Result<()> {
    // SO_PREFER_BUSY_POLL = 69 (Linux 5.11+)
    const SO_PREFER_BUSY_POLL: libc::c_int = 69;
    let val: libc::c_int = if enable { 1 } else { 0 };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PREFER_BUSY_POLL,
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
#[allow(dead_code)]
pub fn set_so_prefer_busy_poll(_fd: i32, _enable: bool) -> std::io::Result<()> {
    Ok(())
}

// ── UDP GRO (Generic Receive Offload) ──────────────────────────────────

/// Enable `UDP_GRO` on a UDP socket (Linux 5.0+ only).
///
/// Tells the kernel to coalesce multiple same-size UDP datagrams into a single
/// large buffer on receive. The application reads one large buffer and splits
/// it by the GRO segment size. More efficient than `recvmmsg` because it avoids
/// per-datagram metadata overhead and reduces cache pressure.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // GRO infrastructure ready but not active (recv_from lacks cmsg)
pub fn set_udp_gro(fd: std::os::unix::io::RawFd, enable: bool) -> std::io::Result<()> {
    // UDP_GRO = 104 (Linux 5.0+)
    const UDP_GRO: libc::c_int = 104;
    let val: libc::c_int = if enable { 1 } else { 0 };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            UDP_GRO,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    debug!("UDP_GRO enabled on socket");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_udp_gro(_fd: i32, _enable: bool) -> std::io::Result<()> {
    Ok(())
}

// ── UDP GSO (Generic Segmentation Offload) ─────────────────────────────

/// Enable `UDP_SEGMENT` (GSO) for batched UDP sending (Linux 4.18+ only).
///
/// Allows sending multiple datagrams in a single `sendmsg()` call by specifying
/// a segment size via ancillary data. The kernel (or NIC if offload-capable) splits
/// the large buffer into individual datagrams. Dramatically reduces syscall overhead
/// for high-rate UDP sending.
///
/// Call `send_with_gso()` to use GSO-enabled sends after enabling this option.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn send_with_gso(
    fd: std::os::unix::io::RawFd,
    data: &[u8],
    segment_size: u16,
    dest: &libc::sockaddr_storage,
    dest_len: libc::socklen_t,
) -> std::io::Result<usize> {
    // UDP_SEGMENT = 103 (Linux 4.18+)
    const UDP_SEGMENT: libc::c_int = 103;

    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    // Build control message for UDP_SEGMENT (GSO segment size).
    // cmsg layout: cmsg_hdr + u16 segment_size
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = dest as *const libc::sockaddr_storage as *mut libc::c_void;
    msg.msg_namelen = dest_len;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    // Fill in the cmsg header and data.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &segment_size as *const u16 as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<u16>(),
        );
    }

    let ret = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ret as usize)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn send_with_gso(
    _fd: i32,
    _data: &[u8],
    _segment_size: u16,
    _dest: &(),
    _dest_len: u32,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "UDP GSO not available on this platform",
    ))
}

/// Read the GRO segment size from a received GRO-coalesced datagram.
///
/// After `recvmsg()` with `UDP_GRO` enabled, the kernel attaches a
/// `UDP_GRO` cmsg with the segment size. The application uses this to
/// split the coalesced buffer into individual datagrams.
///
/// Returns `None` if no GRO cmsg was present (single datagram).
#[cfg(target_os = "linux")]
pub fn extract_gro_segment_size(msg: &libc::msghdr) -> Option<u16> {
    const UDP_GRO: libc::c_int = 104;

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == UDP_GRO {
                let data_ptr = libc::CMSG_DATA(cmsg);
                let mut segment_size: u16 = 0;
                std::ptr::copy_nonoverlapping(
                    data_ptr,
                    &mut segment_size as *mut u16 as *mut u8,
                    std::mem::size_of::<u16>(),
                );
                return Some(segment_size);
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn extract_gro_segment_size(_msg: &()) -> Option<u16> {
    None
}

// ── IP_PKTINFO / IPV6_PKTINFO ──────────────────────────────────────────
//
// Tells the kernel to attach the destination address of inbound datagrams as a
// cmsg on recv, and (on send) to use a specific source address without a
// routing-table lookup. Combining this with `UDP_SEGMENT` (GSO) in a single
// `sendmsg` call saves one routing lookup per GSO batch flush — worth ~2% at
// 100K+ datagrams/sec on hosts with large routing tables.
//
// Must be paired on a wildcard-bound listener so each session can capture the
// per-datagram destination (the address the client sent to) and reuse it as
// the reply source. Without pktinfo, a multi-homed server's kernel picks the
// outgoing interface via routing decisions, which may differ from the
// inbound interface and break stateful middleboxes / NAT.

/// Enable `IP_PKTINFO` (IPv4) on a UDP socket (Linux only).
///
/// After enabling, recvmsg()/recvmmsg() cmsg buffers will contain the
/// `in_pktinfo` struct carrying `ipi_spec_dst` — the address the packet
/// was addressed to.
#[cfg(target_os = "linux")]
pub fn set_ip_pktinfo(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Enable `IPV6_RECVPKTINFO` on a UDP socket (Linux only).
#[cfg(target_os = "linux")]
pub fn set_ipv6_recvpktinfo(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
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
#[allow(dead_code)]
pub fn set_ip_pktinfo(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_ipv6_recvpktinfo(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

/// Captured local (reply-source) address from an `IP_PKTINFO` / `IPV6_PKTINFO`
/// cmsg. The interface index is preserved so scoped IPv6 replies (notably
/// link-local `fe80::/10`) egress the correct interface zone on send; for IPv4
/// it's informational and safe to leave at 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PktinfoLocal {
    pub ip: std::net::IpAddr,
    pub ifindex: u32,
}

/// Parse an `IP_PKTINFO` or `IPV6_PKTINFO` cmsg and return the captured local
/// address along with its interface index.
///
/// Returns `None` if neither cmsg is present.
#[cfg(target_os = "linux")]
pub fn extract_pktinfo_local_addr(msg: &libc::msghdr) -> Option<PktinfoLocal> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        unsafe {
            let level = (*cmsg).cmsg_level;
            let ty = (*cmsg).cmsg_type;
            if level == libc::IPPROTO_IP && ty == libc::IP_PKTINFO {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                // `ipi_spec_dst` is the destination address on the packet as
                // received (what the client targeted). `ipi_addr` is the
                // local host's header dst after routing — for reply-source
                // selection we want `ipi_spec_dst`.
                let pi = std::ptr::read_unaligned(data_ptr);
                return Some(PktinfoLocal {
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                        pi.ipi_spec_dst.s_addr,
                    ))),
                    ifindex: pi.ipi_ifindex as u32,
                });
            }
            if level == libc::IPPROTO_IPV6 && ty == libc::IPV6_PKTINFO {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                let pi = std::ptr::read_unaligned(data_ptr);
                return Some(PktinfoLocal {
                    ip: std::net::IpAddr::V6(std::net::Ipv6Addr::from(pi.ipi6_addr.s6_addr)),
                    ifindex: pi.ipi6_ifindex,
                });
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn extract_pktinfo_local_addr(_msg: &()) -> Option<PktinfoLocal> {
    None
}

/// Cmsg buffer size large enough to hold UDP_GRO (u16) plus either IP_PKTINFO
/// or IPV6_PKTINFO on recv. Sized for the worst case (IPv6) so a single
/// allocation works for both address families.
#[cfg(target_os = "linux")]
pub fn recv_cmsg_space() -> usize {
    unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize
            + libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize
    }
}

/// Send a UDP datagram (or a GSO-batched buffer of same-size datagrams) with
/// the source address set via `IP_PKTINFO` / `IPV6_PKTINFO` ancillary data.
///
/// When `gso_segment_size` is `Some(n)`, the kernel treats `data` as a series
/// of `n`-byte datagrams (last may be shorter) and an additional `UDP_SEGMENT`
/// cmsg is attached — combining pktinfo with GSO in a single `sendmsg(2)` call.
///
/// `local_ip` is the source IP to use; its family must match `dest`. On v4 a
/// v4-mapped v6 address would be silently rejected.
#[cfg(target_os = "linux")]
pub fn send_with_pktinfo(
    fd: std::os::unix::io::RawFd,
    data: &[u8],
    local: PktinfoLocal,
    dest: &libc::sockaddr_storage,
    dest_len: libc::socklen_t,
    gso_segment_size: Option<u16>,
) -> std::io::Result<usize> {
    let local_ip = local.ip;
    let ifindex = local.ifindex;
    const UDP_SEGMENT: libc::c_int = 103;

    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    // Compute cmsg buffer: pktinfo (v4 or v6) + optional UDP_SEGMENT.
    let pktinfo_space = match local_ip {
        std::net::IpAddr::V4(_) => unsafe {
            libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize
        },
        std::net::IpAddr::V6(_) => unsafe {
            libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize
        },
    };
    let gso_space = if gso_segment_size.is_some() {
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize }
    } else {
        0
    };
    let mut cmsg_buf = vec![0u8; pktinfo_space + gso_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = dest as *const libc::sockaddr_storage as *mut libc::c_void;
    msg.msg_namelen = dest_len;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    // First cmsg: pktinfo.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
    }
    match local_ip {
        std::net::IpAddr::V4(v4) => unsafe {
            (*cmsg).cmsg_level = libc::IPPROTO_IP;
            (*cmsg).cmsg_type = libc::IP_PKTINFO;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
            // ipi_ifindex intentionally 0 for IPv4: per ip(7), a nonzero
            // ifindex makes the kernel prefer the interface's primary address
            // over ipi_spec_dst on multi-IP interfaces, which would defeat the
            // "reply from captured destination" semantics. ipi_spec_dst alone
            // is sufficient on IPv4; ifindex is only honored for IPv6 scopes.
            let pi = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr {
                    s_addr: u32::from(v4).to_be(),
                },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            std::ptr::copy_nonoverlapping(
                &pi as *const libc::in_pktinfo as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<libc::in_pktinfo>(),
            );
        },
        std::net::IpAddr::V6(v6) => unsafe {
            (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
            (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize;
            let pi = libc::in6_pktinfo {
                ipi6_addr: libc::in6_addr {
                    s6_addr: v6.octets(),
                },
                ipi6_ifindex: ifindex,
            };
            std::ptr::copy_nonoverlapping(
                &pi as *const libc::in6_pktinfo as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<libc::in6_pktinfo>(),
            );
        },
    }

    // Optional second cmsg: UDP_SEGMENT (GSO).
    if let Some(seg) = gso_segment_size {
        let next = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        if next.is_null() {
            return Err(std::io::Error::other("CMSG_NXTHDR returned null for GSO"));
        }
        unsafe {
            (*next).cmsg_level = libc::SOL_UDP;
            (*next).cmsg_type = UDP_SEGMENT;
            (*next).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as usize;
            std::ptr::copy_nonoverlapping(
                &seg as *const u16 as *const u8,
                libc::CMSG_DATA(next),
                std::mem::size_of::<u16>(),
            );
        }
    }

    let ret = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ret as usize)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn send_with_pktinfo(
    _fd: i32,
    _data: &[u8],
    _local: PktinfoLocal,
    _dest: &(),
    _dest_len: u32,
    _gso_segment_size: Option<u16>,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "IP_PKTINFO not available on this platform",
    ))
}

/// Probe whether pktinfo can be enabled on a UDP socket (Linux only).
///
/// Tries `IP_PKTINFO` on a v4 socket and `IPV6_RECVPKTINFO` on a v6 socket.
/// Returns `true` if either succeeds — sufficient for enabling auto mode on
/// IPv4-only, IPv6-only, or dual-stack hosts.
#[cfg(target_os = "linux")]
pub fn is_udp_pktinfo_available() -> bool {
    let v4_ok = {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            false
        } else {
            let ok = set_ip_pktinfo(fd).is_ok();
            unsafe { libc::close(fd) };
            ok
        }
    };
    let v6_ok = {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            false
        } else {
            let ok = set_ipv6_recvpktinfo(fd).is_ok();
            unsafe { libc::close(fd) };
            ok
        }
    };
    v4_ok || v6_ok
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn is_udp_pktinfo_available() -> bool {
    false
}

// ── kTLS (kernel TLS for splice on encrypted paths) ────────────────────

/// kTLS crypto information for installing TLS session keys into the kernel.
///
/// After the TLS handshake completes in userspace (rustls), the symmetric
/// session keys can be installed into the kernel via `setsockopt(SOL_TLS)`.
/// This enables `splice(2)` to work on TLS-encrypted connections because
/// encryption/decryption is handled in the kernel rather than userspace.
///
/// Supported cipher suites: AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
/// AES-GCM kTLS landed in Linux 4.13/4.17; ChaCha20-Poly1305 kTLS requires
/// Linux 5.11+.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod ktls {
    use tracing::debug;
    use zeroize::{Zeroize, Zeroizing};

    // Linux TLS ULP constants (from <linux/tls.h>)
    const SOL_TLS: libc::c_int = 282;
    const TLS_TX: libc::c_int = 1;
    const TLS_RX: libc::c_int = 2;

    const TLS_1_2_VERSION: u16 = 0x0303;
    const TLS_1_3_VERSION: u16 = 0x0304;

    const TLS_CIPHER_AES_GCM_128: u16 = 51;
    const TLS_CIPHER_AES_GCM_256: u16 = 52;
    // TLS_CIPHER_CHACHA20_POLY1305 = 54 (Linux 5.11+).
    const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

    /// AES-128-GCM crypto info for kTLS (matches `struct tls12_crypto_info_aes_gcm_128`).
    #[repr(C)]
    struct TlsCryptoInfoAes128Gcm {
        version: u16,
        cipher_type: u16,
        iv: [u8; 8],
        key: [u8; 16],
        salt: [u8; 4],
        rec_seq: [u8; 8],
    }

    // Session keys are confidential. Volatile-zero them on drop so core dumps
    // or post-free heap reads cannot recover them. `[u8; N]` impls `Zeroize`
    // for all `N` via the `zeroize` crate, so we can call it field-by-field.
    impl Drop for TlsCryptoInfoAes128Gcm {
        fn drop(&mut self) {
            self.key.zeroize();
            self.iv.zeroize();
            self.salt.zeroize();
            self.rec_seq.zeroize();
        }
    }

    /// AES-256-GCM crypto info for kTLS (matches `struct tls12_crypto_info_aes_gcm_256`).
    #[repr(C)]
    struct TlsCryptoInfoAes256Gcm {
        version: u16,
        cipher_type: u16,
        iv: [u8; 8],
        key: [u8; 32],
        salt: [u8; 4],
        rec_seq: [u8; 8],
    }

    impl Drop for TlsCryptoInfoAes256Gcm {
        fn drop(&mut self) {
            self.key.zeroize();
            self.iv.zeroize();
            self.salt.zeroize();
            self.rec_seq.zeroize();
        }
    }

    /// ChaCha20-Poly1305 crypto info for kTLS (matches
    /// `struct tls12_crypto_info_chacha20_poly1305` from Linux 5.11+
    /// `include/uapi/linux/tls.h`).
    ///
    /// Layout: `version`, `cipher_type`, `iv[12]`, `key[32]`, `salt[4]`
    /// (present but unused by the kernel — ChaCha20-Poly1305 uses the full
    /// 12-byte IV directly with no salt/explicit-nonce split like AES-GCM),
    /// `rec_seq[8]`.
    #[repr(C)]
    struct TlsCryptoInfoChaCha20Poly1305 {
        version: u16,
        cipher_type: u16,
        iv: [u8; 12],
        key: [u8; 32],
        salt: [u8; 4],
        rec_seq: [u8; 8],
    }

    impl Drop for TlsCryptoInfoChaCha20Poly1305 {
        fn drop(&mut self) {
            self.key.zeroize();
            self.iv.zeroize();
            self.salt.zeroize();
            self.rec_seq.zeroize();
        }
    }

    /// Parameters needed to install kTLS on a socket.
    ///
    /// Key and IV material is wrapped in `Zeroizing<Vec<u8>>` so the
    /// heap allocations are volatile-zeroed when the params are dropped.
    /// `Zeroizing<T>` impls `Deref<Target = T>`, so `.as_ref()`,
    /// `.copy_from_slice()`, `.len()`, and slice indexing all continue
    /// to work transparently at the call sites.
    pub struct KtlsParams {
        pub tls_version: u16,
        pub cipher_suite: KtlsCipher,
        pub tx_key: Zeroizing<Vec<u8>>,
        pub tx_iv: Zeroizing<Vec<u8>>,
        pub tx_seq: [u8; 8],
        pub rx_key: Zeroizing<Vec<u8>>,
        pub rx_iv: Zeroizing<Vec<u8>>,
        pub rx_seq: [u8; 8],
    }

    /// Supported kTLS cipher suites.
    #[derive(Debug, Clone, Copy)]
    pub enum KtlsCipher {
        Aes128Gcm,
        Aes256Gcm,
        /// ChaCha20-Poly1305 — requires Linux 5.11+ for kTLS support.
        /// (AES-GCM kTLS support landed in 4.13/4.17.)
        Chacha20Poly1305,
    }

    /// Attempt to enable kTLS on a connected TCP socket.
    ///
    /// Steps:
    /// 1. Set TCP_ULP to "tls" to install the TLS upper-layer protocol handler
    /// 2. Set SOL_TLS/TLS_TX with the transmit key material
    /// 3. Set SOL_TLS/TLS_RX with the receive key material
    ///
    /// Returns `Ok(true)` if kTLS was successfully enabled, `Ok(false)` if
    /// the kernel doesn't support kTLS (ENOPROTOOPT), and `Err` on other failures.
    pub fn enable_ktls(fd: std::os::unix::io::RawFd, params: &KtlsParams) -> std::io::Result<bool> {
        // Step 1: Install the TLS ULP on the socket.
        let ulp_name = b"tls\0";
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_ULP,
                ulp_name.as_ptr() as *const libc::c_void,
                ulp_name.len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
                // Kernel doesn't support kTLS — fall back silently.
                return Ok(false);
            }
            if err.raw_os_error() == Some(libc::EEXIST) {
                // TCP_ULP already installed (e.g., by pre-flight probe) — continue.
            } else {
                return Err(err);
            }
        }

        let tls_version = match params.tls_version {
            0x0303 => TLS_1_2_VERSION,
            0x0304 => TLS_1_3_VERSION,
            v => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsupported TLS version for kTLS: 0x{:04x}", v),
                ));
            }
        };

        // Step 2 & 3: Install TX and RX keys.
        match params.cipher_suite {
            KtlsCipher::Aes128Gcm => {
                install_aes128gcm(
                    fd,
                    tls_version,
                    true,
                    &params.tx_key,
                    &params.tx_iv,
                    &params.tx_seq,
                )?;
                install_aes128gcm(
                    fd,
                    tls_version,
                    false,
                    &params.rx_key,
                    &params.rx_iv,
                    &params.rx_seq,
                )?;
            }
            KtlsCipher::Aes256Gcm => {
                install_aes256gcm(
                    fd,
                    tls_version,
                    true,
                    &params.tx_key,
                    &params.tx_iv,
                    &params.tx_seq,
                )?;
                install_aes256gcm(
                    fd,
                    tls_version,
                    false,
                    &params.rx_key,
                    &params.rx_iv,
                    &params.rx_seq,
                )?;
            }
            KtlsCipher::Chacha20Poly1305 => {
                install_chacha20_poly1305(
                    fd,
                    tls_version,
                    true,
                    &params.tx_key,
                    &params.tx_iv,
                    &params.tx_seq,
                )?;
                install_chacha20_poly1305(
                    fd,
                    tls_version,
                    false,
                    &params.rx_key,
                    &params.rx_iv,
                    &params.rx_seq,
                )?;
            }
        }

        debug!("kTLS enabled on fd {}", fd);
        Ok(true)
    }

    fn install_aes128gcm(
        fd: std::os::unix::io::RawFd,
        version: u16,
        is_tx: bool,
        key: &[u8],
        iv: &[u8],
        seq: &[u8; 8],
    ) -> std::io::Result<()> {
        if key.len() != 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "AES-128-GCM key must be 16 bytes",
            ));
        }

        let mut info = TlsCryptoInfoAes128Gcm {
            version,
            cipher_type: TLS_CIPHER_AES_GCM_128,
            iv: [0u8; 8],
            key: [0u8; 16],
            salt: [0u8; 4],
            rec_seq: *seq,
        };
        info.key.copy_from_slice(key);
        // IV must be exactly 12 bytes for AES-GCM (4 salt + 8 explicit nonce).
        if iv.len() < 12 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("AES-128-GCM IV must be 12 bytes, got {}", iv.len()),
            ));
        }
        info.salt.copy_from_slice(&iv[..4]);
        info.iv.copy_from_slice(&iv[4..12]);

        let optname = if is_tx { TLS_TX } else { TLS_RX };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_TLS,
                optname,
                &info as *const TlsCryptoInfoAes128Gcm as *const libc::c_void,
                std::mem::size_of::<TlsCryptoInfoAes128Gcm>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn install_aes256gcm(
        fd: std::os::unix::io::RawFd,
        version: u16,
        is_tx: bool,
        key: &[u8],
        iv: &[u8],
        seq: &[u8; 8],
    ) -> std::io::Result<()> {
        if key.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "AES-256-GCM key must be 32 bytes",
            ));
        }

        let mut info = TlsCryptoInfoAes256Gcm {
            version,
            cipher_type: TLS_CIPHER_AES_GCM_256,
            iv: [0u8; 8],
            key: [0u8; 32],
            salt: [0u8; 4],
            rec_seq: *seq,
        };
        info.key.copy_from_slice(key);
        if iv.len() < 12 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("AES-256-GCM IV must be 12 bytes, got {}", iv.len()),
            ));
        }
        info.salt.copy_from_slice(&iv[..4]);
        info.iv.copy_from_slice(&iv[4..12]);

        let optname = if is_tx { TLS_TX } else { TLS_RX };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_TLS,
                optname,
                &info as *const TlsCryptoInfoAes256Gcm as *const libc::c_void,
                std::mem::size_of::<TlsCryptoInfoAes256Gcm>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn install_chacha20_poly1305(
        fd: std::os::unix::io::RawFd,
        version: u16,
        is_tx: bool,
        key: &[u8],
        iv: &[u8],
        seq: &[u8; 8],
    ) -> std::io::Result<()> {
        if key.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ChaCha20-Poly1305 key must be 32 bytes",
            ));
        }
        // ChaCha20-Poly1305 uses the full 12-byte IV directly (no salt split).
        if iv.len() != 12 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("ChaCha20-Poly1305 IV must be 12 bytes, got {}", iv.len()),
            ));
        }

        let mut info = TlsCryptoInfoChaCha20Poly1305 {
            version,
            cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
            iv: [0u8; 12],
            key: [0u8; 32],
            // `salt` is present in the struct for layout parity with AES-GCM
            // but is unused by the kernel for ChaCha20-Poly1305.
            salt: [0u8; 4],
            rec_seq: *seq,
        };
        info.key.copy_from_slice(key);
        info.iv.copy_from_slice(iv);

        let optname = if is_tx { TLS_TX } else { TLS_RX };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_TLS,
                optname,
                &info as *const TlsCryptoInfoChaCha20Poly1305 as *const libc::c_void,
                std::mem::size_of::<TlsCryptoInfoChaCha20Poly1305>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Check if kTLS is available on this kernel.
    ///
    /// Per-cipher kTLS availability, probed once at first call to
    /// `is_ktls_available()` / the per-cipher accessors. The three cipher
    /// suites kTLS supports landed in different kernel versions (AES-GCM
    /// in 4.13/4.17, ChaCha20-Poly1305 in 5.11+), so a blanket "kTLS is
    /// available" answer is incorrect: a kernel may accept the ULP and
    /// AES-128-GCM key install but reject ChaCha20-Poly1305 with EINVAL /
    /// EOPNOTSUPP.
    ///
    /// We must probe each cipher independently. If we probed only AES-128
    /// and then tried to install ChaCha20 keys at runtime, the install
    /// would fail AFTER we have already consumed the TLS stream via
    /// `into_inner()` + `dangerous_extract_secrets()` — at which point
    /// there is no safe way back to userspace TLS, forcing a hard
    /// connection drop. The per-cipher gate in `try_ktls_splice` prevents
    /// this by refusing connections for ciphers whose kernel probe failed
    /// BEFORE extracting secrets.
    struct KtlsAvailability {
        aes128gcm: bool,
        aes256gcm: bool,
        chacha20_poly1305: bool,
    }

    static KTLS_AVAILABILITY: std::sync::OnceLock<KtlsAvailability> = std::sync::OnceLock::new();

    fn ktls_availability() -> &'static KtlsAvailability {
        KTLS_AVAILABILITY.get_or_init(|| {
            // Probe each cipher on its own fresh TCP loopback pair. We cannot
            // reuse a single socket across all three ciphers because the
            // kernel refuses further TLS_TX installs on a socket that already
            // has keys installed. Three separate probes cost ~3ms at startup
            // (one-time), which is acceptable for one-shot auto-detection.
            let aes128gcm = unsafe {
                let info = TlsCryptoInfoAes128Gcm {
                    version: TLS_1_2_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_128,
                    iv: [0u8; 8],
                    key: [0u8; 16],
                    salt: [0u8; 4],
                    rec_seq: [0u8; 8],
                };
                probe_cipher(
                    &info as *const TlsCryptoInfoAes128Gcm as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoAes128Gcm>() as libc::socklen_t,
                )
            };
            let aes256gcm = unsafe {
                let info = TlsCryptoInfoAes256Gcm {
                    version: TLS_1_2_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_256,
                    iv: [0u8; 8],
                    key: [0u8; 32],
                    salt: [0u8; 4],
                    rec_seq: [0u8; 8],
                };
                probe_cipher(
                    &info as *const TlsCryptoInfoAes256Gcm as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoAes256Gcm>() as libc::socklen_t,
                )
            };
            let chacha20_poly1305 = unsafe {
                let info = TlsCryptoInfoChaCha20Poly1305 {
                    version: TLS_1_2_VERSION,
                    cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                    iv: [0u8; 12],
                    key: [0u8; 32],
                    salt: [0u8; 4],
                    rec_seq: [0u8; 8],
                };
                probe_cipher(
                    &info as *const TlsCryptoInfoChaCha20Poly1305 as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoChaCha20Poly1305>() as libc::socklen_t,
                )
            };
            KtlsAvailability {
                aes128gcm,
                aes256gcm,
                chacha20_poly1305,
            }
        })
    }

    /// Attempts to load the TLS ULP module via `modprobe tls` (requires root).
    /// Returns `true` if the module is already loaded or was loaded successfully.
    /// This is a best-effort check — kTLS can still fail per-socket if the
    /// negotiated cipher is unsupported.
    ///
    /// Returns `true` iff ANY supported cipher (AES-128-GCM, AES-256-GCM, or
    /// ChaCha20-Poly1305) can be installed via the TLS ULP. Use the
    /// per-cipher accessors below to gate cipher-specific code paths before
    /// consuming the TLS stream — `is_ktls_available()` alone is not
    /// sufficient because different ciphers landed in different kernel
    /// versions (see `KtlsAvailability`).
    pub fn is_ktls_available() -> bool {
        let a = ktls_availability();
        a.aes128gcm || a.aes256gcm || a.chacha20_poly1305
    }

    /// Returns `true` if the kernel accepts AES-128-GCM kTLS key installs.
    /// Gate `try_ktls_splice` on this before extracting secrets for AES-128-GCM
    /// sessions.
    pub fn is_ktls_aes128gcm_available() -> bool {
        ktls_availability().aes128gcm
    }

    /// Returns `true` if the kernel accepts AES-256-GCM kTLS key installs.
    pub fn is_ktls_aes256gcm_available() -> bool {
        ktls_availability().aes256gcm
    }

    /// Returns `true` if the kernel accepts ChaCha20-Poly1305 kTLS key installs
    /// (Linux 5.11+). Kernels with AES-GCM kTLS but no ChaCha20 kTLS exist in
    /// the wild (4.13+ vs 5.11+), so this MUST be checked independently before
    /// handing a ChaCha20-Poly1305 connection to `try_ktls_splice`.
    pub fn is_ktls_chacha20_poly1305_available() -> bool {
        ktls_availability().chacha20_poly1305
    }

    /// Set up a real TCP loopback connection and run the kTLS setsockopt sequence
    /// on the accepted server-side socket. Returns `true` iff BOTH the TCP_ULP
    /// install AND the dummy cipher TX key install returned 0.
    ///
    /// The `info_ptr` / `info_len` describe the cipher-specific
    /// `TlsCryptoInfo*` struct to install via `setsockopt(SOL_TLS, TLS_TX)`.
    ///
    /// All syscalls are raw libc. On any failure anywhere in setup, we close
    /// whatever fds we managed to open and return `false`.
    ///
    /// IMPORTANT: We MUST use real TCP sockets here, not AF_UNIX socketpair.
    /// TCP_ULP with IPPROTO_TCP is only valid on TCP sockets; an AF_UNIX socket
    /// will return EOPNOTSUPP/ENOPROTOOPT on every kernel — even ones that
    /// fully support kTLS. Using socketpair(AF_UNIX, ...) would make this
    /// probe silently return false forever and defeat kTLS auto-detection.
    #[allow(clippy::cast_possible_truncation)]
    unsafe fn probe_cipher(info_ptr: *const libc::c_void, info_len: libc::socklen_t) -> bool {
        unsafe {
            // 1. Create listener socket, bind to 127.0.0.1:0, listen.
            let listener_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if listener_fd < 0 {
                return false;
            }

            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            // 127.0.0.1 in network byte order.
            addr.sin_addr.s_addr = u32::to_be(0x7f000001);
            addr.sin_port = 0;

            let addr_ptr = &addr as *const libc::sockaddr_in as *const libc::sockaddr;
            if libc::bind(
                listener_fd,
                addr_ptr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) < 0
            {
                libc::close(listener_fd);
                return false;
            }

            if libc::listen(listener_fd, 1) < 0 {
                libc::close(listener_fd);
                return false;
            }

            // Read back the assigned ephemeral port.
            let mut assigned: libc::sockaddr_in = std::mem::zeroed();
            let mut assigned_len: libc::socklen_t =
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockname(
                listener_fd,
                &mut assigned as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut assigned_len,
            ) < 0
            {
                libc::close(listener_fd);
                return false;
            }

            // 2. Create client socket, set O_NONBLOCK, connect (EINPROGRESS expected).
            let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if client_fd < 0 {
                libc::close(listener_fd);
                return false;
            }

            let flags = libc::fcntl(client_fd, libc::F_GETFL, 0);
            if flags < 0 || libc::fcntl(client_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                libc::close(client_fd);
                libc::close(listener_fd);
                return false;
            }

            let connect_ret = libc::connect(
                client_fd,
                &assigned as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if connect_ret < 0 {
                let err = *libc::__errno_location();
                if err != libc::EINPROGRESS {
                    libc::close(client_fd);
                    libc::close(listener_fd);
                    return false;
                }
            }

            // 3. Accept on listener.
            let mut peer: libc::sockaddr_in = std::mem::zeroed();
            let mut peer_len: libc::socklen_t =
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let server_fd = libc::accept(
                listener_fd,
                &mut peer as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut peer_len,
            );
            if server_fd < 0 {
                libc::close(client_fd);
                libc::close(listener_fd);
                return false;
            }

            // We no longer need the listener.
            libc::close(listener_fd);

            // 4. Install TCP_ULP "tls" on the server-side TCP socket.
            let ulp_name = b"tls\0";
            let ulp_ret = libc::setsockopt(
                server_fd,
                libc::IPPROTO_TCP,
                libc::TCP_ULP,
                ulp_name.as_ptr() as *const libc::c_void,
                ulp_name.len() as libc::socklen_t,
            );
            if ulp_ret != 0 {
                libc::close(server_fd);
                libc::close(client_fd);
                return false;
            }

            // 5. Install dummy TX key for the cipher under test. A value of 0
            //    for tx_ret means the kernel accepted the cipher install and
            //    the full kTLS path works for this cipher.
            let tx_ret = libc::setsockopt(server_fd, SOL_TLS, TLS_TX, info_ptr, info_len);

            libc::close(server_fd);
            libc::close(client_fd);
            tx_ret == 0
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub mod ktls {
    use zeroize::Zeroizing;

    pub struct KtlsParams {
        pub tls_version: u16,
        pub cipher_suite: KtlsCipher,
        pub tx_key: Zeroizing<Vec<u8>>,
        pub tx_iv: Zeroizing<Vec<u8>>,
        pub tx_seq: [u8; 8],
        pub rx_key: Zeroizing<Vec<u8>>,
        pub rx_iv: Zeroizing<Vec<u8>>,
        pub rx_seq: [u8; 8],
    }

    #[derive(Debug, Clone, Copy)]
    pub enum KtlsCipher {
        Aes128Gcm,
        Aes256Gcm,
        Chacha20Poly1305,
    }

    #[allow(dead_code)]
    pub fn enable_ktls(_fd: i32, _params: &KtlsParams) -> std::io::Result<bool> {
        Ok(false)
    }

    #[allow(dead_code)]
    pub fn is_ktls_available() -> bool {
        false
    }

    #[allow(dead_code)]
    pub fn is_ktls_aes128gcm_available() -> bool {
        false
    }

    #[allow(dead_code)]
    pub fn is_ktls_aes256gcm_available() -> bool {
        false
    }

    #[allow(dead_code)]
    pub fn is_ktls_chacha20_poly1305_available() -> bool {
        false
    }
}

// ── io_uring splice ────────────────────────────────────────────────────

/// io_uring-based splice for zero-copy TCP relay (Linux 5.6+ only).
///
/// Uses `IORING_OP_SPLICE` via the `io-uring` crate to perform splice
/// operations through the io_uring submission queue. Each splice direction
/// gets its own ring (8 entries) and runs on a dedicated blocking thread
/// via `tokio::task::spawn_blocking`. The splice loop submits SQEs and
/// waits for CQEs, reducing per-operation overhead vs direct `libc::splice`
/// syscalls.
///
/// The TCP proxy creates a ring per direction when `FERRUM_IO_URING_SPLICE_ENABLED`
/// resolves to true (auto-detected at startup via `check_io_uring_available()`).
#[cfg(target_os = "linux")]
pub mod io_uring_splice {
    use std::sync::atomic::{AtomicBool, Ordering};

    static IO_URING_AVAILABLE: AtomicBool = AtomicBool::new(false);
    static IO_URING_CHECKED: AtomicBool = AtomicBool::new(false);

    /// Check if io_uring is available on this kernel (Linux 5.6+).
    ///
    /// Probes the `io_uring_setup` syscall. Returns `true` if the syscall
    /// exists (even if params are invalid — EINVAL still means io_uring is present).
    /// ENOSYS means the kernel doesn't support io_uring.
    pub fn check_io_uring_available() -> bool {
        if IO_URING_CHECKED.load(Ordering::Relaxed) {
            return IO_URING_AVAILABLE.load(Ordering::Relaxed);
        }

        // Probe by actually submitting an IORING_OP_SPLICE on a pipe pair.
        // Ring creation alone is insufficient — seccomp or kernel config may
        // allow ring setup but reject specific opcodes like SPLICE.
        let available = (|| -> bool {
            let mut ring = match io_uring::IoUring::new(2) {
                Ok(r) => r,
                Err(_) => return false,
            };
            // Create a throwaway pipe to test SPLICE.
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
                return false;
            }
            // Submit a splice from pipe_r→pipe_w with 0 bytes — should return 0 (EOF-like)
            // or EAGAIN. Either means SPLICE opcode is supported.
            let sqe = io_uring::opcode::Splice::new(
                io_uring::types::Fd(fds[0]),
                -1,
                io_uring::types::Fd(fds[1]),
                -1,
                0, // len: 0 bytes for probe
            )
            .build();
            let push_ok = unsafe { ring.submission().push(&sqe).is_ok() };
            let result = if push_ok && ring.submit_and_wait(1).is_ok() {
                // Check the CQE result. `result() >= 0` means the kernel accepted
                // SPLICE and returned a byte count (possibly 0 for a 0-byte probe).
                //
                // We ALSO accept `result() == -EAGAIN`: for a 0-byte splice on an
                // empty pipe, some kernels return -EAGAIN which indicates the
                // SPLICE opcode was recognized and dispatched, but there was no
                // data to move. That is exactly the expected state for this probe,
                // so EAGAIN still proves the opcode is supported.
                //
                // Rejections we still treat as "io_uring SPLICE unavailable":
                //   -EINVAL, -EOPNOTSUPP, -ENOSYS (seccomp or kernel config).
                ring.completion().next().is_some_and(|cqe| {
                    let r = cqe.result();
                    r >= 0 || r == -libc::EAGAIN
                })
            } else {
                false
            };
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            result
        })();

        IO_URING_AVAILABLE.store(available, Ordering::Relaxed);
        IO_URING_CHECKED.store(true, Ordering::Relaxed);
        available
    }

    /// Errors from an io_uring splice call tagged with the side of the relay
    /// that produced them.
    ///
    /// `is_write_side = false` — the src_fd → pipe splice failed (read side).
    /// `is_write_side = true` — the pipe → dst_fd splice failed (write side).
    /// `is_write_side = false` is also used for out-of-band failures (ring
    /// creation, idle timeout, submission-queue full) where the side isn't
    /// meaningful; callers that care should inspect `source.kind()`.
    #[derive(Debug)]
    pub struct SpliceError {
        pub is_write_side: bool,
        pub source: std::io::Error,
    }

    impl SpliceError {
        fn read(source: std::io::Error) -> Self {
            Self {
                is_write_side: false,
                source,
            }
        }
        fn write(source: std::io::Error) -> Self {
            Self {
                is_write_side: true,
                source,
            }
        }
    }

    /// Splice data in one direction using io_uring: src_fd → pipe → dst_fd.
    ///
    /// Runs on a blocking thread (called via `tokio::task::spawn_blocking`).
    /// Creates a small io_uring ring (8 entries) and submits IORING_OP_SPLICE
    /// operations for each chunk. Returns total bytes transferred.
    ///
    /// Returns `Err` with `source.kind() == ErrorKind::Unsupported` if the ring
    /// cannot be created, signaling the caller to fall back to `libc::splice`.
    ///
    /// `timeout_ms` is the idle timeout — if no data is transferred on either
    /// direction for this duration, returns `ErrorKind::TimedOut`.
    /// `shared_last_activity_ms` is an `AtomicU64` shared between both splice
    /// directions so that activity in one direction prevents the other from
    /// timing out (critical for one-way streaming like downloads).
    pub fn io_uring_splice_loop(
        src_fd: i32,
        pipe_w: i32,
        pipe_r: i32,
        dst_fd: i32,
        shared_last_activity_ms: &std::sync::atomic::AtomicU64,
        timeout_ms: u64,
    ) -> Result<u64, SpliceError> {
        let mut ring = match io_uring::IoUring::new(8) {
            Ok(r) => r,
            Err(_) => {
                // Ring creation failed (memlock pressure, resource limits).
                // Signal caller to fall back to libc::splice. Side is N/A but
                // the caller checks ErrorKind::Unsupported before side.
                return Err(SpliceError::read(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "io_uring ring creation failed, falling back to libc splice",
                )));
            }
        };
        let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
        let mut total: u64 = 0;
        let chunk_size: u32 = 128 * 1024;

        loop {
            // Inline idle timeout check using the shared cross-direction timestamp.
            // Both splice directions update the same AtomicU64, so activity in either
            // direction prevents the other from timing out (critical for one-way streams).
            //
            // Uses `monotonic_now_ms()` (Instant-based) — NOT `SystemTime::now()` —
            // because wall-clock time can slew backwards under NTP correction or
            // admin clock changes, which would pin `saturating_sub` at 0 forever
            // and cause the timeout to never fire. `shared_last_activity_ms` is
            // also written by the libc fallback loop using the same helper, so the
            // clocks on both sides of the shared atomic agree.
            if timeout_ms > 0 {
                let now = super::monotonic_now_ms();
                let last = shared_last_activity_ms.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= timeout_ms {
                    return Err(SpliceError::read(std::io::Error::from(
                        std::io::ErrorKind::TimedOut,
                    )));
                }
            }

            // Phase 1: splice src_fd → pipe_w via io_uring
            let sqe = io_uring::opcode::Splice::new(
                io_uring::types::Fd(src_fd),
                -1, // no offset for pipes/sockets
                io_uring::types::Fd(pipe_w),
                -1,
                chunk_size,
            )
            .flags(splice_flags)
            .build();

            unsafe {
                ring.submission()
                    .push(&sqe)
                    .map_err(|_| SpliceError::read(std::io::Error::other("io_uring SQ full")))?;
            }
            ring.submit_and_wait(1).map_err(SpliceError::read)?;

            let cqe = ring
                .completion()
                .next()
                .ok_or_else(|| SpliceError::read(std::io::Error::other("io_uring no CQE")))?;
            let n = cqe.result();

            if n == 0 {
                return Ok(total); // EOF
            }
            if n < 0 {
                let err = std::io::Error::from_raw_os_error(-n);
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // Recheck idle timeout inline before sleeping, even though the
                    // outer loop also checks it. Keeping the check here makes the
                    // two WouldBlock branches (Phase 1 here, Phase 2 below) behave
                    // uniformly and avoids relying on reviewers to trace control flow.
                    if timeout_ms > 0 {
                        let now = super::monotonic_now_ms();
                        let last =
                            shared_last_activity_ms.load(std::sync::atomic::Ordering::Relaxed);
                        if now.saturating_sub(last) >= timeout_ms {
                            return Err(SpliceError::read(std::io::Error::from(
                                std::io::ErrorKind::TimedOut,
                            )));
                        }
                    }
                    // Back off to avoid tight spin — sleep 1ms then retry.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                return Err(SpliceError::read(err));
            }

            // Phase 2: splice pipe_r → dst_fd via io_uring
            let mut remaining = n as u32;
            while remaining > 0 {
                let sqe = io_uring::opcode::Splice::new(
                    io_uring::types::Fd(pipe_r),
                    -1,
                    io_uring::types::Fd(dst_fd),
                    -1,
                    remaining,
                )
                .flags(splice_flags)
                .build();

                unsafe {
                    ring.submission().push(&sqe).map_err(|_| {
                        SpliceError::write(std::io::Error::other("io_uring SQ full"))
                    })?;
                }
                ring.submit_and_wait(1).map_err(SpliceError::write)?;

                let cqe = ring
                    .completion()
                    .next()
                    .ok_or_else(|| SpliceError::write(std::io::Error::other("io_uring no CQE")))?;
                let w = cqe.result();

                if w == 0 {
                    return Ok(total);
                }
                if w < 0 {
                    let err = std::io::Error::from_raw_os_error(-w);
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        // CRITICAL: This inner-loop WouldBlock branch must recheck
                        // the idle timeout before sleeping. The `while remaining > 0`
                        // loop has no timeout check, so if the destination socket
                        // stops reading while data is buffered in the pipe, this
                        // branch would spin at 1000 iters/sec forever without
                        // releasing the blocking thread to the tokio pool.
                        if timeout_ms > 0 {
                            let now = super::monotonic_now_ms();
                            let last =
                                shared_last_activity_ms.load(std::sync::atomic::Ordering::Relaxed);
                            if now.saturating_sub(last) >= timeout_ms {
                                return Err(SpliceError::write(std::io::Error::from(
                                    std::io::ErrorKind::TimedOut,
                                )));
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    return Err(SpliceError::write(err));
                }
                remaining -= w as u32;
                total += w as u64;
                // Refresh shared idle timeout — activity in either direction
                // prevents the connection from timing out. Must use the same
                // monotonic clock as the reader loop above (and the libc
                // fallback's `coarse_now_ms`) so the shared atomic is coherent.
                if timeout_ms > 0 {
                    shared_last_activity_ms.store(
                        super::monotonic_now_ms(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub mod io_uring_splice {
    #[allow(dead_code)]
    pub fn check_io_uring_available() -> bool {
        false
    }

    /// Errors from an io_uring splice call tagged with the side of the relay
    /// that produced them. `is_write_side = false` for all non-Linux stubs.
    #[derive(Debug)]
    #[allow(dead_code)] // Fields are consumed only by the Linux splice path.
    pub struct SpliceError {
        pub is_write_side: bool,
        pub source: std::io::Error,
    }

    #[allow(dead_code)]
    pub fn io_uring_splice_loop(
        _src_fd: i32,
        _pipe_w: i32,
        _pipe_r: i32,
        _dst_fd: i32,
        _shared_last_activity_ms: &std::sync::atomic::AtomicU64,
        _timeout_ms: u64,
    ) -> Result<u64, SpliceError> {
        Err(SpliceError {
            is_write_side: false,
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "io_uring not available on this platform",
            ),
        })
    }
}

// ── Auto-detection probes ──────────────────────────────────────────────

/// Check if TCP Fast Open is enabled on this kernel via sysctl.
///
/// Reads `/proc/sys/net/ipv4/tcp_fastopen` and checks that both the
/// server bit (0x1) and client bit (0x2) are set. Returns `true` if
/// the sysctl value has bits 0x3 set (both server and client TFO enabled).
#[cfg(target_os = "linux")]
pub fn is_tcp_fastopen_available() -> bool {
    if let Ok(val) = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_fastopen")
        && let Ok(n) = val.trim().parse::<u32>()
    {
        return (n & 0x3) == 0x3; // bits 0 (server) + 1 (client) both set
    }
    false
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn is_tcp_fastopen_available() -> bool {
    false
}

/// Check if UDP GRO is available by probing `setsockopt(UDP_GRO)` on a temp socket.
///
/// Creates a temporary UDP socket, attempts to set `UDP_GRO=1`, and closes it.
/// Returns `true` if the setsockopt succeeds (Linux 5.0+).
#[cfg(target_os = "linux")]
pub fn is_udp_gro_available() -> bool {
    const UDP_GRO: libc::c_int = 104;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return false;
    }
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            UDP_GRO,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };
    ret == 0
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn is_udp_gro_available() -> bool {
    false
}

/// Check if UDP GSO is available by probing `setsockopt(UDP_SEGMENT)` on a temp socket.
///
/// Creates a temporary UDP socket, attempts to set `UDP_SEGMENT=1400`, and closes it.
/// Returns `true` if the setsockopt succeeds (Linux 4.18+).
#[cfg(target_os = "linux")]
pub fn is_udp_gso_available() -> bool {
    const UDP_SEGMENT: libc::c_int = 103;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return false;
    }
    let val: libc::c_int = 1400; // typical segment size for probe
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            UDP_SEGMENT,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };
    ret == 0
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn is_udp_gso_available() -> bool {
    false
}

// ── TCP connect with socket options ────────────────────────────────────────

/// Connect to a pre-resolved `SocketAddr` with `IP_BIND_ADDRESS_NO_PORT` set
/// before `connect()` so the kernel can co-select ephemeral ports using 4-tuple
/// optimization.
///
/// Creates a `TcpSocket` for the correct address family (v4/v6), applies
/// `IP_BIND_ADDRESS_NO_PORT` on Linux, then connects. The caller must resolve
/// the hostname via the shared DNS cache before calling this — no DNS lookup
/// happens here.
///
/// Used by the HTTP/2 direct pool and gRPC pool for outbound backend connections.
pub async fn connect_with_socket_opts(
    sock_addr: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    let socket = if sock_addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let _ = set_ip_bind_address_no_port(socket.as_raw_fd(), true);
    }

    socket.connect(sock_addr).await
}

#[cfg(all(test, target_os = "linux"))]
mod pktinfo_tests {
    //! Roundtrip tests for IP_PKTINFO capture + send_with_pktinfo reply.
    //!
    //! Exercises the full cycle on a loopback socket: bind to 0.0.0.0, enable
    //! IP_PKTINFO, have a client send a datagram to 127.0.0.1, parse pktinfo
    //! on recv, and confirm send_with_pktinfo succeeds (combined with optional
    //! UDP_SEGMENT GSO). The test does not depend on routing — any kernel
    //! with IP_PKTINFO support can run it.
    use super::*;
    use std::net::SocketAddr;
    use std::os::unix::io::AsRawFd;
    use tokio::net::UdpSocket;
    use tokio::runtime::Runtime;

    fn v4_sockaddr_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        match addr {
            SocketAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(*v4.ip()).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &sin as *const libc::sockaddr_in as *const u8,
                        &mut storage as *mut libc::sockaddr_storage as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );
                }
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            SocketAddr::V6(_) => panic!("v4 helper called with v6 address"),
        }
    }

    #[test]
    fn pktinfo_probe_does_not_panic() {
        let _ = is_udp_pktinfo_available();
    }

    #[test]
    fn roundtrip_captures_local_destination() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Skip gracefully on kernels without IP_PKTINFO (shouldn't happen
            // on Linux but keep the test robust).
            if !is_udp_pktinfo_available() {
                return;
            }
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            set_ip_pktinfo(server.as_raw_fd()).unwrap();

            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(b"hello", server_addr).await.unwrap();

            // Use recvmsg via recvmmsg wrapper (already exercises the cmsg path).
            let mut batch = crate::proxy::udp_batch::RecvMmsgBatch::new(1);
            // Poll until the datagram arrives.
            server.readable().await.unwrap();
            let n = batch.recv(server.as_raw_fd(), 1).unwrap();
            assert_eq!(n, 1);
            let local = batch.local_addr(0);
            assert!(local.is_some(), "pktinfo should yield local addr");
            assert_eq!(local.unwrap().ip.to_string(), "127.0.0.1");
        });
    }

    #[test]
    fn send_with_pktinfo_roundtrip_plain() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            if !is_udp_pktinfo_available() {
                return;
            }
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            let (dest, dest_len) = v4_sockaddr_storage(client_addr);
            let sent = send_with_pktinfo(
                server.as_raw_fd(),
                b"pong",
                PktinfoLocal {
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    ifindex: 0,
                },
                &dest,
                dest_len,
                None,
            )
            .unwrap();
            assert_eq!(sent, 4);
            let _ = server_addr; // silence

            let mut buf = [0u8; 16];
            let (n, _from) = client.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"pong");
        });
    }

    #[test]
    fn send_with_pktinfo_and_gso_combined_cmsg() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            if !is_udp_pktinfo_available() || !is_udp_gso_available() {
                return;
            }
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            // Two 3-byte segments in one GSO buffer.
            let buf = b"aaabbb";
            let (dest, dest_len) = v4_sockaddr_storage(client_addr);
            let sent = send_with_pktinfo(
                server.as_raw_fd(),
                buf,
                PktinfoLocal {
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    ifindex: 0,
                },
                &dest,
                dest_len,
                Some(3),
            )
            .unwrap();
            assert_eq!(sent, 6);

            // First datagram should be 3 bytes.
            let mut rbuf = [0u8; 16];
            let (n, _) = client.recv_from(&mut rbuf).await.unwrap();
            assert_eq!(n, 3);
            assert_eq!(&rbuf[..n], b"aaa");
        });
    }

    #[test]
    fn cmsg_space_is_large_enough_for_both() {
        // The recv cmsg buffer must fit UDP_GRO + IP(v6)_PKTINFO simultaneously.
        let space = recv_cmsg_space();
        let v6_pkt =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize };
        let gro = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize };
        assert!(space >= v6_pkt + gro);
        let _ = SocketAddr::from(([127, 0, 0, 1], 0)); // silence unused import
    }
}

#[cfg(all(test, target_os = "linux"))]
mod ktls_availability_tests {
    //! Tests for the per-cipher kTLS availability accessors.
    //!
    //! These tests cannot assert specific values (the CI kernel may or may not
    //! have any given cipher's kTLS support) — they only verify that the
    //! accessors can be called without panicking and that the composite
    //! `is_ktls_available()` is consistent with the per-cipher probes.
    //!
    //! `OnceLock` makes these probes idempotent — even though multiple tests
    //! call them, the underlying loopback socketpair probes only run once.
    use super::ktls::{
        is_ktls_aes128gcm_available, is_ktls_aes256gcm_available, is_ktls_available,
        is_ktls_chacha20_poly1305_available,
    };

    #[test]
    fn per_cipher_accessors_do_not_panic() {
        // Calling each accessor must not panic regardless of kernel support.
        let _ = is_ktls_aes128gcm_available();
        let _ = is_ktls_aes256gcm_available();
        let _ = is_ktls_chacha20_poly1305_available();
    }

    #[test]
    fn composite_is_any_of_three() {
        // `is_ktls_available()` must return true iff at least one per-cipher
        // probe returned true. This invariant is what upstream auto-detection
        // depends on to set `ktls_enabled`, and is what the `try_ktls_splice`
        // per-cipher gate relies on to safely refuse connections whose
        // specific cipher's probe failed.
        let any_supported = is_ktls_aes128gcm_available()
            || is_ktls_aes256gcm_available()
            || is_ktls_chacha20_poly1305_available();
        assert_eq!(is_ktls_available(), any_supported);
    }

    #[test]
    fn per_cipher_probes_are_stable() {
        // OnceLock caches results. Calling twice must return the same value —
        // no second loopback socketpair probe should run.
        let first = (
            is_ktls_aes128gcm_available(),
            is_ktls_aes256gcm_available(),
            is_ktls_chacha20_poly1305_available(),
        );
        let second = (
            is_ktls_aes128gcm_available(),
            is_ktls_aes256gcm_available(),
            is_ktls_chacha20_poly1305_available(),
        );
        assert_eq!(first, second);
    }
}
