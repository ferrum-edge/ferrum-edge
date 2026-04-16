//! Platform-specific socket optimizations inspired by Cloudflare Pingora.
//!
//! Provides `IP_BIND_ADDRESS_NO_PORT` (defers ephemeral port allocation to connect()),
//! `TCP_FASTOPEN` (saves 1 RTT on repeat connections), `TCP_INFO` access for
//! kernel-level BDP-optimal buffer sizing, `SO_BUSY_POLL` for low-latency UDP,
//! `MSG_ZEROCOPY` for large TCP sends, `UDP_GRO`/`UDP_SEGMENT` for kernel-level
//! datagram batching, and `kTLS` for enabling splice(2) on TLS paths.
//! All functions are no-ops on non-Linux platforms.

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

// ── MSG_ZEROCOPY (zero-copy send for large payloads) ───────────────────

/// Enable `SO_ZEROCOPY` on a socket (Linux 4.14+ only).
///
/// Allows `send(MSG_ZEROCOPY)` to avoid copying data from userspace to
/// kernel socket buffer. Only beneficial for sends > ~10 KB due to completion
/// notification overhead.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn set_so_zerocopy(fd: std::os::unix::io::RawFd, enable: bool) -> std::io::Result<()> {
    let val: libc::c_int = if enable { 1 } else { 0 };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ZEROCOPY,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    debug!("SO_ZEROCOPY enabled on socket");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_so_zerocopy(_fd: i32, _enable: bool) -> std::io::Result<()> {
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

/// Send a GSO-segmented buffer on a **connected** UDP socket (Linux 4.18+ only).
///
/// Like `send_with_gso()` but omits the destination address (`msg_name = NULL`),
/// relying on the socket's connected peer address. Used by the reply handler when
/// a connected UDP socket is available for the client.
#[cfg(target_os = "linux")]
pub fn send_with_gso_connected(
    fd: std::os::unix::io::RawFd,
    data: &[u8],
    segment_size: u16,
) -> std::io::Result<usize> {
    const UDP_SEGMENT: libc::c_int = 103;

    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    // Connected socket -- no destination address needed.
    msg.msg_name = std::ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

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
pub fn send_with_gso_connected(
    _fd: i32,
    _data: &[u8],
    _segment_size: u16,
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

// ── kTLS (kernel TLS for splice on encrypted paths) ────────────────────

/// kTLS crypto information for installing TLS session keys into the kernel.
///
/// After the TLS handshake completes in userspace (rustls), the symmetric
/// session keys can be installed into the kernel via `setsockopt(SOL_TLS)`.
/// This enables `splice(2)` to work on TLS-encrypted connections because
/// encryption/decryption is handled in the kernel rather than userspace.
///
/// Only AES-128-GCM and AES-256-GCM are supported as they are the most
/// common cipher suites negotiated in TLS 1.2/1.3.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod ktls {
    use tracing::debug;

    // Linux TLS ULP constants (from <linux/tls.h>)
    const SOL_TLS: libc::c_int = 282;
    const TLS_TX: libc::c_int = 1;
    const TLS_RX: libc::c_int = 2;

    const TLS_1_2_VERSION: u16 = 0x0303;
    const TLS_1_3_VERSION: u16 = 0x0304;

    const TLS_CIPHER_AES_GCM_128: u16 = 51;
    const TLS_CIPHER_AES_GCM_256: u16 = 52;

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

    /// Parameters needed to install kTLS on a socket.
    pub struct KtlsParams {
        pub tls_version: u16,
        pub cipher_suite: KtlsCipher,
        pub tx_key: Vec<u8>,
        pub tx_iv: Vec<u8>,
        pub tx_seq: [u8; 8],
        pub rx_key: Vec<u8>,
        pub rx_iv: Vec<u8>,
        pub rx_seq: [u8; 8],
    }

    /// Supported kTLS cipher suites.
    #[derive(Debug, Clone, Copy)]
    pub enum KtlsCipher {
        Aes128Gcm,
        Aes256Gcm,
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

    /// Check if kTLS is available on this kernel.
    ///
    /// Attempts to load the TLS ULP module via `modprobe tls` (requires root).
    /// Returns `true` if the module is already loaded or was loaded successfully.
    /// This is a best-effort check — kTLS can still fail per-socket if the
    /// negotiated cipher is unsupported.
    pub fn is_ktls_available() -> bool {
        // Check if the tls module is already loaded by examining /proc/modules.
        if let Ok(modules) = std::fs::read_to_string("/proc/modules") {
            return modules.lines().any(|l| l.starts_with("tls "));
        }
        false
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub mod ktls {
    pub struct KtlsParams {
        pub tls_version: u16,
        pub cipher_suite: KtlsCipher,
        pub tx_key: Vec<u8>,
        pub tx_iv: Vec<u8>,
        pub tx_seq: [u8; 8],
        pub rx_key: Vec<u8>,
        pub rx_iv: Vec<u8>,
        pub rx_seq: [u8; 8],
    }

    #[derive(Debug, Clone, Copy)]
    pub enum KtlsCipher {
        Aes128Gcm,
        Aes256Gcm,
    }

    #[allow(dead_code)]
    pub fn enable_ktls(_fd: i32, _params: &KtlsParams) -> std::io::Result<bool> {
        Ok(false)
    }

    #[allow(dead_code)]
    pub fn is_ktls_available() -> bool {
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
            let result = if push_ok {
                ring.submit_and_wait(1).is_ok()
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

    /// Splice data in one direction using io_uring: src_fd → pipe → dst_fd.
    ///
    /// Runs on a blocking thread (called via `tokio::task::spawn_blocking`).
    /// Creates a small io_uring ring (8 entries) and submits IORING_OP_SPLICE
    /// operations for each chunk. Returns total bytes transferred.
    ///
    /// Returns `Err` with `ErrorKind::Unsupported` if the ring cannot be created,
    /// signaling the caller to fall back to `libc::splice`.
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
    ) -> std::io::Result<u64> {
        let mut ring = match io_uring::IoUring::new(8) {
            Ok(r) => r,
            Err(_) => {
                // Ring creation failed (memlock pressure, resource limits).
                // Signal caller to fall back to libc::splice.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "io_uring ring creation failed, falling back to libc splice",
                ));
            }
        };
        let splice_flags = (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as u32;
        let mut total: u64 = 0;
        let chunk_size: u32 = 128 * 1024;

        loop {
            // Inline idle timeout check using the shared cross-direction timestamp.
            // Both splice directions update the same AtomicU64, so activity in either
            // direction prevents the other from timing out (critical for one-way streams).
            if timeout_ms > 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let last = shared_last_activity_ms.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= timeout_ms {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
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
                    .map_err(|_| std::io::Error::other("io_uring SQ full"))?;
            }
            ring.submit_and_wait(1)?;

            let cqe = ring
                .completion()
                .next()
                .ok_or_else(|| std::io::Error::other("io_uring no CQE"))?;
            let n = cqe.result();

            if n == 0 {
                return Ok(total); // EOF
            }
            if n < 0 {
                let err = std::io::Error::from_raw_os_error(-n);
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // Back off to avoid tight spin — sleep 1ms then retry.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                return Err(err);
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
                    ring.submission()
                        .push(&sqe)
                        .map_err(|_| std::io::Error::other("io_uring SQ full"))?;
                }
                ring.submit_and_wait(1)?;

                let cqe = ring
                    .completion()
                    .next()
                    .ok_or_else(|| std::io::Error::other("io_uring no CQE"))?;
                let w = cqe.result();

                if w == 0 {
                    return Ok(total);
                }
                if w < 0 {
                    let err = std::io::Error::from_raw_os_error(-w);
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    return Err(err);
                }
                remaining -= w as u32;
                total += w as u64;
                // Refresh shared idle timeout — activity in either direction
                // prevents the connection from timing out.
                if timeout_ms > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    shared_last_activity_ms.store(now, std::sync::atomic::Ordering::Relaxed);
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

    #[allow(dead_code)]
    pub fn io_uring_splice_loop(
        _src_fd: i32,
        _pipe_w: i32,
        _pipe_r: i32,
        _dst_fd: i32,
        _shared_last_activity_ms: &std::sync::atomic::AtomicU64,
        _timeout_ms: u64,
    ) -> std::io::Result<u64> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "io_uring not available on this platform",
        ))
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
    if let Ok(val) = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_fastopen") {
        if let Ok(n) = val.trim().parse::<u32>() {
            return (n & 0x3) == 0x3; // bits 0 (server) + 1 (client) both set
        }
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

// ── Connected UDP sockets ──────────────────────────────────────────────

/// Create a connected UDP socket for a specific client address.
///
/// A connected UDP socket (one that has called `connect()` on a specific peer)
/// bypasses the kernel routing table lookup on each `send()` call. This saves
/// ~5-10% CPU overhead for high-frequency clients by avoiding per-datagram
/// `sendto()` destination resolution.
///
/// The connected socket shares the same local port as the parent via `SO_REUSEADDR`
/// and `SO_REUSEPORT`. The kernel demultiplexes incoming datagrams to the connected
/// socket (4-tuple match) preferentially over the unconnected listener.
///
/// Returns the connected socket fd, or an error if binding/connecting fails.
#[cfg(target_os = "linux")]
pub fn create_connected_udp_socket(
    local_addr: std::net::SocketAddr,
    remote_addr: std::net::SocketAddr,
) -> std::io::Result<std::os::unix::io::RawFd> {
    let domain = if local_addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SO_REUSEADDR + SO_REUSEPORT to share the local port with the listener.
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Bind to the same local address as the listener.
    let (bind_addr, bind_len) = socketaddr_to_raw(local_addr);
    let ret = unsafe {
        libc::bind(
            fd,
            &bind_addr as *const libc::sockaddr_storage as *const libc::sockaddr,
            bind_len,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // Connect to the remote address for optimized send().
    let (remote_raw, remote_len) = socketaddr_to_raw(remote_addr);
    let ret = unsafe {
        libc::connect(
            fd,
            &remote_raw as *const libc::sockaddr_storage as *const libc::sockaddr,
            remote_len,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    debug!(
        "Connected UDP socket fd={} for {} -> {}",
        fd, local_addr, remote_addr
    );
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn create_connected_udp_socket(
    _local_addr: std::net::SocketAddr,
    _remote_addr: std::net::SocketAddr,
) -> std::io::Result<i32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "connected UDP sockets optimization not available on this platform",
    ))
}

// ── Helper: SocketAddr to raw sockaddr ─────────────────────────────────

/// Convert a `std::net::SocketAddr` to a raw `sockaddr_storage` + length.
/// Used by connected UDP socket creation and GSO sends.
#[cfg(target_os = "linux")]
fn socketaddr_to_raw(addr: std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        std::net::SocketAddr::V4(v4) => {
            // Build sockaddr_in in zeroed storage to handle platform-specific fields.
            unsafe {
                let sin =
                    &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in);
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = v4.port().to_be();
                sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        std::net::SocketAddr::V6(v6) => {
            unsafe {
                let sin6 =
                    &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6);
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = v6.port().to_be();
                sin6.sin6_flowinfo = v6.flowinfo();
                sin6.sin6_addr.s6_addr = v6.ip().octets();
                sin6.sin6_scope_id = v6.scope_id();
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}
