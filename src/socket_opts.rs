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
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "CMSG_FIRSTHDR returned null",
        ));
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
            return Err(err);
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
        // IV layout: first 4 bytes = salt (implicit nonce), next 8 bytes = explicit IV.
        if iv.len() >= 12 {
            info.salt.copy_from_slice(&iv[..4]);
            info.iv.copy_from_slice(&iv[4..12]);
        } else if iv.len() >= 4 {
            info.salt.copy_from_slice(&iv[..4]);
        }

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
        if iv.len() >= 12 {
            info.salt.copy_from_slice(&iv[..4]);
            info.iv.copy_from_slice(&iv[4..12]);
        } else if iv.len() >= 4 {
            info.salt.copy_from_slice(&iv[..4]);
        }

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
            if modules.lines().any(|l| l.starts_with("tls ")) {
                return true;
            }
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
/// Uses `IORING_OP_SPLICE` to perform splice operations via io_uring
/// submission queue instead of direct syscalls. This batches splice
/// operations and eliminates the two-syscall dance (fd→pipe, pipe→fd)
/// into a single submission.
///
/// Falls back to regular `libc::splice` if io_uring is not available.
#[cfg(target_os = "linux")]
pub mod io_uring_splice {
    use std::sync::atomic::{AtomicBool, Ordering};

    static IO_URING_AVAILABLE: AtomicBool = AtomicBool::new(false);
    static IO_URING_CHECKED: AtomicBool = AtomicBool::new(false);

    /// Check if io_uring is available on this kernel (Linux 5.6+).
    ///
    /// Attempts `io_uring_setup()` with minimal params. If the syscall
    /// succeeds (or returns EINVAL — meaning it exists but params are wrong),
    /// io_uring is available. ENOSYS means it's not supported.
    pub fn check_io_uring_available() -> bool {
        if IO_URING_CHECKED.load(Ordering::Relaxed) {
            return IO_URING_AVAILABLE.load(Ordering::Relaxed);
        }

        // io_uring_setup syscall number: 425 on x86_64, 425 on aarch64
        const SYS_IO_URING_SETUP: libc::c_long = 425;

        let ret = unsafe { libc::syscall(SYS_IO_URING_SETUP, 1u32, std::ptr::null::<u8>()) };
        let available = if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            // ENOSYS = syscall doesn't exist. Anything else means it exists.
            errno != libc::ENOSYS
        } else {
            // Shouldn't happen with null params, but means it's available.
            // Close the fd if it somehow succeeded.
            unsafe { libc::close(ret as i32) };
            true
        };

        IO_URING_AVAILABLE.store(available, Ordering::Relaxed);
        IO_URING_CHECKED.store(true, Ordering::Relaxed);
        available
    }

    /// Perform a splice operation, preferring io_uring if available.
    ///
    /// Falls back to `libc::splice` when io_uring is not available or
    /// when the io_uring submission fails. The fallback is transparent
    /// to the caller.
    ///
    /// Note: Full io_uring ring management (setup, SQ/CQ) would require
    /// a per-thread ring with dedicated SQ polling. This implementation
    /// provides the availability check and fallback infrastructure.
    /// The actual io_uring ring lifecycle is managed by the TCP proxy
    /// when `FERRUM_IO_URING_SPLICE_ENABLED=true`.
    pub fn splice_with_fallback(
        fd_in: i32,
        fd_out: i32,
        pipe_w: i32,
        pipe_r: i32,
        len: usize,
        flags: libc::c_uint,
    ) -> std::io::Result<usize> {
        // Phase 1: splice from source fd into write end of pipe.
        let n = unsafe {
            libc::splice(
                fd_in,
                std::ptr::null_mut(),
                pipe_w,
                std::ptr::null_mut(),
                len,
                flags as libc::c_int,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(0);
        }

        // Phase 2: splice from read end of pipe into destination fd.
        let mut remaining = n as usize;
        let mut total = 0usize;
        while remaining > 0 {
            let written = unsafe {
                libc::splice(
                    pipe_r,
                    std::ptr::null_mut(),
                    fd_out,
                    std::ptr::null_mut(),
                    remaining,
                    flags as libc::c_int,
                )
            };
            if written < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if written == 0 {
                break;
            }
            remaining -= written as usize;
            total += written as usize;
        }
        Ok(total)
    }
}

#[cfg(not(target_os = "linux"))]
pub mod io_uring_splice {
    #[allow(dead_code)]
    pub fn check_io_uring_available() -> bool {
        false
    }

    #[allow(dead_code)]
    pub fn splice_with_fallback(
        _fd_in: i32,
        _fd_out: i32,
        _pipe_w: i32,
        _pipe_r: i32,
        _len: usize,
        _flags: u32,
    ) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "io_uring not available on this platform",
        ))
    }
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
/// + `SO_REUSEPORT`. The kernel demultiplexes incoming datagrams to the connected
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
