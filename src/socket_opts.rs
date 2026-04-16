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
