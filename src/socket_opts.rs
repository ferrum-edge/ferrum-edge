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
    // Saturate rather than wrap if the process survives for more than u64
    // milliseconds (~584 million years). Callers handle unrepresentable future
    // deadlines conservatively; the shared tick itself never jumps backwards.
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
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

/// Set `SO_MARK` on an outbound socket (Linux only).
///
/// NodeWaypoint uses this to distinguish authorized local backend dials made
/// by the inbound HBONE relay from direct pod-IP traffic. Failures are surfaced
/// to the caller so the datapath fails closed rather than sending unmarked
/// traffic that the tc direct-pod guard will drop.
#[cfg(target_os = "linux")]
pub fn set_socket_mark(fd: std::os::unix::io::RawFd, mark: u32) -> std::io::Result<()> {
    let val: libc::c_int = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
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
pub fn set_socket_mark(_fd: i32, _mark: u32) -> std::io::Result<()> {
    Ok(())
}

// ── SO_COOKIE ───────────────────────────────────────────────────────────────

/// Read the kernel socket cookie for a TCP stream.
///
/// Node-waypoint identity resolution uses this accepted-socket cookie as the
/// lookup key for metadata captured by the node-agent eBPF programs. The
/// accepted server-side socket has a different cookie than the source pod's
/// connecting socket; the GAP-2M sockops/sk_lookup bridge is responsible for
/// registering records keyed by this accept-side cookie before node-waypoint
/// traffic is admitted. Non-Linux platforms do not expose `SO_COOKIE`, so
/// node-waypoint topology fails closed there.
#[cfg(target_os = "linux")]
pub fn socket_cookie(stream: &tokio::net::TcpStream) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd;
    socket_cookie_from_raw_fd(stream.as_raw_fd())
}

#[cfg(target_os = "linux")]
pub fn socket_cookie_from_raw_fd(fd: std::os::fd::RawFd) -> std::io::Result<u64> {
    // Linux uapi: include/uapi/asm-generic/socket.h
    const SO_COOKIE: libc::c_int = 57;
    let mut cookie = 0u64;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_COOKIE,
            &mut cookie as *mut u64 as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<u64>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SO_COOKIE returned an unexpected value size",
        ));
    }
    Ok(cookie)
}

#[cfg(not(target_os = "linux"))]
pub fn socket_cookie(_stream: &tokio::net::TcpStream) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_COOKIE is only available on Linux",
    ))
}

// ── dual-stack bind classification ──────────────────────────────────────────

/// Whether `e` reports that IPv6 is unavailable on this host, so a caller that
/// PREFERS a dual-stack `[::]` bind may safely fall back to the IPv4 wildcard.
///
/// True ONLY for "address family not supported" / "cannot assign requested
/// address" / "protocol not supported". A real conflict such as `EADDRINUSE`
/// must NOT be classified here: falling back on it would report a capture
/// listener "started" on IPv4 while `ip6tables` still redirects IPv6 to that
/// port with nothing listening for it — a silent black hole behind a healthy
/// readiness signal. This is the single definition shared by the mesh TCP
/// capture listener bind and the mesh UDP capture socket bind.
pub fn is_ipv6_unavailable_io_error(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AddrNotAvailable || ipv6_unavailable_errno(e)
}

/// The platform-specific half of [`is_ipv6_unavailable_io_error`], split out so
/// the public predicate has one unconditional body.
#[cfg(unix)]
fn ipv6_unavailable_errno(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EAFNOSUPPORT) | Some(libc::EADDRNOTAVAIL) | Some(libc::EPROTONOSUPPORT)
    )
}

#[cfg(not(unix))]
fn ipv6_unavailable_errno(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::Unsupported
}

// ── SO_ORIGINAL_DST ─────────────────────────────────────────────────────────

/// The local address `original_dst_from_raw_fd` uses to choose the conntrack
/// socket-option family for an accepted connection.
///
/// An IPv4-mapped IPv6 local address (`::ffff:a.b.c.d`) — what a dual-stack
/// listener reports for an IPv4 connection — describes an IPv4 flow and folds to
/// its plain IPv4 form, selecting `SOL_IP`/`SO_ORIGINAL_DST`. Native IPv6 and
/// native IPv4 addresses are returned unchanged. Exposed (and platform
/// independent) so the family choice is unit-testable without a live
/// netfilter-redirected socket; the Linux lookup calls exactly this.
pub fn original_dst_lookup_addr(local_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    crate::util::client_identity::canonical_socket_addr(local_addr)
}

/// Read the pre-NAT original destination of an iptables-`REDIRECT`ed TCP
/// connection (Linux netfilter `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`).
///
/// Mesh capture listeners use this to recover the original app/service port:
/// outbound routing uses it to disambiguate multi-port services, while inbound
/// TLS selection uses it to enforce PeerAuthentication `portLevelMtls` before
/// the handshake. **`None` means "no captured original destination"**: non-Linux
/// platforms, traffic that was not NATed (direct dials — every functional test
/// and any sidecar-less client), `getsockopt` failure (`ENOENT` for
/// un-redirected flows), or a reported destination identical to the accepted
/// socket's local address (defensive: some conntrack states answer with the
/// post-NAT address). Callers must treat `None` as "fall back to existing
/// behavior", never as an error.
///
/// Note this only covers netfilter REDIRECT capture (Sidecar's injector
/// iptables model). eBPF `connect4`-rewritten capture (NodeWaypoint) never
/// creates a conntrack entry; its original destination lives in the eBPF
/// orig-dst records instead.
///
/// The conntrack lookup family comes from [`original_dst_lookup_addr`], so a
/// dual-stack capture listener's IPv4-mapped accept (`::ffff:a.b.c.d`) uses the
/// IPv4 socket option and recovers the pre-NAT IPv4 destination (issue #4271).
#[cfg(target_os = "linux")]
pub fn original_dst(stream: &tokio::net::TcpStream) -> Option<std::net::SocketAddr> {
    use std::os::fd::AsRawFd;
    let local_addr = stream.local_addr().ok()?;
    original_dst_from_raw_fd(stream.as_raw_fd(), local_addr)
}

/// Raw-fd core of [`original_dst`] (mirrors `socket_cookie_from_raw_fd`) so
/// the privileged live-netns test can exercise the real getsockopt path on a
/// std socket without a tokio runtime inside its `setns` thread.
#[cfg(target_os = "linux")]
pub fn original_dst_from_raw_fd(
    fd: std::os::fd::RawFd,
    local_addr: std::net::SocketAddr,
) -> Option<std::net::SocketAddr> {
    // Linux uapi: include/uapi/linux/netfilter_ipv4.h (SO_ORIGINAL_DST = 80)
    // and include/uapi/linux/netfilter_ipv6/ip6_tables.h
    // (IP6T_SO_ORIGINAL_DST = 80).
    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    // Pick the conntrack socket-option family from the CANONICAL local address,
    // never from the raw `SocketAddr` variant (issue #4271).
    //
    // The mesh TCP capture listeners bind the dual-stack IPv6 wildcard so a
    // single socket claims both families, and a dual-stack accept reports an
    // IPv4 connection's local address as the IPv4-MAPPED form `::ffff:a.b.c.d`
    // — an `AF_INET6` `SocketAddr` describing an IPv4 flow. Branching on the
    // raw variant would then issue `getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST)`
    // against an IPv4 conntrack entry, which answers `ENOENT`, and every
    // captured IPv4 connection would silently report "no original destination"
    // — losing multi-port service disambiguation and pre-handshake
    // `PeerAuthentication.portLevelMtls` selection. Folding the mapped form back
    // to IPv4 first selects `SOL_IP`/`SO_ORIGINAL_DST` and recovers the real
    // pre-NAT IPv4 destination. A NATIVE IPv6 local address is untouched and
    // keeps the `IP6T_SO_ORIGINAL_DST` path.
    let canonical_local = original_dst_lookup_addr(local_addr);

    let orig: std::net::SocketAddr = if canonical_local.is_ipv4() {
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
                &mut len as *mut libc::socklen_t,
            )
        };
        if ret != 0 {
            // Diagnostic only: `ENOENT` here is the ordinary "this flow was not
            // REDIRECTed" answer, which callers must keep treating as "no
            // captured original destination". Log the errno so a genuine
            // lookup failure (a wrong-family probe, a missing conntrack module)
            // is distinguishable in the field instead of vanishing into `None`.
            log_original_dst_lookup_failure("SOL_IP/SO_ORIGINAL_DST", local_addr);
            return None;
        }
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr))),
            u16::from_be(addr.sin_port),
        )
    } else {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                IP6T_SO_ORIGINAL_DST,
                &mut addr as *mut libc::sockaddr_in6 as *mut libc::c_void,
                &mut len as *mut libc::socklen_t,
            )
        };
        if ret != 0 {
            log_original_dst_lookup_failure("SOL_IPV6/IP6T_SO_ORIGINAL_DST", local_addr);
            return None;
        }
        std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr)),
            u16::from_be(addr.sin6_port),
        )
    };

    // A destination equal to the accepted socket's own local address means the
    // flow was not redirected (or conntrack echoed the post-NAT tuple back) —
    // there is no original destination to act on. Compare against the CANONICAL
    // local address: on a dual-stack accept the recovered v4 destination is an
    // `AF_INET` address while the raw local address is v4-mapped `AF_INET6`, so
    // comparing the raw forms would never match and this defensive check would
    // be dead for exactly the family the dual-stack listener serves.
    if orig == canonical_local {
        return None;
    }
    Some(orig)
}

/// Structured, secret-free diagnostic for a failed `SO_ORIGINAL_DST` lookup.
///
/// Kept out of [`original_dst_from_raw_fd`] so the success path stays a straight
/// line, and deliberately at `debug` level: the overwhelmingly common cause is
/// an un-redirected connection (`ENOENT`), which is normal on every direct dial.
#[cfg(target_os = "linux")]
fn log_original_dst_lookup_failure(option: &str, local_addr: std::net::SocketAddr) {
    debug!(
        sockopt = option,
        local_addr = %local_addr,
        error = %std::io::Error::last_os_error(),
        "SO_ORIGINAL_DST lookup failed; treating the connection as having no captured \
         original destination"
    );
}

#[cfg(not(target_os = "linux"))]
pub fn original_dst(_stream: &tokio::net::TcpStream) -> Option<std::net::SocketAddr> {
    None
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

// ── TCP_KEEPALIVE (DestinationRule connectionPool.tcp.tcpKeepalive) ─────────

/// Apply per-target TCP keepalive overrides on an already-connected backend
/// socket.
///
/// Wraps `socket2::Socket::set_tcp_keepalive`, which fans out to the right
/// per-platform socket options:
///   * Linux: `TCP_KEEPIDLE` (time), `TCP_KEEPINTVL` (interval), `TCP_KEEPCNT` (probes)
///   * macOS / iOS: `TCP_KEEPALIVE` (time), `TCP_KEEPINTVL` (interval), `TCP_KEEPCNT` (probes)
///   * BSDs: `TCP_KEEPIDLE` / `TCP_KEEPINTVL` / `TCP_KEEPCNT`
///   * Windows: a single `WSAIoctl(SIO_KEEPALIVE_VALS)` carrying time + interval (probes ignored)
///
/// Returns `Ok(())` on every supported platform when at least one field is set;
/// the helper is a no-op when `cfg.is_empty()`. We also enable `SO_KEEPALIVE`
/// itself first so the per-knob values actually take effect — otherwise the
/// kernel keeps the connection in default keepalive-disabled mode regardless
/// of `TCP_KEEPIDLE` / friends.
///
/// `time_seconds` and `interval_seconds` are always set as whole seconds
/// (sub-second precision is rejected at the K8s translator boundary because
/// the underlying socket options are second-granular on every supported
/// platform).
///
/// Failures from `setsockopt` are bubbled up; callers (`tcp_proxy.rs`) treat
/// keepalive setup as best-effort and log + continue rather than dropping the
/// backend connection.
#[cfg(unix)]
pub fn apply_tcp_keepalive(
    fd: std::os::fd::RawFd,
    cfg: &crate::config::types::TcpKeepaliveCfg,
) -> std::io::Result<()> {
    if cfg.is_empty() {
        return Ok(());
    }
    // SAFETY: `from_raw_fd` takes ownership of the fd. We immediately call
    // `into_raw_fd()` after the setsockopts complete to release ownership
    // back to the caller so dropping `socket` does NOT close the still-live
    // backend connection.
    use std::os::fd::{FromRawFd, IntoRawFd};
    let socket = unsafe { socket2::Socket::from_raw_fd(fd) };
    let result = apply_tcp_keepalive_inner(&socket, cfg);
    // Release the fd back so socket Drop does not close the connection.
    let _ = socket.into_raw_fd();
    result
}

#[cfg(windows)]
pub fn apply_tcp_keepalive(
    sock: std::os::windows::io::RawSocket,
    cfg: &crate::config::types::TcpKeepaliveCfg,
) -> std::io::Result<()> {
    if cfg.is_empty() {
        return Ok(());
    }
    // SAFETY: same lifecycle contract as the unix branch — re-release the
    // underlying raw socket via `into_raw_socket()` so the caller keeps
    // ownership of the live connection.
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};
    let socket = unsafe { socket2::Socket::from_raw_socket(sock) };
    let result = apply_tcp_keepalive_inner(&socket, cfg);
    let _ = socket.into_raw_socket();
    result
}

/// Shared helper that owns the `socket2::TcpKeepalive` construction so the
/// per-platform `apply_tcp_keepalive` wrappers only differ in how they wrap
/// the raw handle. Kept private so callers always go through the
/// fd / socket-typed entry points above.
fn apply_tcp_keepalive_inner(
    socket: &socket2::Socket,
    cfg: &crate::config::types::TcpKeepaliveCfg,
) -> std::io::Result<()> {
    socket.set_keepalive(true)?;
    let mut params = socket2::TcpKeepalive::new();
    if let Some(secs) = cfg.time_seconds {
        params = params.with_time(std::time::Duration::from_secs(u64::from(secs)));
    }
    // `with_interval` and `with_retries` are gated behind platform cfgs in
    // socket2. They are present on every platform Ferrum currently builds
    // for (Linux, macOS, Windows, BSDs) per Cargo target list, so we feed
    // them unconditionally inside the cross-platform setter.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "windows",
    ))]
    {
        if let Some(secs) = cfg.interval_seconds {
            params = params.with_interval(std::time::Duration::from_secs(u64::from(secs)));
        }
        if let Some(probes) = cfg.probes {
            params = params.with_retries(probes);
        }
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "windows",
    )))]
    {
        // Unused on platforms that don't expose interval/retries.
        let _ = cfg.interval_seconds;
        let _ = cfg.probes;
    }
    socket.set_tcp_keepalive(&params)
}

/// Apply TCP keepalive on a freshly connected, socket-owning H2-family pool
/// connection, honoring a DestinationRule `connectionPool.tcp.tcpKeepalive`
/// per-port override when present and otherwise falling back to the global
/// pool keepalive (whole-seconds `time` only, the pre-existing behavior).
///
/// This is the pooled-connection analogue of `tcp_proxy::apply_backend_tcp_keepalive`
/// (stream-family). The H2-family pools (direct-H2, gRPC, HBONE, mesh-mTLS)
/// previously applied only the global `pool_config.tcp_keepalive_seconds` here;
/// this resolves the per-port DR override the SAME way the stream path does
/// (`proxy.dispatch_port_overrides[port].tcp_keepalive`, keyed by the dial
/// target's app/service port) and applies its full time/interval/probes when
/// set. The DR override is additive and takes precedence; the global value
/// remains the fallback so existing (non-mesh / no-DR) behavior is unchanged.
///
/// IMPORTANT: keepalive is NOT part of the pool key (forbidden by the
/// proxy-protocol rules — see `.claude/rules/proxy-protocols.md` "Never add
/// policy fields ... keepalives to pool keys"). Because the setting is applied
/// once at connection creation on a pooled+shared multiplexed connection, the
/// "first proxy to materialize the pooled connection wins" tradeoff applies
/// (same as documented for `idleTimeout` / `maxRequestsPerConnection`): later
/// dispatchers that differ only in keepalive reuse the existing connection and
/// inherit the keepalive of whoever created it.
///
/// Best-effort: a `setsockopt` failure logs at `warn!` and continues rather
/// than dropping the backend connection — keepalive is an operational hint,
/// not a correctness requirement (matches the stream path).
pub fn apply_pooled_tcp_keepalive(
    pool: &str,
    stream: &tokio::net::TcpStream,
    port_override: Option<&crate::config::types::TcpKeepaliveCfg>,
    global_enabled: bool,
    global_seconds: u64,
) {
    // Per-port DR override takes precedence (full time/interval/probes).
    if let Some(cfg) = port_override.filter(|c| !c.is_empty()) {
        apply_pooled_tcp_keepalive_cfg(pool, stream, cfg);
        return;
    }
    // Fallback: global pool keepalive (whole-seconds idle time only).
    if global_enabled {
        apply_pooled_tcp_keepalive_cfg(
            pool,
            stream,
            &crate::config::types::TcpKeepaliveCfg {
                time_seconds: Some(global_seconds as u32),
                interval_seconds: None,
                probes: None,
            },
        );
    }
}

/// Shared apply that maps a [`crate::config::types::TcpKeepaliveCfg`] onto a
/// connected `tokio::net::TcpStream`, logging at `warn!` (best-effort) on a
/// `setsockopt` failure. Used by [`apply_pooled_tcp_keepalive`] for both the
/// DR-override and global-fallback branches so the two share one fd-lifecycle
/// and error contract.
fn apply_pooled_tcp_keepalive_cfg(
    pool: &str,
    stream: &tokio::net::TcpStream,
    cfg: &crate::config::types::TcpKeepaliveCfg,
) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if let Err(e) = apply_tcp_keepalive(stream.as_raw_fd(), cfg) {
            tracing::warn!(
                pool = %pool,
                error = %e,
                "Failed to apply TCP keepalive on pooled backend socket; continuing"
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        if let Err(e) = apply_tcp_keepalive(stream.as_raw_socket(), cfg) {
            tracing::warn!(
                pool = %pool,
                error = %e,
                "Failed to apply TCP keepalive on pooled backend socket; continuing"
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pool, stream, cfg);
    }
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

// ── Required ingress-pktinfo families for attributed UDP listeners ─────
//
// A NodeWaypoint scoped UDP/DTLS listener derives its per-datagram SOURCE
// workload from the kernel-reported ingress interface, which only
// `IP_PKTINFO` / `IPV6_RECVPKTINFO` surfaces. "Either option succeeded" is NOT
// a sufficient outcome there: a dual-stack `[::]` listener receives native IPv6
// through `IPV6_PKTINFO` and IPv4-mapped clients through `IP_PKTINFO`, so a
// success on the family the socket does not actually serve would mask a
// black-hole listener that reports itself healthy while denying every scoped
// session. The decision below is therefore explicit per bound family.

/// Which pktinfo option(s) a bound UDP socket must have enabled before
/// per-datagram ingress-interface attribution is possible on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressPktinfoFamilies {
    /// An `AF_INET` socket: only `IP_PKTINFO` is meaningful.
    V4,
    /// An `AF_INET6` socket with `IPV6_V6ONLY` set: only `IPV6_RECVPKTINFO`
    /// is meaningful, because no IPv4 datagram can be delivered on it.
    V6,
    /// A dual-stack `AF_INET6` socket: native IPv6 datagrams carry
    /// `IPV6_PKTINFO` and IPv4-mapped datagrams carry `IP_PKTINFO`, so BOTH
    /// must be enabled or one family silently loses its ingress interface.
    Both,
}

impl IngressPktinfoFamilies {
    /// Whether IPv4 ingress datagrams can reach a socket with this shape.
    pub fn needs_v4(self) -> bool {
        matches!(self, Self::V4 | Self::Both)
    }

    /// Whether IPv6 ingress datagrams can reach a socket with this shape.
    pub fn needs_v6(self) -> bool {
        matches!(self, Self::V6 | Self::Both)
    }
}

/// Decide which pktinfo options a bound UDP socket needs for ingress-interface
/// attribution, from its bound local address and its `IPV6_V6ONLY` state.
///
/// `v6only` is ignored for an IPv4 bind (it cannot apply) and is read from the
/// socket rather than assumed, because the dual-stack default is a sysctl
/// (`net.ipv6.bindv6only`) rather than a Ferrum choice.
pub fn required_ingress_pktinfo_families(
    local: std::net::SocketAddr,
    v6only: bool,
) -> IngressPktinfoFamilies {
    match local.ip() {
        std::net::IpAddr::V4(_) => IngressPktinfoFamilies::V4,
        std::net::IpAddr::V6(_) if v6only => IngressPktinfoFamilies::V6,
        std::net::IpAddr::V6(_) => IngressPktinfoFamilies::Both,
    }
}

/// A required ingress-pktinfo option could not be enabled on a socket that
/// depends on it for source attribution.
///
/// Carries the family shape that was required and which of the two setsockopt
/// calls failed, so the caller can report a listener as failed rather than
/// starting a black hole that denies every scoped session.
#[derive(Debug)]
pub struct IngressPktinfoError {
    /// The families the bound socket actually serves.
    pub required: IngressPktinfoFamilies,
    /// `IP_PKTINFO` failure, when IPv4 was required.
    pub v4: Option<std::io::Error>,
    /// `IPV6_RECVPKTINFO` failure, when IPv6 was required.
    pub v6: Option<std::io::Error>,
}

impl std::fmt::Display for IngressPktinfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ingress-interface capture unavailable for {:?} UDP socket",
            self.required
        )?;
        if let Some(error) = &self.v4 {
            write!(f, "; IP_PKTINFO: {error}")?;
        }
        if let Some(error) = &self.v6 {
            write!(f, "; IPV6_RECVPKTINFO: {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for IngressPktinfoError {}

/// Build the fail-closed verdict for a required family shape from the two
/// setsockopt outcomes.
///
/// Split out from the syscalls so the decision itself is exercised without a
/// socket: success on an irrelevant family must never satisfy the family the
/// socket actually serves.
pub fn ingress_pktinfo_outcome(
    required: IngressPktinfoFamilies,
    v4: Result<(), std::io::Error>,
    v6: Result<(), std::io::Error>,
) -> Result<(), IngressPktinfoError> {
    let v4 = match (required.needs_v4(), v4) {
        (true, Err(error)) => Some(error),
        _ => None,
    };
    let v6 = match (required.needs_v6(), v6) {
        (true, Err(error)) => Some(error),
        _ => None,
    };
    if v4.is_none() && v6.is_none() {
        return Ok(());
    }
    Err(IngressPktinfoError { required, v4, v6 })
}

/// Read `IPV6_V6ONLY` from a bound socket (Linux only).
#[cfg(target_os = "linux")]
pub fn get_ipv6_v6only(fd: std::os::unix::io::RawFd) -> std::io::Result<bool> {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &mut val as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(val != 0)
}

/// Enable every ingress-pktinfo option the bound socket's family actually
/// needs, failing closed when one of them cannot be enabled.
///
/// Used only by listeners whose security decision depends on the ingress
/// interface (NodeWaypoint scoped UDP/DTLS). Ordinary UDP/DTLS listeners keep
/// the best-effort `set_ip_pktinfo` / `set_ipv6_recvpktinfo` pair, where a
/// failure only costs a routing-table lookup.
#[cfg(target_os = "linux")]
pub fn enable_ingress_pktinfo(
    fd: std::os::unix::io::RawFd,
    local: std::net::SocketAddr,
) -> Result<IngressPktinfoFamilies, IngressPktinfoError> {
    // A getsockopt failure on an IPv6 socket must not be read as "dual-stack
    // is off"; treat the wider (Both) requirement as the safe assumption.
    let v6only = local.is_ipv6() && get_ipv6_v6only(fd).unwrap_or(false);
    let required = required_ingress_pktinfo_families(local, v6only);
    let v4 = if required.needs_v4() {
        set_ip_pktinfo(fd)
    } else {
        Ok(())
    };
    let v6 = if required.needs_v6() {
        set_ipv6_recvpktinfo(fd)
    } else {
        Ok(())
    };
    ingress_pktinfo_outcome(required, v4, v6).map(|()| required)
}

/// Non-Linux builds have no `IP_PKTINFO` ingress-interface channel at all, so
/// a listener that depends on it fails closed here rather than starting.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn enable_ingress_pktinfo(
    _fd: i32,
    local: std::net::SocketAddr,
) -> Result<IngressPktinfoFamilies, IngressPktinfoError> {
    fn unsupported() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "IP_PKTINFO ingress-interface capture is Linux-only",
        )
    }

    let required = required_ingress_pktinfo_families(local, false);
    let v4 = if required.needs_v4() {
        Err(unsupported())
    } else {
        Ok(())
    };
    let v6 = if required.needs_v6() {
        Err(unsupported())
    } else {
        Ok(())
    };
    ingress_pktinfo_outcome(required, v4, v6).map(|()| required)
}

// ── Do-not-fragment / path-MTU discovery (RFC 9298 §3.1) ────────────────────

/// Whether the running target exposes a usable do-not-fragment socket option.
///
/// RFC 9298 §3.1 says a UDP proxy "MUST NOT introduce IP fragmentation" and
/// that the DF bit "MUST be set if possible" on IPv4. That is not a
/// best-effort requirement, so this constant is a *capability gate*, not a
/// hint: where it is `false` the guarantee cannot be enforced and the RFC 9298
/// profile is refused outright (`EnvConfig::validate_h3_connect_udp_limits` at
/// startup, and the CONNECT-UDP dispatcher at admission). There is deliberately
/// no path that relays UDP through a socket whose fragmentation behaviour the
/// gateway did not set.
///
/// Supported here: Linux/Android (`IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` set
/// to the `PMTUDISC_DO` policy, which both sets DF and reports oversized sends
/// as `EMSGSIZE`) and Apple (`IP_DONTFRAG` / `IPV6_DONTFRAG`). Windows exposes
/// `IP_DONTFRAGMENT`, but Ferrum links no Winsock binding (`libc` is a
/// `cfg(unix)` dependency and `socket2` 0.6 has no fragmentation setter), so
/// installing it there would mean adding a dependency for one `setsockopt`;
/// other BSDs are omitted because the repository builds and tests none of them,
/// so an untested `setsockopt` there would be a guarantee nobody has verified.
/// Both are handled by refusing the profile rather than by relaying without it.
pub const UDP_DONT_FRAGMENT_SUPPORTED: bool =
    cfg!(any(target_os = "linux", target_os = "android")) || cfg!(target_vendor = "apple");

/// Set the do-not-fragment / path-MTU-discovery policy on a UDP socket.
///
/// `is_ipv4` selects the address-family option; pass the family the socket was
/// actually created with, because the IPv4 option is meaningless on an
/// `AF_INET6` socket and vice versa.
///
/// On targets where [`UDP_DONT_FRAGMENT_SUPPORTED`] is `false` this fails with
/// [`std::io::ErrorKind::Unsupported`] instead of silently succeeding: a caller
/// that needs the RFC 9298 §3.1 guarantee must never be told it was installed
/// when it was not. On supported targets a `setsockopt` failure is surfaced
/// verbatim so the caller can refuse the tunnel instead of relaying datagrams
/// the kernel may fragment.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_udp_dont_fragment(fd: std::os::unix::io::RawFd, is_ipv4: bool) -> std::io::Result<()> {
    let (level, name, value) = if is_ipv4 {
        (
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_DO,
        )
    } else {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_DO,
        )
    };
    let value: libc::c_int = value;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
pub fn set_udp_dont_fragment(fd: std::os::unix::io::RawFd, is_ipv4: bool) -> std::io::Result<()> {
    let (level, name) = if is_ipv4 {
        (libc::IPPROTO_IP, libc::IP_DONTFRAG)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
    };
    let value: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Fail-closed arm: this target has no do-not-fragment option Ferrum can
/// install, so it reports that fact instead of returning a success the caller
/// would read as "the RFC 9298 §3.1 guarantee is in force".
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android")),
    not(target_vendor = "apple")
))]
#[allow(dead_code)]
pub fn set_udp_dont_fragment(_fd: std::os::unix::io::RawFd, _is_ipv4: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        UDP_DONT_FRAGMENT_UNSUPPORTED_MESSAGE,
    ))
}

/// Fail-closed arm for non-Unix targets. See the Unix arm above.
#[cfg(not(unix))]
#[allow(dead_code)]
pub fn set_udp_dont_fragment(_fd: i32, _is_ipv4: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        UDP_DONT_FRAGMENT_UNSUPPORTED_MESSAGE,
    ))
}

/// Fixed diagnostic for the unsupported-target arms of
/// [`set_udp_dont_fragment`]. Named so the message cannot drift between them.
#[allow(dead_code)]
pub const UDP_DONT_FRAGMENT_UNSUPPORTED_MESSAGE: &str =
    "no do-not-fragment socket option is available on this build target";

/// Captured local (reply-source) address from an `IP_PKTINFO` / `IPV6_PKTINFO`
/// cmsg. The interface index is the RECEIVE-side ingress interface the kernel
/// reported for the datagram, which NodeWaypoint UDP source attribution treats
/// as authoritative evidence. It is deliberately NOT the same quantity as the
/// send-side egress interface — see [`PktinfoLocal::send_ifindex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PktinfoLocal {
    pub ip: std::net::IpAddr,
    pub ifindex: u32,
}

impl PktinfoLocal {
    /// Interface index to place in an OUTBOUND pktinfo cmsg for this reply
    /// source.
    ///
    /// `ifindex` as captured is a receive-side fact ("the datagram arrived on
    /// this interface"). In an outbound `in_pktinfo` / `in6_pktinfo` the same
    /// field means something different — it constrains the egress route lookup
    /// the way `SO_BINDTODEVICE` does, and on IPv4 it additionally makes the
    /// kernel prefer the interface's primary address over `ipi_spec_dst`. Those
    /// two meanings coincide only by accident, so the ingress interface must
    /// never be reused blindly on send: replying to a same-node pod whose
    /// datagram arrived on one device while the captured local address lives on
    /// another would pin egress to a device the reply source does not belong
    /// to, and the routing table would no longer be free to pick the path back
    /// to the client.
    ///
    /// The one case where the field is genuinely REQUIRED on send is a scoped
    /// IPv6 source address, whose zone is ambiguous without it: link-local
    /// unicast (`fe80::/10`) and interface-local / link-local multicast
    /// (`ff01::/16`, `ff02::/16`). Everything else — every IPv4 source and
    /// every global IPv6 source — sends `0` and lets the route table choose the
    /// egress device, while `ipi_spec_dst` / `ipi6_addr` still pins the source
    /// address exactly to the local destination the client targeted.
    ///
    /// Both cmsg construction sites are Linux-only, so the binary target has no
    /// caller for this on other platforms; the external unit tests still do.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn send_ifindex(self) -> u32 {
        match self.ip {
            std::net::IpAddr::V4(_) => 0,
            std::net::IpAddr::V6(v6) => {
                let octets = v6.octets();
                // Link-local unicast: `fe80::/10`.
                if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                    return self.ifindex;
                }
                // Interface-local / link-local multicast: `ff01::/16`, `ff02::/16`.
                if octets[0] == 0xff && matches!(octets[1] & 0x0f, 0x01 | 0x02) {
                    return self.ifindex;
                }
                0
            }
        }
    }
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

/// Cmsg buffer size large enough to hold UDP_GRO (u16), either IP_PKTINFO or
/// IPV6_PKTINFO, and either an IP_RECVORIGDSTADDR (`sockaddr_in`) or
/// IPV6_RECVORIGDSTADDR (`sockaddr_in6`) original-destination cmsg on recv. All
/// three can arrive on the same datagram (a mesh UDP TPROXY capture socket
/// enables PKTINFO + RECVORIGDSTADDR together, and GRO may coalesce on top), so
/// the buffer reserves room for each. Sized for the worst case (IPv6) so a
/// single allocation works for both address families.
#[cfg(target_os = "linux")]
pub fn recv_cmsg_space() -> usize {
    unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize
            + libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize
            + libc::CMSG_SPACE(std::mem::size_of::<libc::sockaddr_in6>() as u32) as usize
    }
}

// ── IP_TRANSPARENT / IPV6_TRANSPARENT ──────────────────────────────────
//
// `IP_TRANSPARENT` lets a socket bind to and receive packets addressed to a
// non-local address. The mesh UDP capture listener (F3 §3.3 Stage 3) needs it
// to accept datagrams that netfilter `TPROXY` delivered transparently: TPROXY
// does NOT rewrite the datagram's destination (unlike the TCP REDIRECT model),
// so the socket receiving them must be transparent to claim packets whose dst
// is the captured pod's real `service:port`, not the listener's own bind addr.

/// Enable `IP_TRANSPARENT` on a socket (Linux only).
///
/// Required on the UDP TPROXY capture socket so it can receive datagrams whose
/// destination address is not local to this host (the original, un-rewritten
/// `service:port` the captured pod dialed). Needs `CAP_NET_ADMIN`.
///
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
pub fn set_ip_transparent(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Enable `IPV6_TRANSPARENT` on a socket (Linux only). IPv6 analogue of
/// [`set_ip_transparent`].
#[cfg(target_os = "linux")]
pub fn set_ipv6_transparent(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    // IPV6_TRANSPARENT = 75 (Linux 2.6.37+). Not exposed by the `libc` crate.
    const IPV6_TRANSPARENT: libc::c_int = 75;
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_TRANSPARENT,
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
pub fn set_ip_transparent(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_ipv6_transparent(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

/// Make a NodeWaypoint-scoped datagram listener socket transparent so it may
/// SOURCE replies from an address that is not configured on this host.
///
/// This is a thin family dispatcher over the two established helpers above —
/// [`set_ip_transparent`] and [`set_ipv6_transparent`] — deliberately NOT a
/// third `setsockopt` implementation. Rust has no function overloading, so
/// adding a second `set_ip_transparent` arity would not compile; the family
/// decision belongs here, once, rather than being repeated at each scoped
/// listener.
///
/// The NodeWaypoint Service datapath needs exactly this flag: a workload
/// addresses its Service's ClusterIP, the steering rules deliver that datagram
/// locally **without rewriting it**, and the reply must therefore leave with
/// the ClusterIP as its source or the workload's connected socket discards it.
/// The kernel refuses a non-local source address unless the socket carries
/// `FLOWI_FLAG_ANYSRC`, which is what `IP_TRANSPARENT` / `IPV6_TRANSPARENT`
/// sets. Both option numbers set the SAME kernel flag
/// (`inet_sk(sk)->transparent`); the family-appropriate one is used so a
/// failure names an option that socket can actually carry.
///
/// Requires `CAP_NET_ADMIN` (or `CAP_NET_RAW` on newer kernels). Unlike the
/// per-family helpers — whose non-Linux stubs are historic no-ops for the
/// TPROXY capture paths — this one FAILS CLOSED off Linux, because its only
/// callers are scoped listeners that must not start when they cannot source
/// their replies correctly.
#[cfg(target_os = "linux")]
pub fn set_scoped_reply_transparent(
    fd: std::os::unix::io::RawFd,
    ipv6: bool,
) -> std::io::Result<()> {
    if ipv6 {
        set_ipv6_transparent(fd)
    } else {
        set_ip_transparent(fd)
    }
}

/// Non-Linux builds have no transparent-socket concept, and the NodeWaypoint
/// steering datapath is Linux-only, so a scoped listener refuses to start here
/// rather than serving a one-way datapath.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_scoped_reply_transparent(_fd: i32, _ipv6: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "transparent sockets (IP_TRANSPARENT / IPV6_TRANSPARENT) are Linux-only",
    ))
}

// ── IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR ──────────────────────────
//
// Tells the kernel to attach the ORIGINAL (pre-`TPROXY`) destination address of
// inbound datagrams as a cmsg on recv. This is how the mesh UDP capture listener
// recovers which `service:port` a captured pod dialed: `TPROXY` delivers the
// datagram WITHOUT rewriting its destination, so — unlike the TCP REDIRECT path
// which uses `SO_ORIGINAL_DST` (a getsockopt, TCP/conntrack-only) — the orig-dst
// rides a per-datagram cmsg. Must be paired with `IP_TRANSPARENT` on the capture
// socket.

/// Enable `IP_RECVORIGDSTADDR` (IPv4) on a UDP socket (Linux only).
///
/// After enabling, recvmsg()/recvmmsg() cmsg buffers carry an `IP_RECVORIGDSTADDR`
/// (`SOL_IP`, type 20) `sockaddr_in` with the datagram's original destination —
/// recovered per-datagram by [`extract_origdst`].
#[cfg(target_os = "linux")]
pub fn set_ip_recvorigdstaddr(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    // IP_RECVORIGDSTADDR = 20 (a.k.a. IP_ORIGDSTADDR). Not exposed by `libc`.
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Enable `IPV6_RECVORIGDSTADDR` on a UDP socket (Linux only). IPv6 analogue of
/// [`set_ip_recvorigdstaddr`] (`SOL_IPV6`, type 74, `sockaddr_in6` payload).
#[cfg(target_os = "linux")]
pub fn set_ipv6_recvorigdstaddr(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    // IPV6_RECVORIGDSTADDR = 74 (a.k.a. IPV6_ORIGDSTADDR). Not exposed by `libc`.
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_RECVORIGDSTADDR,
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
pub fn set_ip_recvorigdstaddr(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_ipv6_recvorigdstaddr(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

/// Parse an `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR` cmsg and return the
/// datagram's original (pre-`TPROXY`) destination address.
///
/// Returns `None` when neither cmsg is present (e.g. the socket has the option
/// disabled, or the datagram arrived through a cmsg-less recv path). Mirrors
/// [`extract_pktinfo_local_addr`] but parses the orig-dst sockaddr instead of
/// the pktinfo reply-source. The IPv4 cmsg carries a `sockaddr_in`
/// (`SOL_IP`, type 20); the IPv6 cmsg carries a `sockaddr_in6`
/// (`SOL_IPV6`, type 74). The address/port are read with `read_unaligned`
/// because cmsg payloads are not guaranteed aligned for the wider sockaddr
/// structs.
#[cfg(target_os = "linux")]
pub fn extract_origdst(msg: &libc::msghdr) -> Option<std::net::SocketAddr> {
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        unsafe {
            let level = (*cmsg).cmsg_level;
            let ty = (*cmsg).cmsg_type;
            if level == libc::SOL_IP && ty == IP_RECVORIGDSTADDR {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let sin = std::ptr::read_unaligned(data_ptr);
                return Some(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                        sin.sin_addr.s_addr,
                    ))),
                    u16::from_be(sin.sin_port),
                ));
            }
            if level == libc::SOL_IPV6 && ty == IPV6_RECVORIGDSTADDR {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let sin6 = std::ptr::read_unaligned(data_ptr);
                return Some(std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                    u16::from_be(sin6.sin6_port),
                ));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn extract_origdst(_msg: &()) -> Option<std::net::SocketAddr> {
    None
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
    // Send-side interface selection is derived, never the captured ingress
    // interface: see `PktinfoLocal::send_ifindex`.
    let send_ifindex = local.send_ifindex();
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
            // `send_ifindex` is always 0 on IPv4: per ip(7), a nonzero ifindex
            // makes the kernel prefer the interface's primary address over
            // ipi_spec_dst on multi-IP interfaces, which would defeat the
            // "reply from captured destination" semantics. ipi_spec_dst alone
            // is sufficient on IPv4; ifindex is only honored for IPv6 scopes.
            let pi = libc::in_pktinfo {
                ipi_ifindex: send_ifindex as libc::c_int,
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
                ipi6_ifindex: send_ifindex,
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
    /// `setsockopt`/`cmsg` level for the kernel TLS ULP. Also used by
    /// [`crate::proxy::ktls_record`] for the record-type ancillary contract, so
    /// the two cannot drift.
    pub const SOL_TLS: libc::c_int = 282;
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
    /// Layout: `version`, `cipher_type`, `iv[12]`, `key[32]`, `salt[0]`,
    /// `rec_seq[8]`.
    ///
    /// `TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE` is **0**, not 4: ChaCha20-Poly1305
    /// uses the full 12-byte IV directly with no salt/explicit-nonce split like
    /// AES-GCM, so the UAPI struct keeps the member for shape parity at length
    /// zero. The whole struct is therefore 56 bytes, and `do_tls_setsockopt_conf`
    /// compares `optlen` against that size for **exact** equality — a struct
    /// with a 4-byte salt is 60 bytes and is rejected with `EINVAL` on every
    /// kernel, which presents as "this kernel has no ChaCha20-Poly1305 kTLS"
    /// rather than as a layout bug. The `const` block below pins all three
    /// layouts to `libc`'s own `tls12_crypto_info_*` definitions so that
    /// mistake cannot recur silently.
    #[repr(C)]
    struct TlsCryptoInfoChaCha20Poly1305 {
        version: u16,
        cipher_type: u16,
        iv: [u8; 12],
        key: [u8; 32],
        salt: [u8; 0],
        rec_seq: [u8; 8],
    }

    /// Compile-time parity between the structs above and the kernel UAPI.
    ///
    /// The TLS ULP rejects any `setsockopt(SOL_TLS, TLS_TX|TLS_RX)` whose
    /// `optlen` is not exactly the cipher's `tls12_crypto_info_*` size, and the
    /// `getsockopt` readback in [`read_ktls_record_seq`] locates `rec_seq` by
    /// offset. A silent divergence in either therefore disables a cipher
    /// (install `EINVAL`) or misreads its record counter, so both are asserted
    /// against `libc`'s definitions at build time rather than discovered from a
    /// capability probe that reports `false`.
    const _: () = {
        assert!(
            std::mem::size_of::<TlsCryptoInfoAes128Gcm>()
                == std::mem::size_of::<libc::tls12_crypto_info_aes_gcm_128>()
        );
        assert!(
            std::mem::offset_of!(TlsCryptoInfoAes128Gcm, rec_seq)
                == std::mem::offset_of!(libc::tls12_crypto_info_aes_gcm_128, rec_seq)
        );
        assert!(
            std::mem::size_of::<TlsCryptoInfoAes256Gcm>()
                == std::mem::size_of::<libc::tls12_crypto_info_aes_gcm_256>()
        );
        assert!(
            std::mem::offset_of!(TlsCryptoInfoAes256Gcm, rec_seq)
                == std::mem::offset_of!(libc::tls12_crypto_info_aes_gcm_256, rec_seq)
        );
        assert!(
            std::mem::size_of::<TlsCryptoInfoChaCha20Poly1305>()
                == std::mem::size_of::<libc::tls12_crypto_info_chacha20_poly1305>()
        );
        assert!(
            std::mem::offset_of!(TlsCryptoInfoChaCha20Poly1305, rec_seq)
                == std::mem::offset_of!(libc::tls12_crypto_info_chacha20_poly1305, rec_seq)
        );
    };

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

    /// Where a cipher's `tls12_crypto_info_*` struct keeps the fields the
    /// record-sequence readback has to validate and extract.
    ///
    /// Sizes and offsets come from the real `#[repr(C)]` definitions above via
    /// `size_of` / `offset_of`, so the parser cannot drift from the structs the
    /// installer hands the kernel.
    struct CryptoInfoLayout {
        size: usize,
        seq_offset: usize,
        cipher_type: u16,
    }

    fn crypto_info_layout(cipher: KtlsCipher) -> CryptoInfoLayout {
        match cipher {
            KtlsCipher::Aes128Gcm => CryptoInfoLayout {
                size: std::mem::size_of::<TlsCryptoInfoAes128Gcm>(),
                seq_offset: std::mem::offset_of!(TlsCryptoInfoAes128Gcm, rec_seq),
                cipher_type: TLS_CIPHER_AES_GCM_128,
            },
            KtlsCipher::Aes256Gcm => CryptoInfoLayout {
                size: std::mem::size_of::<TlsCryptoInfoAes256Gcm>(),
                seq_offset: std::mem::offset_of!(TlsCryptoInfoAes256Gcm, rec_seq),
                cipher_type: TLS_CIPHER_AES_GCM_256,
            },
            KtlsCipher::Chacha20Poly1305 => CryptoInfoLayout {
                size: std::mem::size_of::<TlsCryptoInfoChaCha20Poly1305>(),
                seq_offset: std::mem::offset_of!(TlsCryptoInfoChaCha20Poly1305, rec_seq),
                cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
            },
        }
    }

    /// Read one direction's live TLS record sequence number from the kernel.
    ///
    /// `getsockopt(SOL_TLS, TLS_TX | TLS_RX)` returns the direction's whole
    /// `tls12_crypto_info_*` structure, whose `rec_seq` field is the **next**
    /// record sequence number the kernel will use — i.e. exactly the count of
    /// records that traffic key has already protected, including everything
    /// consumed by the handshake before the keys were installed. That is the
    /// message counter `rustls`'s kernel-connection API requires the caller to
    /// track once it stops tracking it itself (see
    /// [`crate::proxy::ktls_confidentiality`]).
    ///
    /// Everything about the answer is validated rather than assumed: the
    /// option length must be exactly the struct this cipher installs, and the
    /// echoed `version` / `cipher_type` must be the ones this session
    /// installed. A kernel that answers with a different layout therefore fails
    /// closed instead of yielding a plausible-looking wrong counter.
    ///
    /// The reply also carries the session key, so the scratch buffer is
    /// `Zeroizing` and nothing but `rec_seq` is ever read out of it or logged.
    pub fn read_ktls_record_seq(
        fd: std::os::unix::io::RawFd,
        cipher: KtlsCipher,
        tls_version: u16,
        is_tx: bool,
    ) -> std::io::Result<u64> {
        let layout = crypto_info_layout(cipher);
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; layout.size]);
        let mut len = layout.size as libc::socklen_t;
        let optname = if is_tx { TLS_TX } else { TLS_RX };
        // SAFETY: `buf` is a live allocation of exactly `layout.size` bytes and
        // `len` describes it, so the kernel cannot write past it. `fd` is
        // borrowed from a live socket by the caller for the duration of the
        // call.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_TLS,
                optname,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len as usize != layout.size {
            return Err(std::io::Error::other(format!(
                "kTLS: crypto info readback returned {len} bytes, expected {}",
                layout.size
            )));
        }
        let version = u16::from_ne_bytes([buf[0], buf[1]]);
        let cipher_type = u16::from_ne_bytes([buf[2], buf[3]]);
        if version != tls_version {
            return Err(std::io::Error::other(format!(
                "kTLS: crypto info readback reports version 0x{version:04x}, \
                 expected 0x{tls_version:04x}"
            )));
        }
        if cipher_type != layout.cipher_type {
            return Err(std::io::Error::other(format!(
                "kTLS: crypto info readback reports cipher {cipher_type}, expected {}",
                layout.cipher_type
            )));
        }
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&buf[layout.seq_offset..layout.seq_offset + 8]);
        Ok(u64::from_be_bytes(seq))
    }

    /// Current `SO_RCVBUF` for a socket, in bytes.
    ///
    /// This is the kernel's `sk_rcvbuf`, already doubled for skb overhead. TCP
    /// admits another skb only while the receive-memory charge is at or below
    /// this value, so it bounds unread wire data together with one admitted-skb
    /// overshoot. On its own it is **not** a stable bound: TCP receive
    /// autotuning rewrites it as the connection runs.
    /// [`pin_socket_receive_buffer`] is what makes a readback hold still.
    pub fn socket_receive_buffer_bytes(fd: std::os::unix::io::RawFd) -> std::io::Result<u64> {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value` is a live `c_int` and `len` describes it exactly.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of_mut!(value).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len as usize != std::mem::size_of::<libc::c_int>() || value < 0 {
            return Err(std::io::Error::other(
                "kTLS: SO_RCVBUF readback is not a non-negative int",
            ));
        }
        Ok(value as u64)
    }

    /// Bytes currently queued on `fd` for reading, from the kernel's own
    /// `FIONREAD` accounting.
    ///
    /// Called on a socket that carries the TLS ULP but no keys yet, so this is
    /// still plain `tcp_ioctl` accounting: exactly the unread wire bytes
    /// `rcv_nxt - copied_seq`. It is the *only* sound way to bound data that
    /// was already queued before [`pin_socket_receive_buffer`] took effect —
    /// that data was admitted under whatever `sk_rcvbuf` autotuning had reached
    /// at the time, which no later observation can reconstruct.
    pub fn socket_receive_queue_bytes(fd: std::os::unix::io::RawFd) -> std::io::Result<u64> {
        let mut queued: libc::c_int = 0;
        // SAFETY: `fd` is borrowed from a live socket by the caller and
        // `FIONREAD` writes exactly one `c_int` through the pointer.
        let ret = unsafe { libc::ioctl(fd, libc::FIONREAD, std::ptr::addr_of_mut!(queued)) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if queued < 0 {
            return Err(std::io::Error::other(
                "kTLS: FIONREAD reported a negative receive queue",
            ));
        }
        Ok(queued as u64)
    }

    /// Pin this socket's receive buffer so the kernel can never grow it again,
    /// and return the kernel's own readback of the pinned size.
    ///
    /// # The invariant this establishes
    ///
    /// A successful `setsockopt(SOL_SOCKET, SO_RCVBUF)` sets `SOCK_RCVBUF_LOCK`
    /// in `sk->sk_userlocks`, and every kernel path that would otherwise raise
    /// `sk_rcvbuf` — `tcp_rcv_space_adjust`, `tcp_clamp_window` — is gated on
    /// that flag being clear. From the moment this returns, `sk_rcvbuf` for this
    /// socket can only change through another `setsockopt` on this same fd,
    /// which the gateway never issues. Raising `net.ipv4.tcp_rmem[2]` or
    /// `net.core.rmem_max` afterwards therefore cannot move it: those sysctls
    /// feed autotuning and future `setsockopt` clamping, not a locked socket.
    ///
    /// That is what a confidentiality bound needs and what a `/proc` snapshot
    /// can never give: a *per-socket* ceiling the kernel itself enforces for the
    /// remaining life of the connection.
    ///
    /// # Linux doubling and clamping, handled by readback
    ///
    /// The kernel clamps the requested value to `net.core.rmem_max`, then stores
    /// `max(2 * value, SOCK_MIN_RCVBUF)`. Neither adjustment is predicted here —
    /// the `getsockopt` readback afterwards *is* the answer, and it is the value
    /// the caller must bound with. `request_bytes` is only a request.
    ///
    /// The request is floored at half the socket's live `SO_RCVBUF`, converting
    /// the doubled readback back into `setsockopt` request units so pinning does
    /// not accidentally double an already-large buffer. If the kernel still
    /// lands below the prior readback (a small `rmem_max` against an
    /// already-autotuned socket), no queued byte is lost: Linux keeps skbs that
    /// are already on the receive queue and merely stops admitting more, and
    /// the caller bounds the pre-existing queue separately with
    /// [`socket_receive_queue_bytes`].
    pub fn pin_socket_receive_buffer(
        fd: std::os::unix::io::RawFd,
        request_bytes: u64,
    ) -> std::io::Result<u64> {
        let current = socket_receive_buffer_bytes(fd)?;
        // `sk_setsockopt` rejects a negative value and internally clamps to
        // `INT_MAX / 2` before doubling, so saturate here rather than wrap. A
        // getsockopt readback is already doubled; convert it back to request
        // units before applying the throughput floor.
        let current_request_units = current.div_ceil(2);
        let want = request_bytes
            .max(current_request_units)
            .min(libc::c_int::MAX as u64 / 2) as libc::c_int;
        // SAFETY: `want` is a live `c_int` and `len` describes it exactly; `fd`
        // is borrowed from a live socket by the caller.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of!(want).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // The readback, not the request, is the bound. A kernel that answered
        // the set but cannot report the result leaves nothing to bound with, so
        // the error propagates and the caller refuses the handoff.
        let pinned = socket_receive_buffer_bytes(fd)?;
        if pinned == 0 {
            return Err(std::io::Error::other(
                "kTLS: pinned SO_RCVBUF read back as zero",
            ));
        }
        Ok(pinned)
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
            // `TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE` is 0: the member exists
            // for shape parity with the other UAPI structs and carries no
            // bytes, because the full 12-byte IV is used directly.
            salt: [],
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
    /// connection drop. The per-cipher gate in `proxy::ktls_accept` prevents
    /// this by refusing connections for ciphers whose kernel probe failed
    /// BEFORE extracting secrets.
    ///
    /// The `*_record_seq` flags are a second, independent capability: whether
    /// this kernel will hand back the direction's live `rec_seq` through
    /// `getsockopt(SOL_TLS, TLS_TX | TLS_RX)`. A cipher with a finite
    /// confidentiality limit (both AES-GCM suites) cannot be handed off without
    /// it, because that counter is the only trustworthy record count once
    /// rustls stops tracking one. It is probed separately from installability
    /// so a kernel that cannot report sequence numbers still keeps
    /// ChaCha20-Poly1305 kTLS, whose rustls confidentiality limit is
    /// `u64::MAX`.
    struct KtlsAvailability {
        aes128gcm: bool,
        aes256gcm: bool,
        chacha20_poly1305: bool,
        aes128gcm_record_seq: bool,
        aes256gcm_record_seq: bool,
        chacha20_poly1305_record_seq: bool,
        /// Raw `errno` from each cipher's one-shot install probe: `0` when the
        /// kernel took the keys, [`PROBE_SETUP_FAILED`] when the throwaway
        /// loopback socket or the `TCP_ULP` install failed before the cipher
        /// was ever offered, otherwise the `setsockopt` error.
        ///
        /// Kept so an unavailable cipher can say *why*. A bare `false` is
        /// ambiguous between "this kernel lacks the cipher" and "the gateway
        /// asked for it wrongly" — exactly the ambiguity that let a 60-byte
        /// ChaCha20-Poly1305 `tls12_crypto_info` (the UAPI struct is 56) read
        /// as a missing kernel capability.
        aes128gcm_probe_errno: i32,
        aes256gcm_probe_errno: i32,
        chacha20_poly1305_probe_errno: i32,
    }

    /// Sentinel for "the probe never reached the cipher install".
    const PROBE_SETUP_FAILED: i32 = -1;

    static KTLS_AVAILABILITY: std::sync::OnceLock<KtlsAvailability> = std::sync::OnceLock::new();

    fn ktls_availability() -> &'static KtlsAvailability {
        KTLS_AVAILABILITY.get_or_init(|| {
            // Probe each cipher on its own fresh TCP loopback pair. We cannot
            // reuse a single socket across all three ciphers because the
            // kernel refuses further TLS_TX installs on a socket that already
            // has keys installed. Three separate probes cost ~3ms at startup
            // (one-time), which is acceptable for one-shot auto-detection.
            let aes128gcm_probe_errno = unsafe {
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
            let aes256gcm_probe_errno = unsafe {
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
            let chacha20_poly1305_probe_errno = unsafe {
                let info = TlsCryptoInfoChaCha20Poly1305 {
                    version: TLS_1_2_VERSION,
                    cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                    iv: [0u8; 12],
                    key: [0u8; 32],
                    salt: [],
                    rec_seq: [0u8; 8],
                };
                probe_cipher(
                    &info as *const TlsCryptoInfoChaCha20Poly1305 as *const libc::c_void,
                    std::mem::size_of::<TlsCryptoInfoChaCha20Poly1305>() as libc::socklen_t,
                )
            };
            let aes128gcm = aes128gcm_probe_errno == 0;
            let aes256gcm = aes256gcm_probe_errno == 0;
            let chacha20_poly1305 = chacha20_poly1305_probe_errno == 0;
            // Sequence-number observability is probed only for ciphers that
            // installed: an unusable cipher has nothing to report.
            let aes128gcm_record_seq =
                aes128gcm && probe_record_seq_observable(KtlsCipher::Aes128Gcm);
            let aes256gcm_record_seq =
                aes256gcm && probe_record_seq_observable(KtlsCipher::Aes256Gcm);
            let chacha20_poly1305_record_seq =
                chacha20_poly1305 && probe_record_seq_observable(KtlsCipher::Chacha20Poly1305);
            KtlsAvailability {
                aes128gcm,
                aes256gcm,
                chacha20_poly1305,
                aes128gcm_record_seq,
                aes256gcm_record_seq,
                chacha20_poly1305_record_seq,
                aes128gcm_probe_errno,
                aes256gcm_probe_errno,
                chacha20_poly1305_probe_errno,
            }
        })
    }

    /// Human-readable, secret-free summary of this kernel's kTLS posture.
    ///
    /// Every cipher is named with its install verdict *and the reason it
    /// failed*, plus its record-sequence observability. Only probe outcomes are
    /// reported: the probes install all-zero throwaway key material on a
    /// loopback socket that never carries traffic, so nothing here derives from
    /// a session secret.
    ///
    /// Used by the hosted live-kernel gate's failure message, where "the cipher
    /// is unavailable" without an `errno` is not enough to tell a kernel
    /// without the capability from a gateway-side layout or argument error.
    pub fn ktls_availability_diagnostic() -> String {
        fn install_reason(errno: i32) -> String {
            match errno {
                0 => "ok".to_string(),
                PROBE_SETUP_FAILED => "no TLS ULP (probe setup failed)".to_string(),
                other => std::io::Error::from_raw_os_error(other).to_string(),
            }
        }
        let a = ktls_availability();
        format!(
            "aes128={} (install: {}, record_seq={}) \
             aes256={} (install: {}, record_seq={}) \
             chacha20={} (install: {}, record_seq={})",
            a.aes128gcm,
            install_reason(a.aes128gcm_probe_errno),
            a.aes128gcm_record_seq,
            a.aes256gcm,
            install_reason(a.aes256gcm_probe_errno),
            a.aes256gcm_record_seq,
            a.chacha20_poly1305,
            install_reason(a.chacha20_poly1305_probe_errno),
            a.chacha20_poly1305_record_seq,
        )
    }

    /// Whether this kernel exposes a usable live record sequence number for
    /// `cipher` in **both** directions.
    ///
    /// Probed once at startup on a throwaway loopback socket, exactly like
    /// installability, so a cipher whose confidentiality limit could not be
    /// enforced is refused *before* a handshake is consumed rather than after
    /// the keys have already left userspace.
    pub fn is_ktls_record_seq_observable(cipher: KtlsCipher) -> bool {
        let a = ktls_availability();
        match cipher {
            KtlsCipher::Aes128Gcm => a.aes128gcm_record_seq,
            KtlsCipher::Aes256Gcm => a.aes256gcm_record_seq,
            KtlsCipher::Chacha20Poly1305 => a.chacha20_poly1305_record_seq,
        }
    }

    /// Install both directions on a throwaway kTLS socket with two distinct,
    /// non-zero record sequence numbers and require the kernel to hand each of
    /// them back on the direction it belongs to.
    ///
    /// That single check covers everything the enforcement path depends on:
    /// the `getsockopt` exists for `TLS_TX` *and* `TLS_RX`, the reply matches
    /// this cipher's `tls12_crypto_info_*` layout and version, the `rec_seq`
    /// field is where the struct says it is and is big-endian, and TX and RX
    /// are not aliased onto one counter. Distinct probe values are what make
    /// the direction check meaningful — equal values would pass even on a
    /// kernel that answered both queries from the same context.
    fn probe_record_seq_observable(cipher: KtlsCipher) -> bool {
        /// Distinctive, direction-specific, non-zero probe sequence numbers.
        const PROBE_TX_SEQ: u64 = 0x0102_0304_0506_0708;
        const PROBE_RX_SEQ: u64 = 0x1112_1314_1516_1718;

        // SAFETY: raw socket setup and teardown, with every fd closed on every
        // exit path below.
        let Some((server_fd, client_fd)) = (unsafe { probe_socket_pair() }) else {
            return false;
        };
        let observable = probe_record_seq_on_fd(server_fd, cipher, PROBE_TX_SEQ, PROBE_RX_SEQ);
        // SAFETY: both fds were produced by `probe_socket_pair` and are closed
        // exactly once here.
        unsafe {
            libc::close(server_fd);
            libc::close(client_fd);
        }
        if !observable {
            debug!(
                "kTLS: kernel does not report a usable record sequence number for {cipher:?}; \
                 handoff for this cipher will be declined when its suite has a \
                 confidentiality limit"
            );
        }
        observable
    }

    /// Install and read back both directions on an already-connected socket.
    fn probe_record_seq_on_fd(
        fd: std::os::unix::io::RawFd,
        cipher: KtlsCipher,
        tx_seq: u64,
        rx_seq: u64,
    ) -> bool {
        let ulp_name = b"tls\0";
        // SAFETY: `fd` is a live connected TCP socket and `ulp_name` is a
        // NUL-terminated buffer of the given length.
        let ulp_ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_ULP,
                ulp_name.as_ptr() as *const libc::c_void,
                ulp_name.len() as libc::socklen_t,
            )
        };
        if ulp_ret != 0 {
            return false;
        }
        let key_len = match cipher {
            KtlsCipher::Aes128Gcm => 16,
            KtlsCipher::Aes256Gcm | KtlsCipher::Chacha20Poly1305 => 32,
        };
        // Throwaway all-zero key material: nothing is ever encrypted or
        // decrypted on this socket, only the sequence bookkeeping is read.
        let key = vec![0u8; key_len];
        let iv = [0u8; 12];
        let version = TLS_1_2_VERSION;
        let install = |is_tx: bool, seq: u64| -> bool {
            let seq = seq.to_be_bytes();
            let installed = match cipher {
                KtlsCipher::Aes128Gcm => install_aes128gcm(fd, version, is_tx, &key, &iv, &seq),
                KtlsCipher::Aes256Gcm => install_aes256gcm(fd, version, is_tx, &key, &iv, &seq),
                KtlsCipher::Chacha20Poly1305 => {
                    install_chacha20_poly1305(fd, version, is_tx, &key, &iv, &seq)
                }
            };
            installed.is_ok()
        };
        if !install(true, tx_seq) || !install(false, rx_seq) {
            return false;
        }
        let observed_tx = read_ktls_record_seq(fd, cipher, TLS_1_2_VERSION, true);
        let observed_rx = read_ktls_record_seq(fd, cipher, TLS_1_2_VERSION, false);
        matches!(observed_tx, Ok(seq) if seq == tx_seq)
            && matches!(observed_rx, Ok(seq) if seq == rx_seq)
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
    /// Gate the kTLS accept on this before extracting secrets for AES-128-GCM
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
    /// handing a ChaCha20-Poly1305 connection to the kTLS accept path.
    pub fn is_ktls_chacha20_poly1305_available() -> bool {
        ktls_availability().chacha20_poly1305
    }

    /// Set up a real TCP loopback connection and run the kTLS setsockopt sequence
    /// on the accepted server-side socket. Returns `0` iff BOTH the TCP_ULP
    /// install AND the dummy cipher TX key install returned 0; otherwise the
    /// `setsockopt` `errno`, or [`PROBE_SETUP_FAILED`] when the probe never got
    /// as far as offering the cipher.
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
    unsafe fn probe_cipher(info_ptr: *const libc::c_void, info_len: libc::socklen_t) -> i32 {
        unsafe {
            let Some((server_fd, client_fd)) = probe_socket_pair() else {
                return PROBE_SETUP_FAILED;
            };

            // Install `TCP_ULP` "tls" on the server-side TCP socket.
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
                return PROBE_SETUP_FAILED;
            }

            // Install a dummy TX key for the cipher under test. A value of 0
            // for tx_ret means the kernel accepted the cipher install and the
            // full kTLS path works for this cipher. Capture `errno` before the
            // closes, which would otherwise overwrite it.
            let tx_ret = libc::setsockopt(server_fd, SOL_TLS, TLS_TX, info_ptr, info_len);
            let install_errno = if tx_ret == 0 {
                0
            } else {
                // A zero `errno` must never masquerade as a successful install.
                match *libc::__errno_location() {
                    0 => libc::EINVAL,
                    raw => raw,
                }
            };

            libc::close(server_fd);
            libc::close(client_fd);
            install_errno
        }
    }

    /// Establish a throwaway loopback TCP connection and return
    /// `(server_fd, client_fd)`, or `None` if anything in the setup failed.
    ///
    /// The caller owns both fds and must close them. Shared by the
    /// installability probe and the record-sequence observability probe so the
    /// two cannot drift on what "a real kTLS-capable socket" means.
    #[allow(clippy::cast_possible_truncation)]
    unsafe fn probe_socket_pair() -> Option<(std::os::unix::io::RawFd, std::os::unix::io::RawFd)> {
        unsafe {
            // 1. Create listener socket, bind to 127.0.0.1:0, listen.
            let listener_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if listener_fd < 0 {
                return None;
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
                return None;
            }

            if libc::listen(listener_fd, 1) < 0 {
                libc::close(listener_fd);
                return None;
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
                return None;
            }

            // 2. Create client socket, set O_NONBLOCK, connect (EINPROGRESS expected).
            let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if client_fd < 0 {
                libc::close(listener_fd);
                return None;
            }

            let flags = libc::fcntl(client_fd, libc::F_GETFL, 0);
            if flags < 0 || libc::fcntl(client_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                libc::close(client_fd);
                libc::close(listener_fd);
                return None;
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
                    return None;
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
                return None;
            }

            // We no longer need the listener.
            libc::close(listener_fd);

            Some((server_fd, client_fd))
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

    /// Same shape as the Linux accessor so callers (notably the live-kernel
    /// gate's failure message) need no `cfg`.
    #[allow(dead_code)]
    pub fn ktls_availability_diagnostic() -> String {
        "kTLS is Linux-only: aes128=false aes256=false chacha20=false".to_string()
    }

    /// No kernel TLS ULP exists off Linux, so no record sequence number can be
    /// observed. Reporting `false` keeps the confidentiality-limit gate
    /// fail-closed on every non-Linux build.
    #[allow(dead_code)]
    pub fn is_ktls_record_seq_observable(_cipher: KtlsCipher) -> bool {
        false
    }

    #[allow(dead_code)]
    pub fn read_ktls_record_seq(
        _fd: i32,
        _cipher: KtlsCipher,
        _tls_version: u16,
        _is_tx: bool,
    ) -> std::io::Result<u64> {
        Err(std::io::Error::other("kTLS is Linux-only"))
    }

    #[allow(dead_code)]
    pub fn socket_receive_buffer_bytes(_fd: i32) -> std::io::Result<u64> {
        Err(std::io::Error::other("kTLS is Linux-only"))
    }

    #[allow(dead_code)]
    pub fn socket_receive_queue_bytes(_fd: i32) -> std::io::Result<u64> {
        Err(std::io::Error::other("kTLS is Linux-only"))
    }

    /// No socket can be pinned off Linux because no socket can carry kTLS
    /// there. Failing keeps the receive-window bound fail-closed.
    #[allow(dead_code)]
    pub fn pin_socket_receive_buffer(_fd: i32, _request_bytes: u64) -> std::io::Result<u64> {
        Err(std::io::Error::other("kTLS is Linux-only"))
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
    use std::sync::OnceLock;

    static IO_URING_AVAILABLE: OnceLock<bool> = OnceLock::new();

    /// Check if io_uring is available on this kernel (Linux 5.6+).
    ///
    /// Probes by submitting an `IORING_OP_SPLICE` on a pipe pair. Ring creation
    /// alone is insufficient — seccomp or kernel config may allow ring setup but
    /// reject specific opcodes like SPLICE. Uses `OnceLock` for thread-safe
    /// one-shot initialization without TOCTOU races.
    pub fn check_io_uring_available() -> bool {
        *IO_URING_AVAILABLE.get_or_init(|| {
            // Probe by actually submitting an IORING_OP_SPLICE on a pipe pair.
            // Ring creation alone is insufficient — seccomp or kernel config may
            // allow ring setup but reject specific opcodes like SPLICE.
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
        })
    }

    /// Errors from an io_uring splice call tagged with the side of the relay
    /// that produced them.
    ///
    /// `is_write_side = false` — the src_fd → pipe splice failed (read side).
    /// `is_write_side = true` — the pipe → dst_fd splice failed (write side).
    /// `is_write_side = false` is also used for out-of-band failures (ring
    /// creation, idle timeout, submission-queue full) where the side isn't
    /// meaningful; callers that care should inspect `source.kind()`.
    ///
    /// `bytes_so_far` is the count of bytes successfully spliced pipe→dst
    /// before this failure. Callers must surface it in `StreamCopyResult`
    /// even when the direction ends in timeout/error — discarding it under-
    /// reports metrics and contradicts the stream-copy contract.
    #[derive(Debug)]
    pub struct SpliceError {
        pub is_write_side: bool,
        pub bytes_so_far: u64,
        pub source: std::io::Error,
    }

    impl SpliceError {
        fn read(bytes_so_far: u64, source: std::io::Error) -> Self {
            Self {
                is_write_side: false,
                bytes_so_far,
                source,
            }
        }
        fn write(bytes_so_far: u64, source: std::io::Error) -> Self {
            Self {
                is_write_side: true,
                bytes_so_far,
                source,
            }
        }
    }

    /// Stable message bodies the loop emits via `io::Error::TimedOut` to
    /// signal which per-direction watermark fired. `tcp_proxy.rs` re-exports
    /// these as `STREAM_SPLICE_BACKEND_READ_TIMEOUT_PREFIX` /
    /// `STREAM_SPLICE_BACKEND_WRITE_TIMEOUT_PREFIX` via `const = &str`
    /// reference, so this module is the single source of truth and any
    /// drift is a compile error rather than a silent metric mis-attribution.
    pub const BACKEND_READ_TIMEOUT_MSG: &str = "backend read inactivity timeout";
    pub const BACKEND_WRITE_TIMEOUT_MSG: &str = "backend write inactivity timeout";

    /// Splice data in one direction using io_uring: src_fd → pipe → dst_fd.
    ///
    /// Runs on a blocking thread (called via `tokio::task::spawn_blocking`).
    /// Creates a small io_uring ring (8 entries) and submits IORING_OP_SPLICE
    /// operations for each chunk. Returns total bytes transferred.
    ///
    /// On error (including idle / per-direction timeouts), the returned
    /// `SpliceError.bytes_so_far` carries bytes already delivered pipe→dst so
    /// the parent can preserve them in `StreamCopyResult` without contested
    /// atomics on the hot path.
    ///
    /// Returns `Err` with `source.kind() == ErrorKind::Unsupported` if the ring
    /// cannot be created, signaling the caller to fall back to `libc::splice`.
    ///
    /// `timeout_ms` is the idle timeout — if no data is transferred on either
    /// direction for this duration, returns `ErrorKind::TimedOut` with the
    /// generic message body (caller maps to `Direction::Unknown`).
    /// `shared_last_activity_ms` is an `AtomicU64` shared between both splice
    /// directions so that activity in one direction prevents the other from
    /// timing out (critical for one-way streaming like downloads).
    ///
    /// `read_watermark` / `read_timeout_ms` enforce `backend_read_timeout_ms`
    /// on the read side (src→pipe). Refreshed on every successful read.
    /// `write_watermark` / `write_timeout_ms` enforce `backend_write_timeout_ms`
    /// on the write side (pipe→dst). Primed when the read produces queued
    /// bytes and refreshed on every successful write. Both watermarks emit a
    /// distinct message body (see `BACKEND_*_TIMEOUT_MSG`) so the caller can
    /// attribute the timeout to the correct `(Direction, StreamIoSide)`.
    #[allow(clippy::too_many_arguments)]
    pub fn io_uring_splice_loop(
        src_fd: i32,
        pipe_w: i32,
        pipe_r: i32,
        dst_fd: i32,
        shared_last_activity_ms: &std::sync::atomic::AtomicU64,
        timeout_ms: u64,
        read_watermark: Option<&std::sync::atomic::AtomicU64>,
        read_timeout_ms: u64,
        write_watermark: Option<&std::sync::atomic::AtomicU64>,
        write_timeout_ms: u64,
    ) -> Result<u64, SpliceError> {
        let mut ring = match io_uring::IoUring::new(8) {
            Ok(r) => r,
            Err(_) => {
                // Ring creation failed (memlock pressure, resource limits).
                // Signal caller to fall back to libc::splice. Side is N/A but
                // the caller checks ErrorKind::Unsupported before side.
                return Err(SpliceError::read(
                    0,
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "io_uring ring creation failed, falling back to libc splice",
                    ),
                ));
            }
        };
        let splice_flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
        let mut total: u64 = 0;
        let chunk_size: u32 = 128 * 1024;
        let read_wm_active = read_watermark.is_some() && read_timeout_ms > 0;
        let write_wm_active = write_watermark.is_some() && write_timeout_ms > 0;

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
                    return Err(SpliceError::read(
                        total,
                        std::io::Error::from(std::io::ErrorKind::TimedOut),
                    ));
                }
            }
            if read_wm_active && let Some(wm) = read_watermark {
                let now = super::monotonic_now_ms();
                let last = wm.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= read_timeout_ms {
                    return Err(SpliceError::read(
                        total,
                        std::io::Error::new(std::io::ErrorKind::TimedOut, BACKEND_READ_TIMEOUT_MSG),
                    ));
                }
            }
            // The write watermark is also checked in the outer loop / Phase 1
            // WouldBlock so the c2b worker fires `backend_write_timeout_ms`
            // when it has been stuck in the Reading phase past the deadline
            // (e.g. the client went silent after a complete c2b exchange).
            // This matches `bidirectional_copy`'s parent-watchdog semantics
            // and the async libc-splice path's parent watchdog. Without it,
            // io_uring would diverge: write timeouts would only fire during
            // an active write phase, leaving "client silent" cases for the
            // shared idle timeout alone — operators switching
            // `FERRUM_IO_URING_SPLICE_ENABLED` would see different
            // `DisconnectCause` distributions on identical traffic. The
            // watermark is `u64::MAX` until the first successful read primes
            // it, so this check stays inert until c2b actually carries data.
            if write_wm_active && let Some(wm) = write_watermark {
                let now = super::monotonic_now_ms();
                let last = wm.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= write_timeout_ms {
                    return Err(SpliceError::write(
                        total,
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            BACKEND_WRITE_TIMEOUT_MSG,
                        ),
                    ));
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
                ring.submission().push(&sqe).map_err(|_| {
                    SpliceError::read(total, std::io::Error::other("io_uring SQ full"))
                })?;
            }
            ring.submit_and_wait(1)
                .map_err(|e| SpliceError::read(total, e))?;

            let cqe = ring.completion().next().ok_or_else(|| {
                SpliceError::read(total, std::io::Error::other("io_uring no CQE"))
            })?;
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
                            return Err(SpliceError::read(
                                total,
                                std::io::Error::from(std::io::ErrorKind::TimedOut),
                            ));
                        }
                    }
                    if read_wm_active && let Some(wm) = read_watermark {
                        let now = super::monotonic_now_ms();
                        let last = wm.load(std::sync::atomic::Ordering::Relaxed);
                        if now.saturating_sub(last) >= read_timeout_ms {
                            return Err(SpliceError::read(
                                total,
                                std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    BACKEND_READ_TIMEOUT_MSG,
                                ),
                            ));
                        }
                    }
                    // Mirror the outer-loop check: a Phase 1 WouldBlock means
                    // src has nothing new, so if c2b's write watermark has
                    // gone stale (queued bytes already drained AND the
                    // deadline has now passed) the c2b worker should report
                    // it here rather than wait for a future write attempt.
                    if write_wm_active && let Some(wm) = write_watermark {
                        let now = super::monotonic_now_ms();
                        let last = wm.load(std::sync::atomic::Ordering::Relaxed);
                        if now.saturating_sub(last) >= write_timeout_ms {
                            return Err(SpliceError::write(
                                total,
                                std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    BACKEND_WRITE_TIMEOUT_MSG,
                                ),
                            ));
                        }
                    }
                    // Back off to avoid tight spin — sleep 1ms then retry.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                return Err(SpliceError::read(total, err));
            }

            // Successful src→pipe: refresh the read watermark and prime the
            // write watermark (we now have queued bytes ready for dst).
            let post_read_now = super::monotonic_now_ms();
            if read_wm_active && let Some(wm) = read_watermark {
                wm.store(post_read_now, std::sync::atomic::Ordering::Relaxed);
            }
            if write_wm_active && let Some(wm) = write_watermark {
                wm.store(post_read_now, std::sync::atomic::Ordering::Relaxed);
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
                        SpliceError::write(total, std::io::Error::other("io_uring SQ full"))
                    })?;
                }
                ring.submit_and_wait(1)
                    .map_err(|e| SpliceError::write(total, e))?;

                let cqe = ring.completion().next().ok_or_else(|| {
                    SpliceError::write(total, std::io::Error::other("io_uring no CQE"))
                })?;
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
                                return Err(SpliceError::write(
                                    total,
                                    std::io::Error::from(std::io::ErrorKind::TimedOut),
                                ));
                            }
                        }
                        if write_wm_active && let Some(wm) = write_watermark {
                            let now = super::monotonic_now_ms();
                            let last = wm.load(std::sync::atomic::Ordering::Relaxed);
                            if now.saturating_sub(last) >= write_timeout_ms {
                                return Err(SpliceError::write(
                                    total,
                                    std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        BACKEND_WRITE_TIMEOUT_MSG,
                                    ),
                                ));
                            }
                        }
                        // The b2c worker can be stalled in Phase 2 (client
                        // not reading) while the backend has gone silent —
                        // check the read watermark here too so the firing
                        // matches the parent-watchdog semantics of the
                        // libc-async splice path.
                        if read_wm_active && let Some(wm) = read_watermark {
                            let now = super::monotonic_now_ms();
                            let last = wm.load(std::sync::atomic::Ordering::Relaxed);
                            if now.saturating_sub(last) >= read_timeout_ms {
                                return Err(SpliceError::read(
                                    total,
                                    std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        BACKEND_READ_TIMEOUT_MSG,
                                    ),
                                ));
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    return Err(SpliceError::write(total, err));
                }
                remaining -= w as u32;
                total = total.saturating_add(w as u64);
                // Refresh shared idle timeout — activity in either direction
                // prevents the connection from timing out. Must use the same
                // monotonic clock as the reader loop above (and the libc
                // fallback's `coarse_now_ms`) so the shared atomic is coherent.
                let post_write_now = super::monotonic_now_ms();
                if timeout_ms > 0 {
                    shared_last_activity_ms
                        .store(post_write_now, std::sync::atomic::Ordering::Relaxed);
                }
                if write_wm_active && let Some(wm) = write_watermark {
                    wm.store(post_write_now, std::sync::atomic::Ordering::Relaxed);
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
    /// `bytes_so_far` is always 0 on the stub (no transfer occurs).
    #[derive(Debug)]
    #[allow(dead_code)] // Fields are consumed only by the Linux splice path.
    pub struct SpliceError {
        pub is_write_side: bool,
        pub bytes_so_far: u64,
        pub source: std::io::Error,
    }

    #[allow(dead_code)]
    pub const BACKEND_READ_TIMEOUT_MSG: &str = "backend read inactivity timeout";
    #[allow(dead_code)]
    pub const BACKEND_WRITE_TIMEOUT_MSG: &str = "backend write inactivity timeout";

    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn io_uring_splice_loop(
        _src_fd: i32,
        _pipe_w: i32,
        _pipe_r: i32,
        _dst_fd: i32,
        _shared_last_activity_ms: &std::sync::atomic::AtomicU64,
        _timeout_ms: u64,
        _read_watermark: Option<&std::sync::atomic::AtomicU64>,
        _read_timeout_ms: u64,
        _write_watermark: Option<&std::sync::atomic::AtomicU64>,
        _write_timeout_ms: u64,
    ) -> Result<u64, SpliceError> {
        Err(SpliceError {
            is_write_side: false,
            bytes_so_far: 0,
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
    connect_with_socket_opts_and_mark(sock_addr, None).await
}

/// Connect with the normal socket options plus an optional `SO_MARK`.
pub async fn connect_with_socket_opts_and_mark(
    sock_addr: std::net::SocketAddr,
    socket_mark: Option<u32>,
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
        if let Some(mark) = socket_mark.filter(|mark| *mark != 0) {
            set_socket_mark(socket.as_raw_fd(), mark)?;
        }
    }
    #[cfg(not(unix))]
    let _ = socket_mark;

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
            // `false`: this test exercises pktinfo, not orig-dst recovery.
            let mut batch = crate::proxy::udp_batch::RecvMmsgBatch::new(1, false);
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
        // The recv cmsg buffer must fit UDP_GRO + IP(v6)_PKTINFO + the orig-dst
        // (IP(v6)_RECVORIGDSTADDR) cmsg simultaneously — a mesh UDP capture
        // socket enables PKTINFO + RECVORIGDSTADDR together and GRO may coalesce.
        let space = recv_cmsg_space();
        let v6_pkt =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize };
        let gro = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize };
        let origdst =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::sockaddr_in6>() as u32) as usize };
        assert!(space >= v6_pkt + gro + origdst);
        let _ = SocketAddr::from(([127, 0, 0, 1], 0)); // silence unused import
    }

    /// Build a single `IP_RECVORIGDSTADDR` (IPv4) cmsg by hand and confirm
    /// [`extract_origdst`] recovers the encoded `addr:port`. Mirrors the
    /// pktinfo cmsg-parse coverage but for the original-destination cmsg the
    /// mesh UDP TPROXY capture listener relies on. Does not touch the network —
    /// pure cmsg layout/parse coverage so it runs on any Linux kernel.
    #[test]
    fn extract_origdst_parses_ipv4_cmsg() {
        const IP_RECVORIGDSTADDR: libc::c_int = 20;
        let orig: SocketAddr = "10.1.2.3:5353".parse().unwrap();

        // A cmsg buffer holding exactly one IP_RECVORIGDSTADDR (sockaddr_in).
        let space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::sockaddr_in>() as u32) as usize };
        let mut cmsg_buf = vec![0u8; space];

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len();

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        assert!(!cmsg.is_null());
        let SocketAddr::V4(v4) = orig else {
            unreachable!()
        };
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_IP;
            (*cmsg).cmsg_type = IP_RECVORIGDSTADDR;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::sockaddr_in>() as u32) as usize;
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            std::ptr::copy_nonoverlapping(
                &sin as *const libc::sockaddr_in as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<libc::sockaddr_in>(),
            );
        }

        let parsed = extract_origdst(&msg);
        assert_eq!(parsed, Some(orig));
    }

    /// A msghdr with no orig-dst cmsg yields `None` (e.g. a pktinfo-only cmsg
    /// must not be misread as an original destination).
    #[test]
    fn extract_origdst_absent_is_none() {
        let mut cmsg_buf = vec![0u8; recv_cmsg_space()];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        // Zero controllen ⇒ CMSG_FIRSTHDR returns null ⇒ no cmsg present.
        msg.msg_controllen = 0;
        assert_eq!(extract_origdst(&msg), None);
    }

    /// End-to-end recvmmsg roundtrip: enable IP_RECVORIGDSTADDR on a loopback
    /// socket, send a datagram to it, and confirm [`RecvMmsgBatch::orig_dst`]
    /// surfaces the destination from the cmsg. (On loopback without TPROXY the
    /// orig-dst equals the bind addr, which is enough to prove the cmsg is
    /// parsed end-to-end.) Skips gracefully if the option is unsupported.
    #[test]
    fn recvmmsg_surfaces_origdst_cmsg() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            if set_ip_recvorigdstaddr(server.as_raw_fd()).is_err() {
                return; // kernel without IP_RECVORIGDSTADDR — skip
            }

            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(b"capture", server_addr).await.unwrap();

            // `true`: this test asserts orig-dst recovery, so opt the batch in.
            let mut batch = crate::proxy::udp_batch::RecvMmsgBatch::new(1, true);
            server.readable().await.unwrap();
            let n = batch.recv(server.as_raw_fd(), 1).unwrap();
            assert_eq!(n, 1);
            let orig = batch.orig_dst(0);
            assert_eq!(
                orig,
                Some(server_addr),
                "orig-dst cmsg should surface the datagram destination"
            );
        });
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
        // depends on to set `ktls_enabled`, and is what the `ktls_accept`
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod keepalive_tests {
    //! Roundtrip tests for `apply_tcp_keepalive`. Run on Linux + macOS because
    //! both expose `getsockopt`-readable equivalents of `SO_KEEPALIVE`,
    //! `TCP_KEEPIDLE`/`TCP_KEEPALIVE`, `TCP_KEEPINTVL`, and `TCP_KEEPCNT`.
    //! The test binds an accepted loopback socket pair so the call path
    //! matches the production `connect_backend_plain → apply_tcp_keepalive`
    //! flow byte-for-byte.

    use super::apply_tcp_keepalive;
    use crate::config::types::TcpKeepaliveCfg;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::os::unix::io::AsRawFd;

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn getsockopt_int(fd: i32, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len as *mut libc::socklen_t,
            )
        };
        assert_eq!(
            ret,
            0,
            "getsockopt failed: {}",
            std::io::Error::last_os_error()
        );
        val
    }

    #[test]
    fn empty_cfg_is_noop_and_does_not_enable_keepalive() {
        let (client, _server) = loopback_pair();
        let fd = client.as_raw_fd();
        let cfg = TcpKeepaliveCfg::default();
        apply_tcp_keepalive(fd, &cfg).expect("noop should succeed");
        // SO_KEEPALIVE must remain at its kernel default (off). The exact
        // "on" value differs across platforms (Linux returns `1`; some
        // BSDs / macOS variants return the `SO_KEEPALIVE` constant value
        // `8`), so we only assert "zero == off" here.
        let so_keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
        assert_eq!(so_keepalive, 0, "empty cfg must not enable SO_KEEPALIVE");
    }

    #[test]
    fn applies_time_interval_probes_and_enables_keepalive() {
        let (client, _server) = loopback_pair();
        let fd = client.as_raw_fd();
        let cfg = TcpKeepaliveCfg {
            time_seconds: Some(120),
            interval_seconds: Some(30),
            probes: Some(5),
        };
        apply_tcp_keepalive(fd, &cfg).expect("keepalive setup should succeed");

        // SO_KEEPALIVE must be enabled — without it, the per-knob options
        // have no effect on the actual probe scheduling. The exact "on"
        // value differs across platforms (Linux returns `1`, BSD/macOS
        // returns a bitmask such as `8`), so we assert non-zero rather
        // than `== 1`.
        let so_keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
        assert_ne!(so_keepalive, 0, "SO_KEEPALIVE must be enabled");

        // TCP_KEEPIDLE on Linux, TCP_KEEPALIVE on macOS — both fields name
        // the same kernel concept (idle time before first probe).
        #[cfg(target_os = "linux")]
        let time_name = libc::TCP_KEEPIDLE;
        #[cfg(target_os = "macos")]
        let time_name = libc::TCP_KEEPALIVE;
        let time = getsockopt_int(fd, libc::IPPROTO_TCP, time_name);
        assert_eq!(time, 120, "TCP_KEEP[IDLE|ALIVE] mismatch");

        let interval = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL);
        assert_eq!(interval, 30, "TCP_KEEPINTVL mismatch");

        let probes = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT);
        assert_eq!(probes, 5, "TCP_KEEPCNT mismatch");
    }

    #[test]
    fn applies_only_time_when_other_fields_unset() {
        let (client, _server) = loopback_pair();
        let fd = client.as_raw_fd();
        let cfg = TcpKeepaliveCfg {
            time_seconds: Some(300),
            interval_seconds: None,
            probes: None,
        };
        apply_tcp_keepalive(fd, &cfg).expect("partial keepalive setup should succeed");

        let so_keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
        assert_ne!(so_keepalive, 0, "SO_KEEPALIVE must be enabled");

        #[cfg(target_os = "linux")]
        let time_name = libc::TCP_KEEPIDLE;
        #[cfg(target_os = "macos")]
        let time_name = libc::TCP_KEEPALIVE;
        let time = getsockopt_int(fd, libc::IPPROTO_TCP, time_name);
        assert_eq!(time, 300);

        // Interval and probes remain at their kernel defaults — we cannot
        // assert specific values (they vary by distro/sysctl) but they must
        // be positive, not zero.
        let interval = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL);
        assert!(interval > 0, "TCP_KEEPINTVL default should be positive");
        let probes = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT);
        assert!(probes > 0, "TCP_KEEPCNT default should be positive");
    }

    #[test]
    fn fd_is_not_closed_after_apply() {
        // Regression guard for the `socket2::Socket::from_raw_fd` /
        // `into_raw_fd` pairing — if we forget the `into_raw_fd()` call,
        // dropping the temporary `Socket` would close the still-live fd
        // and the next syscall against it would fail with EBADF.
        let (client, _server) = loopback_pair();
        let fd = client.as_raw_fd();
        let cfg = TcpKeepaliveCfg {
            time_seconds: Some(60),
            interval_seconds: Some(10),
            probes: Some(3),
        };
        apply_tcp_keepalive(fd, &cfg).expect("keepalive should succeed");
        // Any further getsockopt would EBADF if the helper accidentally
        // dropped the borrowed fd.
        let _ = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
    }

    // ── apply_pooled_tcp_keepalive (H2-family pool resolution + fallback) ──
    //
    // These exercise the helper the socket-owning H2-family pools (direct-H2,
    // gRPC, HBONE, mesh-mTLS) call at connection creation: a DR per-port
    // `tcpKeepalive` override takes precedence (full time/interval/probes),
    // and otherwise the global pool keepalive (whole-seconds idle time only)
    // is the fallback — preserving the pre-existing behavior. They use a real
    // `tokio::net::TcpStream` loopback pair so the fd path matches production.

    async fn tokio_loopback_client() -> tokio::net::TcpStream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Keep the accepted server side alive for the connection's lifetime.
        let (server, _) = listener.accept().await.unwrap();
        std::mem::forget(server);
        client
    }

    #[tokio::test]
    async fn pooled_keepalive_override_takes_precedence_over_global() {
        let client = tokio_loopback_client().await;
        let fd = client.as_raw_fd();
        let cfg = TcpKeepaliveCfg {
            time_seconds: Some(150),
            interval_seconds: Some(25),
            probes: Some(7),
        };
        // Override present AND a (different) global value set — the override
        // must win and apply its full time/interval/probes.
        super::apply_pooled_tcp_keepalive("test_pool", &client, Some(&cfg), true, 999);

        let so_keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
        assert_ne!(so_keepalive, 0, "override must enable SO_KEEPALIVE");

        #[cfg(target_os = "linux")]
        let time_name = libc::TCP_KEEPIDLE;
        #[cfg(target_os = "macos")]
        let time_name = libc::TCP_KEEPALIVE;
        let time = getsockopt_int(fd, libc::IPPROTO_TCP, time_name);
        assert_eq!(time, 150, "override time_seconds must win over global 999");
        let interval = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL);
        assert_eq!(interval, 25, "override interval_seconds must apply");
        let probes = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT);
        assert_eq!(probes, 7, "override probes must apply");
    }

    #[tokio::test]
    async fn pooled_keepalive_falls_back_to_global_seconds_when_no_override() {
        let client = tokio_loopback_client().await;
        let fd = client.as_raw_fd();
        // No DR override → fall back to the global pool keepalive (seconds-only
        // idle time), preserving the pre-existing pool behavior.
        super::apply_pooled_tcp_keepalive("test_pool", &client, None, true, 222);

        let so_keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
        assert_ne!(so_keepalive, 0, "global fallback must enable SO_KEEPALIVE");

        #[cfg(target_os = "linux")]
        let time_name = libc::TCP_KEEPIDLE;
        #[cfg(target_os = "macos")]
        let time_name = libc::TCP_KEEPALIVE;
        let time = getsockopt_int(fd, libc::IPPROTO_TCP, time_name);
        assert_eq!(
            time, 222,
            "global keepalive seconds must apply as idle time"
        );
    }

    #[tokio::test]
    async fn pooled_keepalive_global_disabled_is_noop() {
        let client = tokio_loopback_client().await;
        let fd = client.as_raw_fd();
        // No override AND global disabled → nothing applied, SO_KEEPALIVE off.
        super::apply_pooled_tcp_keepalive("test_pool", &client, None, false, 222);
        let so_keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
        assert_eq!(
            so_keepalive, 0,
            "no override + global disabled must not enable keepalive"
        );
    }

    #[tokio::test]
    async fn pooled_keepalive_empty_override_falls_back_to_global() {
        let client = tokio_loopback_client().await;
        let fd = client.as_raw_fd();
        // An empty (all-None) override must NOT be treated as "configured" —
        // it falls through to the global fallback so an upstream that carried
        // an empty `tcpKeepalive` does not suppress the global keepalive.
        let empty = TcpKeepaliveCfg::default();
        super::apply_pooled_tcp_keepalive("test_pool", &client, Some(&empty), true, 333);
        let so_keepalive = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE);
        assert_ne!(so_keepalive, 0, "empty override should fall back to global");
        #[cfg(target_os = "linux")]
        let time_name = libc::TCP_KEEPIDLE;
        #[cfg(target_os = "macos")]
        let time_name = libc::TCP_KEEPALIVE;
        let time = getsockopt_int(fd, libc::IPPROTO_TCP, time_name);
        assert_eq!(time, 333, "empty override falls back to global seconds");
    }
}

#[cfg(test)]
mod original_dst_tests {
    //! `original_dst` contract: a non-REDIRECTed (direct-dial) accepted socket
    //! has no usable conntrack original destination — the helper must answer
    //! `None`, never an error, on every platform. On Linux with conntrack
    //! loaded, `SO_ORIGINAL_DST` for an un-NATed flow either fails (`ENOENT`)
    //! or echoes the post-NAT tuple (= the accepted socket's local address);
    //! both must normalize to `None`. The positive (REDIRECTed) case requires
    //! iptables in a privileged netns and is covered by the live-CI module.

    #[tokio::test]
    async fn direct_dial_has_no_original_dst() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        assert_eq!(crate::socket_opts::original_dst(&server), None);
    }

    #[tokio::test]
    async fn direct_dial_ipv6_has_no_original_dst() {
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return; // environment without IPv6 loopback
        };
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        assert_eq!(crate::socket_opts::original_dst(&server), None);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod original_dst_live_tests {
    //! Privileged live verification of `SO_ORIGINAL_DST` against a real
    //! iptables `REDIRECT` rule, inside a throwaway network namespace (the
    //! host's iptables are never touched). Runs in CI's `netns-capture-live`
    //! job as root with `FERRUM_LIVE_TESTS_REQUIRED=1`, so missing prerequisites
    //! fail there instead of passing as skips. Local ad-hoc runs still self-skip
    //! without root / `unshare` / `iptables`.

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::process::{Child, Command};
    use std::time::Duration;

    /// Where the synthetic sidecar capture listener binds (the :15001 shape).
    const CAPTURE_PORT: u16 = 25001;
    /// The "service port" the client dials; REDIRECTed to `CAPTURE_PORT`.
    const DIAL_PORT: u16 = 18080;

    fn is_root() -> bool {
        // Safety: `geteuid` is always sound and never fails.
        unsafe { libc::geteuid() == 0 }
    }

    fn live_tests_required() -> bool {
        std::env::var("FERRUM_LIVE_TESTS_REQUIRED")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn skip_or_fail(reason: &str) {
        if live_tests_required() {
            panic!(
                "SO_ORIGINAL_DST live test prerequisite missing under FERRUM_LIVE_TESTS_REQUIRED: {reason}"
            );
        }
        eprintln!("SKIP: {reason}");
    }

    /// Reaps the netns child on drop so the test never leaks it.
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Spawn a child in a fresh netns with loopback up and the sidecar-shaped
    /// nat rule: TCP to :18080 is REDIRECTed to :25001. Exits 97 when
    /// `iptables` is unavailable inside the netns so local runs can skip and
    /// required CI can fail.
    fn spawn_redirect_netns_child() -> Option<Child> {
        Command::new("unshare")
            .args([
                "--net",
                "sh",
                "-c",
                &format!(
                    "ip link set lo up 2>/dev/null || true; \
                     iptables -t nat -A OUTPUT -p tcp --dport {DIAL_PORT} \
                     -j REDIRECT --to-ports {CAPTURE_PORT} 2>/dev/null || exit 97; \
                     exec sleep 30"
                ),
            ])
            .spawn()
            .ok()
    }

    #[test]
    #[ignore = "requires root + iptables to create a REDIRECT rule in a fresh netns"]
    fn redirected_ipv4_connection_on_dual_stack_listener_reports_pre_nat_destination() {
        if !is_root() {
            skip_or_fail("not root; cannot create network namespaces");
            return;
        }
        let Some(mut child) = spawn_redirect_netns_child() else {
            skip_or_fail("`unshare --net` unavailable");
            return;
        };
        // Let the child unshare, bring loopback up, and install the rule;
        // exit (97 = iptables unavailable, or any other failure) == local skip
        // or required-mode failure.
        // `try_wait` rather than `kill(pid, 0)`: an exited-but-unreaped child
        // is a zombie that still answers signal 0, which would wrongly run
        // the scenario in a namespace without the REDIRECT rule.
        let mut child_exited = false;
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(50));
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => {
                    child_exited = true;
                    break;
                }
                Ok(None) => {}
            }
        }
        if child_exited {
            skip_or_fail("iptables unavailable inside the test netns");
            return;
        }
        let pid = child.id();
        let _guard = ChildGuard(child);

        // Everything runs on one throwaway thread inside the child's netns
        // (`setns` mutates only the calling thread, which exits right after).
        let (local, orig) = std::thread::spawn(
            move || -> Result<(SocketAddr, Option<SocketAddr>), String> {
                let ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
                    .map_err(|e| format!("open netns handle: {e}"))?;
                // Safety: `ns` is an open netns handle owned for the call.
                if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                    return Err(format!("setns failed: {}", std::io::Error::last_os_error()));
                }
                // Match the production issue-#4271 capture shape exactly: one
                // AF_INET6 wildcard with V6ONLY disabled accepts both native IPv6
                // and IPv4-mapped traffic. A plain IPv4 listener would not exercise
                // the family-selection bug this regression test exists to catch.
                let socket = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )
                .map_err(|e| format!("create dual-stack capture socket: {e}"))?;
                socket
                    .set_only_v6(false)
                    .map_err(|e| format!("disable IPV6_V6ONLY: {e}"))?;
                socket
                    .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, CAPTURE_PORT)).into())
                    .map_err(|e| format!("bind dual-stack capture listener: {e}"))?;
                socket
                    .listen(128)
                    .map_err(|e| format!("listen on dual-stack capture socket: {e}"))?;
                let listener: TcpListener = socket.into();
                // Dial the "service port"; netfilter REDIRECTs it onto the
                // dual-stack capture listener as an IPv4-mapped accept.
                let _client = TcpStream::connect_timeout(
                    &SocketAddr::from((Ipv4Addr::LOCALHOST, DIAL_PORT)),
                    Duration::from_secs(2),
                )
                .map_err(|e| format!("redirected connect: {e}"))?;
                let (accepted, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
                let local = accepted
                    .local_addr()
                    .map_err(|e| format!("local_addr: {e}"))?;
                let orig =
                    crate::socket_opts::original_dst_from_raw_fd(accepted.as_raw_fd(), local);
                Ok((local, orig))
            },
        )
        .join()
        .expect("netns scenario thread must not panic")
        .expect("live SO_ORIGINAL_DST scenario must complete");

        assert!(
            matches!(
                local.ip(),
                IpAddr::V6(v6) if v6.to_ipv4_mapped() == Some(Ipv4Addr::LOCALHOST)
            ),
            "the AF_INET6 dual-stack listener must expose the IPv4 flow as a mapped local address; got {local}"
        );

        assert_eq!(
            orig,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, DIAL_PORT))),
            "an accepted REDIRECTed connection must report the pre-NAT destination"
        );
    }
}
