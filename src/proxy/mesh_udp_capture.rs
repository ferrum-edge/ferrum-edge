//! Mesh UDP TPROXY capture listener + datagram-over-mesh egress (F3 §3.3).
//!
//! Stage 2 (`src/capture/mod.rs`) emits the flag-gated, default-off netfilter
//! `TPROXY` rules that divert a captured pod's UDP egress to a transparent
//! local socket WITHOUT rewriting the destination. This module is the consuming
//! listener + egress relay: it binds that socket (`IP_TRANSPARENT` +
//! `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR`), drains datagrams via
//! `recvmmsg`, recovers each datagram's ORIGINAL destination from the
//! per-datagram cmsg (NOT `SO_ORIGINAL_DST`, which is TCP/conntrack-only), keys a
//! session by `(client SocketAddr, orig-dst SocketAddr)`, and relays it over the
//! topology's mesh transport (Ambient HBONE `:15008`, Sidecar mesh-mTLS `:15006`)
//! to the destination workload, spoofing replies back from the captured
//! destination via a per-session transparent reply socket. All gated behind
//! `FERRUM_MESH_CAPTURE_UDP_ENABLED` (default-off) so there is no behavior change
//! when the flag is off.
//!
//! **Two producers, one relay.** The recv/session/egress loop is factored into
//! [`run_mesh_udp_capture_on_socket`], which runs over an already-bound
//! transparent socket regardless of which network namespace it was bound in:
//! - [`start_mesh_udp_capture_listener`] binds in the CURRENT netns — Sidecar,
//!   whose injected sidecar shares the pod netns where the injector installed the
//!   TPROXY rules.
//! - The Ambient per-pod-netns producer (`src/proxy/netns_udp_capture.rs`) binds
//!   the capture socket, and each session's reply socket, INSIDE each enrolled
//!   pod's netns via a [`ReplySocketFactory`] — Ambient's proxy runs outside the
//!   pod netns, so the producer installs the TPROXY rules and binds the sockets
//!   from within each pod's namespace.
//!
//! **DoS bounds** are reused from the plain UDP proxy (`udp_proxy.rs`): a
//! bounded session map (`FERRUM_UDP_MAX_SESSIONS`), an idle-expiry sweep
//! (`FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`), and the adaptive recvmmsg batch
//! cap (`FERRUM_UDP_RECVMMSG_BATCH_SIZE`) keep a spoofed-source flood from
//! growing memory or starving the runtime.
//!
//! Linux-only (`IP_TRANSPARENT` + recvmsg cmsg). Non-Linux is a stub that logs
//! and returns immediately.

#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::net::SocketAddr as StdSocketAddr;

use tokio::sync::watch;

/// Terminal classification for a captured UDP session.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedUdpOutcome {
    ReturnPathEnded,
    EgressPathEnded,
    IdleTimeout,
    ProducerShutdown,
}

/// Race-safe reason shared by the capture-session map and its relay task.
///
/// The idle sweep records `IdleTimeout` before it drops the map-owned sender,
/// allowing the relay task to distinguish normal expiry from an unexpected
/// sender disappearance. Producer shutdown has precedence over a concurrent
/// sweep so cancellation remains graceful, while real tunnel/return failures
/// bypass this signal and keep their error outcomes.
#[doc(hidden)]
#[derive(Default)]
pub struct CapturedUdpOutcomeSignal {
    reason: std::sync::atomic::AtomicU8,
}

impl CapturedUdpOutcomeSignal {
    const ACTIVE: u8 = 0;
    const IDLE_TIMEOUT: u8 = 1;
    const PRODUCER_SHUTDOWN: u8 = 2;

    pub fn new() -> Self {
        Self {
            reason: std::sync::atomic::AtomicU8::new(Self::ACTIVE),
        }
    }

    pub fn mark_idle_timeout(&self) {
        let _ = self.reason.compare_exchange(
            Self::ACTIVE,
            Self::IDLE_TIMEOUT,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    pub fn mark_producer_shutdown(&self) {
        self.reason.store(
            Self::PRODUCER_SHUTDOWN,
            std::sync::atomic::Ordering::Release,
        );
    }

    /// Resolve completion of the client-to-egress relay. A real tunnel write
    /// failure remains `EgressPathEnded`; only closure of the map-owned sender
    /// consumes the shared cleanup/shutdown reason.
    pub fn resolve_egress_completion(&self, sender_closed: bool) -> CapturedUdpOutcome {
        if !sender_closed {
            return CapturedUdpOutcome::EgressPathEnded;
        }
        match self.reason.load(std::sync::atomic::Ordering::Acquire) {
            Self::IDLE_TIMEOUT => CapturedUdpOutcome::IdleTimeout,
            Self::PRODUCER_SHUTDOWN => CapturedUdpOutcome::ProducerShutdown,
            _ => CapturedUdpOutcome::EgressPathEnded,
        }
    }
}

/// Process-local admission counter for captured UDP sessions.
///
/// Sidecar has one current-netns UDP producer, so its limiter is listener-local.
/// Ambient starts one producer per pod netns; those producers must share a single
/// limiter so `FERRUM_UDP_MAX_SESSIONS` remains a node-wide cap instead of being
/// multiplied by the number of enrolled pods.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct MeshUdpSessionLimiter {
    max_sessions: usize,
    active_sessions: std::sync::atomic::AtomicU64,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl MeshUdpSessionLimiter {
    pub(crate) fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
            active_sessions: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn try_reserve(&self) -> bool {
        let prev = self
            .active_sessions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if prev >= self.max_sessions as u64 {
            self.active_sessions
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        true
    }

    fn release(&self, count: u64) {
        if count > 0 {
            self.active_sessions
                .fetch_sub(count, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn active_count(&self) -> u64 {
        self.active_sessions
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Configuration for the mesh UDP capture listener.
pub struct MeshUdpCaptureConfig {
    /// Address+port to bind. The port is the Stage-2 TPROXY listener port
    /// (`FERRUM_MESH_CAPTURE_UDP_PORT`, default 15011).
    pub addr: StdSocketAddr,
    /// Shared proxy state — threaded in for Stage 4 so the listener can consult
    /// the `mesh_udp_egress` route table, LB-select a workload, gate on the
    /// gateway SVID + HBONE capability, and open the datagram-over-HBONE tunnel.
    /// (Stage 3 dropped captured datagrams and needed no state; this is the
    /// enabling refactor.)
    pub state: std::sync::Arc<super::ProxyState>,
    /// Per-listener shutdown receiver (config-driven removal).
    pub shutdown: watch::Receiver<bool>,
    /// Gateway-wide shutdown receiver (SIGTERM/SIGINT). When `Some`, the recv
    /// loop exits as soon as either this OR `shutdown` fires.
    pub global_shutdown: Option<watch::Receiver<bool>>,
    /// Max concurrent captured sessions (`FERRUM_UDP_MAX_SESSIONS`).
    pub max_sessions: usize,
    /// Idle-session cleanup interval in seconds (`FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`).
    pub cleanup_interval_seconds: u64,
    /// Datagrams per `recvmmsg` syscall (`FERRUM_UDP_RECVMMSG_BATCH_SIZE`).
    pub recvmmsg_batch_size: usize,
    /// DashMap shard count for the session map (`FERRUM_POOL_SHARD_AMOUNT`).
    pub session_shard_amount: usize,
    /// Signalled once the listener has bound and is ready to accept.
    pub started_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Session key: a captured flow is identified by the client's source address,
/// the datagram's original (pre-TPROXY) destination, and the kernel-reported
/// ingress interface when the shared host-network capture socket is used. The
/// interface is required because two network tenants may use the same source
/// IP:port tuple; collapsing them into one session would relay the second pod's
/// datagrams under the first pod's identity. Fixed-evidence placements use `0`.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaptureSessionKey {
    pub client: SocketAddr,
    pub orig_dst: SocketAddr,
    pub ingress_ifindex: u32,
}

/// Whether `e` indicates IPv6 is unavailable on this host (so the dual-stack
/// `[::]` capture bind may safely fall back to the v4 wildcard). The
/// classification itself lives in
/// [`crate::socket_opts::is_ipv6_unavailable_io_error`] so the UDP capture bind
/// and the mesh TCP capture bind (issue #4271) can never disagree about which
/// bind failures are a safe downgrade; this wrapper only unwraps the `anyhow`
/// context this module carries.
#[cfg(target_os = "linux")]
fn is_ipv6_unavailable_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(crate::socket_opts::is_ipv6_unavailable_io_error)
}

/// Canonicalize an IPv4-mapped-IPv6 `SocketAddr` (`::ffff:a.b.c.d`) to its plain
/// IPv4 form, leaving genuine IPv6 and plain IPv4 addresses untouched.
///
/// The dual-stack `[::]` capture socket reports an IPv4 sender as a V4-mapped
/// `SocketAddr::V6` (`::ffff:a.b.c.d`), but the orig-dst recovered from the
/// per-datagram cmsg for that SAME packet is a `SocketAddr::V4`. Left as-is, the
/// reply path builds an AF_INET socket from the V4 orig-dst and then
/// `send_to(client)` with a V6-mapped client — a family mismatch that fails the
/// send, so the pod never sees a reply (codex r2 P1). Canonicalizing the client
/// here (at capture, BEFORE the session key is built) makes the client family
/// match the orig-dst family for the reply socket AND keeps the session key
/// consistent (key + reply agree). `IpAddr::to_canonical()` unmaps only
/// V4-mapped V6; a real IPv6 client keeps its V6 address.
#[cfg(target_os = "linux")]
fn canonicalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    crate::util::client_identity::canonical_socket_addr(addr)
}

#[cfg(target_os = "linux")]
fn mesh_udp_lb_hash_key_for_client_ip(ip: std::net::IpAddr) -> String {
    crate::util::client_identity::canonical_ip_string(ip)
}

/// Creates a per-session transparent UDP reply socket bound (non-locally, via
/// `IP_TRANSPARENT`) to a captured datagram's original destination, so replies
/// to the pod are sourced from the VIP:port it dialed.
///
/// The capture socket and its reply sockets MUST live in the SAME network
/// namespace: the Sidecar/current-netns listener binds both in the process
/// netns; the Ambient per-pod-netns producer binds both INSIDE the captured
/// pod's netns. A reply socket in the wrong netns cannot deliver replies back to
/// the pod client and would spoof the wrong source (risk #1). The factory
/// returns a bound `std::net::UdpSocket` (not a tokio socket) so the pod-netns
/// implementation can build it on a `setns`-bound OS thread with no tokio
/// dependency; the caller adopts it onto the runtime.
#[cfg(target_os = "linux")]
pub(crate) trait ReplySocketFactory: Send + Sync + 'static {
    fn bind_transparent_reply_socket(
        &self,
        orig_dst: SocketAddr,
    ) -> std::io::Result<std::net::UdpSocket>;
}

/// Current-netns reply-socket factory: binds the transparent reply socket in the
/// process's own network namespace (Sidecar, whose capture listener already runs
/// inside the injected pod's netns).
#[cfg(target_os = "linux")]
pub(crate) struct CurrentNetnsReplySocketFactory;

#[cfg(target_os = "linux")]
impl ReplySocketFactory for CurrentNetnsReplySocketFactory {
    fn bind_transparent_reply_socket(
        &self,
        orig_dst: SocketAddr,
    ) -> std::io::Result<std::net::UdpSocket> {
        build_transparent_reply_socket(orig_dst)
    }
}

/// Pod-netns reply-socket factory for the Ambient per-pod-netns producer: builds
/// each session's transparent reply socket INSIDE the captured pod's network
/// namespace, so the spoofed reply source (the captured VIP:port) is emitted from
/// the correct netns and the datagram reaches the pod client. Holds a STABLE
/// netns handle (`/proc/<pid>/ns/net`, opened once at capture start) so the
/// `setns` works for the whole capture lifetime even after the resolving PID
/// exits. Every reply-socket build runs on a dedicated `setns`-bound OS thread
/// via [`crate::proxy::netns_capture::run_in_netns`] (never a tokio worker).
#[cfg(target_os = "linux")]
pub(crate) struct PodNetnsReplySocketFactory {
    netns: std::sync::Arc<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl PodNetnsReplySocketFactory {
    pub(crate) fn new(netns: std::sync::Arc<std::fs::File>) -> Self {
        Self { netns }
    }
}

#[cfg(target_os = "linux")]
impl ReplySocketFactory for PodNetnsReplySocketFactory {
    fn bind_transparent_reply_socket(
        &self,
        orig_dst: SocketAddr,
    ) -> std::io::Result<std::net::UdpSocket> {
        crate::proxy::netns_capture::run_in_netns(self.netns.as_ref(), move || {
            build_transparent_reply_socket(orig_dst)
        })
    }
}

/// Where a captured datagram's source evidence comes from.
///
/// The two capture placements differ in exactly this: a pod-netns (or Sidecar)
/// socket serves ONE workload, so its evidence is fixed for the socket's whole
/// lifetime; the host-namespace socket (issue #3288) serves every enrolled pod on
/// the node, so evidence has to be derived per datagram from kernel-reported
/// facts. Everything downstream — session keying, DoS bounds, the relay, the
/// return path — is identical.
#[cfg(target_os = "linux")]
pub(crate) enum CapturedSourceEvidence {
    /// Fixed per producer. `None` keeps the mesh-wide authorization posture for
    /// the Sidecar listener and for old/malformed registry entries.
    Fixed(Option<std::sync::Arc<crate::modes::mesh::hbone::UdpSourceIdentity>>),
    /// Resolved per datagram from the ingress interface index plus the source
    /// address, both kernel-provided. Fails closed: a datagram that cannot be
    /// attributed to exactly one enrolled pod is dropped, never relayed under an
    /// absent or neighbouring identity.
    HostIngress(std::sync::Arc<super::host_udp_capture::HostUdpIdentityIndex>),
}

/// Evidence retained from the exact snapshot that authorized one datagram.
/// Fixed-evidence listeners borrow their already-owned identity without cloning
/// on refreshes; host listeners retain the binding `Arc` from the one ArcSwap
/// load used for authorization.
#[cfg(target_os = "linux")]
enum AuthorizedCapturedSource<'a> {
    Fixed(Option<&'a std::sync::Arc<crate::modes::mesh::hbone::UdpSourceIdentity>>),
    Host(std::sync::Arc<super::host_udp_capture::HostUdpPodBinding>),
}

#[cfg(target_os = "linux")]
impl AuthorizedCapturedSource<'_> {
    /// Materialize the identity only for a newly admitted session. The host arm
    /// can never produce `None`: host authorization requires an attested binding
    /// and this value retains that exact binding generation.
    fn into_session_identity(
        self,
    ) -> Option<std::sync::Arc<crate::modes::mesh::hbone::UdpSourceIdentity>> {
        match self {
            Self::Fixed(identity) => identity.cloned(),
            Self::Host(binding) => Some(std::sync::Arc::new(binding.identity.clone())),
        }
    }
}

#[cfg(target_os = "linux")]
impl CapturedSourceEvidence {
    /// Per-datagram admission. The `Fixed` arm is clone-free; the `HostIngress`
    /// arm costs one lock-free snapshot load, one hash lookup, and one `Arc`
    /// retain so a later generation swap cannot change the admitted evidence.
    fn authorize<'a>(
        &'a self,
        ingress_ifindex: Option<u32>,
        client: SocketAddr,
    ) -> Result<AuthorizedCapturedSource<'a>, &'static str> {
        match self {
            Self::Fixed(identity) => Ok(AuthorizedCapturedSource::Fixed(identity.as_ref())),
            Self::HostIngress(index) => index
                .authorized_binding(ingress_ifindex, client.ip())
                .map(AuthorizedCapturedSource::Host)
                .map_err(super::host_udp_capture::HostUdpDatagramRefusal::as_str),
        }
    }
}

/// Bind the transparent UDP capture socket on `addr` in the CURRENT network
/// namespace, preferring the dual-stack `[::]` bind and falling back to the v4
/// wildcard only when IPv6 is genuinely unavailable. Returns the bound std
/// socket, the resolved bind address, and which orig-dst cmsg families were
/// enabled. Sync (socket2 only, no tokio) so the Ambient per-pod-netns producer
/// can call it from a `setns`-bound OS thread to bind INSIDE a pod netns.
#[cfg(target_os = "linux")]
pub(crate) fn bind_mesh_udp_capture_socket(
    addr: SocketAddr,
) -> Result<(std::net::UdpSocket, SocketAddr, bool, bool), anyhow::Error> {
    bind_mesh_udp_capture_socket_with_pktinfo(addr, false)
}

/// As [`bind_mesh_udp_capture_socket`], additionally requesting the ingress
/// interface cmsg (`IP_PKTINFO` / `IPV6_RECVPKTINFO`) when `require_pktinfo` is
/// set.
///
/// The host-namespace capture socket (issue #3288) attributes each datagram to a
/// pod BY that interface index, so the option is FATAL there: a socket that
/// cannot report the ingress interface could only deliver unattributable
/// datagrams, and the correct response is to refuse the bind rather than to run a
/// capture path whose identity checks would refuse every datagram. The
/// pod-netns/Sidecar placements pass `false` — their evidence is fixed per
/// socket, so they neither need the cmsg nor should pay to parse it.
#[cfg(target_os = "linux")]
pub(crate) fn bind_mesh_udp_capture_socket_with_pktinfo(
    addr: SocketAddr,
    require_pktinfo: bool,
) -> Result<(std::net::UdpSocket, SocketAddr, bool, bool), anyhow::Error> {
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::AsRawFd;
    use tracing::warn;

    // Build a bound transparent capture socket on `bind_addr`. Factored into a
    // closure so the preferred dual-stack `[::]` bind can fall back to the v4
    // wildcard on hosts without IPv6 (codex r3 P2). Sets IP_TRANSPARENT /
    // IP_RECVORIGDSTADDR BEFORE binding (socket2 gives SO_REUSEADDR + the raw fd
    // without binding twice); returns the bound std socket + which orig-dst
    // families were enabled.
    let build_bound_socket =
        |bind_addr: SocketAddr| -> Result<(std::net::UdpSocket, bool, bool), anyhow::Error> {
            let domain = match bind_addr.ip() {
                IpAddr::V4(_) => socket2::Domain::IPV4,
                IpAddr::V6(_) => socket2::Domain::IPV6,
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            // TPROXY delivery requires SO_REUSEADDR so the transparent socket can
            // claim the marked datagrams alongside the kernel's normal routing.
            socket.set_reuse_address(true)?;
            socket.set_nonblocking(true)?;

            let fd = socket.as_raw_fd();
            // IP_TRANSPARENT: accept datagrams whose dst is not local to this host
            // (the captured pod's real service:port, un-rewritten by TPROXY).
            // Fatal if it fails — without transparency the socket can't receive
            // the captured traffic at all, so a half-bound listener would
            // silently black-hole.
            match bind_addr.ip() {
                IpAddr::V4(_) => crate::socket_opts::set_ip_transparent(fd)?,
                IpAddr::V6(_) => {
                    // Dual-stack `[::]`: disable V6ONLY so this one socket also
                    // receives v4-mapped datagrams, and set BOTH transparencies
                    // so v4-mapped and native-v6 captured traffic are both
                    // claimed (codex r3 P2).
                    socket.set_only_v6(false)?;
                    crate::socket_opts::set_ipv6_transparent(fd)?;
                    // Best-effort v4 transparency for v4-mapped datagrams on `::`.
                    let _ = crate::socket_opts::set_ip_transparent(fd);
                }
            }
            // IP(v6)_RECVORIGDSTADDR: surface each datagram's original destination
            // as a cmsg (TPROXY does not rewrite it). Request both variants so a
            // dual-stack listener recovers orig-dst regardless of family.
            let v4_origdst = crate::socket_opts::set_ip_recvorigdstaddr(fd).is_ok();
            let v6_origdst = crate::socket_opts::set_ipv6_recvorigdstaddr(fd).is_ok();
            if !v4_origdst && !v6_origdst {
                // Without orig-dst recovery a captured datagram cannot be routed
                // to its real destination, so refuse rather than bind a listener
                // that can only drop-without-knowing-where. (Stage 3 drops anyway,
                // but Stage 4 relies on this; failing here surfaces a bad kernel
                // early.)
                return Err(anyhow::anyhow!(
                    "mesh UDP capture: IP_RECVORIGDSTADDR setsockopt failed on both v4 and v6 (kernel lacks orig-dst recovery)"
                ));
            }

            if require_pktinfo {
                // IP(v6)_PKTINFO surfaces the INGRESS interface index per
                // datagram, which is the host-namespace placement's identity key.
                // Both families are requested (the dual-stack socket sees v4 and
                // v6 datagrams) and at least one must succeed for the family this
                // socket actually binds; a kernel that supports neither cannot
                // attribute anything, so refuse the bind instead of coming up as
                // a capture path that drops every datagram.
                let v4_pktinfo = crate::socket_opts::set_ip_pktinfo(fd).is_ok();
                let v6_pktinfo = match bind_addr.ip() {
                    IpAddr::V4(_) => false,
                    IpAddr::V6(_) => crate::socket_opts::set_ipv6_recvpktinfo(fd).is_ok(),
                };
                let sufficient = match bind_addr.ip() {
                    IpAddr::V4(_) => v4_pktinfo,
                    // A dual-stack `[::]` socket needs BOTH: the v6 option covers
                    // native IPv6 datagrams and the v4 option covers the
                    // v4-mapped ones, and an unattributable family would be
                    // dropped wholesale at the identity check.
                    IpAddr::V6(_) => v4_pktinfo && v6_pktinfo,
                };
                if !sufficient {
                    return Err(anyhow::anyhow!(
                        "mesh UDP capture: IP_PKTINFO/IPV6_RECVPKTINFO setsockopt failed \
                         (v4={v4_pktinfo}, v6={v6_pktinfo}); the host-network capture path \
                         attributes each datagram by its ingress interface and cannot run \
                         without it"
                    ));
                }
            }

            socket.bind(&bind_addr.into())?;
            Ok((socket.into(), v4_origdst, v6_origdst))
        };

    // Prefer the dual-stack `[::]` bind so one transparent socket captures both
    // v4-mapped and v6 datagrams; fall back to the v4 wildcard ONLY when IPv6 is
    // genuinely unavailable on this host (codex r4). Falling back on ANY error
    // (e.g. the port is already owned by a v6-only socket, EADDRINUSE) would
    // report the listener "started" on v4 while ip6tables still diverts IPv6 UDP
    // to this port with no working v6 listener — blackholing v6 while the pod
    // looks ready. So a non-IPv6-availability error is returned, not masked.
    match build_bound_socket(addr) {
        Ok((s, v4, v6)) => Ok((s, addr, v4, v6)),
        Err(e) if addr.ip().is_ipv6() && is_ipv6_unavailable_error(&e) => {
            let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), addr.port());
            warn!(
                requested = %addr,
                fallback = %v4_addr,
                "Mesh UDP capture: IPv6 unavailable for dual-stack [::] bind ({e}); falling back to v4 wildcard (IPv6 UDP capture unavailable on this host)"
            );
            let (s, v4, v6) = build_bound_socket(v4_addr)?;
            Ok((s, v4_addr, v4, v6))
        }
        Err(e) => Err(e),
    }
}

/// Shared runtime knobs for the capture recv/session loop, independent of HOW
/// the transparent socket was bound. Built by both the current-netns wrapper and
/// the Ambient per-pod-netns producer.
#[cfg(target_os = "linux")]
pub(crate) struct MeshUdpCaptureRuntime {
    pub state: std::sync::Arc<super::ProxyState>,
    pub cleanup_interval_seconds: u64,
    pub recvmmsg_batch_size: usize,
    pub session_shard_amount: usize,
    pub session_limiter: std::sync::Arc<MeshUdpSessionLimiter>,
    /// Where each captured datagram's source evidence comes from: fixed per
    /// producer for the pod-netns/Sidecar placements, or resolved per datagram
    /// from the ingress interface for the host-network placement.
    pub source_identity: CapturedSourceEvidence,
    /// Builds each session's transparent reply socket in the SAME netns as the
    /// capture socket (current-netns for Sidecar, pod-netns for Ambient).
    pub reply_socket_factory: std::sync::Arc<dyn ReplySocketFactory>,
}

/// Start the mesh UDP capture listener in the CURRENT network namespace
/// (Sidecar: the injected pod's own netns). Binds the transparent socket here,
/// then runs the shared capture loop with a current-netns reply-socket factory.
/// The Ambient per-pod-netns producer instead binds inside each enrolled pod's
/// netns and calls [`run_mesh_udp_capture_on_socket`] directly with a pod-netns
/// reply-socket factory.
#[cfg(target_os = "linux")]
pub async fn start_mesh_udp_capture_listener(
    cfg: MeshUdpCaptureConfig,
) -> Result<(), anyhow::Error> {
    let MeshUdpCaptureConfig {
        addr,
        state,
        shutdown,
        global_shutdown,
        max_sessions,
        cleanup_interval_seconds,
        recvmmsg_batch_size,
        session_shard_amount,
        started_tx,
    } = cfg;
    let (std_socket, addr, v4_origdst, v6_origdst) = bind_mesh_udp_capture_socket(addr)?;
    let frontend_socket = tokio::net::UdpSocket::from_std(std_socket)?;
    run_mesh_udp_capture_on_socket(
        frontend_socket,
        addr,
        v4_origdst,
        v6_origdst,
        MeshUdpCaptureRuntime {
            state,
            cleanup_interval_seconds,
            recvmmsg_batch_size,
            session_shard_amount,
            session_limiter: std::sync::Arc::new(MeshUdpSessionLimiter::new(max_sessions)),
            source_identity: CapturedSourceEvidence::Fixed(None),
            reply_socket_factory: std::sync::Arc::new(CurrentNetnsReplySocketFactory),
        },
        shutdown,
        global_shutdown,
        started_tx,
    )
    .await
}

/// Run the mesh UDP capture recv/session loop over an ALREADY-BOUND transparent
/// socket. Shared by [`start_mesh_udp_capture_listener`] (current netns) and the
/// Ambient per-pod-netns producer (`netns_udp_capture`). `addr` is used only for
/// logging; `v4_origdst`/`v6_origdst` report which orig-dst cmsg families the
/// bind enabled. The recovered orig-dst, session keying, DoS bounds, egress
/// relay, and return-path behavior are identical regardless of which netns the
/// socket was bound in — only [`MeshUdpCaptureRuntime::reply_socket_factory`]
/// differs.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_mesh_udp_capture_on_socket(
    frontend_socket: tokio::net::UdpSocket,
    addr: SocketAddr,
    v4_origdst: bool,
    v6_origdst: bool,
    runtime: MeshUdpCaptureRuntime,
    shutdown: watch::Receiver<bool>,
    global_shutdown: Option<watch::Receiver<bool>>,
    started_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), anyhow::Error> {
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use tracing::{info, warn};

    let MeshUdpCaptureRuntime {
        state,
        cleanup_interval_seconds,
        recvmmsg_batch_size,
        session_shard_amount,
        session_limiter,
        source_identity,
        reply_socket_factory,
    } = runtime;
    let frontend_socket = Arc::new(frontend_socket);

    let session_shard_amount = crate::util::sharding::pool_shard_amount(session_shard_amount);
    // Bounded session map keyed by (client, orig-dst). Kernel-provided keys, so
    // ahash (non-cryptographic) is fine — speed wins on the per-datagram lookup.
    let sessions: Arc<dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>> =
        Arc::new(dashmap::DashMap::with_hasher_and_shard_amount(
            ahash::RandomState::default(),
            session_shard_amount,
        ));
    // Producer-local cancellation for every session task. The listener's
    // shutdown receiver drives the accept loop and cleanup sweep; this separate
    // channel is fired on ANY loop exit (including identity-driven Ambient
    // producer replacement) so old tunnels cannot outlive their fixed evidence.
    let (session_stop_tx, session_stop_rx) = watch::channel(false);
    let mut session_tasks = tokio::task::JoinSet::new();
    if let Some(tx) = started_tx {
        let _ = tx.send(());
    }
    info!(
        addr = %addr,
        v4_origdst,
        v6_origdst,
        "Mesh UDP capture listener started (capture→datagram-over-HBONE egress; Ambient only)"
    );

    // Idle-session sweep — reaps captured sessions whose last datagram is older
    // than the idle timeout, so a spoofed-source flood ages out instead of
    // accumulating. Mirrors `udp_proxy::spawn_session_cleanup`'s identity-aware
    // expiry, simplified (no backend leg / plugins in Stage 3).
    spawn_capture_session_cleanup(
        sessions.clone(),
        session_limiter.clone(),
        shutdown.clone(),
        cleanup_interval_seconds,
    );

    let mut shutdown_rx = shutdown;
    let mut global_shutdown_rx = global_shutdown;
    // `true`: this listener enables `IP_RECVORIGDSTADDR` and keys sessions on
    // the captured orig-dst, so it opts into per-datagram orig-dst cmsg parsing.
    let mut recv_batch = super::udp_batch::RecvMmsgBatch::new(recvmmsg_batch_size, true);

    loop {
        tokio::select! {
            completed = session_tasks.join_next(), if !session_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(%error, "Ambient UDP capture session task failed");
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!(addr = %addr, "Mesh UDP capture listener shutting down");
                    break;
                }
            }
            changed = async {
                match global_shutdown_rx.as_mut() {
                    Some(rx) => rx.changed().await,
                    // No global channel: never resolves so the other arms drive.
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_ok() && global_shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
                    info!(addr = %addr, "Mesh UDP capture listener shutting down (gateway shutdown)");
                    break;
                }
            }
            ready = frontend_socket.readable() => {
                if let Err(e) = ready {
                    warn!(addr = %addr, "Mesh UDP capture readable error: {}", e);
                    continue;
                }
                // ALWAYS recvmmsg here (unlike udp_proxy, which has a recv_from
                // primary path): the original destination rides the cmsg, which
                // tokio's recv_from cannot surface, so every datagram must go
                // through the cmsg-aware recvmmsg path.
                let fd = frontend_socket.as_raw_fd();
                let mut total_drained: usize = 0;
                let cap = recv_batch.capacity();
                'drain: loop {
                    match frontend_socket.try_io(tokio::io::Interest::READABLE, || {
                        recv_batch.recv(fd, cap)
                    }) {
                        Ok(n) if n > 0 => {
                            for i in 0..n {
                                let (data, client) = recv_batch.datagram(i);
                                let orig_dst = recv_batch.orig_dst(i);
                                // Ingress interface index from the IP(v6)_PKTINFO
                                // cmsg. `None` for placements that did not enable
                                // pktinfo (pod-netns / Sidecar), which is fine —
                                // their evidence is fixed and ignores it.
                                let ingress_ifindex =
                                    recv_batch.local_addr(i).map(|local| local.ifindex);
                                let gro = recv_batch.gro_segment_size(i);
                                // GRO may coalesce many datagrams into one buffer;
                                // frame EACH segment separately (a coalesced
                                // superblock is N datagrams, not one — risk #8).
                                match gro {
                                    Some(seg) if (seg as usize) < data.len() => {
                                        for chunk in data.chunks(seg as usize) {
                                            handle_captured_datagram(
                                                &sessions,
                                                &session_limiter,
                                                &state,
                                                client,
                                                orig_dst,
                                                ingress_ifindex,
                                                chunk,
                                                &source_identity,
                                                &reply_socket_factory,
                                                &session_stop_rx,
                                                &mut session_tasks,
                                            );
                                        }
                                    }
                                    _ => {
                                        handle_captured_datagram(
                                            &sessions,
                                            &session_limiter,
                                            &state,
                                            client,
                                            orig_dst,
                                            ingress_ifindex,
                                            data,
                                            &source_identity,
                                            &reply_socket_factory,
                                            &session_stop_rx,
                                            &mut session_tasks,
                                        );
                                    }
                                }
                            }
                            total_drained += n;
                            // Bound the per-wakeup drain so one busy socket can't
                            // starve shutdown/other tasks.
                            if total_drained >= cap.saturating_mul(16) {
                                break 'drain;
                            }
                        }
                        _ => break 'drain, // WouldBlock or error — socket drained
                    }
                }
            }
        }
    }
    // Record producer shutdown before signalling/aborting tasks. `JoinSet::shutdown`
    // may drop a task before it polls the watch receiver, so the lifecycle's
    // Drop fallback must already be able to classify that cancellation.
    for session in sessions.iter() {
        session.outcome_signal.mark_producer_shutdown();
    }
    let _ = session_stop_tx.send(true);
    // The producer handle does not finish until every tunnel opened with its
    // fixed source evidence is gone. This makes manager-side replacement wait
    // for the old identity's sessions, including sessions still connecting and
    // not yet polling the cancellation receiver.
    session_tasks.shutdown().await;
    remove_all_capture_sessions(&sessions, &session_limiter);
    Ok(())
}

/// Bounded depth of a per-session egress channel. Captured datagrams are
/// queued here from the (synchronous, hot-path-light) recv loop and drained by
/// the async egress task that frames + writes them onto the HBONE tunnel. A
/// full channel DROPS the datagram (UDP-appropriate backpressure — UDP gives no
/// delivery guarantee, and blocking the bounded recv-loop drain would let one
/// slow session starve every other captured flow). Sized generously so a brief
/// tunnel-dial stall (the channel buffers datagrams until the tunnel is ready)
/// does not shed a normal burst.
///
/// This datagram-count bound is paired with [`EGRESS_CHANNEL_MAX_QUEUED_BYTES`]:
/// 1024 datagrams of up to 65535 bytes each would let many stalled-dial sessions
/// buffer ~64 MiB apiece, a memory-exhaustion DoS, so the BYTE cap (not the count
/// alone) is what bounds per-session memory (codex r3).
#[cfg(target_os = "linux")]
const EGRESS_CHANNEL_DEPTH: usize = 1024;

/// Maximum total bytes queued in a per-session egress channel. The mpsc bounds
/// datagram COUNT; this bounds their aggregate SIZE so a slow/stalled HBONE
/// dial+write cannot let each admitted session buffer `EGRESS_CHANNEL_DEPTH ×
/// up-to-65535` bytes (a memory-exhaustion DoS). Together with
/// `FERRUM_UDP_MAX_SESSIONS` this bounds worst-case queued memory to
/// `max_sessions × EGRESS_CHANNEL_MAX_QUEUED_BYTES`. A datagram that would push
/// the session over this cap is DROPPED (UDP-appropriate), tracked lock-free via
/// the per-session `queued_bytes` atomic (bumped on enqueue, decremented as the
/// egress task drains), so the cap check stays cheap on the recv-loop hot path.
/// Mirrors the plain UDP proxy's `PENDING_SESSION_MAX_QUEUED_BYTES`; sized larger
/// (256 KiB) because this carries an established session's traffic, not just a
/// connection-setup flight.
#[cfg(target_os = "linux")]
const EGRESS_CHANNEL_MAX_QUEUED_BYTES: usize = 256 * 1024;

/// Fallback write deadline for a single framed tunnel `write_all`, used ONLY when
/// the per-session idle timeout is disabled (`udp_idle_timeout_seconds == 0`). A
/// stalled HBONE peer (stopped reading / exhausted h2 flow-control) must not let
/// the framed `write_all` stay pending forever and leak the egress task; bounding
/// the write tears the session down instead. When an idle timeout IS configured,
/// that window is reused as the write deadline (a write blocked longer than the
/// idle window is itself a dead session), so this only covers the
/// idle-disabled case.
#[cfg(target_os = "linux")]
const EGRESS_TUNNEL_WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Monotonic, process-wide generator of per-session identity tokens. Stamped on
/// every admitted session and re-checked at teardown so a task only ever removes
/// ITS OWN map entry. Wraparound is a non-issue: a `u64` at any realistic admit
/// rate never recycles a live token within one session's lifetime.
#[cfg(target_os = "linux")]
static NEXT_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// What ended one [`drain_queued_datagrams`] pass.
#[derive(Debug, PartialEq, Eq)]
pub enum QueueDrain {
    /// The queue had no further ready datagram (or the batch is full and the
    /// next datagram is parked in `held`).
    Idle,
    /// Every producer handle is gone and the queue is empty: the session's
    /// capture side has shut down.
    Disconnected,
}

/// Drain datagrams that are ALREADY queued into `batch` without waiting.
///
/// `first` opens the batch unconditionally (a single datagram always travels,
/// whatever its size). Further datagrams are taken with `try_recv` while
/// [`FrameBatch::accepts`] holds; the first one that does not fit is parked in
/// `held` so the caller opens the next batch with it, preserving FIFO order.
/// Every dequeued datagram — batched or held — has its byte reservation
/// released from `queued_bytes` right here, regardless of the later write
/// outcome, so the per-session queued-byte cap keeps tracking the live queue
/// depth exactly as the one-datagram loop did.
///
/// Never blocks and never spins: the pass ends at the first empty `try_recv`,
/// at the batch bound, or when the queue is disconnected.
pub fn drain_queued_datagrams(
    rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>,
    first: bytes::Bytes,
    batch: &mut super::mesh_udp_frame::FrameBatch,
    held: &mut Option<bytes::Bytes>,
    queued_bytes: &std::sync::atomic::AtomicUsize,
) -> QueueDrain {
    use tokio::sync::mpsc::error::TryRecvError;

    batch.clear();
    // A captured datagram cannot exceed MAX_FRAME_PAYLOAD, so a push failure is
    // unreachable for real traffic; the caller skips an empty batch.
    let _ = batch.push(&first);
    loop {
        match rx.try_recv() {
            Ok(payload) => {
                queued_bytes.fetch_sub(payload.len(), std::sync::atomic::Ordering::Relaxed);
                if !batch.accepts(payload.len()) {
                    *held = Some(payload);
                    return QueueDrain::Idle;
                }
                let _ = batch.push(&payload);
            }
            Err(TryRecvError::Empty) => return QueueDrain::Idle,
            Err(TryRecvError::Disconnected) => return QueueDrain::Disconnected,
        }
    }
}

/// Per-(client, orig-dst) capture session (Stage 4). `last_activity` is
/// monotonic millis from [`crate::socket_opts::monotonic_now_ms`] (never goes
/// backwards under NTP slew, so idle expiry always fires). `tx` hands captured
/// datagram payloads to the per-session egress task; when the session is reaped
/// (idle sweep) or the map entry is replaced, dropping `tx` closes the channel,
/// which ends the egress task and tears the tunnel down (its `poll_shutdown`
/// sends the h2 end-stream).
#[cfg(target_os = "linux")]
struct CaptureSession {
    /// SHARED monotonic-millis activity clock (codex r3). The same `Arc` is held
    /// by the egress + return-path tasks, which bump it on a delivered datagram
    /// in EITHER direction, and read by the independent idle sweep. Without the
    /// share, the sweep clock (refreshed only on client→egress datagrams) and the
    /// task watchdog clock (bidirectional) disagree, so a session where the
    /// client goes quiet while the destination keeps replying would have its map
    /// entry reaped by the sweep mid-flow while the task is still alive. One
    /// shared atomic keeps both clocks in lockstep.
    last_activity: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Unique identity token for THIS session, stamped at admit from
    /// [`NEXT_SESSION_ID`]. The egress task removes its own map entry only when
    /// the stored token still matches (`remove_if`), so a replacement session
    /// admitted in the gap between the idle sweep dropping this entry's `tx` and
    /// this task observing the closed channel is never clobbered (codex r1 P2:
    /// remove-after-replace race).
    session_id: u64,
    /// Egress channel to the per-session task. `None` for a session whose
    /// orig-dst matched no routable `mesh_udp_egress` entry — but such flows are
    /// never inserted (they drop without a session), so in practice this is
    /// always `Some` for a live session. Kept as `Option` only so the unit
    /// tests can exercise the keying/cap logic without a live tunnel.
    tx: Option<tokio::sync::mpsc::Sender<bytes::Bytes>>,
    /// SHARED count of bytes currently queued in the egress channel (codex r3).
    /// Bumped by the recv loop on a successful enqueue, decremented by the egress
    /// task as it drains each datagram, so a per-session BYTE cap
    /// ([`EGRESS_CHANNEL_MAX_QUEUED_BYTES`]) can be enforced on the hot path
    /// without walking the channel. The `Arc` is shared with the egress task.
    queued_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Cleanup/shutdown reason stored before the map drops `tx`, shared with
    /// the relay task so sender closure is classified without a timing race.
    outcome_signal: std::sync::Arc<CapturedUdpOutcomeSignal>,
    /// Per-session idle window in milliseconds, derived from the relay proxy's
    /// `udp_idle_timeout_seconds` at admit (`0` = idle disabled). The cleanup
    /// sweep reaps a session only after THIS window of inactivity (codex r7):
    /// the egress task's own watchdog already honors `udp_idle_timeout_seconds`,
    /// so the independent sweep must use the same window — a fixed 60s window
    /// would cut a long-lived quiet flow (idle configured > 60s) or a flow whose
    /// idle is disabled before the task's watchdog (or the operator) intends.
    idle_timeout_ms: u64,
}

/// Record a captured datagram against its session and forward it toward mesh
/// egress (Stage 4).
///
/// On a NEW `(client, orig-dst)` flow this consults the `mesh_udp_egress` route
/// table; only a routable (`Relay`) destination admits a session (under the
/// `max_sessions` cap) and spawns the per-session egress task. A non-routable
/// orig-dst (no match, or a declared-but-`CloseNotRoutable` pair) DROPS the
/// datagram WITHOUT creating a session — fail closed, never guessed, and never
/// holding a slot for un-routable traffic. An EXISTING flow refreshes its
/// `last_activity` and enqueues the payload (drop-on-full).
///
/// Returns `true` if the datagram was accounted (existing or newly admitted),
/// `false` if it was dropped (no orig-dst, not routable, cap reached, or the
/// egress channel was full) — exposed for unit testing the keying/cap logic.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn handle_captured_datagram(
    sessions: &std::sync::Arc<
        dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    >,
    session_limiter: &std::sync::Arc<MeshUdpSessionLimiter>,
    state: &std::sync::Arc<super::ProxyState>,
    client: SocketAddr,
    orig_dst: Option<SocketAddr>,
    ingress_ifindex: Option<u32>,
    data: &[u8],
    source_identity: &CapturedSourceEvidence,
    reply_factory: &std::sync::Arc<dyn ReplySocketFactory>,
    session_shutdown: &watch::Receiver<bool>,
    session_tasks: &mut tokio::task::JoinSet<()>,
) -> bool {
    use tracing::debug;

    // Canonicalize an IPv4-mapped-V6 client (`::ffff:a.b.c.d`, how the dual-stack
    // `[::]` socket reports v4 senders) to its V4 form so it matches the V4
    // orig-dst family on the reply path AND keys the session consistently (codex
    // r2 P1). Genuine IPv6 clients are unchanged.
    let client = canonicalize_socket_addr(client);

    // Source attribution runs BEFORE routing, keying, or slot reservation, and on
    // EVERY datagram — not only at admission. On the host-network capture socket
    // one workload's unenrollment or a spoofed source must stop being relayed
    // immediately, not when the session happens to idle out; and a refused
    // datagram must never reserve a session slot, so an unattributable flood
    // cannot evict attributable flows. The `Fixed` placements short-circuit to
    // `Ok(())` with no work.
    let authorized_source = match source_identity.authorize(ingress_ifindex, client) {
        Ok(authorized) => authorized,
        Err(reason) => {
            debug!(
                client = %client,
                // `0` is the kernel's "unspecified interface" value, so it doubles as
                // the absent-cmsg marker without logging an `Option`.
                ingress_ifindex = ingress_ifindex.unwrap_or(0),
                reason,
                "Mesh UDP capture: dropping datagram whose source could not be attributed to an \
                 enrolled workload"
            );
            return false;
        }
    };

    let Some(orig_dst) = orig_dst else {
        // No orig-dst cmsg ⇒ we cannot tell where the pod dialed, so there is
        // nothing to route and nothing meaningful to key on. Drop.
        debug!(
            client = %client,
            size = data.len(),
            "Mesh UDP capture: dropping datagram with no original destination cmsg"
        );
        return false;
    };
    // Canonicalize the orig-dst too: it normally arrives as `SocketAddr::V4`, but
    // canonicalizing keeps the reply socket's bind family aligned with the
    // canonicalized client unconditionally (the reply socket is built from
    // `key.orig_dst`), so `send_to(client)` never trips a family mismatch.
    let orig_dst = canonicalize_socket_addr(orig_dst);

    let key = CaptureSessionKey {
        client,
        orig_dst,
        // `0` is reserved by the kernel as "unspecified" and is never admitted
        // by HostIngress, so it is an unambiguous scope for fixed-evidence
        // pod-netns and Sidecar listeners.
        ingress_ifindex: ingress_ifindex.unwrap_or(0),
    };

    // Routability is resolved ONCE per (potentially new) flow via a closure so
    // the cap/keying bookkeeping (`admit_or_refresh_session`) stays a pure,
    // unit-testable function: it only evaluates the closure on the Vacant path
    // (an existing flow already proved routable when it was admitted). A
    // captured datagram whose orig-dst matches no declared `(VIP, UDP port)`
    // pair — or matches a declared-but-`CloseNotRoutable` pair — drops here,
    // holding no slot and spawning no task (fail closed, never guessed).
    // Capture the admission epoch alongside the routability decision so the
    // spawned session task reuses the SAME snapshot for LB/upstream selection
    // (codex r7 P2): a config reload landing between admission and session setup
    // must not pair an old route-table entry with a new load-balancer/upstream
    // snapshot. The closure (and its epoch load) runs ONLY on the Vacant/admit
    // path, so the refresh hot path keeps its zero-epoch-load cost.
    let mut admission_epoch: Option<std::sync::Arc<crate::request_epoch::RequestEpoch>> = None;
    let resolve_entry = || {
        let epoch = state.request_epoch.load();
        let entry = match epoch.route_table.mesh_udp_egress_decision(orig_dst) {
            Some(crate::router_cache::MeshTcpEgressDecision::Relay(entry)) => entry.clone(),
            _ => return None,
        };
        admission_epoch = Some(epoch);
        Some(entry)
    };

    match admit_or_refresh_session(sessions, session_limiter, key, data, resolve_entry) {
        SessionAdmission::Refreshed => true,
        SessionAdmission::Admitted {
            entry,
            rx,
            session_id,
            last_activity,
            queued_bytes,
            outcome_signal,
        } => {
            // Spawn the per-session egress task (tunnel dial + return path); the
            // session's `tx` (already inserted by the bookkeeping above) feeds it.
            // The shared `last_activity`/`queued_bytes` atomics keep the task's
            // bidirectional clock + byte-drain accounting in sync with the sweep
            // and recv loop.
            // Reuse the epoch captured at admission for the session's one-shot
            // LB/upstream selection (codex r7 P2). `admission_epoch` is always
            // `Some` on the Admitted path (the routability closure set it);
            // fall back to a fresh load only defensively.
            let epoch = admission_epoch
                .take()
                .unwrap_or_else(|| state.request_epoch.load());
            spawn_udp_egress_session(
                state.clone(),
                sessions.clone(),
                session_limiter.clone(),
                key,
                session_id,
                entry,
                rx,
                last_activity,
                queued_bytes,
                outcome_signal,
                epoch,
                authorized_source.into_session_identity(),
                reply_factory.clone(),
                session_shutdown.clone(),
                session_tasks,
            );
            true
        }
        SessionAdmission::Dropped => false,
    }
}

/// Outcome of [`admit_or_refresh_session`].
#[cfg(target_os = "linux")]
enum SessionAdmission {
    /// An existing flow's session was refreshed and the datagram enqueued
    /// (or dropped-on-full, which still counts as "accounted" for the flow).
    Refreshed,
    /// A NEW routable flow was admitted: the caller must spawn the egress task
    /// driven by `rx`, relaying to `entry`'s LB-selected workload. `session_id`
    /// is the unique token stamped on the inserted map entry, handed to the task
    /// so its teardown only removes its own entry (`remove_if`). `last_activity`
    /// and `queued_bytes` are the SHARED atomics stored on the map entry, handed
    /// to the task so its bidirectional clock and byte-drain accounting update the
    /// same atomics the sweep / recv-loop read (codex r3).
    Admitted {
        entry: std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>,
        rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        session_id: u64,
        last_activity: std::sync::Arc<std::sync::atomic::AtomicU64>,
        queued_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        outcome_signal: std::sync::Arc<CapturedUdpOutcomeSignal>,
    },
    /// The datagram was dropped (not routable, or the session cap was reached).
    Dropped,
}

/// Pure cap/keying bookkeeping for one captured datagram, factored out of
/// [`handle_captured_datagram`] so it is unit-testable without a live
/// `ProxyState`/tunnel. Refreshes-or-admits the `(client, orig-dst)` session
/// under `max_sessions` using a SINGLE DashMap `entry()` guard:
///
/// - Occupied flow → refresh `last_activity`, enqueue the payload (drop-on-full),
///   return [`SessionAdmission::Refreshed`].
/// - Vacant flow → evaluate `resolve_entry` (the routability gate); on `None`
///   drop without holding a slot; on `Some(entry)` reserve a slot via the cheap
///   `active_sessions` atomic (NOT `DashMap::len()`, which walks/locks every
///   shard on the per-datagram flood path the cap defends against), insert the
///   session with a fresh channel, enqueue the first datagram, and return
///   [`SessionAdmission::Admitted`] with the receiver for the caller to drive.
///
/// Only the atomic (never another `sessions.*` op) is touched while the entry
/// guard is held, so this cannot self-deadlock the way a nested `len()` did.
#[cfg(target_os = "linux")]
fn admit_or_refresh_session<F>(
    sessions: &dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    session_limiter: &MeshUdpSessionLimiter,
    key: CaptureSessionKey,
    data: &[u8],
    resolve_entry: F,
) -> SessionAdmission
where
    F: FnOnce() -> Option<std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>>,
{
    use dashmap::mapref::entry::Entry;
    use std::sync::atomic::Ordering;
    use tracing::debug;

    let now = crate::socket_opts::monotonic_now_ms();
    match sessions.entry(key) {
        Entry::Occupied(mut occupied) => {
            let session = occupied.get_mut();
            // Refresh the SHARED clock (the sweep + watchdog both read it).
            session.last_activity.store(now, Ordering::Relaxed);
            if let Some(tx) = session.tx.as_ref() {
                // Drop-on-full by datagram COUNT (the channel bound) OR by queued
                // BYTES (the per-session memory cap) — UDP backpressure is "drop",
                // and we must never block the bounded recv-loop drain.
                enqueue_egress_datagram(tx, &session.queued_bytes, data, key.client, key.orig_dst);
            }
            SessionAdmission::Refreshed
        }
        Entry::Vacant(vacant) => {
            // Routability gate BEFORE reserving a slot.
            let Some(entry) = resolve_entry() else {
                debug!(
                    client = %key.client,
                    orig_dst = %key.orig_dst,
                    "Mesh UDP capture: captured datagram is not a routable mesh UDP destination; \
                     dropping"
                );
                return SessionAdmission::Dropped;
            };

            // Reserve a slot atomically; hand it back and shed if over the cap.
            if !session_limiter.try_reserve() {
                debug!(
                    client = %key.client,
                    orig_dst = %key.orig_dst,
                    "Mesh UDP capture: session cap reached, dropping datagram from new flow"
                );
                return SessionAdmission::Dropped;
            }

            let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(EGRESS_CHANNEL_DEPTH);
            // SHARED atomics: the activity clock and the queued-byte counter both
            // live on the map entry AND are handed to the egress task, so the
            // sweep, the recv loop, and the task all read/write the same state.
            let last_activity = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now));
            let queued_bytes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let outcome_signal = std::sync::Arc::new(CapturedUdpOutcomeSignal::new());
            // The first datagram fits trivially (empty channel, depth >= 1, byte
            // cap >> one datagram), so account it and enqueue; `rx` is alive
            // (returned below) so the send cannot fail.
            enqueue_egress_datagram(&tx, &queued_bytes, data, key.client, key.orig_dst);
            // Stamp a unique identity token so teardown removes only THIS entry.
            let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
            // Per-session idle window for the cleanup sweep, from the relay
            // proxy's `udp_idle_timeout_seconds` (`0` = disabled). Mirrors the
            // egress task's own watchdog source so the sweep and the watchdog
            // agree on liveness (codex r7).
            let idle_timeout_ms = entry
                .relay_proxy
                .udp_idle_timeout_seconds
                .saturating_mul(1000);
            vacant.insert(CaptureSession {
                last_activity: last_activity.clone(),
                session_id,
                tx: Some(tx),
                queued_bytes: queued_bytes.clone(),
                outcome_signal: outcome_signal.clone(),
                idle_timeout_ms,
            });
            SessionAdmission::Admitted {
                entry,
                rx,
                session_id,
                last_activity,
                queued_bytes,
                outcome_signal,
            }
        }
    }
}

/// Enqueue one captured datagram onto a session's egress channel, dropping it
/// (UDP-appropriate) if either the channel's datagram-COUNT bound or the
/// per-session queued-BYTE cap ([`EGRESS_CHANNEL_MAX_QUEUED_BYTES`]) would be
/// exceeded (codex r3). Lock-free: a single relaxed `fetch_add` reserves the
/// byte budget, handed back on a full/closed channel; the egress task decrements
/// `queued_bytes` as it drains, so the counter tracks the live queue depth in
/// bytes. Kept cheap so the recv-loop hot path stays allocation-light beyond the
/// unavoidable payload copy into `Bytes`.
#[cfg(target_os = "linux")]
fn enqueue_egress_datagram(
    tx: &tokio::sync::mpsc::Sender<bytes::Bytes>,
    queued_bytes: &std::sync::atomic::AtomicUsize,
    data: &[u8],
    client: SocketAddr,
    orig_dst: SocketAddr,
) {
    use std::sync::atomic::Ordering;
    use tracing::debug;

    // Reserve the byte budget first; if it would overflow the cap, hand it back
    // and drop (do NOT enqueue, or the byte counter and channel would diverge).
    let prev = queued_bytes.fetch_add(data.len(), Ordering::Relaxed);
    if prev.saturating_add(data.len()) > EGRESS_CHANNEL_MAX_QUEUED_BYTES {
        queued_bytes.fetch_sub(data.len(), Ordering::Relaxed);
        debug!(
            client = %client,
            orig_dst = %orig_dst,
            "Mesh UDP capture: egress queued-byte cap reached; dropping datagram"
        );
        return;
    }
    if tx.try_send(bytes::Bytes::copy_from_slice(data)).is_err() {
        // Channel full (count bound) or closed (task gone): undo the byte
        // reservation so the counter does not leak, and drop.
        queued_bytes.fetch_sub(data.len(), Ordering::Relaxed);
        debug!(
            client = %client,
            orig_dst = %orig_dst,
            "Mesh UDP capture: egress channel full or closed; dropping datagram"
        );
    }
}

/// Spawn the per-session UDP egress task: open a `udp`-marked datagram-over-HBONE
/// tunnel to the LB-selected workload, frame + write captured datagrams onto it,
/// and (return path) read framed replies back off it and send them to the client
/// SOURCED FROM the captured original destination so the pod sees replies from
/// the VIP:port it dialed.
///
/// All the fail-closed gates from the raw-TCP egress path apply (LB selection,
/// gateway SVID present, HBONE capability proven, pinned-peer identity intact);
/// any gate failure logs and ends the session (the recv loop already created the
/// map entry, so it is cleaned up by the idle sweep — the channel just goes
/// undrained and fills, which drop-on-full handles harmlessly).
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn spawn_udp_egress_session(
    state: std::sync::Arc<super::ProxyState>,
    sessions: std::sync::Arc<
        dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    >,
    session_limiter: std::sync::Arc<MeshUdpSessionLimiter>,
    key: CaptureSessionKey,
    session_id: u64,
    entry: std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>,
    rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    last_activity: std::sync::Arc<std::sync::atomic::AtomicU64>,
    queued_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    outcome_signal: std::sync::Arc<CapturedUdpOutcomeSignal>,
    epoch: std::sync::Arc<crate::request_epoch::RequestEpoch>,
    source_identity: Option<std::sync::Arc<crate::modes::mesh::hbone::UdpSourceIdentity>>,
    reply_factory: std::sync::Arc<dyn ReplySocketFactory>,
    session_shutdown: watch::Receiver<bool>,
    session_tasks: &mut tokio::task::JoinSet<()>,
) {
    session_tasks.spawn(async move {
        run_udp_egress_session(
            &state,
            &entry,
            key,
            rx,
            last_activity,
            queued_bytes,
            outcome_signal,
            epoch,
            source_identity.as_deref(),
            &reply_factory,
            session_shutdown,
        )
        .await;
        // Session teardown: remove the map entry and decrement the live count so
        // a finished/failed flow frees its slot immediately (the idle sweep is a
        // backstop for sessions whose task is still alive but quiescent).
        //
        // CONDITIONAL removal (codex r1 P2): see [`remove_session_if_owned`].
        remove_session_if_owned(&sessions, &session_limiter, &key, session_id);
    });
}

/// Remove every session owned by a capture producer and release exactly the
/// slots this call won. Session tasks race through conditional removal; only
/// one side can remove each key, so the shared Ambient limiter cannot be
/// double-decremented.
#[cfg(target_os = "linux")]
fn remove_all_capture_sessions(
    sessions: &dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    session_limiter: &MeshUdpSessionLimiter,
) {
    let keys: Vec<CaptureSessionKey> = sessions.iter().map(|entry| *entry.key()).collect();
    let mut removed = 0;
    for key in keys {
        if sessions.remove(&key).is_some() {
            removed += 1;
        }
    }
    session_limiter.release(removed);
}

/// Tear down a finished/failed egress session: remove its map entry and
/// decrement the live-session count, but ONLY if the map entry is still THIS
/// task's session (its `session_id` matches).
///
/// If the idle sweep already reaped this entry and a new datagram on the same
/// `(client, orig-dst)` admitted a REPLACEMENT session in the gap before this
/// task observed its closed channel, the map now holds the replacement's
/// `session_id`, not ours. `remove_if` removes (and we decrement) ONLY when the
/// stored token is still ours — so we never clobber the replacement and never
/// double-decrement the cap counter. Factored out (pure over the map + atomic)
/// so the remove-after-replace race is unit-testable without a live tunnel.
#[cfg(target_os = "linux")]
fn remove_session_if_owned(
    sessions: &dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    session_limiter: &MeshUdpSessionLimiter,
    key: &CaptureSessionKey,
    session_id: u64,
) {
    // `remove_if` returns `Some` only when the predicate held and the entry was
    // removed; a non-matching (replaced) entry is left intact.
    if sessions
        .remove_if(key, |_, session| session.session_id == session_id)
        .is_some()
    {
        session_limiter.release(1);
    }
}

/// Body of the per-session egress task. Returns when the session ends (client
/// idle, tunnel closed, or a fail-closed gate tripped). Never panics.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn run_udp_egress_session(
    state: &std::sync::Arc<super::ProxyState>,
    entry: &std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>,
    key: CaptureSessionKey,
    mut rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    last_activity: std::sync::Arc<std::sync::atomic::AtomicU64>,
    queued_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    outcome_signal: std::sync::Arc<CapturedUdpOutcomeSignal>,
    epoch: std::sync::Arc<crate::request_epoch::RequestEpoch>,
    source_identity: Option<&crate::modes::mesh::hbone::UdpSourceIdentity>,
    reply_factory: &std::sync::Arc<dyn ReplySocketFactory>,
    mut session_shutdown: watch::Receiver<bool>,
) {
    use super::{LoadBalancerConnectionGuard, backend_dispatch};
    use crate::load_balancer::{LoadBalancerCache, LoadBalancerCacheInner};
    use tracing::{debug, warn};

    // The admission epoch is reused here (codex r7 P2) so route resolution (done
    // at admission) and LB/upstream selection below see ONE coherent config
    // snapshot — a reload between the two can't pair an old route entry with a new
    // LB/upstream view. It is needed only for this one-shot setup and is dropped
    // right after selection (below) rather than pinning the generation for the
    // session's lifetime.
    let proxy = entry.relay_proxy.as_ref();
    let mut observability = super::mesh_egress_observability::CapturedMeshEgressLifecycle::start(
        &epoch,
        proxy,
        crate::plugins::ProxyProtocol::Udp,
        key.client.ip(),
        &entry.service_fqdn,
        key.orig_dst.port(),
        source_identity.map(|identity| &identity.principal),
    )
    .await;
    if let Some(observability) = observability.as_mut() {
        observability.set_udp_outcome_signal(outcome_signal.clone());
    }

    // ── Fail-closed egress gates (mirrors handle_mesh_tcp_egress) ──────────
    // Engage the per-port LB lane (algorithm / locality) when all upstream
    // targets share a single port — same pre-selection semantics as the HTTP
    // dispatch path. Selection respects active/passive health state already
    // recorded for the relay proxy/upstream.
    //
    // All lb operations are done in a scoped block so the reference to
    // `epoch.load_balancer` (the Arc inner snapshot) is released before
    // `drop(epoch)` below (codex r7 P2: epoch is setup-only; drop early).
    let (target, balancer) = {
        let lb: &LoadBalancerCacheInner = &epoch.load_balancer;
        // Engage the per-port lane only on a non-zero override port: the relay
        // proxy's `backend_port` is a placeholder, so the HTTP path's fallback
        // must not pin a mixed-port upstream (see tcp_proxy::resolve_backend_target).
        let override_port = LoadBalancerCache::initial_dispatch_port_override_from(
            lb,
            &proxy.namespace,
            &entry.upstream_id,
        );
        let health_port_scope = backend_dispatch::stream_health_port_scope(
            proxy,
            lb,
            &entry.upstream_id,
            override_port,
        );
        let port_lane = (health_port_scope.is_some()
            && match mesh_stream_port_lane_supported(proxy, override_port) {
                Ok(supported) => supported,
                Err(message) => {
                    warn!(
                        service = %entry.service_fqdn,
                        port = override_port,
                        orig_dst = %key.orig_dst,
                        %message,
                        "Mesh UDP egress per-port LB policy is unsupported; ending session"
                    );
                    return;
                }
            })
        .then_some(override_port);
        if let Some(port) = port_lane {
            let strategy = LoadBalancerCache::get_hash_on_strategy_for_selection_from(
                lb,
                &proxy.namespace,
                &entry.upstream_id,
                Some(port),
                None,
            );
            if !matches!(strategy, crate::load_balancer::HashOnStrategy::Ip) {
                warn!(
                    service = %entry.service_fqdn,
                    port,
                    orig_dst = %key.orig_dst,
                    "Mesh UDP egress per-port consistent hashing supports only source-IP hash keys; ending session"
                );
                return;
            }
        }
        let lb_hash_key = mesh_udp_lb_hash_key_for_client_ip(key.client.ip());
        let health_ctx = backend_dispatch::health_context_for_selection(
            proxy,
            &state.health_checker,
            lb,
            &entry.upstream_id,
            health_port_scope,
        );
        let selection = if let Some(port) = port_lane {
            LoadBalancerCache::select_target_for_port_from(
                lb,
                &proxy.namespace,
                &entry.upstream_id,
                &lb_hash_key,
                port,
                Some(&health_ctx),
            )
        } else {
            LoadBalancerCache::select_target_from(
                lb,
                &proxy.namespace,
                &entry.upstream_id,
                &lb_hash_key,
                Some(&health_ctx),
            )
        };
        let Some(selection) = selection else {
            warn!(
                service = %entry.service_fqdn,
                orig_dst = %key.orig_dst,
                "Mesh UDP egress has no selectable workload target; ending session"
            );
            return;
        };
        let balancer = lb.balancer(&proxy.namespace, &entry.upstream_id).cloned();
        (selection.target, balancer)
    };

    // Least-connection accounting parity with the raw-TCP / HTTP relay paths
    // (mirrors handle_mesh_tcp_egress): acquire the guard immediately after
    // target selection and HOLD it for the session's lifetime so per-target
    // active-connection counts include long-lived UDP sessions. Dropped on any
    // early return below and at session teardown, so least-connections LB sees a
    // UDP session start/stop exactly once.

    // Setup-only snapshot: release the epoch now so a long-lived UDP session does
    // not pin an old config generation in memory (codex r7 P2).
    drop(epoch);
    let _lb_guard =
        LoadBalancerConnectionGuard::new(Some(std::sync::Arc::clone(&target)), balancer);
    if let Some(observability) = observability.as_mut() {
        observability.set_target(&target);
    }

    // Admitted-generation gateway trust, not the live SVID slot: see the same
    // gate in `mesh_tcp_egress::handle_mesh_tcp_egress` (issue #3727). A UDP
    // session is long-lived, so it must be created from a generation whose
    // trust is actually live rather than one still being published.
    if !state.admits_gateway_mesh_identity() {
        warn!(
            service = %entry.service_fqdn,
            "Mesh UDP egress requires a live gateway trust generation; ending session"
        );
        return;
    }

    // ── Dual-transport datagram tunnel (mirrors the raw-TCP egress branch in
    // `mesh_tcp_egress::handle_mesh_tcp_egress`) ───────────────────────────────
    // The materializer stamps exactly one transport tag per target (mutually
    // exclusive). Ambient relays the datagram tunnel over a fresh HBONE CONNECT
    // (`:15008`, capability-probe-gated); Sidecar relays it over a fresh
    // mesh-mTLS CONNECT (`:15006`, NO capability registry — a slice-declared
    // sidecar speaks mesh-mTLS by construction). Both stamp the `udp` marker so
    // the destination's transport-agnostic inbound relay unframes the tunnel into
    // a local `UdpSocket` (`is_udp_hbone_connect` → `handle_hbone_udp_request`).
    // A target with neither tag fails closed (materializer bug).
    let tunnel = if crate::proxy::hbone_pool::target_hbone_enabled(&target) {
        // In-cluster HBONE capability must be proven (the enrollment pass + widened probe
        // gate keep these records alive; the dispatch gate fails closed until
        // proven). Target-effective keying: enrollment builds probe keys from
        // the relay proxy AFTER per-target override resolution, so this
        // fail-closed gate must read the same key or a per-port DR TLS override
        // on the stream upstream drops every UDP session forever. Cross-cluster
        // targets bypass probing because only the operator gateway is dialable;
        // SNI/trust-domain metadata is validated below.
        let cross_cluster = crate::proxy::hbone_pool::target_hbone_cross_cluster(&target);
        if !cross_cluster
            && !crate::proxy::get_backend_capability_for_target(
                state.backend_capabilities.as_ref(),
                proxy,
                Some(&target),
            )
            .is_some_and(|record| record.hbone.is_supported())
        {
            debug!(
                service = %entry.service_fqdn,
                target_host = %target.host,
                target_port = target.port,
                "Mesh UDP egress target has no proven HBONE capability yet; ending session \
                 (retry after the next capability refresh)"
            );
            return;
        }
        // Pinned peer identity: present-but-corrupt fails closed. An absent tag
        // keeps trust-domain-only verification for operator-supplied targets.
        let authority_host = match crate::proxy::hbone_pool::target_hbone_authority_host(&target) {
            Ok(host) => host,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Mesh UDP egress target carries an invalid CONNECT authority; refusing dial"
                );
                return;
            }
        };
        if cross_cluster
            && !target
                .tags
                .contains_key(crate::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG)
        {
            warn!(
                service = %entry.service_fqdn,
                target_host = %target.host,
                "Cross-cluster UDP HBONE target is missing its real-pod CONNECT authority; refusing dial"
            );
            return;
        }
        let (expected_peer, expected_trust_domain, sni_override) = if cross_cluster {
            let Some(sni) = crate::proxy::hbone_pool::target_hbone_eastwest_sni(&target) else {
                warn!(service = %entry.service_fqdn, "Cross-cluster UDP HBONE target is missing its SNI override; refusing dial");
                return;
            };
            let Some(td) =
                crate::proxy::hbone_pool::target_hbone_cross_cluster_trust_domain(&target)
            else {
                warn!(service = %entry.service_fqdn, "Cross-cluster UDP HBONE target is missing its trust domain; refusing dial");
                return;
            };
            (None, Some(td), Some(sni))
        } else {
            let expected_peer = match crate::proxy::hbone_pool::target_expected_peer_spiffe(&target)
            {
                Ok(peer) => peer,
                Err(err) => {
                    warn!(service = %entry.service_fqdn, target_host = %target.host, error = %err,
                        "Mesh UDP egress target carries a corrupt pinned identity; refusing dial");
                    return;
                }
            };
            (expected_peer, None, None)
        };
        let hbone_port = crate::proxy::hbone_pool::target_hbone_port(&target);
        let dial_host = match crate::proxy::hbone_pool::target_hbone_dial_host(&target) {
            Ok(host) => host,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Mesh UDP egress target carries a corrupt HBONE dial host; refusing dial"
                );
                return;
            }
        };
        match state
            .hbone_pool
            .get_datagram_tunnel(
                proxy,
                dial_host,
                hbone_port,
                authority_host,
                target.port,
                target.dispatch_policy_port(),
                expected_peer.as_ref(),
                expected_trust_domain.as_ref(),
                sni_override,
                source_identity,
            )
            .await
        {
            Ok(tunnel) => tunnel,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    target_port = target.port,
                    error = %err,
                    "Mesh UDP egress datagram-over-HBONE tunnel failed; ending session"
                );
                return;
            }
        }
    } else if crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(&target) {
        // Same-cluster targets require a pinned peer; cross-cluster targets use
        // the shared Sidecar dial plan's mandatory SNI + trust-domain scope.
        // No capability registry: a slice-declared sidecar peer speaks
        // mesh-mTLS by construction.
        let dial_plan = match crate::proxy::mesh_mtls_pool::MeshMtlsDialPlan::resolve(&target) {
            Ok(plan) => plan,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    error = %err,
                    "Mesh UDP egress mesh.mtls dial metadata is invalid; refusing dial"
                );
                return;
            }
        };
        let dial_host = match crate::proxy::mesh_mtls_pool::target_mesh_mtls_dial_host(&target) {
            Ok(host) => host,
            Err(err) => {
                warn!(service = %entry.service_fqdn, target_host = %target.host, error = %err,
                    "Mesh UDP egress mesh.mtls dial host is invalid; refusing dial");
                return;
            }
        };
        let authority_host = match crate::proxy::mesh_mtls_pool::target_mesh_mtls_authority_host(
            &target,
        ) {
            Some(host) => host,
            None if dial_plan.cross_cluster => {
                warn!(service = %entry.service_fqdn,
                        "Cross-cluster UDP mesh.mtls target is missing its CONNECT authority; refusing dial");
                return;
            }
            None => target.host.as_str(),
        };
        let mtls_port = crate::proxy::mesh_mtls_pool::target_mesh_mtls_port(&target);
        match state
            .mesh_mtls_pool
            .open_datagram_tunnel(
                proxy,
                dial_host,
                authority_host,
                target.port,
                target.dispatch_policy_port(),
                mtls_port,
                dial_plan.expected_peer.as_ref(),
                dial_plan.expected_trust_domain.as_ref(),
                dial_plan.sni_override,
                source_identity,
            )
            .await
        {
            Ok(tunnel) => tunnel,
            Err(err) => {
                warn!(
                    service = %entry.service_fqdn,
                    target_host = %target.host,
                    target_port = target.port,
                    error = %err,
                    "Mesh UDP egress sidecar mesh-mTLS datagram tunnel failed; ending session"
                );
                return;
            }
        }
    } else {
        warn!(
            service = %entry.service_fqdn,
            target_host = %target.host,
            "Mesh UDP egress target carries neither mesh.hbone nor mesh.mtls; ending session \
             (materializer bug?)"
        );
        return;
    };

    // ── Return-path socket: a transparent UDP socket bound NON-LOCALLY to the
    // captured original destination so replies to the pod appear sourced from
    // the VIP:port it dialed (IP_TRANSPARENT lets us bind a non-local addr;
    // the reply's source IP AND port then come from this bind). Risk #1. ──────
    // Built through the reply-socket factory so the socket lands in the SAME
    // netns as the capture socket: current-netns for Sidecar, the captured pod's
    // netns for Ambient. A reply socket in the wrong netns would not reach the
    // pod client and would spoof the wrong source.
    let reply_socket = match reply_factory.bind_transparent_reply_socket(key.orig_dst) {
        Ok(std_sock) => match tokio::net::UdpSocket::from_std(std_sock) {
            Ok(sock) => std::sync::Arc::new(sock),
            Err(e) => {
                warn!(
                    service = %entry.service_fqdn,
                    orig_dst = %key.orig_dst,
                    error = %e,
                    "Mesh UDP egress could not adopt the transparent reply socket onto the \
                     runtime; ending session"
                );
                return;
            }
        },
        Err(e) => {
            warn!(
                service = %entry.service_fqdn,
                orig_dst = %key.orig_dst,
                error = %e,
                "Mesh UDP egress could not bind a transparent reply socket; ending session \
                 (replies must be sourced from the captured destination)"
            );
            return;
        }
    };

    debug!(
        service = %entry.service_fqdn,
        orig_dst = %key.orig_dst,
        client = %key.client,
        target_host = %target.host,
        target_port = target.port,
        "Mesh UDP egress session established (datagram-over-mesh CONNECT)"
    );

    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel);
    let idle = udp_session_idle_timeout(proxy);
    // Single framed-write deadline: reuse the idle window when configured (a write
    // blocked longer than the whole idle window is a dead session anyway), else a
    // fixed fallback so a stalled tunnel write can never hang forever (codex r2
    // P2). Always `Some` — a write is always bounded.
    let write_deadline = idle.unwrap_or(EGRESS_TUNNEL_WRITE_DEADLINE);

    // Shared last-activity clock (monotonic millis — never rewinds under NTP
    // slew), passed in from the map entry so the idle SWEEP, the recv loop, and
    // this task's watchdog all read/write the SAME atomic (codex r3). Bumped on a
    // delivered datagram in EITHER direction (client→egress sends AND return-path
    // tunnel→client replies), so a one-way reply stream (client quiet, dest
    // streaming back) does NOT time out mid-flow AND is not reaped by the sweep
    // (codex r2 P2 + r3 — mirrors `relay_hbone_udp`).
    last_activity.store(
        crate::socket_opts::monotonic_now_ms(),
        std::sync::atomic::Ordering::Relaxed,
    );

    // Return path: read framed datagrams off the tunnel and reply to the client
    // from the transparent socket. Activity here keeps the session alive.
    let return_client = key.client;
    let return_socket = reply_socket.clone();
    let return_activity = last_activity.clone();
    let bytes_received = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bytes_sent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    if let Some(observability) = observability.as_mut() {
        observability.set_udp_byte_counters(bytes_sent.clone(), bytes_received.clone());
    }
    let return_bytes_received = std::sync::Arc::clone(&bytes_received);
    enum ReturnPathCompletion {
        TunnelEnded,
        ClientReplySendFailed,
    }

    let return_path = async move {
        let mut buf = bytes::BytesMut::with_capacity(super::mesh_udp_frame::MAX_FRAME_PAYLOAD);
        loop {
            match super::mesh_udp_frame::read_datagram(&mut tunnel_read, &mut buf).await {
                Ok(Some(payload)) => {
                    return_activity.store(
                        crate::socket_opts::monotonic_now_ms(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    // Count bytes read from the backend even when the client
                    // delivery below fails, matching the generic UDP lifecycle.
                    return_bytes_received
                        .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    // Best-effort reply; a send error (client gone) ends the
                    // return path, which tears the session down.
                    if let Err(e) = return_socket.send_to(&payload, return_client).await {
                        debug!(
                            client = %return_client,
                            error = %e,
                            "Mesh UDP egress: reply send to client failed; ending return path"
                        );
                        break ReturnPathCompletion::ClientReplySendFailed;
                    }
                }
                Ok(None) => break ReturnPathCompletion::TunnelEnded, // tunnel half-closed
                Err(_) => break ReturnPathCompletion::TunnelEnded,   // tunnel read error
            }
        }
    };

    // Egress loop: drain captured datagrams, frame them, write onto the tunnel.
    // Idle expiry is enforced by the shared watchdog (NOT a per-`recv` timeout,
    // which would ignore return-path activity); each batched write is bounded
    // by `write_deadline` so a stalled HBONE peer tears the session down instead
    // of leaking this task (codex r2 P2).
    //
    // Datagrams ALREADY queued when one is dequeued are drained with `try_recv`
    // into a bounded `FrameBatch` and written as one tunnel write (one h2 DATA
    // frame instead of one per datagram). Nothing waits for a batch to fill: an
    // isolated datagram is written at once and the drain stops at the first
    // empty `try_recv`. A datagram that does not fit the batch bound is held and
    // opens the next batch, preserving FIFO order.
    let egress_activity = last_activity.clone();
    let egress_bytes_sent = std::sync::Arc::clone(&bytes_sent);
    // Moved into the egress loop: it is the sole drainer, so it owns releasing
    // the byte reservations. (The recv loop only ever ADDS to this counter.)
    let egress_queued_bytes = queued_bytes;
    enum EgressCompletion {
        SenderClosed,
        TunnelEnded,
    }

    let egress_loop = async move {
        use super::mesh_udp_frame::{BatchWriteFailureKind, FrameBatch};
        let mut batch = FrameBatch::new();
        // A dequeued datagram not admitted to the just-written batch.
        let mut held: Option<bytes::Bytes> = None;
        let completion = loop {
            let first = match held.take() {
                Some(payload) => payload,
                None => {
                    let Some(payload) = rx.recv().await else {
                        break EgressCompletion::SenderClosed;
                    };
                    // This datagram has left the queue: release its byte
                    // reservation so the per-session queued-byte cap tracks the
                    // live queue depth (codex r3). Released for EVERY dequeued
                    // datagram regardless of the write outcome below.
                    egress_queued_bytes
                        .fetch_sub(payload.len(), std::sync::atomic::Ordering::Relaxed);
                    payload
                }
            };
            egress_activity.store(
                crate::socket_opts::monotonic_now_ms(),
                std::sync::atomic::Ordering::Relaxed,
            );
            // Observed the queue closed while draining: finish writing the
            // batch it interrupted, then end the session.
            let sender_closed =
                drain_queued_datagrams(&mut rx, first, &mut batch, &mut held, &egress_queued_bytes)
                    == QueueDrain::Disconnected;
            if batch.is_empty() {
                if sender_closed {
                    break EgressCompletion::SenderClosed;
                }
                continue;
            }
            match batch.write_to(&mut tunnel_write, write_deadline).await {
                Ok(()) => {
                    egress_bytes_sent.fetch_add(
                        batch.payload_bytes() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                Err(failure) => {
                    // Only the datagrams the tunnel fully accepted count as
                    // sent; the rest of the batch (and any held datagram) is
                    // dropped with the session.
                    egress_bytes_sent.fetch_add(
                        failure.committed_payload_bytes as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    match failure.kind {
                        BatchWriteFailureKind::Io(e) => {
                            debug!(
                                error = %e,
                                batched = batch.len(),
                                committed = failure.committed_datagrams,
                                "Mesh UDP egress: tunnel write failed; ending session"
                            );
                        }
                        BatchWriteFailureKind::Stalled => {
                            // The HBONE peer stopped reading / flow-control is
                            // exhausted; the write stalled past the deadline.
                            // Tear the session down rather than leak a task
                            // pinned on a never-completing write.
                            debug!(
                                write_deadline_ms = write_deadline.as_millis() as u64,
                                batched = batch.len(),
                                committed = failure.committed_datagrams,
                                "Mesh UDP egress: tunnel write stalled past deadline; ending session"
                            );
                        }
                    }
                    break EgressCompletion::TunnelEnded;
                }
            }
            if sender_closed {
                break EgressCompletion::SenderClosed;
            }
        };
        // Return the write half to the selected branch. Half-closing it inside
        // this future could wake `return_path` first and misclassify a cleanup-
        // driven sender close as a return-path failure.
        (completion, tunnel_write)
    };

    // Idle watchdog: ends the session when neither direction has been active for
    // `idle`. `None` disables it (the future never resolves, so the two relay arms
    // drive). Polls at a fraction of the window (clamped 100ms..1s) so an expiry
    // fires within ~one poll of the deadline (mirrors `relay_hbone_udp`).
    let watchdog = async move {
        let Some(idle) = idle else {
            std::future::pending::<()>().await;
            return;
        };
        let idle_ms = idle.as_millis().min(u64::MAX as u128) as u64;
        let poll_ms = (idle_ms / 4).clamp(100, 1_000);
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(poll_ms));
        loop {
            interval.tick().await;
            let last = last_activity.load(std::sync::atomic::Ordering::Relaxed);
            if crate::socket_opts::monotonic_now_ms().saturating_sub(last) > idle_ms {
                debug!("Mesh UDP egress: session idle timeout; ending");
                break;
            }
        }
    };

    let producer_outcome_signal = outcome_signal.clone();
    let producer_cancelled = async move {
        if *session_shutdown.borrow() {
            producer_outcome_signal.mark_producer_shutdown();
            return;
        }
        let _ = session_shutdown.changed().await;
        producer_outcome_signal.mark_producer_shutdown();
    };

    // Any arm completing ends the session (and, on return, the caller's
    // `remove_session_if_owned` frees the slot + decrements `active_sessions`).
    enum SessionCompletion {
        Relay(CapturedUdpOutcome),
        ClientReplySendFailed,
    }

    let completion = tokio::select! {
        biased;
        return_completion = return_path => match return_completion {
            ReturnPathCompletion::TunnelEnded => {
                SessionCompletion::Relay(CapturedUdpOutcome::ReturnPathEnded)
            }
            ReturnPathCompletion::ClientReplySendFailed => {
                SessionCompletion::ClientReplySendFailed
            }
        },
        (completion, mut tunnel_write) = egress_loop => {
            // The egress completion has won before its local half-close can
            // wake the return reader. Preserve h2 end-stream semantics, then
            // resolve sender closure through the sweep/shutdown signal.
            use tokio::io::AsyncWriteExt as _;
            let _ = tunnel_write.shutdown().await;
            SessionCompletion::Relay(outcome_signal.resolve_egress_completion(matches!(
                completion,
                EgressCompletion::SenderClosed,
            )))
        },
        _ = watchdog => SessionCompletion::Relay(CapturedUdpOutcome::IdleTimeout),
        _ = producer_cancelled => {
            SessionCompletion::Relay(CapturedUdpOutcome::ProducerShutdown)
        },
    };
    if let Some(observability) = observability.as_mut() {
        let bytes_sent = bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
        let bytes_received = bytes_received.load(std::sync::atomic::Ordering::Relaxed);
        match completion {
            SessionCompletion::Relay(outcome) => {
                observability.complete_udp(bytes_sent, bytes_received, outcome);
            }
            SessionCompletion::ClientReplySendFailed => {
                observability.complete_udp_client_reply_failure(bytes_sent, bytes_received);
            }
        }
    }
}

/// Build a transparent UDP socket bound (non-locally) to `orig_dst` so replies
/// to the captured client carry `orig_dst` as their source address AND port.
/// `IP_TRANSPARENT` (Linux, needs `CAP_NET_ADMIN`) is what permits binding to a
/// non-local address; `SO_REUSEADDR` mirrors the capture socket so multiple
/// sessions to the same VIP:port coexist. This is the TPROXY return-path
/// pattern: the kernel emits replies from the bound transparent address rather
/// than the host's own IP.
#[cfg(target_os = "linux")]
fn build_transparent_reply_socket(orig_dst: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use std::net::IpAddr;
    use std::os::fd::AsRawFd;

    let domain = match orig_dst.ip() {
        IpAddr::V4(_) => socket2::Domain::IPV4,
        IpAddr::V6(_) => socket2::Domain::IPV6,
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let fd = socket.as_raw_fd();
    match orig_dst.ip() {
        IpAddr::V4(_) => crate::socket_opts::set_ip_transparent(fd)?,
        IpAddr::V6(_) => crate::socket_opts::set_ipv6_transparent(fd)?,
    }
    // Bind to the captured original destination (the VIP:port the pod dialed).
    // IP_TRANSPARENT makes this non-local bind succeed; replies sent on this
    // socket then originate from orig_dst. Returns a std socket (no tokio) so the
    // pod-netns factory can build it on a `setns`-bound OS thread; the caller
    // adopts it onto the runtime via `tokio::net::UdpSocket::from_std`.
    socket.bind(&orig_dst.into())?;
    Ok(socket.into())
}

/// Resolve the per-session idle timeout for an egress session from the relay
/// proxy's `udp_idle_timeout_seconds` (the materialized relay proxy carries the
/// repo's stream-proxy default). `0` disables the idle timeout.
#[cfg(target_os = "linux")]
fn udp_session_idle_timeout(proxy: &crate::config::types::Proxy) -> Option<std::time::Duration> {
    let secs = proxy.udp_idle_timeout_seconds;
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

/// Spawn the idle-session sweep for the capture listener. Reaps each session
/// after its own `idle_timeout_ms` of inactivity (derived from the relay proxy's
/// `udp_idle_timeout_seconds`; `0` = disabled = never idle-reaped) on a fixed
/// interval; exits when the per-listener shutdown fires.
#[cfg(target_os = "linux")]
fn spawn_capture_session_cleanup(
    sessions: std::sync::Arc<
        dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState>,
    >,
    session_limiter: std::sync::Arc<MeshUdpSessionLimiter>,
    mut shutdown: watch::Receiver<bool>,
    cleanup_interval_seconds: u64,
) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(cleanup_interval_seconds.max(1)));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = crate::socket_opts::monotonic_now_ms();
                    // Count reaped sessions so the `active_sessions` cap counter
                    // stays in lockstep with the map. `retain`'s closure is
                    // `FnMut` (called sequentially across shards), so a plain
                    // accumulator is safe; one `fetch_sub` after keeps it lock-free.
                    let mut reaped: u64 = 0;
                    sessions.retain(|_, session| {
                        // Read the SHARED activity clock (codex r3): the egress +
                        // return-path tasks bump it on a delivered datagram in
                        // EITHER direction, so a session whose client is quiet but
                        // whose destination keeps replying is NOT reaped mid-flow
                        // (the watchdog and this sweep now agree on liveness).
                        let last = session.last_activity.load(Ordering::Relaxed);
                        // Honor the session's CONFIGURED idle window (codex r7):
                        // `idle_timeout_ms == 0` means the per-proxy idle is
                        // DISABLED, so the sweep does not idle-reap it (the egress
                        // task's teardown + the session cap bound it, matching the
                        // task watchdog which also never fires when idle is
                        // disabled). A fixed 60s window would otherwise cut a
                        // long-lived quiet flow whose idle is configured > 60s or
                        // disabled, before the watchdog/operator intends.
                        let keep = session.idle_timeout_ms == 0
                            || now.saturating_sub(last) <= session.idle_timeout_ms;
                        if !keep {
                            // Publish the normal outcome before `retain` drops
                            // the sender. The receiver can then distinguish this
                            // cleanup race from a real egress-path failure.
                            session.outcome_signal.mark_idle_timeout();
                            reaped += 1;
                        }
                        keep
                    });
                    session_limiter.release(reaped);
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn stream_port_override_affects_selection(proxy: &crate::config::types::Proxy, port: u16) -> bool {
    let Some(override_config) = proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&port))
    else {
        return false;
    };
    override_config.algorithm.is_some()
        || override_config.hash_on.is_some()
        || override_config.locality_lb_setting.is_some()
}

#[cfg(target_os = "linux")]
fn mesh_stream_port_lane_supported(
    proxy: &crate::config::types::Proxy,
    port: u16,
) -> Result<bool, &'static str> {
    let Some(override_config) = proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&port))
    else {
        return Ok(false);
    };
    match override_config.algorithm {
        Some(crate::config::types::LoadBalancerAlgorithm::LeastLatency) => {
            Err("per-port LEAST_LATENCY requires stream latency accounting")
        }
        _ => Ok(stream_port_override_affects_selection(proxy, port)),
    }
}

/// Non-Linux stub. `IP_TRANSPARENT` and recvmsg cmsg orig-dst recovery are
/// Linux-only; mesh UDP capture is unsupported elsewhere, so the listener logs
/// and returns immediately (the flag is default-off, so this is never reached
/// in a supported deployment).
#[cfg(not(target_os = "linux"))]
pub async fn start_mesh_udp_capture_listener(
    cfg: MeshUdpCaptureConfig,
) -> Result<(), anyhow::Error> {
    // Touch the Stage-4 fields so the non-Linux build doesn't flag them dead
    // (their only real consumer is the Linux listener / egress path).
    let _ = &cfg.state;
    let _ = cfg.max_sessions;
    let _ = cfg.cleanup_interval_seconds;
    let _ = cfg.recvmmsg_batch_size;
    let _ = cfg.session_shard_amount;
    let _ = cfg.shutdown;
    let _ = cfg.global_shutdown;
    // Fire the startup-ready signal before returning: mesh startup's
    // `wait_for_start_signals()` blocks on this listener's `started_tx` even on
    // non-Linux, so dropping the sender unsent would fail startup with a closed
    // oneshot instead of behaving as the documented no-op (codex r1 P3). Mirror
    // the other listener stubs and signal ready, then return.
    if let Some(tx) = cfg.started_tx {
        let _ = tx.send(());
    }
    tracing::warn!(
        addr = %cfg.addr,
        "Mesh UDP capture listener is Linux-only (IP_TRANSPARENT + recvmsg cmsg); not starting"
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Build a test session map sized via the same hot-path helper the
    /// listener uses ([`crate::util::sharding::pool_shard_amount`]). Pass `0`
    /// to auto-size (the production default, which floors at 64); an explicit
    /// override of `1` is invalid for DashMap (it asserts `shard_amount > 1`),
    /// so callers must use `0` or a value the helper rounds up to >= 2.
    fn new_sessions(
        shards: usize,
    ) -> dashmap::DashMap<CaptureSessionKey, CaptureSession, ahash::RandomState> {
        dashmap::DashMap::with_hasher_and_shard_amount(
            ahash::RandomState::default(),
            crate::util::sharding::pool_shard_amount(shards),
        )
    }

    /// A minimal routable egress entry for the keying/cap tests (no live tunnel
    /// is dialed — `admit_or_refresh_session` only stores the entry/channel).
    fn fake_entry() -> std::sync::Arc<crate::router_cache::MeshTcpEgressEntry> {
        let proxy = crate::modes::mesh::mesh_outbound_udp_relay_proxy(
            "default",
            "dns",
            53,
            "__mesh-out-udp-upstream-default-dns-53",
        );
        std::sync::Arc::new(crate::router_cache::MeshTcpEgressEntry {
            upstream_id: "__mesh-out-udp-upstream-default-dns-53".to_string(),
            relay_proxy: std::sync::Arc::new(proxy),
            service_fqdn: "dns.default.svc.cluster.local".to_string(),
        })
    }

    /// `resolve_entry` closure that always routes (returns a fake entry).
    fn routable() -> Option<std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>> {
        Some(fake_entry())
    }

    /// `resolve_entry` closure that never routes (no declared mesh UDP dest).
    fn unroutable() -> Option<std::sync::Arc<crate::router_cache::MeshTcpEgressEntry>> {
        None
    }

    fn key(client: &str, dst: &str) -> CaptureSessionKey {
        CaptureSessionKey {
            client: client.parse().unwrap(),
            orig_dst: dst.parse().unwrap(),
            ingress_ifindex: 0,
        }
    }

    fn proxy_with_override(
        override_config: crate::config::types::ResolvedPortOverride,
    ) -> crate::config::types::Proxy {
        let mut proxy: crate::config::types::Proxy = serde_yaml::from_str(
            r#"
id: mesh-udp-relay
backend_scheme: udp
backend_host: placeholder.local
backend_port: 0
listen_port: 15011
"#,
        )
        .expect("proxy fixture should deserialize");
        proxy.dispatch_port_overrides =
            Some(std::collections::HashMap::from([(53, override_config)]));
        proxy
    }

    #[test]
    fn mesh_udp_stream_port_override_affects_selection_only_for_lb_fields() {
        let timeout_only = proxy_with_override(crate::config::types::ResolvedPortOverride {
            connect_timeout_ms: Some(250),
            ..Default::default()
        });
        assert!(!stream_port_override_affects_selection(&timeout_only, 53));

        let passive_only = proxy_with_override(crate::config::types::ResolvedPortOverride {
            passive_health_check: Some(crate::config::types::PassiveHealthCheck::default()),
            ..Default::default()
        });
        assert!(!stream_port_override_affects_selection(&passive_only, 53));

        let locality = proxy_with_override(crate::config::types::ResolvedPortOverride {
            locality_lb_setting: Some(crate::config::types::UpstreamLocalityLbSetting::default()),
            ..Default::default()
        });
        assert!(stream_port_override_affects_selection(&locality, 53));

        let algorithm = proxy_with_override(crate::config::types::ResolvedPortOverride {
            algorithm: Some(crate::config::types::LoadBalancerAlgorithm::ConsistentHashing),
            ..Default::default()
        });
        assert!(stream_port_override_affects_selection(&algorithm, 53));
    }

    #[test]
    fn mesh_udp_stream_port_lane_rejects_least_latency() {
        let least_latency = proxy_with_override(crate::config::types::ResolvedPortOverride {
            algorithm: Some(crate::config::types::LoadBalancerAlgorithm::LeastLatency),
            ..Default::default()
        });

        assert!(stream_port_override_affects_selection(&least_latency, 53));
        assert!(mesh_stream_port_lane_supported(&least_latency, 53).is_err());
    }

    #[test]
    fn mesh_udp_lb_hash_key_canonicalizes_ipv4_mapped_clients() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x020a));
        let plain = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        assert_eq!(
            mesh_udp_lb_hash_key_for_client_ip(mapped),
            mesh_udp_lb_hash_key_for_client_ip(plain)
        );
        assert_eq!(mesh_udp_lb_hash_key_for_client_ip(plain), "192.0.2.10");

        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10));
        assert_eq!(mesh_udp_lb_hash_key_for_client_ip(ipv6), "2001:db8::a");
    }

    #[test]
    fn unroutable_destination_is_dropped_without_a_slot() {
        // A captured datagram whose orig-dst matches no mesh UDP destination is
        // dropped: no session, no slot consumed (fail closed).
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(1000);
        let outcome = admit_or_refresh_session(
            &sessions,
            &limiter,
            key("10.0.0.5:40000", "1.1.1.1:53"),
            b"q",
            unroutable,
        );
        assert!(matches!(outcome, SessionAdmission::Dropped));
        assert_eq!(sessions.len(), 0);
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn session_keyed_by_client_and_origdst() {
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(1000);
        // Hold the receivers so refreshes' channel sends don't fail (irrelevant
        // to the keying assertions, but keeps the sessions' channels open).
        let mut keepalive = Vec::new();

        // Same client, two distinct destinations ⇒ two sessions.
        for dst in ["10.96.0.10:53", "10.96.0.11:53"] {
            match admit_or_refresh_session(
                &sessions,
                &limiter,
                key("10.0.0.5:40000", dst),
                b"x",
                routable,
            ) {
                SessionAdmission::Admitted { rx, .. } => keepalive.push(rx),
                other => panic!("expected Admitted, got {}", admission_name(&other)),
            }
        }
        assert_eq!(sessions.len(), 2);

        // A second datagram on an existing (client, dst) flow refreshes — no new
        // session.
        let outcome = admit_or_refresh_session(
            &sessions,
            &limiter,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            routable,
        );
        assert!(matches!(outcome, SessionAdmission::Refreshed));
        assert_eq!(sessions.len(), 2);

        // A different client to the same dst is a distinct session.
        match admit_or_refresh_session(
            &sessions,
            &limiter,
            key("10.0.0.6:50000", "10.96.0.10:53"),
            b"x",
            routable,
        ) {
            SessionAdmission::Admitted { rx, .. } => keepalive.push(rx),
            other => panic!("expected Admitted, got {}", admission_name(&other)),
        }
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn host_ingress_interface_scopes_the_session_key() {
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(1000);
        let mut first = key("10.0.0.5:40000", "10.96.0.10:53");
        first.ingress_ifindex = 11;
        let mut second = first;
        second.ingress_ifindex = 12;
        let mut keepalive = Vec::new();

        for session_key in [first, second] {
            match admit_or_refresh_session(&sessions, &limiter, session_key, b"x", routable) {
                SessionAdmission::Admitted { rx, .. } => keepalive.push(rx),
                other => panic!("expected Admitted, got {}", admission_name(&other)),
            }
        }

        assert_eq!(
            sessions.len(),
            2,
            "overlapping tenant source tuples on different ingress interfaces must never share \
             a session or source identity"
        );
    }

    #[test]
    fn first_datagram_new_session_does_not_deadlock() {
        // Regression for codex r1 P1: admitting a fresh flow must not re-enter
        // the DashMap (`len()`) while an entry guard is held — a plain return
        // here is the proof it no longer nests map ops under a guard.
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(64);
        let outcome = admit_or_refresh_session(
            &sessions,
            &limiter,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            routable,
        );
        assert!(matches!(outcome, SessionAdmission::Admitted { .. }));
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn producer_session_removal_releases_every_owned_slot() {
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(4);
        let mut receivers = Vec::new();
        for (client, destination) in [
            ("10.0.0.5:40000", "10.96.0.10:53"),
            ("10.0.0.6:40001", "10.96.0.11:53"),
        ] {
            match admit_or_refresh_session(
                &sessions,
                &limiter,
                key(client, destination),
                b"x",
                routable,
            ) {
                SessionAdmission::Admitted { rx, .. } => receivers.push(rx),
                other => panic!("expected Admitted, got {}", admission_name(&other)),
            }
        }
        assert_eq!(limiter.active_count(), 2);

        remove_all_capture_sessions(&sessions, &limiter);

        assert!(sessions.is_empty());
        assert_eq!(limiter.active_count(), 0);
        drop(receivers);
    }

    #[test]
    fn session_cap_sheds_new_flows_but_serves_existing() {
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(1);

        // Cap of 1: first new flow admitted.
        let first = admit_or_refresh_session(
            &sessions,
            &limiter,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            routable,
        );
        let _rx = match first {
            SessionAdmission::Admitted { rx, .. } => rx,
            other => panic!("expected Admitted, got {}", admission_name(&other)),
        };
        assert_eq!(sessions.len(), 1);

        // Second NEW flow is shed at the cap.
        let second = admit_or_refresh_session(
            &sessions,
            &limiter,
            key("10.0.0.6:40000", "10.96.0.10:53"),
            b"x",
            routable,
        );
        assert!(matches!(second, SessionAdmission::Dropped));
        assert_eq!(sessions.len(), 1);

        // The already-admitted flow is still served (refresh), even at the cap.
        let refreshed = admit_or_refresh_session(
            &sessions,
            &limiter,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            routable,
        );
        assert!(matches!(refreshed, SessionAdmission::Refreshed));
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn shared_limiter_caps_sessions_across_producers() {
        // Ambient runs one capture loop per pod netns, each with its own session
        // map. The limiter is the shared node-wide cap: a flow admitted by one
        // producer must consume the only slot and shed a new flow in another.
        let producer_a = new_sessions(0);
        let producer_b = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(1);

        let first = admit_or_refresh_session(
            &producer_a,
            &limiter,
            key("10.0.0.5:40000", "10.96.0.10:53"),
            b"x",
            routable,
        );
        let _rx = match first {
            SessionAdmission::Admitted { rx, .. } => rx,
            other => panic!("expected Admitted, got {}", admission_name(&other)),
        };

        let second = admit_or_refresh_session(
            &producer_b,
            &limiter,
            key("10.0.0.6:40000", "10.96.0.10:53"),
            b"x",
            routable,
        );

        assert!(matches!(second, SessionAdmission::Dropped));
        assert_eq!(producer_a.len(), 1);
        assert_eq!(producer_b.len(), 0);
        assert_eq!(limiter.active_count(), 1);
    }

    #[test]
    fn egress_enqueue_caps_queued_bytes_not_just_count() {
        // Regression for codex r3: the per-session egress queue is bounded by
        // BYTES, not just datagram count. With the receiver held (nothing
        // drains), enqueues are accepted until the byte budget is exhausted, then
        // dropped — and the byte counter never exceeds the cap nor leaks on a
        // dropped datagram.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(EGRESS_CHANNEL_DEPTH);
        let queued = AtomicUsize::new(0);
        let client: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let dst: SocketAddr = "10.96.0.10:53".parse().unwrap();

        // 1 KiB datagrams: the BYTE cap (256 KiB) bites long before the 1024-
        // datagram COUNT cap, proving the byte bound is what limits memory.
        let chunk = vec![0u8; 1024];
        let cap_in_chunks = EGRESS_CHANNEL_MAX_QUEUED_BYTES / chunk.len();
        for _ in 0..cap_in_chunks {
            enqueue_egress_datagram(&tx, &queued, &chunk, client, dst);
        }
        assert_eq!(
            queued.load(Ordering::Relaxed),
            EGRESS_CHANNEL_MAX_QUEUED_BYTES,
            "queued bytes should fill exactly to the cap"
        );

        // The next datagram would exceed the cap: dropped, counter unchanged.
        enqueue_egress_datagram(&tx, &queued, &chunk, client, dst);
        assert_eq!(
            queued.load(Ordering::Relaxed),
            EGRESS_CHANNEL_MAX_QUEUED_BYTES,
            "an over-cap datagram must be dropped and must not bump the counter"
        );
        assert!(
            queued.load(Ordering::Relaxed) <= EGRESS_CHANNEL_MAX_QUEUED_BYTES,
            "the byte counter must never exceed the cap"
        );
    }

    #[test]
    fn egress_enqueue_releases_bytes_when_channel_closed() {
        // If the egress task is gone (receiver dropped), an enqueue fails and the
        // byte reservation is handed back so the counter does not leak (codex r3).
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(EGRESS_CHANNEL_DEPTH);
        drop(rx); // task gone
        let queued = AtomicUsize::new(0);
        let client: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let dst: SocketAddr = "10.96.0.10:53".parse().unwrap();
        enqueue_egress_datagram(&tx, &queued, b"hello", client, dst);
        assert_eq!(
            queued.load(Ordering::Relaxed),
            0,
            "a closed-channel enqueue must release its byte reservation"
        );
    }

    #[test]
    fn admitted_sessions_get_distinct_identity_tokens() {
        // Two admits for the SAME key (the second after the first is removed)
        // must stamp DISTINCT session_ids, so a teardown carrying the old token
        // can be told apart from the replacement.
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(1000);
        let k = key("10.0.0.5:40000", "10.96.0.10:53");

        let (first_id, _rx1) =
            match admit_or_refresh_session(&sessions, &limiter, k, b"x", routable) {
                SessionAdmission::Admitted { session_id, rx, .. } => (session_id, rx),
                other => panic!("expected Admitted, got {}", admission_name(&other)),
            };
        // Simulate the idle sweep reaping the first session.
        sessions.remove(&k);
        limiter.release(1);

        let (second_id, _rx2) =
            match admit_or_refresh_session(&sessions, &limiter, k, b"x", routable) {
                SessionAdmission::Admitted { session_id, rx, .. } => (session_id, rx),
                other => panic!("expected Admitted, got {}", admission_name(&other)),
            };
        assert_ne!(first_id, second_id, "replacement must get a fresh token");
    }

    #[test]
    fn teardown_does_not_clobber_replacement_session() {
        // Regression for codex r1 P2 (remove-after-replace race): a stale task's
        // teardown carrying the OLD session_id must NOT remove a replacement
        // session that reused the same (client, orig-dst) key, and must NOT
        // decrement the cap counter for it.
        let sessions = new_sessions(0);
        let limiter = MeshUdpSessionLimiter::new(1000);
        let k = key("10.0.0.5:40000", "10.96.0.10:53");

        // Admit the original (session_id A), then simulate the idle sweep
        // reaping it (drop entry + decrement), exactly as the sweep would.
        let old_id = match admit_or_refresh_session(&sessions, &limiter, k, b"x", routable) {
            SessionAdmission::Admitted { session_id, .. } => session_id,
            other => panic!("expected Admitted, got {}", admission_name(&other)),
        };
        sessions.remove(&k);
        limiter.release(1);
        assert_eq!(limiter.active_count(), 0);

        // A new datagram on the same key admits a REPLACEMENT (session_id B).
        let (new_id, _rx) = match admit_or_refresh_session(&sessions, &limiter, k, b"x", routable) {
            SessionAdmission::Admitted { session_id, rx, .. } => (session_id, rx),
            other => panic!("expected Admitted, got {}", admission_name(&other)),
        };
        assert_ne!(old_id, new_id);
        assert_eq!(sessions.len(), 1);
        assert_eq!(limiter.active_count(), 1);

        // The OLD task finally runs its teardown with the stale token: it must be
        // a no-op (replacement survives, counter unchanged).
        remove_session_if_owned(&sessions, &limiter, &k, old_id);
        assert_eq!(sessions.len(), 1, "replacement session must survive");
        assert_eq!(
            limiter.active_count(),
            1,
            "cap counter must not be decremented for the replacement"
        );

        // The replacement's OWN teardown (matching token) removes it and frees
        // the slot.
        remove_session_if_owned(&sessions, &limiter, &k, new_id);
        assert_eq!(sessions.len(), 0);
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn canonicalize_unmaps_v4_mapped_clients_only() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        // An IPv4-mapped-V6 client (how the dual-stack `[::]` socket reports a v4
        // sender) canonicalizes to its plain V4 form, port preserved — so it
        // matches the V4 orig-dst family on the reply path (codex r2 P1).
        let mapped: SocketAddr = "[::ffff:10.0.0.5]:40000".parse().unwrap();
        let canon = canonicalize_socket_addr(mapped);
        assert_eq!(
            canon,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 40000)
        );
        assert!(canon.is_ipv4(), "v4-mapped client must canonicalize to V4");

        // A plain V4 address is unchanged.
        let v4: SocketAddr = "10.0.0.6:50000".parse().unwrap();
        assert_eq!(canonicalize_socket_addr(v4), v4);

        // A genuine IPv6 client is left untouched (NOT a v4-mapped address).
        let v6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            40000,
        );
        assert_eq!(canonicalize_socket_addr(v6), v6);
        assert!(canonicalize_socket_addr(v6).is_ipv6());
    }

    #[test]
    fn egress_transport_branch_selects_by_tag() {
        // The dual-transport branch in `run_udp_egress_session` (#1808, mirroring
        // raw-TCP egress) keys off the target's transport tag, which the
        // materializer stamps mutually-exclusively: an Ambient `mesh.hbone` target
        // takes the HBONE datagram branch; a Sidecar `mesh.mtls` target takes the
        // mesh-mTLS datagram branch; a target with neither tag ends the session.
        // These are the exact predicates the branch evaluates, in order.
        use crate::config::types::UpstreamTarget;
        let target_with = |tags: &[(&str, &str)]| UpstreamTarget {
            host: "10.0.0.9".to_string(),
            port: 53,
            service_port_policy_key: None,
            weight: 1,
            tags: tags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            locality: None,
            path: None,
        };

        let hbone = target_with(&[(crate::proxy::hbone_pool::HBONE_TARGET_TAG, "true")]);
        assert!(crate::proxy::hbone_pool::target_hbone_enabled(&hbone));
        assert!(
            !crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(&hbone),
            "an Ambient mesh.hbone target must NOT take the mesh-mTLS branch"
        );

        let mtls = target_with(&[(crate::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG, "true")]);
        // The HBONE predicate is evaluated FIRST, so a mesh.mtls target must fall
        // through it to reach the mesh-mTLS branch.
        assert!(
            !crate::proxy::hbone_pool::target_hbone_enabled(&mtls),
            "a Sidecar mesh.mtls target must fall through the HBONE branch"
        );
        assert!(crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(
            &mtls
        ));

        // Neither tag → both predicates false → the fail-closed `else` arm.
        let untagged = target_with(&[]);
        assert!(!crate::proxy::hbone_pool::target_hbone_enabled(&untagged));
        assert!(!crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(
            &untagged
        ));

        // BOTH tags → both predicates true. The materializer stamps exactly one
        // transport tag, so a both-tags target is only reachable via a
        // hand-authored / corrupted upstream; the branch is documented
        // PRECEDENCE (not a rejection): `run_udp_egress_session` evaluates
        // `target_hbone_enabled` FIRST, so a both-tags target takes the HBONE
        // branch. That is the safe resolution — a target carrying `mesh.hbone` is
        // an Ambient HBONE target regardless, and HBONE egress is itself
        // identity-pinned + capability-gated, so precedence never relaxes a gate.
        let both = target_with(&[
            (crate::proxy::hbone_pool::HBONE_TARGET_TAG, "true"),
            (crate::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG, "true"),
        ]);
        assert!(crate::proxy::hbone_pool::target_hbone_enabled(&both));
        assert!(crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(
            &both
        ));
    }

    fn admission_name(a: &SessionAdmission) -> &'static str {
        match a {
            SessionAdmission::Refreshed => "Refreshed",
            SessionAdmission::Admitted { .. } => "Admitted",
            SessionAdmission::Dropped => "Dropped",
        }
    }
}

/// Privileged live verification of the mesh UDP **source-capture** path (F3 §3.3
/// Stage 3) against a real netfilter `TPROXY` rule + policy routing, inside a
/// throwaway network namespace (the host's iptables / routing tables are never
/// touched). Runs in CI's `netns-capture-live` job as root with
/// `FERRUM_LIVE_TESTS_REQUIRED=1`, so prerequisite gaps fail there instead of
/// passing as skips. Local ad-hoc runs still self-skip without root / `unshare` /
/// `iptables` / `ip`.
///
/// This is the UDP analogue of `socket_opts::original_dst_live_tests` (which
/// proves the raw-TCP `SO_ORIGINAL_DST` recovery against an iptables `REDIRECT`).
/// UDP differs fundamentally: TPROXY does NOT rewrite the datagram's destination
/// (unlike the TCP REDIRECT model), so the original `service:port` rides a
/// per-datagram `IP_RECVORIGDSTADDR` cmsg rather than a `getsockopt`. The mesh UDP
/// destination relay is already e2e-tested without root; the remaining gap this
/// closes is the live SOURCE-capture path, which needs `CAP_NET_ADMIN` (TPROXY +
/// `IP_TRANSPARENT`) and so cannot run in the unprivileged test matrix.
///
/// ## What this covers
/// - The exact transparent-capture socket the production listener binds
///   (`build_bound_socket`'s `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR` recipe), so a
///   regression in the socket-option recipe surfaces here.
/// - The Stage-2 TPROXY rule + Stage-3 policy-routing shapes
///   (`udp_tproxy_commands_for_family`): an `OUTPUT -j MARK` on pod egress, the
///   fwmark `ip rule` (priority [`crate::capture::TPROXY_ROUTE_RULE_PRIORITY`] →
///   table [`crate::capture::TPROXY_ROUTE_TABLE`]), the `local 0.0.0.0/0 dev lo`
///   route that loops the marked datagram back to the INPUT path, and the
///   PREROUTING mark-match `-j TPROXY --on-port <port> --tproxy-mark <mark>` that
///   reinjects it onto the transparent socket. All constants are read from
///   `src/capture/mod.rs` (NOT hardcoded) so a default change keeps this honest.
/// - The per-datagram orig-dst recovery the listener relies on: a single UDP
///   datagram sent to a *remote* (non-local) destination is captured and the
///   recovered original destination equals what the client dialed — the value
///   `handle_captured_datagram` keys each session by.
/// - That a reply can be SOURCED from the captured original destination on an
///   `IP_TRANSPARENT` socket (`build_transparent_reply_socket`'s recipe), the
///   return-path primitive the egress session uses.
/// - The host-network placement's distinct live boundary: a veth-side datagram
///   re-enters a throwaway host namespace on the peer interface, matches a real
///   `PREROUTING -i <peer> -j TPROXY` rule, reaches the production
///   pktinfo-enabled transparent socket, preserves its original destination, and
///   reports that exact peer ifindex for per-pod attribution. The test also runs
///   the production dedicated-peer sysfs check against the live veth and rejects
///   the self-linked loopback device.
///
/// ## What this does NOT cover (deliberately — a thin smoke test)
/// - No full two-gateway loop: no HBONE / mesh-mTLS tunnel, no egress relay, no
///   destination workload. The async listener task, LB selection, capability
///   gating, and tunnel framing are exercised by the unit tests and the existing
///   root-free destination-relay e2e, not here.
/// - It drains with one `RecvMmsgBatch` (the listener's recv primitive) rather
///   than spinning up `start_mesh_udp_capture_listener`, because the orig-dst
///   recovery + transparent bind is the OS mechanism under test; the async
///   plumbing around it is covered elsewhere.
/// - IPv4 only (the netns gets a single fwmark rule + v4 `local` route); the
///   v6 path shares the same code with a different cmsg level, covered by the
///   unit-level extraction tests.
#[cfg(all(test, target_os = "linux"))]
mod live_netns_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    /// Where the transparent capture listener binds inside the netns (the
    /// production `FERRUM_MESH_CAPTURE_UDP_PORT` shape). Read from
    /// [`crate::capture::DEFAULT_UDP_OUTBOUND_PORT`] so a default change is
    /// reflected automatically.
    const CAPTURE_PORT: u16 = crate::capture::DEFAULT_UDP_OUTBOUND_PORT;
    /// The remote destination the in-netns client dials. A NON-local address so
    /// the `OUTPUT ! --dst-type LOCAL` mark rule matches it (exactly as it would
    /// a real pod dialing a service VIP); TPROXY then delivers it WITHOUT
    /// rewriting this destination, which is what `IP_RECVORIGDSTADDR` recovers.
    const REMOTE_DST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10); // TEST-NET-1 (RFC 5737)
    /// The remote UDP port the client dials; recovered as the captured orig-dst.
    const DIAL_PORT: u16 = 5300;

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
            panic!("required live netns UDP capture test prerequisite missing: {reason}");
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

    /// Spawn a child in a fresh netns with loopback up and the Stage-2/Stage-3
    /// UDP TPROXY datapath installed: pod-egress UDP to a remote dst is MARKed in
    /// `mangle OUTPUT`, the fwmark `ip rule` + `local` route loop it back to the
    /// INPUT path, and a PREROUTING mark-match `-j TPROXY` reinjects it onto the
    /// transparent capture socket on [`CAPTURE_PORT`]. This mirrors the rule set
    /// `crate::capture::udp_tproxy_commands_for_family` emits for a catch-all
    /// outbound config (the `OUTPUT_MARK` + `REINJECT` chains, collapsed to bare
    /// rules for the test). A `default dev lo` route is added FIRST so the initial
    /// route lookup for the remote dst resolves (a bare netns has no such route —
    /// a real pod gets one from its CNI); the marked-packet output reroute then
    /// overrides it with the fwmark rule's local-delivery table. Exits 97 when
    /// `iptables` / `ip` is unavailable inside the netns so local runs can skip
    /// (or required CI can fail); the `set -e` aborts (non-97 exit) if any
    /// load-bearing rule fails to install.
    fn spawn_tproxy_netns_child() -> Option<Child> {
        // Constants pulled from production (NOT hardcoded from memory): a default
        // change in `src/capture/mod.rs` flows through here.
        let mark = crate::capture::DEFAULT_TPROXY_MARK;
        let mask = crate::capture::TPROXY_MARK_MASK;
        let table = crate::capture::TPROXY_ROUTE_TABLE;
        let prio = crate::capture::TPROXY_ROUTE_RULE_PRIORITY;
        let mark_arg = format!("0x{mark:x}/0x{mask:x}");
        // A default route via `lo` so the INITIAL `ip_route_output` for the
        // remote dst succeeds (a bare netns has only `lo` up and no route to the
        // TEST-NET dst, so `send_to` would fail ENETUNREACH BEFORE the mangle
        // OUTPUT chain ever runs). This route only needs to make the first lookup
        // resolve; once the OUTPUT MARK fires, the marked-packet output reroute
        // (`ip_route_me_harder`) consults the higher-priority fwmark `ip rule`
        // and steers the datagram to table {table}'s `local 0.0.0.0/0 dev lo`
        // for local delivery instead — exactly the production reroute path. A
        // real pod gets this initial route from its CNI default route.
        let script = format!(
            // Exit-code discipline (codex #1823 review): `exit 97` == a genuine
            // missing PREREQUISITE (no `iptables`/`ip` binary) → the test SKIPS.
            // `exit 98` == a LOAD-BEARING route / fwmark-rule / `-j TPROXY` rule
            // failed to install (e.g. a missing `xt_TPROXY` target or a
            // mangle-table error on the CI kernel) → the test FAILS, because the
            // capture path it exists to validate would otherwise pass vacuously.
            "set -e; \
             command -v iptables >/dev/null 2>&1 || exit 97; \
             command -v ip >/dev/null 2>&1 || exit 97; \
             ip link set lo up 2>/dev/null || true; \
             ip route add default dev lo || exit 98; \
             ip rule add priority {prio} fwmark {mark_arg} lookup {table} || exit 98; \
             ip route add local 0.0.0.0/0 dev lo table {table} || exit 98; \
             iptables -t mangle -A OUTPUT -p udp -m addrtype ! --dst-type LOCAL \
               -j MARK --set-mark {mark_arg} || exit 98; \
             iptables -t mangle -A PREROUTING -p udp -m mark --mark {mark_arg} \
               -j TPROXY --on-port {CAPTURE_PORT} --tproxy-mark {mark_arg} || exit 98; \
             exec sleep 30"
        );
        Command::new("unshare")
            .args(["--net", "sh", "-c", &script])
            .spawn()
            .ok()
    }

    /// Spawn a throwaway host-shaped network + mount namespace with both ends of
    /// a veth pair in that network namespace. The private sysfs mount is
    /// load-bearing: a sysfs superblock is bound to the network namespace it was
    /// mounted from, so the runner's original `/sys` cannot expose a veth created
    /// after `unshare --net`. The parent reaches this mount through
    /// `/proc/<pid>/root/sys` when it exercises the production sysfs validator.
    ///
    /// A locally generated client datagram leaves `pod0`, re-enters through its
    /// peer `vethhost`, and therefore traverses the same
    /// `mangle PREROUTING -i <pod host interface>` hook as real pod egress. The
    /// host-network capture rule then TPROXY-delivers it to the production
    /// transparent socket while preserving both the original destination and
    /// the ingress-interface pktinfo cmsg.
    fn spawn_host_tproxy_veth_child() -> Option<Child> {
        let mark = crate::capture::DEFAULT_TPROXY_MARK;
        let mask = crate::capture::TPROXY_MARK_MASK;
        let table = crate::capture::TPROXY_HOST_ROUTE_TABLE;
        let prio = crate::capture::TPROXY_HOST_ROUTE_RULE_PRIORITY;
        let mark_arg = format!("0x{mark:x}/0x{mask:x}");
        // Pin the host peer's locally administered MAC before bringing it up so
        // neighbour setup uses an explicit fixture value rather than consulting
        // sysfs while the namespace is still being assembled. The scenario
        // separately validates the production sysfs lookup through the child's
        // namespace-local mount after the exact readiness marker is observed.
        // Both veth ends intentionally live in this one throwaway namespace, so
        // the packet entering `vethhost` has a source address locally assigned
        // to `pod0`. Disable reverse-path filtering before sending it; otherwise
        // a strict runner default can discard that fixture-only local-source
        // shape before PREROUTING. Real host-veth capture has the pod address
        // routed back through the same peer, and the repository's other live
        // veth harness likewise makes the rp_filter prerequisite explicit.
        let script = format!(
            "set -e; \
             command -v iptables >/dev/null 2>&1 || exit 97; \
             command -v ip >/dev/null 2>&1 || exit 97; \
             command -v mount >/dev/null 2>&1 || exit 97; \
             mount -t sysfs sysfs /sys || exit 98; \
             ip link set lo up 2>/dev/null || true; \
             ip link add pod0 type veth peer name vethhost || exit 98; \
             ip link set vethhost address 02:00:00:00:00:01 || exit 98; \
             ip link set pod0 up || exit 98; \
             ip link set vethhost up || exit 98; \
             ip address add 10.0.0.2/32 dev pod0 || exit 98; \
             printf '0\n' > /proc/sys/net/ipv4/conf/all/rp_filter || exit 98; \
             printf '0\n' > /proc/sys/net/ipv4/conf/vethhost/rp_filter || exit 98; \
             printf '1\n' > /proc/sys/net/ipv4/conf/vethhost/accept_local || exit 98; \
             ip neigh add {REMOTE_DST} lladdr 02:00:00:00:00:01 dev pod0 nud permanent || exit 98; \
             ip route add {REMOTE_DST}/32 dev pod0 src 10.0.0.2 || exit 98; \
             ip rule add priority {prio} fwmark {mark_arg} lookup {table} || exit 98; \
             ip route add local 0.0.0.0/0 dev lo table {table} || exit 98; \
             iptables -t mangle -A PREROUTING -i vethhost -p udp \
               -j TPROXY --on-port {CAPTURE_PORT} --tproxy-mark {mark_arg} || exit 98; \
             exec sleep 30"
        );
        Command::new("unshare")
            .args([
                "--mount",
                "--net",
                "--propagation",
                "private",
                "sh",
                "-c",
                &script,
            ])
            .spawn()
            .ok()
    }

    /// Build the transparent capture socket EXACTLY as the production listener's
    /// `build_bound_socket` does (`SO_REUSEADDR` + `IP_TRANSPARENT` +
    /// `IP_RECVORIGDSTADDR`, options before bind), bound to the v4 wildcard on
    /// `CAPTURE_PORT`. Returns the bound std socket so the test can drain it with
    /// the listener's own `RecvMmsgBatch` primitive.
    fn build_capture_socket() -> Result<std::net::UdpSocket, String> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| format!("socket: {e}"))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| format!("SO_REUSEADDR: {e}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("set_nonblocking: {e}"))?;
        let fd = socket.as_raw_fd();
        crate::socket_opts::set_ip_transparent(fd).map_err(|e| format!("IP_TRANSPARENT: {e}"))?;
        crate::socket_opts::set_ip_recvorigdstaddr(fd)
            .map_err(|e| format!("IP_RECVORIGDSTADDR: {e}"))?;
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), CAPTURE_PORT);
        socket
            .bind(&bind_addr.into())
            .map_err(|e| format!("bind {bind_addr}: {e}"))?;
        Ok(socket.into())
    }

    #[test]
    #[ignore = "requires root + iptables/TPROXY + iproute2 to capture UDP in a fresh netns"]
    fn captured_udp_recovers_pre_tproxy_destination() {
        if !is_root() {
            skip_or_fail("not root; cannot create network namespaces / TPROXY rules");
            return;
        }
        let Some(mut child) = spawn_tproxy_netns_child() else {
            skip_or_fail("`unshare --net` unavailable");
            return;
        };
        // Let the child unshare, bring loopback up, and install the TPROXY +
        // policy-routing datapath, then `exec sleep 30` (stays alive). If it
        // EXITS during setup, branch on the exit code: 97 == a missing
        // prerequisite (no iptables/ip binary) → SKIP; anything else (98 == a
        // load-bearing route/fwmark/TPROXY rule failed) → FAIL, so a broken
        // capture setup never passes vacuously (codex #1823). `try_wait` rather
        // than `kill(pid, 0)`: an exited-but-unreaped child is a zombie that
        // still answers signal 0, which would wrongly run the scenario in a
        // namespace without the rules.
        let mut setup_exit: Option<std::process::ExitStatus> = None;
        let mut setup_status_unknown = false;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(50));
            match child.try_wait() {
                Ok(Some(status)) => {
                    setup_exit = Some(status);
                    break;
                }
                Err(_) => {
                    setup_status_unknown = true;
                    break;
                }
                Ok(None) => {}
            }
        }
        if let Some(status) = setup_exit {
            // ONLY exit 98 is a load-bearing failure: it is emitted by the script
            // ITSELF, which means `unshare --net` created the netns and `sh` ran,
            // but a route / fwmark / `-j TPROXY` rule failed to install — a real
            // break in the path under test → FAIL (don't pass vacuously). Every
            // other exit is an ENVIRONMENTAL prerequisite the live job can't meet
            // → local SKIP / required-mode failure: 97 = no `iptables`/`ip`
            // binary; anything else means the script never ran (e.g.
            // `unshare --net` exits 1 without CAP_SYS_ADMIN, or `sh`/`unshare`
            // missing → 127), so no netns or UDP capture was exercised.
            // (codex #1823 r1 + r2)
            if status.code() == Some(98) {
                panic!(
                    "netns UDP TPROXY setup failed (exit 98): a load-bearing policy-route / \
                     fwmark-rule / `-j TPROXY` rule did not install, so the capture path was \
                     NOT exercised — failing rather than skipping vacuously"
                );
            }
            skip_or_fail(&format!(
                "netns/capture prerequisites unavailable (setup child exited {:?}: \
                     `unshare --net` denied, or no iptables/ip binary)",
                status.code()
            ));
            return;
        }
        if setup_status_unknown {
            // `try_wait` errored — an environmental ambiguity reading the child,
            // NOT a confirmed load-bearing failure → skip rather than fail.
            skip_or_fail("could not determine netns setup-child status (try_wait errored)");
            return;
        }
        let pid = child.id();
        let _guard = ChildGuard(child);

        // Everything runs on one throwaway thread inside the child's netns
        // (`setns` mutates only the calling thread, which exits right after).
        let recovered = std::thread::spawn(move || -> Result<Option<SocketAddr>, String> {
            let ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
                .map_err(|e| format!("open netns handle: {e}"))?;
            // Safety: `ns` is an open netns handle owned for the call.
            if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return Err(format!("setns failed: {}", std::io::Error::last_os_error()));
            }

            // Bind the production transparent capture socket inside the netns.
            let capture = build_capture_socket()?;
            let capture_fd = capture.as_raw_fd();

            // Client datagram to a REMOTE dst. The MARK rule matches (non-local
            // dst), the fwmark route loops it to `lo`, and the PREROUTING
            // mark-match TPROXY reinjects it onto the transparent socket WITHOUT
            // rewriting REMOTE_DST:DIAL_PORT — which IP_RECVORIGDSTADDR recovers.
            // A wildcard-bound (ephemeral-port) client is fine: the captured
            // value under test is the ORIGINAL DESTINATION, not the source.
            let client = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .map_err(|e| format!("bind client: {e}"))?;
            let dst = SocketAddr::new(IpAddr::V4(REMOTE_DST), DIAL_PORT);
            client
                .send_to(b"capture-me", dst)
                .map_err(|e| format!("client send_to {dst}: {e}"))?;

            // Drain via the listener's own cmsg-aware recv primitive
            // (`MSG_DONTWAIT`), polling for a short window since the reroute +
            // reinject is asynchronous to the send.
            let mut batch = super::super::udp_batch::RecvMmsgBatch::new(8, true);
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match batch.recv(capture_fd, 8) {
                    Ok(n) if n > 0 => {
                        // A datagram landed on the capture socket; return its
                        // recovered original destination (the value the listener
                        // keys each session by).
                        return Ok(batch.orig_dst(0));
                    }
                    _ => {
                        if Instant::now() >= deadline {
                            return Err("capture socket received no datagram within the deadline \
                                 (TPROXY did not reinject the marked datagram)"
                                .to_string());
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        })
        .join()
        .expect("netns capture scenario thread must not panic")
        .expect("live UDP TPROXY capture scenario must complete");

        assert_eq!(
            recovered,
            Some(SocketAddr::new(IpAddr::V4(REMOTE_DST), DIAL_PORT)),
            "a TPROXY-captured datagram must recover its pre-TPROXY (original) \
             destination from the IP_RECVORIGDSTADDR cmsg"
        );

        run_host_veth_capture_scenario();
    }

    /// Exercise the host-network veth-ingress capture boundary as the second
    /// half of [`captured_udp_recovers_pre_tproxy_destination`]. Keeping both
    /// scenarios in one ignored test preserves the trusted hosted live-test
    /// count while extending that test's datapath coverage.
    fn run_host_veth_capture_scenario() {
        if !is_root() {
            skip_or_fail("not root; cannot create a veth / TPROXY namespace");
            return;
        }
        let Some(mut child) = spawn_host_tproxy_veth_child() else {
            skip_or_fail("`unshare --net` unavailable");
            return;
        };

        let pid = child.id();
        let mut setup_exit: Option<std::process::ExitStatus> = None;
        let mut setup_status_unknown = false;
        let mut setup_ready = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(50));
            match child.try_wait() {
                Ok(Some(status)) => {
                    setup_exit = Some(status);
                    break;
                }
                Err(_) => {
                    setup_status_unknown = true;
                    break;
                }
                Ok(None) => {
                    // The setup script ends with `exec sleep 30`; seeing that
                    // executable is an exact readiness signal that the private
                    // sysfs mount, veth, routes, sysctl, and TPROXY rule all
                    // completed. Merely seeing the child alive races the setup
                    // sequence on a loaded host.
                    setup_ready = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .is_ok_and(|comm| comm.trim() == "sleep");
                    if setup_ready {
                        break;
                    }
                }
            }
        }
        if let Some(status) = setup_exit {
            if status.code() == Some(98) {
                panic!(
                    "host-veth UDP TPROXY setup failed (exit 98): the private sysfs mount, veth, \
                     route, fwmark, or interface-scoped TPROXY rule did not install"
                );
            }
            skip_or_fail(&format!(
                "host-veth capture prerequisites unavailable (setup child exited {:?})",
                status.code()
            ));
            return;
        }
        if setup_status_unknown {
            let _ = child.kill();
            let _ = child.wait();
            skip_or_fail("could not determine host-veth setup-child status");
            return;
        }
        if !setup_ready {
            let _ = child.kill();
            let _ = child.wait();
            skip_or_fail("host-veth setup did not reach its steady-state readiness marker");
            return;
        }
        let _guard = ChildGuard(child);

        // `/proc/<pid>/root` resolves through the child's private mount
        // namespace, whose `/sys` was mounted after entering its new network
        // namespace. Reading the runner's own `/sys/class/net` here would always
        // inspect the original network namespace, even after a thread-level
        // `setns`, and would make the live validator fail for the wrong reason.
        let child_sysfs = std::path::PathBuf::from(format!("/proc/{pid}/root/sys/class/net"));
        let expected_ifindex =
            super::super::host_udp_capture::dedicated_host_ifindex(&child_sysfs, "vethhost")
                .unwrap_or_else(|error| panic!("validate live host-side veth: {error}"));
        if super::super::host_udp_capture::dedicated_host_ifindex(&child_sysfs, "lo").is_ok() {
            panic!("self-linked loopback device passed the dedicated-peer check");
        }

        let observed = std::thread::spawn(move || -> Result<_, String> {
            let ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
                .map_err(|e| format!("open host-shaped netns handle: {e}"))?;
            // Safety: `ns` is an open netns handle owned for this throwaway
            // thread, which exits without returning to the test runtime.
            if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return Err(format!("setns failed: {}", std::io::Error::last_os_error()));
            }

            let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), CAPTURE_PORT);
            let (capture, _, v4_origdst, _) =
                super::bind_mesh_udp_capture_socket_with_pktinfo(bind, true)
                    .map_err(|error| format!("bind production host capture socket: {error}"))?;
            if !v4_origdst {
                return Err("production socket did not enable IPv4 orig-dst recovery".to_string());
            }
            let capture_fd = capture.as_raw_fd();

            let client = std::net::UdpSocket::bind("10.0.0.2:0")
                .map_err(|error| format!("bind veth-side client: {error}"))?;
            let dst = SocketAddr::new(IpAddr::V4(REMOTE_DST), DIAL_PORT);
            client
                .send_to(b"host-veth-capture", dst)
                .map_err(|error| format!("send veth-side datagram to {dst}: {error}"))?;

            let mut batch = super::super::udp_batch::RecvMmsgBatch::new(8, true);
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match batch.recv(capture_fd, 8) {
                    Ok(n) if n > 0 => {
                        let (payload, source) = batch.datagram(0);
                        let local = batch.local_addr(0).ok_or_else(|| {
                            "captured datagram carried no IP_PKTINFO cmsg".to_string()
                        })?;
                        return Ok((
                            payload.to_vec(),
                            source,
                            batch.orig_dst(0),
                            local.ifindex,
                            expected_ifindex,
                        ));
                    }
                    _ if Instant::now() >= deadline => {
                        return Err(
                            "host capture socket received no veth-ingress datagram within the \
                             deadline"
                                .to_string(),
                        );
                    }
                    _ => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        })
        .join()
        .expect("host-veth capture scenario thread must not panic")
        .expect("live host-veth UDP capture scenario must complete");

        assert_eq!(observed.0, b"host-veth-capture");
        assert_eq!(observed.1.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(
            observed.2,
            Some(SocketAddr::new(IpAddr::V4(REMOTE_DST), DIAL_PORT)),
            "the host capture socket must recover the pre-TPROXY destination"
        );
        assert_eq!(
            observed.3, observed.4,
            "IP_PKTINFO must report the pod's host-side ingress interface, which is the \
             production attribution key"
        );
    }

    #[test]
    #[ignore = "requires root + CAP_NET_ADMIN for IP_TRANSPARENT non-local bind in a fresh netns"]
    fn reply_socket_binds_non_local_captured_destination() {
        // The return-path primitive: a reply to the captured client must be
        // SOURCED from the captured original destination (the VIP:port the pod
        // dialed), which requires an IP_TRANSPARENT socket bound NON-LOCALLY to
        // that address. This exercises `build_transparent_reply_socket`'s exact
        // recipe (SO_REUSEADDR + IP_TRANSPARENT + non-local bind) against a real
        // kernel inside the netns — proving the bind the egress return path
        // depends on actually succeeds with CAP_NET_ADMIN.
        if !is_root() {
            skip_or_fail("not root; IP_TRANSPARENT non-local bind needs CAP_NET_ADMIN");
            return;
        }
        // A plain `unshare --net` (loopback up) is enough — no iptables needed,
        // only CAP_NET_ADMIN for the transparent non-local bind. Skip if unshare
        // is unavailable.
        let Some(mut child) = Command::new("unshare")
            .args([
                "--net",
                "sh",
                "-c",
                "ip link set lo up 2>/dev/null || true; exec sleep 30",
            ])
            .spawn()
            .ok()
        else {
            skip_or_fail("`unshare --net` unavailable");
            return;
        };
        // Confirm the netns child is alive (did not immediately fail).
        std::thread::sleep(Duration::from_millis(200));
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            skip_or_fail("netns child exited before setup completed");
            let _ = child.wait();
            return;
        }
        let pid = child.id();
        let _guard = ChildGuard(child);

        let bound = std::thread::spawn(move || -> Result<SocketAddr, String> {
            let ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
                .map_err(|e| format!("open netns handle: {e}"))?;
            if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return Err(format!("setns failed: {}", std::io::Error::last_os_error()));
            }
            // Mirror `build_transparent_reply_socket` for a NON-LOCAL captured
            // destination (TEST-NET-1 — never assigned to `lo`, so the bind only
            // succeeds because IP_TRANSPARENT permits binding a non-local addr).
            let orig_dst = SocketAddr::new(IpAddr::V4(REMOTE_DST), DIAL_PORT);
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .map_err(|e| format!("socket: {e}"))?;
            socket
                .set_reuse_address(true)
                .map_err(|e| format!("SO_REUSEADDR: {e}"))?;
            socket
                .set_nonblocking(true)
                .map_err(|e| format!("set_nonblocking: {e}"))?;
            crate::socket_opts::set_ip_transparent(socket.as_raw_fd())
                .map_err(|e| format!("IP_TRANSPARENT: {e}"))?;
            socket
                .bind(&orig_dst.into())
                .map_err(|e| format!("non-local transparent bind {orig_dst}: {e}"))?;
            let std_sock: std::net::UdpSocket = socket.into();
            std_sock
                .local_addr()
                .map_err(|e| format!("local_addr: {e}"))
        })
        .join()
        .expect("transparent reply-bind thread must not panic")
        .expect("IP_TRANSPARENT non-local bind must succeed under CAP_NET_ADMIN");

        assert_eq!(
            bound,
            SocketAddr::new(IpAddr::V4(REMOTE_DST), DIAL_PORT),
            "a transparent reply socket must bind the captured (non-local) original \
             destination so pod replies are sourced from the VIP:port it dialed"
        );
    }
}
