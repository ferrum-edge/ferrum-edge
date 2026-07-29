//! Shared types between Ferrum eBPF programs and userspace loader.
//!
//! All types are `#[repr(C)]` for BPF map compatibility and `Copy` since BPF
//! maps operate on raw bytes. Fields use fixed-width integers aligned to 4-byte
//! boundaries (BPF verifier requirement).

#![no_std]

/// Key for the `FERRUM_ORIG_DST4` / `FERRUM_ORIG_DST6` maps.
///
/// Uses `bpf_get_socket_cookie()` rather than a connection tuple because the
/// local port is not assigned at `connect()` time — the kernel picks it during
/// the syscall after the BPF hook runs. The proxy retrieves the cookie via
/// `getsockopt(SO_COOKIE)` to look up the original destination.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrigDstKey {
    pub cookie: u64,
}

/// Original IPv4 destination stored before connect rewrite.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrigDst4 {
    pub addr: u32,
    pub port: u32,
    /// Kubernetes pod UID encoded as raw UUID bytes. Zero means "unknown" and
    /// must be treated as fail-closed by node-waypoint identity resolution.
    pub pod_uid: [u8; 16],
    /// Stable first-eight-bytes SHA-256 hash of the workload SPIFFE ID.
    /// Zero means the node-agent did not attach a hash for this socket.
    pub workload_spiffe_hash: u64,
}

/// Original IPv6 destination stored before connect rewrite.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrigDst6 {
    pub addr: [u32; 4],
    pub port: u32,
    pub _pad: u32,
    /// Kubernetes pod UID encoded as raw UUID bytes. Zero means "unknown" and
    /// must be treated as fail-closed by node-waypoint identity resolution.
    pub pod_uid: [u8; 16],
    /// Stable first-eight-bytes SHA-256 hash of the workload SPIFFE ID.
    /// Zero means the node-agent did not attach a hash for this socket.
    pub workload_spiffe_hash: u64,
}

/// IPv4 connection 4-tuple key for the accept-side cookie bridge (GAP-2M),
/// used by `FERRUM_ORIG_DST_BY_TUPLE4`.
///
/// The connect hook stamps `FERRUM_ORIG_DST4` under the *connecting* socket's
/// cookie, but the node-waypoint proxy resolves by the *accepted* server-side
/// socket's cookie — a different kernel socket. The `sock_ops` program bridges
/// the two: at active-established it re-keys the record by this tuple, and at
/// passive-established it looks the tuple up and re-stamps the record under the
/// accept-side cookie. Both callbacks must compute an identical key, so:
///
/// - `netns_cookie` (`bpf_get_netns_cookie`) disambiguates pods, and is the
///   load-bearing part of the preferred key. Every captured connection is
///   rewritten to `127.0.0.1:15001`, so `client_addr`/`server_addr` collapse to
///   loopback and only the ephemeral `client_port` varies — and ephemeral ports
///   are per-netns, so two pods can present the *same* 4-tuple into this one
///   global map. The exact netns key stops one pod's record from overwriting
///   another's. The sock-ops program may also publish a best-effort
///   `netns_cookie = 0` fallback for kernels where the passive callback reports
///   the accepting task's netns rather than the accepted socket's workload
///   netns; the proxy must validate the accepted record against the pod-specific
///   in-netns listener before admitting the connection.
/// - `client_addr` / `server_addr` are kept in **network byte order** (the
///   kernel stores `local_ip4` / `remote_ip4` that way on both sides).
/// - `client_port` / `server_port` are normalized to **host byte order** (see
///   [`sock_ops_peer_port_host_order`]).
///
/// "client" is the originating pod socket; "server" is the loopback capture
/// endpoint (127.0.0.1:15001). `_pad` keeps `netns_cookie` 8-byte aligned with
/// no implicit padding, so the map-key bytes are fully defined.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnTuple4 {
    pub client_addr: u32,
    pub server_addr: u32,
    pub client_port: u16,
    pub server_port: u16,
    pub _pad: u32,
    pub netns_cookie: u64,
}

impl ConnTuple4 {
    pub const fn new(
        netns_cookie: u64,
        client_addr: u32,
        client_port: u16,
        server_addr: u32,
        server_port: u16,
    ) -> Self {
        Self {
            client_addr,
            server_addr,
            client_port,
            server_port,
            _pad: 0,
            netns_cookie,
        }
    }

    /// Same connection tuple with the netns discriminator removed. Used only as
    /// a secondary bridge key on live kernels whose sock-ops passive callback
    /// reports the accepting task's netns instead of the accepted socket's
    /// workload netns; userspace still validates the resolved pod UID against
    /// the listener's expected pod before admitting traffic.
    pub const fn any_netns(self) -> Self {
        Self {
            client_addr: self.client_addr,
            server_addr: self.server_addr,
            client_port: self.client_port,
            server_port: self.server_port,
            _pad: 0,
            netns_cookie: 0,
        }
    }
}

/// IPv6 connection 4-tuple key for the accept-side cookie bridge (GAP-2M).
/// Mirrors [`ConnTuple4`] (including the `netns_cookie` pod discriminator); the
/// `sock_ops` bridge handles this key for captured IPv6 loopback connections.
/// `_pad` keeps `netns_cookie` 8-byte aligned with no implicit padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnTuple6 {
    pub client_addr: [u32; 4],
    pub server_addr: [u32; 4],
    pub client_port: u16,
    pub server_port: u16,
    pub _pad: u32,
    pub netns_cookie: u64,
}

impl ConnTuple6 {
    pub const fn new(
        netns_cookie: u64,
        client_addr: [u32; 4],
        client_port: u16,
        server_addr: [u32; 4],
        server_port: u16,
    ) -> Self {
        Self {
            client_addr,
            server_addr,
            client_port,
            server_port,
            _pad: 0,
            netns_cookie,
        }
    }

    /// Same connection tuple with the netns discriminator removed. See
    /// [`ConnTuple4::any_netns`] for the live-kernel compatibility rationale.
    pub const fn any_netns(self) -> Self {
        Self {
            client_addr: self.client_addr,
            server_addr: self.server_addr,
            client_port: self.client_port,
            server_port: self.server_port,
            _pad: 0,
            netns_cookie: 0,
        }
    }
}

/// Pod metadata in the `FERRUM_POD_IPS` map, keyed by IPv4 address (`u32`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodInfo {
    pub proxy_port: u32,
    /// Per-pod capture lifecycle flags. Kept in the existing second word so the
    /// map ABI remains eight bytes.
    pub capture_flags: u32,
}

pub const POD_CAPTURE_FLAG_UDP_ENABLED: u32 = 1 << 0;
pub const POD_CAPTURE_FLAG_UDP_READY: u32 = 1 << 1;
/// Per-pod opt-in for the NodeWaypoint inbound tc ingress redirect.
///
/// Set by the node-agent only for a pod that is fully enrolled for NodeWaypoint
/// inbound capture: its identity is known, its inbound application ports are
/// installed in `FERRUM_POD_INBOUND_PORTS` / `FERRUM_POD_INBOUND_PORTS6`, and
/// the destination NodeWaypoint relay is the authorized owner of its inbound
/// traffic. The tc ingress program redirects nothing for a pod without this
/// flag, so an un-enrolled or partially-enrolled pod is never captured.
pub const POD_CAPTURE_FLAG_INBOUND_REDIRECT: u32 = 1 << 2;

impl PodInfo {
    pub const fn udp_capture_not_ready(&self) -> bool {
        self.capture_flags & POD_CAPTURE_FLAG_UDP_ENABLED != 0
            && self.capture_flags & POD_CAPTURE_FLAG_UDP_READY == 0
    }

    /// `true` when this pod opted in to the inbound tc ingress redirect.
    pub const fn inbound_redirect_enabled(&self) -> bool {
        self.capture_flags & POD_CAPTURE_FLAG_INBOUND_REDIRECT != 0
    }
}

/// Key for `FERRUM_POD_INBOUND_PORTS`: an enrolled pod IPv4 address (network
/// byte order) plus one inbound TCP application port that the NodeWaypoint
/// relay is authorized to terminate on that pod's behalf.
///
/// The tc ingress redirect requires an exact `(pod address, destination port)`
/// hit, so redirection is scoped to the ports the workload actually declares.
/// Traffic to an enrolled pod on an undeclared port is left to the existing
/// direct-pod guard and is never steered into the waypoint.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundRedirectKey4 {
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

impl InboundRedirectKey4 {
    pub const fn new(addr: u32, port: u16) -> Self {
        Self {
            addr,
            port,
            _pad: 0,
        }
    }
}

/// IPv6 counterpart to [`InboundRedirectKey4`].
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundRedirectKey6 {
    pub addr: [u32; 4],
    pub port: u16,
    pub _pad: u16,
}

impl InboundRedirectKey6 {
    pub const fn new(addr: [u32; 4], port: u16) -> Self {
        Self {
            addr,
            port,
            _pad: 0,
        }
    }
}

/// What `ferrum_tc_ingress_redirect` must do with one inbound packet.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressRedirectAction {
    /// Out of scope. Return the packet untouched (`TC_ACT_OK`) and leave the
    /// pre-existing direct-pod guard as the only inbound control.
    Pass = 0,
    /// In scope. Steer the packet into the local NodeWaypoint relay with
    /// `bpf_sk_assign()`, or **drop** it if no relay socket resolves — never
    /// deliver an in-scope packet to the pod unredirected.
    Steer = 1,
}

impl IngressRedirectAction {
    pub const fn is_steer(self) -> bool {
        matches!(self, Self::Steer)
    }
}

/// The per-packet facts the redirect decision is made from. Deliberately a
/// plain value type with no kernel dependencies so the decision table can be
/// exercised deterministically from host-side unit tests — the kernel program
/// only parses the packet and looks maps up, it does not re-implement policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressRedirectPacket {
    /// `skb->mark` as it arrived.
    pub skb_mark: u32,
    /// TCP destination port in host byte order.
    pub dst_port: u16,
    /// `true` when the IP payload is TCP. `bpf_sk_assign()` is TCP-only here,
    /// so anything else passes.
    pub protocol_is_tcp: bool,
    /// `true` when the destination address is an enrolled pod carrying
    /// [`POD_CAPTURE_FLAG_INBOUND_REDIRECT`]. Proof of verified ownership: the
    /// node-agent sets the flag only for a pod whose identity it resolved and
    /// whose inbound ports it already installed.
    pub destination_pod_opted_in: bool,
    /// `true` when `(destination address, dst_port)` is present in
    /// `FERRUM_POD_INBOUND_PORTS` / `FERRUM_POD_INBOUND_PORTS6`.
    pub destination_port_declared: bool,
    /// `true` when the datagram is an IPv4 fragment (More-Fragments set, or a
    /// non-zero fragment offset), or an IPv6 packet carrying a fragment /
    /// extension header.
    ///
    /// A fragmented datagram has **no trustworthy L4 header**: only the first
    /// fragment carries the TCP ports at all, and a *non-first* fragment's
    /// payload begins with arbitrary application bytes that would be read as
    /// ports. Redirecting (or dropping) on those bytes would steer an unrelated
    /// flow, so a fragment is always [`IngressRedirectAction::Pass`] — the
    /// pre-existing direct-pod guard stays its only inbound control.
    pub fragmented: bool,
}

impl IngressRedirectPacket {
    /// A packet that is in scope on every axis. Tests flip one field at a time
    /// off this baseline so a new gate cannot be added without a test noticing.
    pub const fn fully_in_scope(dst_port: u16) -> Self {
        Self {
            skb_mark: 0,
            dst_port,
            protocol_is_tcp: true,
            destination_pod_opted_in: true,
            destination_port_declared: true,
            fragmented: false,
        }
    }
}

/// `true` when an IPv4 header's flags/fragment-offset word describes a
/// **fragment** whose L4 ports must not be read.
///
/// `word` is the third 16-bit field of the IPv4 header (offset 6) in **host**
/// byte order. Bit 13 (`0x2000`) is More-Fragments; bits 0..12 (`0x1fff`) are
/// the fragment offset. Either being set means this datagram is one piece of a
/// larger one:
///
/// * offset `!= 0` — a non-first fragment. Its payload starts with arbitrary
///   application bytes, so "the TCP ports" read at `IHL` are attacker-chosen
///   data that can be made to match any declared `(pod, port)` pair.
/// * offset `== 0` with More-Fragments — the first fragment. Its ports ARE
///   real, but its successors will not be redirected, so steering it would
///   split one datagram across two destinations.
///
/// Declining both is the only answer that never misattributes a packet, which
/// is why this is a shared predicate rather than an inline kernel branch: the
/// classifier and the host-side tests evaluate the same function.
pub const fn ipv4_is_fragment(word: u16) -> bool {
    const MORE_FRAGMENTS: u16 = 0x2000;
    const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
    word & MORE_FRAGMENTS != 0 || word & FRAGMENT_OFFSET_MASK != 0
}

/// The single source of truth for the inbound tc redirect decision.
///
/// Every gate is a conjunction, so the kernel program may evaluate them in any
/// order (it short-circuits the cheap mark/port guards before spending a map
/// lookup) without diverging from this table:
///
/// `Steer` ⟺ armed ∧ TCP ∧ ¬fragmented ∧ ¬bypass ∧ pod opted in ∧ port declared.
pub const fn ingress_redirect_action(
    config: &BpfCaptureConfig,
    packet: &IngressRedirectPacket,
) -> IngressRedirectAction {
    if !config.ingress_redirect_armed() {
        return IngressRedirectAction::Pass;
    }
    if !packet.protocol_is_tcp {
        return IngressRedirectAction::Pass;
    }
    // Ordered BEFORE every scope gate: a fragment's "ports" may be arbitrary
    // payload bytes, so it must not reach a decision that could drop it as the
    // wrong flow either.
    if packet.fragmented {
        return IngressRedirectAction::Pass;
    }
    if config.ingress_redirect_bypass(packet.skb_mark, packet.dst_port) {
        return IngressRedirectAction::Pass;
    }
    if !packet.destination_pod_opted_in || !packet.destination_port_declared {
        return IngressRedirectAction::Pass;
    }
    IngressRedirectAction::Steer
}

/// Node-source kubelet probe exemption for IPv4 direct-inbound traffic.
///
/// Keyed by enrolled pod IPv4 address (network byte order) and TCP
/// destination port. Node source IPs alone are intentionally not sufficient to
/// bypass the NodeWaypoint direct-inbound guard.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeProbePortKey4 {
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

impl NodeProbePortKey4 {
    pub const fn new(addr: u32, port: u16) -> Self {
        Self {
            addr,
            port,
            _pad: 0,
        }
    }
}

/// IPv6 counterpart to [`NodeProbePortKey4`].
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeProbePortKey6 {
    pub addr: [u32; 4],
    pub port: u16,
    pub _pad: u16,
}

impl NodeProbePortKey6 {
    pub const fn new(addr: [u32; 4], port: u16) -> Self {
        Self {
            addr,
            port,
            _pad: 0,
        }
    }
}

/// Per-cgroup workload identity in the `FERRUM_WORKLOAD_IDENTITY` map, keyed by
/// cgroup id (`bpf_get_current_cgroup_id`).
///
/// The node-agent writes one entry per enrolled pod cgroup so the connect
/// hooks (which run in the pod's cgroup context) can stamp the original
/// destination record with the source pod's identity. Without this, the
/// connect programs hardcode `pod_uid: [0; 16]` / `workload_spiffe_hash: 0`
/// and the node-waypoint resolver can never recover a real identity from the
/// `FERRUM_ORIG_DST4/6` records.
///
/// Both fields zero means "node-agent has not enrolled this cgroup yet"; the
/// connect program copies them through verbatim, and node-waypoint identity
/// resolution treats an all-zero `pod_uid` as fail-closed.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadIdentity {
    /// Kubernetes pod UID encoded as raw UUID bytes.
    pub pod_uid: [u8; 16],
    /// Stable first-eight-bytes SHA-256 hash of the workload SPIFFE ID.
    pub workload_spiffe_hash: u64,
    /// Reserved for future fields; keeps the struct 8-byte aligned for the
    /// BPF verifier and leaves headroom without an ABI break.
    pub _pad: u64,
}

impl WorkloadIdentity {
    /// Construct an identity entry. `pod_uid` is the raw 16-byte UUID;
    /// `workload_spiffe_hash` is the first-eight-bytes SHA-256 of the SPIFFE
    /// ID (matching `OrigDst4::workload_spiffe_hash`).
    pub const fn new(pod_uid: [u8; 16], workload_spiffe_hash: u64) -> Self {
        Self {
            pod_uid,
            workload_spiffe_hash,
            _pad: 0,
        }
    }

    /// The all-zero sentinel the connect hooks fall back to when no entry
    /// exists for the cgroup. Node-waypoint resolution treats this as
    /// fail-closed (unknown identity).
    pub const fn unknown() -> Self {
        Self::new([0u8; 16], 0)
    }

    /// `true` when neither the pod UID nor the SPIFFE hash has been populated.
    pub fn is_unknown(&self) -> bool {
        self.workload_spiffe_hash == 0 && self.pod_uid == [0u8; 16]
    }
}

/// Node-agent supplied capture settings in the `FERRUM_CAPTURE_CONFIG` map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpfCaptureConfig {
    pub outbound_capture_port: u32,
    pub hbone_redirect_port: u32,
    /// Non-zero → captured IPv6 outbound connections are DENIED (the `connect6`
    /// hook returns `EPERM`) instead of redirected. This is an explicit safety
    /// valve for deployments that cannot provide an IPv6 pod-loopback listener;
    /// the normal NodeWaypoint path leaves it clear and redirects to `[::1]`.
    /// Excluded v6 (bypass UID / port / CIDR excludes) is decided before the deny
    /// and still flows.
    pub ipv6_outbound_deny: u32,
    /// `SO_MARK` value trusted by the pod-veth tc guard for destination
    /// NodeWaypoint relay backend dials. Packets to enrolled pod IPs without
    /// this mark are direct pod traffic and are dropped fail-closed.
    pub node_waypoint_inbound_auth_mark: u32,
    /// `skb->mark` the tc ingress redirect program stamps on a packet it has
    /// steered to the local NodeWaypoint inbound listener with
    /// `bpf_sk_assign()`. The node-agent installs a matching policy-routing
    /// rule (`ip rule fwmark <mark> lookup <table>` + `ip route add local
    /// default dev lo table <table>`) so the assigned packet is delivered
    /// locally instead of being forwarded on to the pod.
    ///
    /// **Zero disables the inbound redirect entirely** — the tc ingress
    /// program returns `TC_ACT_OK` without touching a single packet, and the
    /// pre-existing direct-pod guard remains the only inbound control. This is
    /// the default, so a node that has not been explicitly opted in keeps its
    /// previous behavior.
    pub node_waypoint_ingress_redirect_mark: u32,
    /// TCP port of the NodeWaypoint **transparent inbound capture** listener —
    /// the socket `ferrum_tc_ingress_redirect` steers captured `podIP:appPort`
    /// bytes into.
    ///
    /// **This is deliberately NOT [`Self::hbone_redirect_port`].** The HBONE
    /// listener terminates authenticated HTTP/2 CONNECT over verified mesh
    /// mTLS; captured application bytes are ordinary plaintext (or the app's
    /// own TLS) and `IP_TRANSPARENT` does not transform them into an HBONE
    /// handshake. Steering them at the HBONE port would either fail the mesh
    /// TLS handshake or drop them. The capture listener is a separate protocol
    /// boundary — a plaintext L4 relay that recovers the original destination
    /// and re-enters mesh inbound routing under the PeerAuthentication and
    /// authorization gates — so the two ports must stay distinct.
    ///
    /// Zero disarms the redirect (see [`Self::ingress_redirect_armed`]).
    pub node_waypoint_ingress_capture_port: u32,
}

/// Maximum number of explicit `includeOutboundPorts` ports the per-cgroup
/// BPF gate supports. Sized to cover normal pod annotations (typically 1-5
/// ports). Pods exceeding this cap fall through to capture-all behavior so
/// the gate degrades gracefully instead of silently dropping ports — the
/// userspace loader emits a `warn!` when truncation happens.
pub const INCLUDE_PORTS_MAX: usize = 16;

/// Per-cgroup outbound `includeOutboundPorts` policy in the
/// `FERRUM_INCLUDE_PORTS` map, keyed by cgroup id (`bpf_get_current_cgroup_id`).
///
/// Semantics:
/// - No entry for a cgroup → no narrowing, capture every TCP port (preserves
///   pre-existing un-annotated pod behavior).
/// - Entry with `all_ports == 1` → matches the `*` wildcard annotation;
///   capture every port. `port_count` is ignored in this case.
/// - Entry with `all_ports == 0` and `port_count > 0` → capture only those
///   ports; everything else returns from the connect hook without rewrite.
/// - Entry with `all_ports == 0` and `port_count == 0` → fail-open, behaves
///   like "no entry" (the userspace side should not write this shape; the
///   BPF program tolerates it defensively).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncludePortsPolicy {
    /// Non-zero means "capture all outbound ports" (the `*` wildcard).
    /// `u32` to keep the struct 4-byte aligned for the BPF verifier.
    pub all_ports: u32,
    /// Number of valid entries in `ports`. Always `<= INCLUDE_PORTS_MAX`.
    pub port_count: u32,
    /// Sorted ascending. Trailing entries beyond `port_count` are ignored
    /// and may be uninitialized in flight.
    pub ports: [u16; INCLUDE_PORTS_MAX],
}

impl IncludePortsPolicy {
    /// Construct a `*`-style "capture all ports" policy.
    pub const fn all() -> Self {
        Self {
            all_ports: 1,
            port_count: 0,
            ports: [0u16; INCLUDE_PORTS_MAX],
        }
    }

    /// Construct an explicit-ports policy. Caller must have already sorted
    /// and deduped `ports`; truncates at `INCLUDE_PORTS_MAX` (the userspace
    /// side warns when this happens).
    pub fn explicit(ports: &[u16]) -> Self {
        let mut storage = [0u16; INCLUDE_PORTS_MAX];
        let count = ports.len().min(INCLUDE_PORTS_MAX);
        for (slot, value) in storage.iter_mut().zip(ports.iter().take(count)) {
            *slot = *value;
        }
        Self {
            all_ports: 0,
            port_count: count as u32,
            ports: storage,
        }
    }

    /// `true` when this entry encodes the `*` wildcard.
    pub const fn is_all_ports(&self) -> bool {
        self.all_ports != 0
    }
}

/// IPv4 address payload for `FERRUM_CIDR_INCLUDE` / `FERRUM_CIDR_EXCLUDE`.
///
/// Aya's LPM trie wrapper stores the leading `prefix_len` separately in
/// `aya_ebpf::maps::lpm_trie::Key`, so this shared payload intentionally holds
/// only address bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrKey4 {
    pub addr: u32,
}

/// IPv6 address payload for LPM trie keys.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrKey6 {
    pub addr: [u32; 4],
}

/// Outbound capture port. Connect hooks rewrite destinations here.
pub const OUTBOUND_CAPTURE_PORT: u16 = 15001;

/// Inbound HBONE port carried in the capture config for sidecarless topologies.
pub const INBOUND_HBONE_PORT: u16 = 15008;

/// Default TCP port of the NodeWaypoint transparent inbound **capture**
/// listener — the redirect's steer target.
///
/// Deliberately the mesh inbound listener port (`FERRUM_MESH_INBOUND_LISTEN_ADDR`,
/// default `0.0.0.0:15006`), which NodeWaypoint topology otherwise leaves
/// unused, rather than a new port with its own environment variable: the proxy
/// binds that address and the node-agent reads the same variable, so the two
/// processes cannot drift apart. It is NOT [`INBOUND_HBONE_PORT`] — see
/// `BpfCaptureConfig::node_waypoint_ingress_capture_port`.
pub const NODE_WAYPOINT_INGRESS_CAPTURE_PORT: u16 = 15006;

/// Socket mark used by the destination NodeWaypoint inbound HBONE relay when
/// dialing the local backend pod. Chosen adjacent to Ferrum's TPROXY mark but
/// distinct from it, and outside the common masked CNI mark classes.
pub const NODE_WAYPOINT_INBOUND_AUTH_MARK: u32 = 0x734;

/// `skb->mark` stamped by `ferrum_tc_ingress_redirect` on a packet it steered
/// to the local NodeWaypoint inbound listener.
///
/// Chosen adjacent to — and distinct from — the UDP TPROXY mark (`0x733`) and
/// the inbound relay auth mark (`0x734`), and outside the common masked CNI
/// mark classes (`0x735 & 0xF00 == 0x700`, so it does not alias Cilium's
/// `0xF00` class). It must never equal the auth mark: the tc programs treat
/// the auth mark as "already relayed" for loop prevention, so collapsing the
/// two would make a redirected packet indistinguishable from a relay dial.
pub const NODE_WAYPOINT_INGRESS_REDIRECT_MARK: u32 = 0x735;

/// Ferrum-owned policy-routing table for tc-ingress-redirected inbound TCP.
/// Distinct from the UDP TPROXY table (`33133`) so teardown of one path can
/// never reap the other, and distinct from Istio's conventional tables.
pub const NODE_WAYPOINT_INGRESS_REDIRECT_TABLE: u32 = 33134;

/// `ip rule` priority for the inbound-redirect local-delivery rule. Like the
/// UDP TPROXY rule it must sort BELOW the kernel `main` rule (priority 32766)
/// or `main` resolves the marked packet first and the redirect black-holes.
/// One above the UDP rule (`100`) so the two are independently deletable.
pub const NODE_WAYPOINT_INGRESS_REDIRECT_RULE_PRIORITY: u32 = 101;

// The two NodeWaypoint marks must stay distinct from each other and from the
// UDP TPROXY mark, and must not alias the common masked CNI mark classes.
const _: () = assert!(NODE_WAYPOINT_INGRESS_REDIRECT_MARK != NODE_WAYPOINT_INBOUND_AUTH_MARK);
const _: () = assert!(NODE_WAYPOINT_INGRESS_REDIRECT_MARK & 0xF00 != 0xF00);

/// Singleton key for `FERRUM_CAPTURE_CONFIG`.
pub const FERRUM_CAPTURE_CONFIG_KEY: u32 = 0;

/// Single SOCK_OPS event record published by the kernel-side
/// `BPF_PROG_TYPE_SOCK_OPS` program over the ringbuf and consumed by the
/// userspace `SockOpsConsumer`. Fixed-width fields for stable BPF wire
/// shape; the userspace decoder maps this into the `SockOpsEvent` enum.
///
/// `event_type` selects which variant the record carries; meaning of the
/// remaining fields depends on the variant — see the `SOCK_OPS_EVENT_*`
/// constants. `_pad` keeps the struct 8-byte aligned for the BPF verifier.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockOpsRecord {
    /// One of the `SOCK_OPS_EVENT_*` constants.
    pub event_type: u32,
    /// Direction when meaningful (`SOCK_OPS_DIRECTION_*`); zero otherwise.
    pub direction: u32,
    /// Drop reason when `event_type == SOCK_OPS_EVENT_DROP_REASON`
    /// (`SOCK_OPS_DROP_*`); zero otherwise.
    pub drop_reason: u32,
    pub _pad: u32,
    /// Payload value for latency / RTT variants in microseconds. Zero for
    /// pure event types (connect, accept_established, rst, fin).
    pub value: u64,
}

// `SockOpsRecord::event_type` discriminants. Matches the
// `SockOpsEvent` enum on the userspace side.
pub const SOCK_OPS_EVENT_CONNECT: u32 = 1;
pub const SOCK_OPS_EVENT_ACCEPT_ESTABLISHED: u32 = 2;
pub const SOCK_OPS_EVENT_RST: u32 = 3;
pub const SOCK_OPS_EVENT_FIN: u32 = 4;
pub const SOCK_OPS_EVENT_RTT_SAMPLE: u32 = 5;
pub const SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY: u32 = 6;
/// Reserved discriminant. SOCK_OPS has no first-inbound-data-byte callback, so
/// no kernel producer emits this value; userspace ignores it if observed.
pub const SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY: u32 = 7;
pub const SOCK_OPS_EVENT_DROP_REASON: u32 = 8;

// `SockOpsRecord::direction` values. Zero is "unused / unknown" (RST uses
// unknown; FIN uses sent/received).
pub const SOCK_OPS_DIRECTION_SENT: u32 = 1;
pub const SOCK_OPS_DIRECTION_RECEIVED: u32 = 2;

// `SockOpsRecord::drop_reason` values. Zero is "unused".
pub const SOCK_OPS_DROP_BYPASS_UID_HIT: u32 = 1;
pub const SOCK_OPS_DROP_EXCLUDE_CIDR_HIT: u32 = 2;
pub const SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR: u32 = 3;
pub const SOCK_OPS_DROP_EXCLUDE_PORT_HIT: u32 = 4;

/// Default ringbuf byte size (4 MiB) used when
/// `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` is unset. Must be a power of two.
pub const SOCK_OPS_RINGBUF_DEFAULT_BYTES: u32 = 4 * 1024 * 1024;

/// `FERRUM_SOCK_OPS_STATS` index for "events dropped because the ringbuf
/// could not be reserved". Userspace polls this counter periodically; when
/// it advances between polls, [`SockOpsConsumer::record_overrun`] fires.
pub const SOCK_OPS_STATS_EVENTS_DROPPED: u32 = 0;
/// Length of `FERRUM_SOCK_OPS_STATS` array map.
pub const SOCK_OPS_STATS_LEN: u32 = 1;

/// IPv4 loopback (127.0.0.1) stored as the `u32` the kernel's `user_ip4`
/// field expects (network byte order in memory).
pub const IPV4_LOOPBACK_NBO: u32 = u32::from_ne_bytes([127, 0, 0, 1]);

/// IPv6 loopback `[::1]` stored as the kernel's `user_ip6` expects (NBO).
pub const IPV6_LOOPBACK_NBO: [u32; 4] = [0, 0, 0, u32::from_ne_bytes([0, 0, 0, 1])];

/// Convert a `bpf_sock_ops.remote_port` value to a host-byte-order port.
///
/// `remote_port` is the peer port in network byte order, but the kernel does
/// **not** store it in the low 16 bits: on little-endian kernels the sock_ops
/// ctx rewrite stores it as `(__be16 dport) << 16`, so the real port sits in
/// the upper half. The canonical decode (matching the kernel's own
/// `bpf_ntohl(skops->remote_port)` samples) is a full 32-bit
/// network-to-host swap, then truncate — `u32::from_be(remote_port) as u16`.
/// Truncating first (`remote_port as u16`) would read the always-zero low half
/// on LE and yield `0`. `bpf_sock_ops.local_port`, by contrast, is already in
/// host byte order and needs no conversion.
pub const fn sock_ops_peer_port_host_order(remote_port: u32) -> u16 {
    u32::from_be(remote_port) as u16
}

/// Decode a `bpf_sock_addr.user_port` value to a host-byte-order port.
///
/// Unlike `bpf_sock_ops.remote_port` (see [`sock_ops_peer_port_host_order`]),
/// the cgroup `connect4`/`connect6`/`getpeername` address context stores the
/// port the way a `sockaddr_in.sin_port` does: **network byte order in the low
/// 16 bits**, high 16 bits zero (the kernel sets and reads it as
/// `bpf_htons(port)`). The sock_ops high-half `<< 16` convention does **not**
/// apply here — using it reads the always-zero high half and yields `0`. So the
/// decode is "take the low half, swap to host order".
pub const fn sock_addr_user_port_to_host(user_port: u32) -> u16 {
    u16::from_be((user_port & 0xFFFF) as u16)
}

/// Encode a host-byte-order port into a `bpf_sock_addr.user_port` value: network
/// byte order in the low 16 bits, high 16 bits zero — the inverse of
/// [`sock_addr_user_port_to_host`], and what the kernel expects when a
/// cgroup/connect program rewrites the destination port.
pub const fn host_port_to_sock_addr_user_port(port: u16) -> u32 {
    port.to_be() as u32
}

impl CidrKey4 {
    /// Build an LPM key payload from a network-byte-order IPv4 address.
    pub const fn new(addr_nbo: u32) -> Self {
        Self { addr: addr_nbo }
    }

    /// Full /32 match for a single IPv4 address.
    pub const fn host(addr_nbo: u32) -> Self {
        Self::new(addr_nbo)
    }
}

impl CidrKey6 {
    pub const fn new(addr_nbo: [u32; 4]) -> Self {
        Self { addr: addr_nbo }
    }

    pub const fn host(addr_nbo: [u32; 4]) -> Self {
        Self::new(addr_nbo)
    }
}

impl BpfCaptureConfig {
    pub const fn new(outbound_capture_port: u16, hbone_redirect_port: u16) -> Self {
        Self {
            outbound_capture_port: outbound_capture_port as u32,
            hbone_redirect_port: hbone_redirect_port as u32,
            ipv6_outbound_deny: 0,
            node_waypoint_inbound_auth_mark: NODE_WAYPOINT_INBOUND_AUTH_MARK,
            // Fail closed to "no redirect": the inbound tc redirect only
            // engages once an operator opts the node in AND the node-agent has
            // installed the matching local-delivery routing.
            node_waypoint_ingress_redirect_mark: 0,
            // Likewise fail closed: with no capture listener port there is
            // nothing to steer into, so the redirect stays disarmed.
            node_waypoint_ingress_capture_port: 0,
        }
    }

    /// Set whether captured IPv6 outbound connections fail closed (denied) —
    /// see [`Self::ipv6_outbound_deny`].
    pub const fn with_ipv6_outbound_deny(mut self, deny: bool) -> Self {
        self.ipv6_outbound_deny = deny as u32;
        self
    }

    pub const fn with_node_waypoint_inbound_auth_mark(mut self, mark: u32) -> Self {
        self.node_waypoint_inbound_auth_mark = mark;
        self
    }

    /// Set the tc ingress redirect mark — see
    /// [`Self::node_waypoint_ingress_redirect_mark`]. Zero disables the
    /// redirect.
    pub const fn with_node_waypoint_ingress_redirect_mark(mut self, mark: u32) -> Self {
        self.node_waypoint_ingress_redirect_mark = mark;
        self
    }

    /// Set the transparent inbound **capture** listener port the redirect
    /// steers into — see [`Self::node_waypoint_ingress_capture_port`]. Zero
    /// disables the redirect.
    pub const fn with_node_waypoint_ingress_capture_port(mut self, port: u16) -> Self {
        self.node_waypoint_ingress_capture_port = port as u32;
        self
    }

    /// `true` when the inbound tc ingress redirect is armed. Requires a
    /// non-zero redirect mark AND a non-zero **capture listener** port to steer
    /// to; either missing leaves the datapath on the pre-existing direct-pod
    /// guard.
    ///
    /// The capture port — not `hbone_redirect_port` — is the gate: HBONE is a
    /// different protocol boundary and can be live while the capture listener
    /// is not.
    pub const fn ingress_redirect_armed(&self) -> bool {
        self.node_waypoint_ingress_redirect_mark != 0
            && self.node_waypoint_ingress_capture_port != 0
    }

    /// Loop / self-capture bypass for the tc ingress redirect: `true` means
    /// "leave this packet completely alone".
    ///
    /// Lives here rather than in the kernel program so the host-side unit tests
    /// exercise the exact truth table the classifier evaluates. Four
    /// independent conditions:
    ///
    /// 1. `mark == node_waypoint_inbound_auth_mark` — the relay's own
    ///    authorized dial down to the local backend pod. Redirecting it would
    ///    feed the relay its own traffic in a loop.
    /// 2. `mark == node_waypoint_ingress_redirect_mark` — already redirected by
    ///    this program (or a peer hook); never redirect twice.
    /// 3. `dst_port == node_waypoint_ingress_capture_port` — already addressed
    ///    to the capture listener, so it must reach it directly. This is the
    ///    self-capture guard proper.
    /// 4. `dst_port == hbone_redirect_port` — peer-to-peer HBONE. The HBONE
    ///    listener is a distinct protocol boundary (authenticated H2 CONNECT
    ///    over mesh mTLS) and must never be fed captured plaintext, so its port
    ///    is bypassed too.
    ///
    /// A zero auth mark (local-pod mode) must NOT make an unmarked packet look
    /// authorized, which is why condition 1 is guarded on a non-zero mark.
    pub const fn ingress_redirect_bypass(&self, mark: u32, dst_port: u16) -> bool {
        if self.node_waypoint_inbound_auth_mark != 0 && mark == self.node_waypoint_inbound_auth_mark
        {
            return true;
        }
        if self.node_waypoint_ingress_redirect_mark != 0
            && mark == self.node_waypoint_ingress_redirect_mark
        {
            return true;
        }
        if self.node_waypoint_ingress_capture_port != 0
            && dst_port as u32 == self.node_waypoint_ingress_capture_port
        {
            return true;
        }
        self.hbone_redirect_port != 0 && dst_port as u32 == self.hbone_redirect_port
    }

    pub const fn default_ports() -> Self {
        Self::new(OUTBOUND_CAPTURE_PORT, INBOUND_HBONE_PORT)
    }
}

/// `aya::Pod` marks a type as plain-old-data that is safe to copy byte-for-byte
/// in and out of BPF maps. It is implemented for the shared map key/value types
/// only under the `userspace` feature on Linux (the aya userspace loader); the
/// kernel (bpfel) build never links aya. The orphan rule requires these impls to
/// live in this crate, where the types are defined.
///
/// The `target_os = "linux"` gate mirrors aya being a Linux-only dependency in
/// both this crate and `ferrum-edge` (and `ferrum-edge` gating its real backend
/// on `cfg(all(feature = "ebpf", target_os = "linux"))`). `ferrum-edge
/// --features ebpf` enables `ferrum-ebpf-common/userspace` on every target, so
/// without this gate a non-Linux build (e.g. `cargo check --lib --features ebpf`
/// on Darwin) would reference the unlinked `aya` crate; off Linux the tree falls
/// back to the mock backend instead.
///
/// Safety: every type below is `#[repr(C)]` and `Copy`, contains only
/// fixed-width integers / byte arrays (no padding that aliases invalid bit
/// patterns, no pointers), and matches the kernel-side map definition exactly.
#[cfg(all(feature = "userspace", target_os = "linux"))]
mod userspace_pod {
    use super::*;

    macro_rules! impl_pod {
        ($($t:ty),+ $(,)?) => {
            $(unsafe impl aya::Pod for $t {})+
        };
    }

    impl_pod!(
        OrigDstKey,
        OrigDst4,
        OrigDst6,
        ConnTuple4,
        ConnTuple6,
        PodInfo,
        NodeProbePortKey4,
        NodeProbePortKey6,
        InboundRedirectKey4,
        InboundRedirectKey6,
        WorkloadIdentity,
        BpfCaptureConfig,
        IncludePortsPolicy,
        CidrKey4,
        CidrKey6,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::mem;

    #[test]
    fn pod_udp_capture_lifecycle_flags_fail_closed_until_ready() {
        let disabled = PodInfo {
            proxy_port: 15001,
            capture_flags: 0,
        };
        let guarded = PodInfo {
            proxy_port: 15001,
            capture_flags: POD_CAPTURE_FLAG_UDP_ENABLED,
        };
        let ready = PodInfo {
            proxy_port: 15001,
            capture_flags: POD_CAPTURE_FLAG_UDP_ENABLED | POD_CAPTURE_FLAG_UDP_READY,
        };

        assert!(!disabled.udp_capture_not_ready());
        assert!(guarded.udp_capture_not_ready());
        assert!(!ready.udp_capture_not_ready());
    }

    #[test]
    fn type_sizes_are_bpf_aligned() {
        assert_eq!(mem::size_of::<OrigDstKey>(), 8);
        assert_eq!(mem::size_of::<OrigDst4>(), 32);
        assert_eq!(mem::size_of::<OrigDst6>(), 48);
        // ConnTuple4: two u32 (8) + two u16 (4) + u32 pad (4) + u64 netns (8)
        // = 24 bytes, 8-byte aligned (no implicit padding).
        assert_eq!(mem::size_of::<ConnTuple4>(), 24);
        assert_eq!(mem::align_of::<ConnTuple4>(), 8);
        // ConnTuple6: two [u32;4] (32) + two u16 (4) + u32 pad (4) + u64 netns
        // (8) = 48 bytes, 8-byte aligned.
        assert_eq!(mem::size_of::<ConnTuple6>(), 48);
        assert_eq!(mem::align_of::<ConnTuple6>(), 8);
        assert_eq!(mem::size_of::<PodInfo>(), 8);
        // WorkloadIdentity: [u8;16] (16) + u64 (8) + u64 pad (8) = 32 bytes,
        // 8-byte aligned for the BPF verifier.
        assert_eq!(mem::size_of::<WorkloadIdentity>(), 32);
        assert_eq!(mem::align_of::<WorkloadIdentity>(), 8);
        // BpfCaptureConfig: six u32 = 24 bytes, 4-byte aligned. The fifth and
        // sixth words are the tc-ingress-redirect mark and the transparent
        // inbound capture listener port.
        assert_eq!(mem::size_of::<BpfCaptureConfig>(), 24);
        assert_eq!(mem::align_of::<BpfCaptureConfig>(), 4);
        // InboundRedirectKey4: u32 + two u16 = 8 bytes; the v6 key is
        // [u32;4] + two u16 = 20 bytes. Both are fully defined (explicit pad).
        assert_eq!(mem::size_of::<InboundRedirectKey4>(), 8);
        assert_eq!(mem::size_of::<InboundRedirectKey6>(), 20);
        assert_eq!(mem::size_of::<CidrKey4>(), 4);
        assert_eq!(mem::size_of::<CidrKey6>(), 16);
        // IncludePortsPolicy: two u32 (8) + [u16; INCLUDE_PORTS_MAX] (32) = 40 bytes, 4-byte aligned.
        assert_eq!(
            mem::size_of::<IncludePortsPolicy>(),
            8 + 2 * INCLUDE_PORTS_MAX
        );
        assert_eq!(mem::align_of::<IncludePortsPolicy>(), 4);
        // SockOpsRecord: four u32 (16) + one u64 (8) = 24 bytes, 8-byte aligned.
        assert_eq!(mem::size_of::<SockOpsRecord>(), 24);
        assert_eq!(mem::align_of::<SockOpsRecord>(), 8);
    }

    #[test]
    fn types_are_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<OrigDstKey>();
        assert_copy::<OrigDst4>();
        assert_copy::<OrigDst6>();
        assert_copy::<ConnTuple4>();
        assert_copy::<ConnTuple6>();
        assert_copy::<PodInfo>();
        assert_copy::<BpfCaptureConfig>();
        assert_copy::<CidrKey4>();
        assert_copy::<CidrKey6>();
        assert_copy::<IncludePortsPolicy>();
        assert_copy::<SockOpsRecord>();
        assert_copy::<WorkloadIdentity>();
    }

    #[test]
    fn workload_identity_unknown_sentinel() {
        let unknown = WorkloadIdentity::unknown();
        assert!(unknown.is_unknown());
        assert_eq!(unknown.pod_uid, [0u8; 16]);
        assert_eq!(unknown.workload_spiffe_hash, 0);
    }

    #[test]
    fn workload_identity_populated_is_not_unknown() {
        let identity = WorkloadIdentity::new([1u8; 16], 0x1122_3344_5566_7788);
        assert!(!identity.is_unknown());
        assert_eq!(identity.workload_spiffe_hash, 0x1122_3344_5566_7788);
        // A pod UID with a zero hash is still "known" — the UID alone is a
        // valid identity anchor (SPIFFE hash is supplementary).
        let uid_only = WorkloadIdentity::new([2u8; 16], 0);
        assert!(!uid_only.is_unknown());
    }

    #[test]
    fn include_ports_policy_all_sentinel() {
        let policy = IncludePortsPolicy::all();
        assert!(policy.is_all_ports());
        assert_eq!(policy.port_count, 0);
    }

    #[test]
    fn include_ports_policy_explicit_within_cap() {
        let policy = IncludePortsPolicy::explicit(&[80, 443, 5432]);
        assert!(!policy.is_all_ports());
        assert_eq!(policy.port_count, 3);
        assert_eq!(&policy.ports[..3], &[80, 443, 5432]);
        // Trailing slots remain zero so the kernel sees a well-defined struct.
        assert!(policy.ports[3..].iter().all(|&p| p == 0));
    }

    #[test]
    fn include_ports_policy_truncates_at_cap() {
        let mut ports = [0u16; INCLUDE_PORTS_MAX + 4];
        for (i, slot) in ports.iter_mut().enumerate() {
            *slot = (i as u16) + 1;
        }
        let policy = IncludePortsPolicy::explicit(&ports);
        assert_eq!(policy.port_count as usize, INCLUDE_PORTS_MAX);
        // First INCLUDE_PORTS_MAX entries preserved, rest dropped.
        for i in 0..INCLUDE_PORTS_MAX {
            assert_eq!(policy.ports[i], ports[i]);
        }
    }

    #[test]
    fn include_ports_policy_empty_is_fail_open_shape() {
        let policy = IncludePortsPolicy::explicit(&[]);
        assert!(!policy.is_all_ports());
        assert_eq!(policy.port_count, 0);
        assert!(policy.ports.iter().all(|&p| p == 0));
    }

    #[test]
    fn sock_ops_default_ringbuf_size_is_power_of_two() {
        assert!(SOCK_OPS_RINGBUF_DEFAULT_BYTES.is_power_of_two());
    }

    #[test]
    fn sock_ops_event_discriminants_are_stable() {
        // Wire ABI for the SOCK_OPS ringbuf. Discriminant 7 is reserved
        // (accept-to-first-byte has no producer); 8 is drop-reason.
        assert_eq!(SOCK_OPS_EVENT_CONNECT, 1);
        assert_eq!(SOCK_OPS_EVENT_ACCEPT_ESTABLISHED, 2);
        assert_eq!(SOCK_OPS_EVENT_RST, 3);
        assert_eq!(SOCK_OPS_EVENT_FIN, 4);
        assert_eq!(SOCK_OPS_EVENT_RTT_SAMPLE, 5);
        assert_eq!(SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY, 6);
        assert_eq!(SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY, 7);
        assert_eq!(SOCK_OPS_EVENT_DROP_REASON, 8);
        assert_eq!(SOCK_OPS_DROP_BYPASS_UID_HIT, 1);
        assert_eq!(SOCK_OPS_DROP_EXCLUDE_CIDR_HIT, 2);
        assert_eq!(SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR, 3);
        assert_eq!(SOCK_OPS_DROP_EXCLUDE_PORT_HIT, 4);
    }

    #[test]
    fn cidr_key4_host() {
        let key = CidrKey4::host(0x0a000001);
        assert_eq!(key.addr, 0x0a000001);
    }

    #[test]
    fn cidr_key4_subnet() {
        let key = CidrKey4::new(0x0a000000);
        assert_eq!(key.addr, 0x0a000000);
    }

    #[test]
    fn cidr_key6_host() {
        let key = CidrKey6::host([0, 0, 0, u32::from_be(1)]);
        assert_eq!(key.addr, [0, 0, 0, u32::from_be(1)]);
    }

    #[test]
    fn ipv4_loopback_constant() {
        let bytes = IPV4_LOOPBACK_NBO.to_ne_bytes();
        assert_eq!(bytes, [127, 0, 0, 1]);
    }

    #[test]
    fn sock_ops_peer_port_decodes_be_high_half() {
        // bpf_sock_ops.remote_port on little-endian = (__be16 dport) << 16.
        // Port 8080 (0x1F90 host): network bytes [0x1F, 0x90] → 16-bit LE load
        // 0x901F → << 16 = 0x901F_0000.
        assert_eq!(sock_ops_peer_port_host_order(0x901F_0000), 8080);
        // Port 80 (0x0050 host): network bytes [0x00, 0x50] → 0x5000 → << 16.
        assert_eq!(sock_ops_peer_port_host_order(0x5000_0000), 80);
        // The previous bug (`remote_port as u16` first) read the zero low half
        // and returned 0 for both of these.
        assert_ne!(sock_ops_peer_port_host_order(0x901F_0000), 0);
    }

    #[test]
    fn sock_addr_user_port_low_half_round_trip() {
        // bpf_sock_addr.user_port carries sin_port: network byte order in the
        // LOW 16 bits (high half zero), unlike bpf_sock_ops.remote_port. Encode
        // and decode must be inverses, must place the port in the low half, and
        // must NOT use the sock_ops high-half (`<< 16`) convention — which is the
        // bug that left connect4 redirecting to port 0 on the live datapath.
        for port in [1u16, 80, 443, 8080, 15001, 45435, 65535] {
            let encoded = host_port_to_sock_addr_user_port(port);
            assert_eq!(
                encoded & 0xFFFF_0000,
                0,
                "port {port}: the high 16 bits must be zero"
            );
            assert_eq!(
                sock_addr_user_port_to_host(encoded),
                port,
                "encode/decode must round-trip for port {port}"
            );
            assert_ne!(
                encoded,
                (port as u32) << 16,
                "port {port} must not use the sock_ops high-half encoding"
            );
        }
    }

    #[test]
    fn conn_tuple_any_netns_preserves_connection_tuple() {
        let tuple4 = ConnTuple4::new(42, 0x0100_007f, 49152, 0x0100_007f, 15001);
        let any4 = tuple4.any_netns();
        assert_eq!(any4.client_addr, tuple4.client_addr);
        assert_eq!(any4.server_addr, tuple4.server_addr);
        assert_eq!(any4.client_port, tuple4.client_port);
        assert_eq!(any4.server_port, tuple4.server_port);
        assert_eq!(any4.netns_cookie, 0);

        let tuple6 = ConnTuple6::new(99, [0, 0, 0, 1], 49153, [0, 0, 0, 1], 15001);
        let any6 = tuple6.any_netns();
        assert_eq!(any6.client_addr, tuple6.client_addr);
        assert_eq!(any6.server_addr, tuple6.server_addr);
        assert_eq!(any6.client_port, tuple6.client_port);
        assert_eq!(any6.server_port, tuple6.server_port);
        assert_eq!(any6.netns_cookie, 0);
    }

    #[test]
    fn ipv6_loopback_constant() {
        assert_eq!(IPV6_LOOPBACK_NBO[0], 0);
        assert_eq!(IPV6_LOOPBACK_NBO[1], 0);
        assert_eq!(IPV6_LOOPBACK_NBO[2], 0);
        let last = IPV6_LOOPBACK_NBO[3].to_ne_bytes();
        assert_eq!(last, [0, 0, 0, 1]);
    }

    #[test]
    fn capture_config_defaults_match_public_ports() {
        let config = BpfCaptureConfig::default_ports();
        assert_eq!(config.outbound_capture_port, OUTBOUND_CAPTURE_PORT as u32);
        assert_eq!(config.hbone_redirect_port, INBOUND_HBONE_PORT as u32);
        assert_eq!(FERRUM_CAPTURE_CONFIG_KEY, 0);
        // IPv6 egress is redirected (not denied) by default; the deny remains an
        // explicit safety valve for deployments without an IPv6 capture listener.
        assert_eq!(config.ipv6_outbound_deny, 0);
        assert_eq!(
            config.node_waypoint_inbound_auth_mark,
            NODE_WAYPOINT_INBOUND_AUTH_MARK
        );
    }

    #[test]
    fn ipv6_outbound_deny_flag_round_trips() {
        assert_eq!(
            BpfCaptureConfig::new(15001, 15008).ipv6_outbound_deny,
            0,
            "v6 deny is off unless explicitly set"
        );
        assert_ne!(
            BpfCaptureConfig::new(15001, 15008)
                .with_ipv6_outbound_deny(true)
                .ipv6_outbound_deny,
            0,
            "with_ipv6_outbound_deny(true) must set the fail-closed flag the connect6 hook reads"
        );
        assert_eq!(
            BpfCaptureConfig::new(15001, 15008)
                .with_ipv6_outbound_deny(false)
                .ipv6_outbound_deny,
            0
        );
    }

    #[test]
    fn inbound_redirect_flag_is_opt_in_and_orthogonal_to_udp_flags() {
        let plain = PodInfo {
            proxy_port: 15001,
            capture_flags: 0,
        };
        assert!(
            !plain.inbound_redirect_enabled(),
            "a pod with no flags must never be redirected"
        );

        // The UDP lifecycle flags must not imply inbound redirect, and the
        // inbound-redirect flag must not disturb the UDP readiness gate.
        let udp_guarded = PodInfo {
            proxy_port: 15001,
            capture_flags: POD_CAPTURE_FLAG_UDP_ENABLED,
        };
        assert!(!udp_guarded.inbound_redirect_enabled());
        let redirect_only = PodInfo {
            proxy_port: 15001,
            capture_flags: POD_CAPTURE_FLAG_INBOUND_REDIRECT,
        };
        assert!(redirect_only.inbound_redirect_enabled());
        assert!(!redirect_only.udp_capture_not_ready());

        let both = PodInfo {
            proxy_port: 15001,
            capture_flags: POD_CAPTURE_FLAG_INBOUND_REDIRECT | POD_CAPTURE_FLAG_UDP_ENABLED,
        };
        assert!(both.inbound_redirect_enabled());
        assert!(both.udp_capture_not_ready());
    }

    #[test]
    fn inbound_redirect_keys_are_exact_addr_port_pairs() {
        let v4 = InboundRedirectKey4::new(0x0a00_0005, 8080);
        assert_eq!(v4.addr, 0x0a00_0005);
        assert_eq!(v4.port, 8080);
        assert_eq!(v4._pad, 0, "padding must be defined so map-key bytes match");
        assert_ne!(
            v4,
            InboundRedirectKey4::new(0x0a00_0005, 8081),
            "a different port must be a different key (per-port scoping)"
        );

        let v6 = InboundRedirectKey6::new([1, 2, 3, 4], 8080);
        assert_eq!(v6.addr, [1, 2, 3, 4]);
        assert_eq!(v6.port, 8080);
        assert_eq!(v6._pad, 0);
        assert_ne!(v6, InboundRedirectKey6::new([1, 2, 3, 5], 8080));
    }

    #[test]
    fn ingress_redirect_mark_is_disabled_by_default_and_round_trips() {
        let default = BpfCaptureConfig::new(15001, 15008);
        assert_eq!(
            default.node_waypoint_ingress_redirect_mark, 0,
            "the inbound tc redirect must be opt-in, never on by default"
        );
        assert_eq!(
            default.node_waypoint_ingress_capture_port, 0,
            "no capture listener is assumed until one is configured"
        );
        assert!(
            !default.ingress_redirect_armed(),
            "a zero mark must leave the redirect disarmed"
        );

        let armed = default
            .with_node_waypoint_ingress_redirect_mark(NODE_WAYPOINT_INGRESS_REDIRECT_MARK)
            .with_node_waypoint_ingress_capture_port(NODE_WAYPOINT_INGRESS_CAPTURE_PORT);
        assert_eq!(
            armed.node_waypoint_ingress_redirect_mark,
            NODE_WAYPOINT_INGRESS_REDIRECT_MARK
        );
        assert_eq!(
            armed.node_waypoint_ingress_capture_port,
            NODE_WAYPOINT_INGRESS_CAPTURE_PORT as u32
        );
        assert!(armed.ingress_redirect_armed());

        // A CAPTURE port of zero must disarm even with a mark set: there would
        // be no listener to steer to and the program must not drop traffic.
        // A live HBONE port is NOT a substitute — HBONE is a different
        // protocol boundary.
        let no_capture_port = BpfCaptureConfig::new(15001, INBOUND_HBONE_PORT)
            .with_node_waypoint_ingress_redirect_mark(NODE_WAYPOINT_INGRESS_REDIRECT_MARK);
        assert!(
            !no_capture_port.ingress_redirect_armed(),
            "a live HBONE port must never arm the redirect on its own"
        );
    }

    #[test]
    fn the_capture_port_is_never_the_hbone_port() {
        // The regression this pins: steering ordinary plaintext application
        // bytes at the authenticated HBONE listener (H2 CONNECT over verified
        // mesh mTLS) cannot work — IP_TRANSPARENT preserves addresses, it does
        // not transform the payload. The two ports are separate protocol
        // boundaries and the shipped defaults must reflect that.
        assert_ne!(NODE_WAYPOINT_INGRESS_CAPTURE_PORT, INBOUND_HBONE_PORT);
        let armed = armed_redirect_config();
        assert_ne!(
            armed.node_waypoint_ingress_capture_port, armed.hbone_redirect_port,
            "the redirect must steer at the capture listener, never at HBONE"
        );
        // ... and HBONE-addressed traffic still bypasses the redirect entirely.
        assert!(armed.ingress_redirect_bypass(0, INBOUND_HBONE_PORT));
    }

    /// The armed configuration the redirect decision tests are written against.
    fn armed_redirect_config() -> BpfCaptureConfig {
        BpfCaptureConfig::new(15001, INBOUND_HBONE_PORT)
            .with_node_waypoint_inbound_auth_mark(NODE_WAYPOINT_INBOUND_AUTH_MARK)
            .with_node_waypoint_ingress_redirect_mark(NODE_WAYPOINT_INGRESS_REDIRECT_MARK)
            .with_node_waypoint_ingress_capture_port(NODE_WAYPOINT_INGRESS_CAPTURE_PORT)
    }

    #[test]
    fn ingress_redirect_steers_only_a_fully_in_scope_packet() {
        let config = armed_redirect_config();
        let in_scope = IngressRedirectPacket::fully_in_scope(8080);
        assert_eq!(
            ingress_redirect_action(&config, &in_scope),
            IngressRedirectAction::Steer,
            "an enrolled, opted-in pod on a declared TCP port is the one case that redirects"
        );

        // Every gate, flipped one at a time off the in-scope baseline. Each of
        // these MUST leave the packet on the pre-existing direct-pod guard.
        let not_tcp = IngressRedirectPacket {
            protocol_is_tcp: false,
            ..in_scope
        };
        assert_eq!(
            ingress_redirect_action(&config, &not_tcp),
            IngressRedirectAction::Pass,
            "bpf_sk_assign is TCP-only here; non-TCP must never be steered"
        );

        let unenrolled = IngressRedirectPacket {
            destination_pod_opted_in: false,
            ..in_scope
        };
        assert_eq!(
            ingress_redirect_action(&config, &unenrolled),
            IngressRedirectAction::Pass,
            "traffic to a pod that did not opt in must never be captured"
        );

        let undeclared_port = IngressRedirectPacket {
            destination_port_declared: false,
            ..in_scope
        };
        assert_eq!(
            ingress_redirect_action(&config, &undeclared_port),
            IngressRedirectAction::Pass,
            "an enrolled pod's undeclared port stays on the direct-pod guard"
        );

        let fragment = IngressRedirectPacket {
            fragmented: true,
            ..in_scope
        };
        assert_eq!(
            ingress_redirect_action(&config, &fragment),
            IngressRedirectAction::Pass,
            "a fragment carries no trustworthy L4 header; its 'ports' may be payload bytes"
        );
    }

    #[test]
    fn ipv4_fragments_are_declined_before_any_scope_decision() {
        // Third 16-bit word of the IPv4 header, host byte order.
        assert!(
            !ipv4_is_fragment(0x0000),
            "an unfragmented datagram with no flags must be parsed normally"
        );
        assert!(
            !ipv4_is_fragment(0x4000),
            "Don't-Fragment alone does not make a datagram a fragment"
        );
        assert!(
            ipv4_is_fragment(0x2000),
            "the FIRST fragment (More-Fragments, offset 0) must be declined: its successors \
             would not be redirected, splitting one datagram across two destinations"
        );
        assert!(
            ipv4_is_fragment(0x0001),
            "a non-first fragment (offset 8 bytes) must be declined"
        );
        assert!(
            ipv4_is_fragment(0x00b9),
            "a mid-stream non-first fragment must be declined"
        );
        assert!(
            ipv4_is_fragment(0x2001),
            "More-Fragments AND a non-zero offset (a middle fragment) must be declined"
        );
        assert!(
            ipv4_is_fragment(0x1fff),
            "the maximum fragment offset must be declined"
        );
        // Reserved / DF bits must not be mistaken for fragmentation.
        assert!(!ipv4_is_fragment(0x8000), "the reserved bit is not MF");
        assert!(!ipv4_is_fragment(0xc000), "reserved + DF is still not MF");

        // A fragment whose payload bytes happen to look like a declared port is
        // the exact misattribution this gate exists to prevent.
        let config = armed_redirect_config();
        let spoofed = IngressRedirectPacket {
            fragmented: true,
            ..IngressRedirectPacket::fully_in_scope(8080)
        };
        assert_eq!(
            ingress_redirect_action(&config, &spoofed),
            IngressRedirectAction::Pass,
            "a fragment must never be steered — and, just as importantly, never DROPPED as an \
             in-scope packet, because the port it appears to carry is attacker-chosen data"
        );
    }

    #[test]
    fn ingress_redirect_is_inert_until_armed() {
        let in_scope = IngressRedirectPacket::fully_in_scope(8080);

        // Default (opt-out) posture: no redirect mark published.
        let disarmed = BpfCaptureConfig::new(15001, INBOUND_HBONE_PORT);
        assert_eq!(
            ingress_redirect_action(&disarmed, &in_scope),
            IngressRedirectAction::Pass,
            "a node that was never opted in must behave exactly as before"
        );

        // A capture port of zero means there is no listener to steer into, so
        // the program must pass rather than drop in-scope traffic — even with a
        // perfectly live HBONE port configured.
        let no_capture_listener = BpfCaptureConfig::new(15001, INBOUND_HBONE_PORT)
            .with_node_waypoint_ingress_redirect_mark(NODE_WAYPOINT_INGRESS_REDIRECT_MARK);
        assert_eq!(
            ingress_redirect_action(&no_capture_listener, &in_scope),
            IngressRedirectAction::Pass
        );
    }

    #[test]
    fn ingress_redirect_loop_guards_pass_relay_owned_traffic() {
        let config = armed_redirect_config();

        // (1) the relay's own authorized dial down to the local backend pod.
        let relay_dial = IngressRedirectPacket {
            skb_mark: NODE_WAYPOINT_INBOUND_AUTH_MARK,
            ..IngressRedirectPacket::fully_in_scope(8080)
        };
        assert_eq!(
            ingress_redirect_action(&config, &relay_dial),
            IngressRedirectAction::Pass,
            "redirecting the relay's own backend dial would feed it its own traffic forever"
        );

        // (2) a packet this program (or a peer hook) already redirected.
        let already_redirected = IngressRedirectPacket {
            skb_mark: NODE_WAYPOINT_INGRESS_REDIRECT_MARK,
            ..IngressRedirectPacket::fully_in_scope(8080)
        };
        assert_eq!(
            ingress_redirect_action(&config, &already_redirected),
            IngressRedirectAction::Pass,
            "a packet must never be redirected twice"
        );

        // (3) traffic already aimed at the CAPTURE listener — the self-capture
        // guard proper.
        let to_the_capture_listener =
            IngressRedirectPacket::fully_in_scope(NODE_WAYPOINT_INGRESS_CAPTURE_PORT);
        assert_eq!(
            ingress_redirect_action(&config, &to_the_capture_listener),
            IngressRedirectAction::Pass,
            "traffic already addressed to the capture listener must reach it directly"
        );

        // (4) peer-to-peer HBONE. A different protocol boundary that must never
        // be fed captured plaintext.
        let to_hbone = IngressRedirectPacket::fully_in_scope(INBOUND_HBONE_PORT);
        assert_eq!(
            ingress_redirect_action(&config, &to_hbone),
            IngressRedirectAction::Pass,
            "HBONE traffic addressed to the HBONE listener must reach it directly"
        );

        // An unrelated CNI mark is NOT a bypass — otherwise a co-resident CNI
        // could switch the redirect off per packet.
        let foreign_mark = IngressRedirectPacket {
            skb_mark: 0x0F00,
            ..IngressRedirectPacket::fully_in_scope(8080)
        };
        assert_eq!(
            ingress_redirect_action(&config, &foreign_mark),
            IngressRedirectAction::Steer
        );
    }

    #[test]
    fn a_zero_auth_mark_never_bypasses_every_unmarked_packet() {
        // Local-pod mode publishes a zero inbound auth mark. If a zero
        // configured mark matched, `skb_mark == 0` (the overwhelming majority of
        // packets) would read as "already relayed" and disable the redirect.
        let config = BpfCaptureConfig::new(15001, INBOUND_HBONE_PORT)
            .with_node_waypoint_inbound_auth_mark(0)
            .with_node_waypoint_ingress_redirect_mark(NODE_WAYPOINT_INGRESS_REDIRECT_MARK)
            .with_node_waypoint_ingress_capture_port(NODE_WAYPOINT_INGRESS_CAPTURE_PORT);
        assert!(!config.ingress_redirect_bypass(0, 8080));
        assert_eq!(
            ingress_redirect_action(&config, &IngressRedirectPacket::fully_in_scope(8080)),
            IngressRedirectAction::Steer
        );
    }

    #[test]
    fn ingress_redirect_bypasses_the_relays_own_authorized_dial() {
        let config = armed_redirect_config();
        // The relay dials the backend pod with the auth mark. Redirecting that
        // packet would feed the relay its own traffic in a loop.
        assert!(config.ingress_redirect_bypass(NODE_WAYPOINT_INBOUND_AUTH_MARK, 8080));
        // A packet this program already redirected must never be redirected
        // again.
        assert!(config.ingress_redirect_bypass(NODE_WAYPOINT_INGRESS_REDIRECT_MARK, 8080));
        // Traffic already aimed at the capture listener reaches it directly.
        assert!(config.ingress_redirect_bypass(0, NODE_WAYPOINT_INGRESS_CAPTURE_PORT));
        // ... and so does peer-to-peer HBONE.
        assert!(config.ingress_redirect_bypass(0, INBOUND_HBONE_PORT));
        // Ordinary inbound app traffic is NOT bypassed.
        assert!(!config.ingress_redirect_bypass(0, 8080));
        // An unrelated CNI mark is not mistaken for either Ferrum mark.
        assert!(!config.ingress_redirect_bypass(0xF00, 8080));
    }

    #[test]
    fn ingress_redirect_steer_predicate_matches_the_action() {
        let config = armed_redirect_config();
        assert!(
            ingress_redirect_action(&config, &IngressRedirectPacket::fully_in_scope(8080))
                .is_steer()
        );
        assert!(!ingress_redirect_action(
            &config,
            &IngressRedirectPacket::fully_in_scope(NODE_WAYPOINT_INGRESS_CAPTURE_PORT)
        )
        .is_steer());
        assert!(!ingress_redirect_action(
            &config,
            &IngressRedirectPacket::fully_in_scope(INBOUND_HBONE_PORT)
        )
        .is_steer());
    }

    #[test]
    fn node_waypoint_marks_are_mutually_distinct() {
        // Loop prevention keys off the auth mark; local delivery keys off the
        // redirect mark. Collapsing them would make a redirected packet
        // indistinguishable from an authorized relay dial.
        assert_ne!(
            NODE_WAYPOINT_INGRESS_REDIRECT_MARK,
            NODE_WAYPOINT_INBOUND_AUTH_MARK
        );
        // Must not alias the common masked CNI mark classes (Cilium: 0xF00).
        assert_ne!(NODE_WAYPOINT_INGRESS_REDIRECT_MARK & 0xF00, 0xF00);
        // The local-delivery rule must sort below the kernel `main` rule.
        assert!(NODE_WAYPOINT_INGRESS_REDIRECT_RULE_PRIORITY < 32766);
        assert_eq!(NODE_WAYPOINT_INGRESS_REDIRECT_TABLE, 33134);
    }

    #[test]
    fn node_waypoint_inbound_auth_mark_round_trips() {
        assert_eq!(
            BpfCaptureConfig::new(15001, 15008).node_waypoint_inbound_auth_mark,
            NODE_WAYPOINT_INBOUND_AUTH_MARK
        );
        assert_eq!(
            BpfCaptureConfig::new(15001, 15008)
                .with_node_waypoint_inbound_auth_mark(0x735)
                .node_waypoint_inbound_auth_mark,
            0x735
        );
    }
}
