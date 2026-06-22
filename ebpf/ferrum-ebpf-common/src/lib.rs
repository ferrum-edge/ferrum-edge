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
/// `sock_ops` bridge is currently IPv4-only, so this type is the documented v6
/// wire format for the eventual IPv6 follow-up. `_pad` keeps `netns_cookie`
/// 8-byte aligned with no implicit padding.
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
    pub _pad: u32,
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
    /// hook returns `EPERM`) instead of redirected. Set in NodeWaypoint in-netns
    /// capture mode, whose in-netns listener and GAP-2M sock-ops bridge are
    /// IPv4-only: without it, captured IPv6 egress would bypass `mesh_authz`
    /// entirely instead of failing closed. Excluded v6 (bypass UID / port / CIDR
    /// excludes) is decided before the deny and still flows.
    pub ipv6_outbound_deny: u32,
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

/// Inbound HBONE port. TC ingress redirects inbound packets here.
pub const INBOUND_HBONE_PORT: u16 = 15008;

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
pub const SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY: u32 = 7;
pub const SOCK_OPS_EVENT_DROP_REASON: u32 = 8;

// `SockOpsRecord::direction` values. Zero is "unused".
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
        }
    }

    /// Set whether captured IPv6 outbound connections fail closed (denied) —
    /// see [`Self::ipv6_outbound_deny`].
    pub const fn with_ipv6_outbound_deny(mut self, deny: bool) -> Self {
        self.ipv6_outbound_deny = deny as u32;
        self
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
        assert_eq!(mem::size_of::<BpfCaptureConfig>(), 12);
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
        // IPv6 egress is redirected (not denied) by default; the deny is opt-in
        // for the IPv4-only NodeWaypoint in-netns datapath.
        assert_eq!(config.ipv6_outbound_deny, 0);
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
}
