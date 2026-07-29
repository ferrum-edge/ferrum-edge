//! BPF map definitions shared across all Ferrum capture programs.
//!
//! Maps are pinned to `/sys/fs/bpf/` by the userspace loader so they persist
//! across program reloads and can be read by the proxy.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf};
use ferrum_ebpf_common::{
    BpfCaptureConfig, CidrKey4, CidrKey6, ConnTuple4, ConnTuple6, InboundRedirectKey4,
    InboundRedirectKey6, IncludePortsPolicy, NodeProbePortKey4, NodeProbePortKey6, OrigDst4,
    OrigDst6, OrigDstKey, PodInfo, WorkloadIdentity, SOCK_OPS_RINGBUF_DEFAULT_BYTES,
    SOCK_OPS_STATS_LEN,
};

/// Original IPv4 destination before connect rewrite, keyed by socket cookie.
/// The proxy reads this map (via pinned path) to discover the real target.
#[map]
pub static FERRUM_ORIG_DST4: LruHashMap<OrigDstKey, OrigDst4> =
    LruHashMap::with_max_entries(65536, 0);

/// Original IPv6 destination before connect rewrite.
#[map]
pub static FERRUM_ORIG_DST6: LruHashMap<OrigDstKey, OrigDst6> =
    LruHashMap::with_max_entries(65536, 0);

/// GAP-2M accept-side cookie bridge (IPv4): the original destination re-keyed
/// by the connection 4-tuple. The `sock_ops` program writes this at
/// active-established (copying the connect-side record from `FERRUM_ORIG_DST4`)
/// and consumes it at passive-established to re-stamp `FERRUM_ORIG_DST4` under
/// the proxy's accept-side socket cookie. Kernel-internal: not pinned, not read
/// by userspace.
#[map]
pub static FERRUM_ORIG_DST_BY_TUPLE4: LruHashMap<ConnTuple4, OrigDst4> =
    LruHashMap::with_max_entries(65536, 0);

/// GAP-2M callback-order bridge (IPv4): when `PASSIVE_ESTABLISHED` fires before
/// `ACTIVE_ESTABLISHED` for an in-netns loopback connection, remember the
/// accept-side cookie under the same tuple so the later active callback can stamp
/// `FERRUM_ORIG_DST4`. Kernel-internal: not pinned, not read by userspace.
#[map]
pub static FERRUM_ACCEPT_COOKIE_BY_TUPLE4: LruHashMap<ConnTuple4, u64> =
    LruHashMap::with_max_entries(65536, 0);

/// GAP-2M accept-side cookie bridge (IPv6): the IPv6 analogue of
/// `FERRUM_ORIG_DST_BY_TUPLE4`. The `sock_ops` program writes this at
/// active-established (copying the connect-side record from `FERRUM_ORIG_DST6`)
/// and consumes it at passive-established to re-stamp `FERRUM_ORIG_DST6` under
/// the proxy's accept-side socket cookie. The bridge reads the IPv6 ctx address
/// fields element-by-element with verifier-safe volatile loads (see
/// `sock_ops.rs`), so IPv6 node-waypoint resolution now resolves on the same
/// footing as IPv4. Kernel-internal: not pinned, not read by userspace.
#[map]
pub static FERRUM_ORIG_DST_BY_TUPLE6: LruHashMap<ConnTuple6, OrigDst6> =
    LruHashMap::with_max_entries(65536, 0);

/// IPv6 counterpart to `FERRUM_ACCEPT_COOKIE_BY_TUPLE4`.
#[map]
pub static FERRUM_ACCEPT_COOKIE_BY_TUPLE6: LruHashMap<ConnTuple6, u64> =
    LruHashMap::with_max_entries(65536, 0);

/// Enrolled pod IPs. Keyed by IPv4 address (network byte order `u32`).
/// TC ingress checks this to decide whether to redirect inbound packets.
#[map]
pub static FERRUM_POD_IPS: HashMap<u32, PodInfo> = HashMap::with_max_entries(4096, 0);

/// Enrolled pod IPv6 addresses. Keyed by exact IPv6 address in the same word
/// layout used by the connect6/orig-dst maps.
#[map]
pub static FERRUM_POD_IPS6: HashMap<CidrKey6, PodInfo> = HashMap::with_max_entries(4096, 0);

/// Local node IPv4 addresses that may be considered for the kubelet probe
/// exemption. The tc guard also requires an exact pod-IP/probe-port entry.
#[map]
pub static FERRUM_NODE_IPS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Local node IPv6 addresses that may be considered for the kubelet probe
/// exemption. The tc guard also requires an exact pod-IP/probe-port entry.
#[map]
pub static FERRUM_NODE_IPS6: HashMap<CidrKey6, u8> = HashMap::with_max_entries(256, 0);

/// Enrolled pod IPv4 TCP ports that may be reached directly from configured
/// local node IPs for Kubernetes HTTP/TCP/gRPC probes.
#[map]
pub static FERRUM_NODE_PROBE_PORTS: HashMap<NodeProbePortKey4, u8> =
    HashMap::with_max_entries(16384, 0);

/// IPv6 counterpart to `FERRUM_NODE_PROBE_PORTS`.
#[map]
pub static FERRUM_NODE_PROBE_PORTS6: HashMap<NodeProbePortKey6, u8> =
    HashMap::with_max_entries(16384, 0);

/// Inbound TCP application ports the NodeWaypoint relay is authorized to
/// terminate on behalf of an enrolled IPv4 pod.
///
/// `ferrum_tc_ingress_redirect` requires an exact `(pod address, destination
/// port)` hit before it steers a packet into the local relay, so the redirect
/// is scoped to the ports the enrolled workload actually declares. An enrolled
/// pod's undeclared ports and every un-enrolled pod are left untouched.
#[map]
pub static FERRUM_POD_INBOUND_PORTS: HashMap<InboundRedirectKey4, u8> =
    HashMap::with_max_entries(16384, 0);

/// IPv6 counterpart to `FERRUM_POD_INBOUND_PORTS`.
#[map]
pub static FERRUM_POD_INBOUND_PORTS6: HashMap<InboundRedirectKey6, u8> =
    HashMap::with_max_entries(16384, 0);

/// UIDs exempt from outbound capture (proxy UID 1337).
/// Connect hooks skip rewrite when the calling process matches.
#[map]
pub static FERRUM_BYPASS_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// IPv4 CIDRs to exclude from outbound capture (highest priority).
#[map]
pub static FERRUM_CIDR_EXCLUDE4: LpmTrie<CidrKey4, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv6 CIDRs to exclude from outbound capture.
#[map]
pub static FERRUM_CIDR_EXCLUDE6: LpmTrie<CidrKey6, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv4 CIDRs to include for outbound capture (default 0.0.0.0/0 = all).
#[map]
pub static FERRUM_CIDR_INCLUDE4: LpmTrie<CidrKey4, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv6 CIDRs to include for outbound capture.
#[map]
pub static FERRUM_CIDR_INCLUDE6: LpmTrie<CidrKey6, u8> = LpmTrie::with_max_entries(1024, 0);

/// Destination ports to exclude from outbound capture.
#[map]
pub static FERRUM_PORT_EXCLUDE: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

/// Per-cgroup `includeOutboundPorts` narrowing policy, keyed by cgroup id
/// (`bpf_get_current_cgroup_id`). Absent entry → capture all ports (pod is
/// not annotated). Entry with `all_ports != 0` → capture all ports (`*`
/// wildcard). Entry with explicit ports → capture only those ports. See
/// `IncludePortsPolicy` for the wire shape.
#[map]
pub static FERRUM_INCLUDE_PORTS: HashMap<u64, IncludePortsPolicy> =
    HashMap::with_max_entries(4096, 0);

/// Singleton node-agent capture settings.
#[map]
pub static FERRUM_CAPTURE_CONFIG: HashMap<u32, BpfCaptureConfig> = HashMap::with_max_entries(1, 0);

/// Per-cgroup source workload identity, keyed by cgroup id
/// (`bpf_get_current_cgroup_id`). The node-agent writes one entry per enrolled
/// pod cgroup; the connect hooks read it to stamp the original-destination
/// record (`FERRUM_ORIG_DST4/6`) with the source pod's UID and SPIFFE hash.
/// Absent entry → identity is unknown and the connect hook stores the all-zero
/// sentinel, which node-waypoint resolution treats as fail-closed. Sized to
/// match `FERRUM_INCLUDE_PORTS` (one entry per enrolled cgroup).
#[map]
pub static FERRUM_WORKLOAD_IDENTITY: HashMap<u64, WorkloadIdentity> =
    HashMap::with_max_entries(4096, 0);

/// SOCK_OPS event ringbuf. Sized at load time by the userspace loader from
/// `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES`; the kernel default here
/// (`SOCK_OPS_RINGBUF_DEFAULT_BYTES`, 4 MiB) is the fallback when the
/// loader leaves the size unchanged.
#[map]
pub static FERRUM_SOCK_OPS_EVENTS: RingBuf =
    RingBuf::with_byte_size(SOCK_OPS_RINGBUF_DEFAULT_BYTES, 0);

/// SOCK_OPS per-program counters. Index `SOCK_OPS_STATS_EVENTS_DROPPED`
/// tracks events that could not be reserved on the ringbuf (kernel-side
/// "overrun" signal that userspace polls for warn/recover state machine).
/// Per-CPU so the kernel-side increment is contention-free; userspace sums
/// across CPUs when reading.
#[map]
pub static FERRUM_SOCK_OPS_STATS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(SOCK_OPS_STATS_LEN, 0);

/// Per-socket cookie timestamps captured at outbound `TCP_CONNECT_CB` and
/// consumed at `ACTIVE_ESTABLISHED_CB` so we can emit a SynToAck latency
/// sample. Bounded LRU so listening sockets that never connect cannot
/// grow the map unboundedly.
#[map]
pub static FERRUM_SOCK_OPS_CONNECT_TS: LruHashMap<u64, u64> =
    LruHashMap::with_max_entries(65536, 0);
