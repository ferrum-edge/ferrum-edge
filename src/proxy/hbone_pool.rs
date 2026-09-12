//! Gateway-to-mesh HBONE connection pool.
//!
//! The pool owns HTTP/2 client connections to mesh sidecars on the standard
//! HBONE listener. Each request opens a CONNECT stream to the application port
//! and then speaks ordinary HTTP over the resulting byte tunnel.

use crate::fips::approved::Sha256;
use bytes::{Buf, Bytes};
use dashmap::DashMap;
use futures_util::FutureExt;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Method, Request, StatusCode, Version};
use std::cell::RefCell;
use std::fmt::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(test)]
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error};

use crate::config::PoolConfig;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::dns::DnsCache;
use crate::identity::{SharedSvidBundle, SvidBundle};
use crate::modes::mesh::hbone::{
    BAGGAGE_HEADER, ISTIO_HBONE_PORT, UdpSourceIdentity, baggage_header_for_source,
    baggage_header_for_udp_source,
};
use crate::pool::{SharedCreationRole, SharedCreationSlot};
use crate::proxy::mesh_trust_registry::{
    MESH_KEEPALIVE_FAILED_MESSAGE, MeshTransportGate, MeshTransportKind, MeshTransportRegistration,
    MeshTrustRegistry,
};
use crate::retry::{ErrorClass, error_class_log_kind};
use crate::tls::backend::BackendSvidGeneration;
use crate::tls::spiffe::{SpiffeTlsError, build_spiffe_outbound_config};
use arc_swap::ArcSwap;

pub const HBONE_TARGET_TAG: &str = "mesh.hbone";
pub const HBONE_PORT_TAG: &str = "mesh.hbone_port";
/// Optional tag carrying the outer TCP/TLS dial host for an HBONE target. When
/// absent, the target host is both the dial host and CONNECT authority host.
pub const HBONE_DIAL_HOST_TAG: &str = "mesh.hbone_dial_host";
/// Optional tag carrying the inner HBONE CONNECT `:authority` HOST for a target
/// whose `UpstreamTarget.host` is a SCOPED SYNTHETIC identity rather than a real
/// dialable address. This is set for AMBIENT CROSS-CLUSTER targets: their
/// `target.host` is a `(network/gateway, pod IP)`-scoped synthetic so that the
/// load balancer / passive+active health / circuit breaker / retry-exclusion
/// keys (all keyed on `host:port`) never collapse two REMOTE pods that share a
/// pod IP across overlapping CIDRs but are reached through DIFFERENT east-west
/// gateways. The real destination pod addr (the inner CONNECT `:authority` the
/// dest relay dials under the open-relay guard) rides here so dispatch reads it
/// for `app_host` instead of the synthetic `target.host`. ABSENT for every
/// in-cluster target — `target.host` is then both the identity and the CONNECT
/// authority host, byte-identical to the pre-cross-cluster behavior.
pub const HBONE_AUTHORITY_HOST_TAG: &str = "mesh.hbone_authority_host";
/// Prefix of the SCOPED SYNTHETIC `UpstreamTarget.host` minted for AMBIENT
/// CROSS-CLUSTER HBONE targets (see [`HBONE_AUTHORITY_HOST_TAG`]). One shared
/// constant on purpose: the mesh materializer MINTS the synthetic host with it
/// (`modes::mesh::cross_cluster_hbone_synthetic_host`) and SD target validation
/// RECOGNIZES it (`service_discovery::is_synthetic_cross_cluster_hbone_target`)
/// so it can validate the real dial/authority hosts instead of the synthetic
/// identity — if the two strings drifted, every discovered cross-cluster target
/// would fail real-hostname validation and be silently dropped (remote failover
/// vanishes fail-closed).
pub const HBONE_CROSS_CLUSTER_SYNTHETIC_HOST_PREFIX: &str = "mesh-xc-hbone|";
/// Optional tag overriding the server SVID the HBONE mTLS handshake pins. This
/// is used when the peer is a waypoint/relay identity rather than the workload
/// identity carried in [`MESH_SPIFFE_ID_TAG`].
pub const HBONE_PEER_SPIFFE_ID_TAG: &str = "mesh.hbone_peer_spiffe_id";
/// Tag carrying the destination workload's SPIFFE id. When present on a mesh
/// target it is the identity the outbound SVID-mTLS handshake must PIN: the
/// peer's server SVID URI SAN has to equal it exactly, not merely share a trust
/// domain. Stamped by `service_discovery::mesh` tag builders for both HBONE and
/// Sidecar-mTLS targets.
pub const MESH_SPIFFE_ID_TAG: &str = "mesh.spiffe_id";
const MAX_HBONE_WRITE_CHUNK: usize = 16 * 1024;
/// Receive-side `SETTINGS_MAX_HEADER_LIST_SIZE` used when no operator policy has
/// been installed via [`HboneConnectionPool::attach_max_header_list_size`].
///
/// This deliberately matches hyper's own 16 KiB default — the bound every
/// sibling backend transport (`http2_pool.rs`, `grpc_proxy.rs`,
/// `mesh_mtls_pool.rs`) already rides — rather than `h2`'s 16 MiB default, which
/// would let any SVID-holding peer buffer a multi-megabyte response header
/// block per HBONE connection.
pub const HBONE_DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;
const ADAPTIVE_STREAM_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
const ADAPTIVE_CONNECTION_WINDOW_SIZE: u32 = 64 * 1024 * 1024;
/// Bounded poll for the peer's `SETTINGS_ENABLE_CONNECT_PROTOCOL` acknowledgement
/// when opening a WebSocket Extended CONNECT over a freshly handshaked H2
/// connection (see [`open_h2_ws_connect_stream`]). The setting rides the peer's
/// initial SETTINGS frame, processed asynchronously by the connection driver, so
/// one yield + a few short sleeps let a capable peer's frame land before the dial
/// fails closed. The interval is tiny and the count small: SETTINGS is the first
/// frame, so this resolves in well under a millisecond on a healthy connection.
const EXTENDED_CONNECT_SETTINGS_POLL_ATTEMPTS: u32 = 10;
const EXTENDED_CONNECT_SETTINGS_POLL_INTERVAL: Duration = Duration::from_millis(5);

thread_local! {
    static HBONE_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(160));
}

#[derive(Debug)]
struct HbonePoolEntry {
    transport: MeshH2Transport,
    /// Unix seconds of the last checkout. Stored atomically so the shared-lock
    /// fast path (`try_cached_sender_read`) can refresh recency without taking
    /// the exclusive shard write lock — a busy connection must not be pruned as
    /// idle merely because it is only ever served by the fast path.
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
}

enum CachedSender {
    Ready(MeshH2Transport),
    Pending(MeshH2Transport),
}

/// One established gateway-to-mesh HTTP/2 transport, carried together with the
/// retirement gate that owns it (issue #3859).
///
/// The gate travels WITH the sender rather than living in the pool map, which
/// is the whole point: a caller that clones the sender, takes a tunnel out of
/// the pool, or holds a 1:1 WebSocket/datagram bridge still carries a handle the
/// trust-withdrawal sweep can reach. Cloning is two `Arc` bumps.
#[derive(Clone)]
pub(crate) struct MeshH2Transport {
    pub(crate) sender: SendRequest<Bytes>,
    pub(crate) gate: MeshTransportGate,
}

impl std::fmt::Debug for MeshH2Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep diagnostics useful without requiring hyper's sender or the
        // cancellation primitive to expose their internal state. The only
        // transport-lifetime property callers may act on is retirement.
        formatter
            .debug_struct("MeshH2Transport")
            .field("retired", &self.is_retired())
            .field("keepalive_failed", &self.keepalive_failed())
            .finish_non_exhaustive()
    }
}

impl MeshH2Transport {
    /// Wrap a sender with a gate that is never retired. For focused tests and
    /// standalone callers that run without a registry.
    #[cfg(test)]
    pub(crate) fn ungoverned(sender: SendRequest<Bytes>) -> Self {
        Self {
            sender,
            gate: MeshTransportGate::new(),
        }
    }

    fn is_retired(&self) -> bool {
        self.gate.is_retired()
    }

    fn keepalive_failed(&self) -> bool {
        self.gate.keepalive_failed()
    }
}

/// Handle the HBONE pool's keepalive task uses to evict *this* transport from
/// the pool map (issue #4162). Identity is the gate `Arc`, so a newer entry
/// under the same key is left alone.
#[derive(Clone)]
pub(crate) struct HboneKeepalivePoolHandle {
    entries: Arc<DashMap<String, Vec<HbonePoolEntry>>>,
    key: String,
}

impl HboneKeepalivePoolHandle {
    fn evict(&self, gate: &MeshTransportGate) {
        evict_hbone_entry_for_gate(&self.entries, &self.key, gate);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HbonePoolError {
    #[error("gateway SVID bundle is not configured")]
    NoSvid,
    #[error("gateway SVID bundle has no leaf certificate")]
    NoLeafCert,
    #[error("DNS resolution failed for {host}: {message}")]
    DnsLookup { host: String, message: String },
    #[error("connect timeout after {timeout_ms}ms to {addr}")]
    ConnectTimeout { addr: String, timeout_ms: u64 },
    #[error("TCP connect failed to {addr}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid mesh TLS server name {host}: {message}")]
    InvalidServerName { host: String, message: String },
    #[error("invalid {HBONE_DIAL_HOST_TAG} tag '{value}' on mesh target: {message}")]
    InvalidDialHostTag { value: String, message: String },
    #[error("invalid {HBONE_AUTHORITY_HOST_TAG} tag '{value}' on mesh target: {message}")]
    InvalidAuthorityHostTag { value: String, message: String },
    #[error("invalid {MESH_SPIFFE_ID_TAG} tag '{value}' on mesh target: {message}")]
    InvalidPeerSpiffeTag { value: String, message: String },
    #[error("SPIFFE TLS config failed: {0}")]
    TlsConfig(#[from] SpiffeTlsError),
    #[error("TLS handshake failed for {host}: {source}")]
    TlsHandshake {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP/2 handshake failed for {host}: {message}")]
    H2Handshake { host: String, message: String },
    #[error("failed to build HBONE CONNECT request for {authority}: {message}")]
    InvalidConnectRequest { authority: String, message: String },
    #[error("HBONE CONNECT failed for {authority}: {message}")]
    ConnectStream { authority: String, message: String },
    #[error("HBONE CONNECT rejected for {authority} with status {status}")]
    ConnectRejected { authority: String, status: u16 },
    /// A gateway trust authority was withdrawn while this transport was being
    /// established, or the transport it would have reused has since been
    /// retired (issue #3859). Fail closed: the connection is dropped rather
    /// than pooled or returned. The message is deliberately fixed and carries
    /// no trust material, subject, key id, fingerprint, or peer identity.
    #[error(
        "gateway-to-mesh transport refused: gateway trust authority withdrawn before the connection could be admitted"
    )]
    TrustWithdrawn,
    /// The destination is already at its DestinationRule
    /// `connectionPool.tcp.maxConnections` ceiling, so no NEW physical tunnel
    /// connection may be opened. Nothing was dialed — a pre-wire, health-neutral
    /// refusal classified `BackendConnectionLimit`, and NOT a capability failure
    /// (the peer's HBONE/mesh-mTLS support is unchanged; only the gateway's own
    /// ceiling was reached).
    #[error("backend maxConnections reached for {host}:{port}: {current} open (cap {cap})")]
    MaxConnectionsExceeded {
        host: String,
        port: u16,
        current: u64,
        cap: u64,
    },
    #[error(
        "peer at {authority} did not negotiate SETTINGS_ENABLE_CONNECT_PROTOCOL; \
         cannot open a WebSocket Extended CONNECT (RFC 8441) stream"
    )]
    ExtendedConnectUnsupported { authority: String },
    /// Cross-cluster east-west Ambient target with a missing / empty
    /// `mesh.eastwest_sni` tag — the destination-FQDN SNI the remote gateway's
    /// passthrough routes on is mandatory (never dial the gateway IP as SNI).
    /// A PRE-WIRE fail-closed reject: no gateway is dialed. Mirrors the Sidecar
    /// `MeshMtlsDialError::MissingCrossClusterSni` so the WebSocket egress path
    /// can box a TYPED error that `classify_boxed_setup_error` recognizes as
    /// pre-wire (issue #2010 codex).
    #[error(
        "cross-cluster Ambient HBONE target missing mesh.eastwest_sni \
         (fail closed, never dial the gateway address as SNI)"
    )]
    MissingCrossClusterSni,
    /// Cross-cluster east-west Ambient target with a missing / empty /
    /// unparseable `mesh.trust_domain` tag — the remote trust domain verification
    /// is scoped to is mandatory (never fall back to any-federated verification).
    /// A PRE-WIRE fail-closed reject: no gateway is dialed.
    #[error(
        "cross-cluster Ambient HBONE target missing mesh.trust_domain \
         (fail closed, never any-federated verification)"
    )]
    MissingCrossClusterTrustDomain,
    /// Cross-cluster east-west Ambient target with a missing / empty
    /// `mesh.hbone_authority_host` tag. For a cross-cluster target `target.host`
    /// is the SCOPED SYNTHETIC identity (`mesh-xc-hbone|...`), so
    /// `target_hbone_authority_host()` would fall back to that synthetic key as
    /// the inner CONNECT `:authority` — establishing the east-west TLS/H2
    /// connection first and only failing LATER while building the CONNECT to the
    /// synthetic authority. This variant rejects it PRE-WIRE (before any dial),
    /// as the fail-closed invariant requires, so no gateway TLS/H2 connection is
    /// ever opened for a corrupted cross-cluster target. Mirrors the
    /// `MissingCrossClusterSni` / `MissingCrossClusterTrustDomain` pre-wire
    /// rejects (issue #2010 codex).
    #[error(
        "cross-cluster Ambient HBONE target missing mesh.hbone_authority_host \
         (fail closed, never dial to the synthetic identity as CONNECT authority)"
    )]
    MissingCrossClusterAuthorityHost,
}

impl HbonePoolError {
    pub fn error_class(&self) -> ErrorClass {
        match self {
            Self::NoSvid
            | Self::NoLeafCert
            | Self::TlsConfig(_)
            | Self::InvalidDialHostTag { .. }
            | Self::InvalidAuthorityHostTag { .. }
            | Self::InvalidPeerSpiffeTag { .. }
            | Self::MissingCrossClusterSni
            | Self::MissingCrossClusterTrustDomain
            | Self::MissingCrossClusterAuthorityHost => ErrorClass::ConnectionPoolError,
            // Pre-wire, gateway-side policy refusal: the transport is dropped
            // before any request rides it, so a retry may legitimately re-dial
            // under the freshly published trust generation — and the refusal is
            // health-NEUTRAL, because withdrawing a trust root is the operator's
            // own gateway policy, not evidence about the destination workload.
            // The generic `ConnectionPoolError` would open a circuit breaker for
            // every mesh destination the gateway was talking to at the instant
            // of the revocation (issue #3859).
            Self::TrustWithdrawn => ErrorClass::TrustWithdrawn,
            Self::DnsLookup { .. } | Self::InvalidServerName { .. } => ErrorClass::DnsLookupError,
            Self::ConnectTimeout { .. } => ErrorClass::ConnectionTimeout,
            Self::Connect { source, .. } => {
                if crate::retry::is_port_exhaustion(source) {
                    ErrorClass::PortExhaustion
                } else {
                    match source.kind() {
                        std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset => ErrorClass::ConnectionRefused,
                        std::io::ErrorKind::TimedOut => ErrorClass::ConnectionTimeout,
                        std::io::ErrorKind::BrokenPipe => ErrorClass::ConnectionClosed,
                        _ => ErrorClass::RequestError,
                    }
                }
            }
            Self::TlsHandshake { .. } => ErrorClass::TlsError,
            // The H2 handshake completes before any CONNECT/application
            // request is opened, so immutable retry bodies are safe to replay.
            Self::H2Handshake { .. } => ErrorClass::ConnectionPoolError,
            Self::InvalidConnectRequest { .. }
            | Self::ConnectStream { .. }
            | Self::ConnectRejected { .. }
            | Self::ExtendedConnectUnsupported { .. } => ErrorClass::ProtocolError,
            // Pre-wire, gateway-side ceiling refusal: no socket was opened, so
            // `retry_on_connect_failure` may rotate to another LB target with
            // its own admission lane — and the refusal is health-NEUTRAL, so a
            // saturated ceiling never trips the destination's circuit breaker /
            // passive health. That is the full raw-TCP over-cap posture.
            Self::MaxConnectionsExceeded { .. } => ErrorClass::BackendConnectionLimit,
        }
    }

    /// Whether this error is affirmative evidence that the selected peer
    /// cannot establish HBONE with the configured identity/TLS contract.
    ///
    /// DNS, TCP reachability, and post-TLS HTTP/2 preface/handshake errors
    /// fail the current request closed, but they are not capability evidence.
    /// `H2Handshake` is reached only after TLS (including ALPN) already
    /// succeeded; peer restart, EOF, or reset during the H2 handshake is
    /// transient transport loss. Marking any of these `Unsupported` would make
    /// a rolling peer restart permanent: the dispatch gate suppresses every
    /// later tunnel attempt, so live traffic can never prove recovery.
    pub fn is_capability_failure(&self) -> bool {
        match self {
            Self::NoSvid
            | Self::NoLeafCert
            | Self::InvalidServerName { .. }
            | Self::TlsConfig(_) => true,
            Self::TlsHandshake { source, .. } => tls_handshake_is_capability_failure(source),
            _ => false,
        }
    }

    /// A fixed, enumerated, redaction-safe public reason for this failure.
    ///
    /// Issue #3927: the client-visible body used to interpolate `Display`,
    /// which leaks the peer address, the CONNECT authority, and the raw rustls
    /// / SPIFFE verifier text (`invalid peer certificate: BadSignature`,
    /// subject names, trust-domain values). Every arm here is a `&'static str`
    /// chosen from the error VARIANT alone, so no host, address, SPIFFE ID,
    /// certificate subject, trust root, key material, or source-error text can
    /// reach a client through it. The same phrase is the operator-log
    /// `error_phase`; production log records on this path never interpolate
    /// `Display`. `Display` remains useful as the error value itself.
    ///
    /// Keep the reasons coarse: they name the phase that failed, never why the
    /// peer rejected us.
    pub fn public_reason(&self) -> &'static str {
        match self {
            Self::NoSvid | Self::NoLeafCert => "gateway identity unavailable",
            Self::DnsLookup { .. } | Self::InvalidServerName { .. } => "DNS resolution failed",
            Self::ConnectTimeout { .. } => "connect timed out",
            Self::Connect { .. } => "TCP connect failed",
            Self::InvalidDialHostTag { .. }
            | Self::InvalidAuthorityHostTag { .. }
            | Self::InvalidPeerSpiffeTag { .. } => "invalid mesh target metadata",
            Self::TlsConfig(_) => "TLS configuration failed",
            Self::TlsHandshake { .. } => "TLS handshake failed",
            Self::H2Handshake { .. } => "HTTP/2 handshake failed",
            Self::InvalidConnectRequest { .. } | Self::ConnectStream { .. } => {
                "tunnel setup failed"
            }
            Self::ConnectRejected { .. } => "tunnel rejected by peer",
            Self::TrustWithdrawn => "gateway trust authority withdrawn",
            Self::MaxConnectionsExceeded { .. } => "backend connection limit reached",
            Self::ExtendedConnectUnsupported { .. } => "peer does not support WebSocket tunneling",
            Self::MissingCrossClusterSni
            | Self::MissingCrossClusterTrustDomain
            | Self::MissingCrossClusterAuthorityHost => "cross-cluster target misconfigured",
        }
    }

    /// The peer's own CONNECT admission status, when the public body may carry
    /// it. Only [`Self::ConnectRejected`] has one; every other variant returns
    /// `None`, so no other failure can grow a numeric suffix.
    ///
    /// A three-digit HTTP status is the coarse outcome of the PEER's admission
    /// decision — not an address, an identity, a certificate subject, or
    /// verifier text — and it is the only thing that separates an
    /// authorization denial (`403`) from a peer outage on an otherwise
    /// identical tunnel refusal. The NodeWaypoint eBPF live gate
    /// (`tests/k8s/node_waypoint_ebpf_live/run.sh`) matches on it to prove a
    /// forged HBONE baggage assertion was refused by destination POLICY rather
    /// than by any other transport failure, so collapsing it into the bare
    /// reason would silently coarsen that security check.
    pub fn public_status(&self) -> Option<u16> {
        match self {
            Self::ConnectRejected { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// A cloneable reconstruction of this create failure, broadcast to the
    /// coalesced waiters that joined the same in-flight mesh-pool creation
    /// attempt (issue #5046).
    ///
    /// The mesh pools hand waiters the creator's TYPED error rather than a
    /// sanitized payload, so a waiter's [`Self::error_class`],
    /// [`Self::is_capability_failure`], [`Self::public_reason`],
    /// [`Self::public_status`] and gRPC / H3 taxonomy mapping are identical to
    /// the creator's — the pre-wire classification the retry, circuit-breaker
    /// and capability-gate paths read is preserved exactly, without a second
    /// dial. The match is exhaustive on purpose: a new variant must decide how
    /// it reconstructs rather than silently degrading to a generic shape.
    ///
    /// Only the two `std::io::Error` sources cannot be cloned. They are rebuilt
    /// from the raw OS code when there is one — so both `ErrorKind` and
    /// [`crate::retry::is_port_exhaustion`]'s `raw_os_error()` survive — and
    /// from kind plus text otherwise, which is all
    /// `tls_handshake_is_capability_failure` and `error_class` read.
    pub fn clone_for_broadcast(&self) -> Self {
        match self {
            Self::NoSvid => Self::NoSvid,
            Self::NoLeafCert => Self::NoLeafCert,
            Self::DnsLookup { host, message } => Self::DnsLookup {
                host: host.clone(),
                message: message.clone(),
            },
            Self::ConnectTimeout { addr, timeout_ms } => Self::ConnectTimeout {
                addr: addr.clone(),
                timeout_ms: *timeout_ms,
            },
            Self::Connect { addr, source } => Self::Connect {
                addr: addr.clone(),
                source: clone_io_error(source),
            },
            Self::InvalidServerName { host, message } => Self::InvalidServerName {
                host: host.clone(),
                message: message.clone(),
            },
            Self::InvalidDialHostTag { value, message } => Self::InvalidDialHostTag {
                value: value.clone(),
                message: message.clone(),
            },
            Self::InvalidAuthorityHostTag { value, message } => Self::InvalidAuthorityHostTag {
                value: value.clone(),
                message: message.clone(),
            },
            Self::InvalidPeerSpiffeTag { value, message } => Self::InvalidPeerSpiffeTag {
                value: value.clone(),
                message: message.clone(),
            },
            Self::TlsConfig(source) => Self::TlsConfig(source.clone()),
            Self::TlsHandshake { host, source } => Self::TlsHandshake {
                host: host.clone(),
                source: clone_io_error(source),
            },
            Self::H2Handshake { host, message } => Self::H2Handshake {
                host: host.clone(),
                message: message.clone(),
            },
            Self::InvalidConnectRequest { authority, message } => Self::InvalidConnectRequest {
                authority: authority.clone(),
                message: message.clone(),
            },
            Self::ConnectStream { authority, message } => Self::ConnectStream {
                authority: authority.clone(),
                message: message.clone(),
            },
            Self::ConnectRejected { authority, status } => Self::ConnectRejected {
                authority: authority.clone(),
                status: *status,
            },
            Self::TrustWithdrawn => Self::TrustWithdrawn,
            Self::MaxConnectionsExceeded {
                host,
                port,
                current,
                cap,
            } => Self::MaxConnectionsExceeded {
                host: host.clone(),
                port: *port,
                current: *current,
                cap: *cap,
            },
            Self::ExtendedConnectUnsupported { authority } => Self::ExtendedConnectUnsupported {
                authority: authority.clone(),
            },
            Self::MissingCrossClusterSni => Self::MissingCrossClusterSni,
            Self::MissingCrossClusterTrustDomain => Self::MissingCrossClusterTrustDomain,
            Self::MissingCrossClusterAuthorityHost => Self::MissingCrossClusterAuthorityHost,
        }
    }
}

/// Rebuild an [`std::io::Error`] for a coalesced create-failure broadcast.
///
/// `std::io::Error` is not `Clone`. A raw-OS error is rebuilt from its code so
/// both `kind()` and `raw_os_error()` survive — the latter is what
/// [`crate::retry::is_port_exhaustion`] walks for `EADDRNOTAVAIL`. Everything
/// else (rustls handshake failures wrapped by `tokio_rustls`, custom errors)
/// keeps its kind and rendered text, which is all
/// [`HbonePoolError::error_class`] and `tls_handshake_is_capability_failure`
/// read from it.
fn clone_io_error(source: &std::io::Error) -> std::io::Error {
    match source.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(source.kind(), source.to_string()),
    }
}

/// Which mesh transport a client-visible dispatch failure came from.
///
/// Issue #3927: the Sidecar SVID-mTLS pool and the Ambient HBONE pool share
/// [`HbonePoolError`] because they share every failure shape, but they are not
/// the same topology and must not describe themselves the same way to a
/// client. A Sidecar outbound dial is plain HTTP/2 over mutual TLS to the peer
/// sidecar's `:15006` inbound listener — there is no HBONE tunnel anywhere in
/// it — so labeling its handshake failure "HBONE backend unavailable" sends the
/// operator to debug a CONNECT tunnel that was never opened. Ambient/waypoint
/// dispatch really does ride HTTP/2 CONNECT over `:15008` and keeps the HBONE
/// wording.
///
/// The label only selects the fixed public noun; classification, retry
/// accounting, and the closed-cardinality operator log fields are identical
/// on both transports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshTransportLabel {
    /// Ambient / waypoint HTTP/2 CONNECT tunnel (`:15008`).
    Hbone,
    /// Sidecar SVID-mTLS to a peer sidecar's inbound listener (`:15006`).
    SidecarMtls,
}

impl MeshTransportLabel {
    /// Client-visible noun for a dispatch failure on this transport.
    pub fn unavailable_noun(self) -> &'static str {
        match self {
            Self::Hbone => "HBONE backend unavailable",
            Self::SidecarMtls => "Sidecar mTLS backend unavailable",
        }
    }

    /// Fixed JSON error body for a dispatch failure with no further public
    /// detail (a post-dial hyper error, where the cause is already in the log).
    pub fn unavailable_body(self) -> &'static str {
        match self {
            Self::Hbone => r#"{"error":"HBONE backend unavailable"}"#,
            Self::SidecarMtls => r#"{"error":"Sidecar mTLS backend unavailable"}"#,
        }
    }

    /// Fixed JSON error body for a name-resolution failure on this transport.
    pub fn dns_failure_body(self) -> &'static str {
        match self {
            Self::Hbone => r#"{"error":"DNS resolution for HBONE backend failed"}"#,
            Self::SidecarMtls => r#"{"error":"DNS resolution for sidecar mTLS backend failed"}"#,
        }
    }

    /// Fixed JSON error body carrying the enumerated public reason from
    /// [`HbonePoolError::public_reason`], plus the peer's own admission status
    /// where [`HbonePoolError::public_status`] reports one. Accept the typed
    /// error rather than a caller-supplied string so the redaction boundary is
    /// structural: a future call site cannot accidentally pass `Display` (or
    /// another peer-derived value) into the client body.
    pub fn unavailable_body_for_error(self, error: &HbonePoolError) -> String {
        match error.public_status() {
            // Peer-decided admission status only (see
            // [`HbonePoolError::public_status`]); it is rendered from a `u16`,
            // so it can carry no peer-controlled text into the JSON body.
            Some(status) => format!(
                r#"{{"error":"{}: {} with status {status}"}}"#,
                self.unavailable_noun(),
                error.public_reason()
            ),
            None => format!(
                r#"{{"error":"{}: {}"}}"#,
                self.unavailable_noun(),
                error.public_reason()
            ),
        }
    }

    /// Operator-log noun for this transport. Used where the client-visible
    /// surface is transport-neutral (body-ceiling refusals) but the log must
    /// still name the right datapath.
    pub fn log_noun(self) -> &'static str {
        match self {
            Self::Hbone => "HBONE",
            Self::SidecarMtls => "Sidecar mTLS",
        }
    }

    /// Fixed `error!` message for a dispatch failure on this transport.
    pub fn dispatch_failure_log_message(self) -> &'static str {
        match self {
            Self::Hbone => "HBONE backend request failed",
            Self::SidecarMtls => "Sidecar mTLS backend request failed",
        }
    }

    /// Emit the operator `error!` record for a pool-setup failure on this
    /// transport.
    ///
    /// Fields are closed-cardinality: `error_kind`, `error_phase` (from
    /// [`HbonePoolError::public_reason`]), and `peer_status` only for
    /// [`HbonePoolError::ConnectRejected`]. Never interpolates `Display`, so
    /// a host, address, CONNECT authority, tag value, SPIFFE ID, certificate
    /// subject/SAN/issuer/serial/fingerprint, trust root, key id, file path,
    /// verifier message, or peer-controlled string cannot ride this record.
    pub fn log_pool_error(self, proxy_id: &str, err: &HbonePoolError) {
        let error_kind = error_class_log_kind(err.error_class());
        let error_phase = err.public_reason();
        match err.public_status() {
            Some(peer_status) => {
                error!(
                    proxy_id = %proxy_id,
                    error_kind,
                    error_phase,
                    peer_status,
                    "{}",
                    self.dispatch_failure_log_message()
                );
            }
            None => {
                error!(
                    proxy_id = %proxy_id,
                    error_kind,
                    error_phase,
                    "{}",
                    self.dispatch_failure_log_message()
                );
            }
        }
    }

    /// Fixed `error!` message for a tunneled/pooled HTTP failure after the
    /// transport was established.
    pub fn tunneled_failure_log_message(self) -> &'static str {
        match self {
            Self::Hbone => "HBONE tunneled HTTP request failed",
            Self::SidecarMtls => "Sidecar mTLS HTTP request failed",
        }
    }
}

/// Distinguish affirmative TLS protocol/identity rejection from a connection
/// that disappeared while the handshake was in flight. The latter is ordinary
/// peer-restart/reachability loss and must remain retryable so live traffic can
/// prove recovery instead of being suppressed by the capability cache.
fn tls_handshake_is_capability_failure(error: &std::io::Error) -> bool {
    !matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::Interrupted
    )
}

/// Per-key coalesced-creation slot for the HBONE pool (issue #5046).
///
/// The broadcast payload is the creator's own typed [`HbonePoolError`], shared
/// behind an `Arc` and rebuilt per waiter with
/// [`HbonePoolError::clone_for_broadcast`], so every waiter's classification,
/// capability verdict and client-visible reason match the creator's exactly.
pub(crate) type HboneCreationSlot = SharedCreationSlot<Arc<HbonePoolError>>;

/// Upper bound on retired-generation records kept while waiting for their
/// drain timers. With `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS=0` no drain
/// task ever consumes the records, so the registry must be capped or a
/// rotation storm grows it unbounded.
const MAX_RETIRED_SVID_GENERATIONS: usize = 16;
/// Upper bound on fingerprints filed under one generation. Normally a
/// generation retires exactly one fingerprint; a frozen generation counter
/// (starved rotation consumer) funnels every rotation into one bucket, which
/// must not grow unbounded either.
const MAX_RETIRED_FINGERPRINTS_PER_GENERATION: usize = 8;

pub struct HboneConnectionPool {
    entries: Arc<DashMap<String, Vec<HbonePoolEntry>>>,
    /// Per-key creation slots: the serialization mutex the pool has always
    /// used, plus the generation-scoped failure broadcast that releases every
    /// caller queued behind a failed dial instead of letting each repeat it
    /// (issue #5046).
    creation_locks: DashMap<String, Arc<HboneCreationSlot>>,
    gateway_svid: SharedSvidBundle,
    crls: crate::tls::SharedCrlList,
    svid_identity_cache: ArcSwap<Option<HboneSvidIdentityCache>>,
    /// Shared backend SVID generation counter (same `Arc` the HTTP/H2/gRPC/H3
    /// pools stamp into their `|svidg=` key fields). HBONE keys embed the SVID
    /// *fingerprint* instead, so the identity cache stamps the generation it
    /// was built under and `retired_svid_fingerprints` maps each retired
    /// generation back to its fingerprint(s) for the rotation drain.
    backend_svid_generation: BackendSvidGeneration,
    /// generation -> fingerprints that were current under that generation but
    /// have since rotated out. Written only on rotation (cold path); consumed
    /// and removed by `force_drain_svid_generation`.
    retired_svid_fingerprints: DashMap<u64, Vec<Arc<str>>>,
    dns_cache: DnsCache,
    pool_config: PoolConfig,
    last_idle_prune_unix_secs: AtomicU64,
    /// Shared gateway-wide DestinationRule `connectionPool.tcp.maxConnections`
    /// counter, installed once by `ProxyState` via
    /// [`HboneConnectionPool::attach_backend_conn_limit`]. Unset for focused
    /// tests and standalone callers, in which case no cap is enforced.
    backend_conn_limit: OnceLock<crate::backend_conn_limit::SharedBackendConnectionLimiter>,
    /// Gateway-to-mesh transport ownership registry (issue #3859), installed
    /// once by `ProxyState`. Unset for focused tests and standalone callers, in
    /// which case connections are ungoverned: they dial, pool, and serve exactly
    /// as before, and no trust withdrawal can reach them because no publication
    /// path exists without a `ProxyState` either.
    mesh_trust_registry: OnceLock<Arc<MeshTrustRegistry>>,
    /// Receive-side `SETTINGS_MAX_HEADER_LIST_SIZE` this pool advertises on every
    /// outbound HBONE h2 connection, installed once by `ProxyState` via
    /// [`HboneConnectionPool::attach_max_header_list_size`]. Unset for focused
    /// tests and standalone callers, in which case the builder falls back to
    /// [`HBONE_DEFAULT_MAX_HEADER_LIST_SIZE`] — hyper's own 16 KiB — rather than
    /// `h2`'s 16 MiB default.
    max_header_list_size: OnceLock<u32>,
}

struct HboneSvidIdentityCache {
    source: Arc<Option<SvidBundle>>,
    identity: crate::identity::SpiffeId,
    fingerprint: Arc<str>,
    /// Backend SVID generation observed when this cache entry was built.
    /// Used to file the fingerprint under the right generation once it
    /// rotates out, so `force_drain_svid_generation(old_gen)` can resolve
    /// the passed generation to the fingerprint embedded in pool keys.
    svid_generation: u64,
}

pub(crate) fn effective_connect_timeout_ms_for_policy_port(
    proxy: &Proxy,
    app_policy_port: u16,
) -> u64 {
    proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|m| m.get(&app_policy_port))
        .and_then(|o| o.connect_timeout_ms)
        .unwrap_or(proxy.backend_connect_timeout_ms)
}

impl HboneConnectionPool {
    #[allow(dead_code)] // Used by tests and external lib callers; binary wires the shared generation counter.
    pub fn new(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        shard_amount: usize,
    ) -> Self {
        Self::new_with_svid_generation(
            pool_config,
            dns_cache,
            gateway_svid,
            shard_amount,
            Arc::new(AtomicU64::new(0)),
        )
    }

    pub fn new_with_svid_generation(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        shard_amount: usize,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        Self::new_with_svid_generation_and_crls(
            pool_config,
            dns_cache,
            gateway_svid,
            Arc::new(Vec::new()),
            shard_amount,
            backend_svid_generation,
        )
    }

    pub fn new_with_svid_generation_and_crls(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        crls: crate::tls::CrlList,
        shard_amount: usize,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        Self::new_with_svid_generation_and_shared_crls(
            pool_config,
            dns_cache,
            gateway_svid,
            crate::tls::shared_crl_list(crls),
            shard_amount,
            backend_svid_generation,
        )
    }

    pub fn new_with_svid_generation_and_shared_crls(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        crls: crate::tls::SharedCrlList,
        shard_amount: usize,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        Self {
            entries: Arc::new(DashMap::with_shard_amount(shard_amount)),
            creation_locks: DashMap::with_shard_amount(shard_amount),
            gateway_svid,
            crls,
            svid_identity_cache: ArcSwap::new(Arc::new(None)),
            backend_svid_generation,
            // Low-cardinality, rotation-only map — default sharding is fine.
            retired_svid_fingerprints: DashMap::new(),
            dns_cache,
            pool_config,
            last_idle_prune_unix_secs: AtomicU64::new(0),
            backend_conn_limit: OnceLock::new(),
            mesh_trust_registry: OnceLock::new(),
            max_header_list_size: OnceLock::new(),
        }
    }

    /// Install the gateway-wide `connectionPool.tcp.maxConnections` counter so
    /// HBONE tunnel connections are admitted against the same per-destination
    /// ceiling as every other transport. Idempotent; later calls are ignored.
    pub fn attach_backend_conn_limit(
        &self,
        limiter: crate::backend_conn_limit::SharedBackendConnectionLimiter,
    ) {
        let _ = self.backend_conn_limit.set(limiter);
    }

    /// Install the operator's `FERRUM_MAX_HEADER_SIZE_BYTES` policy (floored at
    /// 16 KiB by `h2_parser_max_header_list_size`) as the receive-side
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` for every outbound HBONE h2 connection
    /// this pool dials. Additive and idempotent (`OnceLock::set`); a pool
    /// constructed without it falls back to
    /// [`HBONE_DEFAULT_MAX_HEADER_LIST_SIZE`], which is hyper's own 16 KiB
    /// default and therefore parity with every sibling backend transport.
    pub fn attach_max_header_list_size(&self, max: u32) {
        let _ = self.max_header_list_size.set(max);
    }

    /// Install the gateway trust ownership registry (issue #3859) so every HBONE
    /// transport this pool dials — pooled, WebSocket 1:1, or datagram 1:1 — is
    /// registered under the accepted gateway trust generation and can be
    /// synchronously retired when an authority is withdrawn. Idempotent; later
    /// calls are ignored.
    pub fn attach_mesh_trust_registry(&self, registry: Arc<MeshTrustRegistry>) {
        let _ = self.mesh_trust_registry.set(registry);
    }

    /// The receive-side `SETTINGS_MAX_HEADER_LIST_SIZE` this pool will advertise
    /// on its next outbound HBONE h2 handshake: the operator policy when one has
    /// been attached, otherwise [`HBONE_DEFAULT_MAX_HEADER_LIST_SIZE`].
    pub fn effective_max_header_list_size(&self) -> u32 {
        self.max_header_list_size
            .get()
            .copied()
            .unwrap_or(HBONE_DEFAULT_MAX_HEADER_LIST_SIZE)
    }

    fn trust_registry(&self) -> Option<&Arc<MeshTrustRegistry>> {
        self.mesh_trust_registry.get()
    }

    /// Resolve the `maxConnections` admission lane for a tunnel dial.
    ///
    /// The lane is keyed by the DIAL host (the peer whose socket is opened) and
    /// the destination's APP/service policy port — never the `:15008` transport
    /// listener — so an HBONE tunnel, a WebSocket session, and a raw-TCP relay
    /// to the same destination share one ceiling.
    fn conn_admission<'a>(
        &'a self,
        proxy: &'a Proxy,
        dial_host: &'a str,
        app_policy_port: u16,
    ) -> Option<crate::backend_conn_limit::PooledConnectionAdmission<'a>> {
        crate::backend_conn_limit::PooledConnectionAdmission::resolve(
            self.backend_conn_limit.get().map(|limiter| &**limiter),
            proxy,
            dial_host,
            app_policy_port,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn warmup_connection_via(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        app_host: &str,
        app_port: u16,
        app_policy_port: u16,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
    ) -> Result<(), HbonePoolError> {
        let (source_identity, fingerprint) = self.current_svid_identity_cached()?;
        let pool_config = self.pool_config.for_proxy(proxy);
        let effective_connect_timeout_ms =
            effective_connect_timeout_ms_for_policy_port(proxy, app_policy_port);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);

        // The capability-warmup probe runs only for in-cluster HBONE targets
        // (cross-cluster targets BYPASS the capability registry — they dial the
        // operator-declared gateway `:15443`, never a probeable `:15008`
        // workload), so trust-domain scope + SNI override are always `None` here.
        let fast_sender = with_hbone_pool_key(
            dial_host,
            app_port,
            hbone_port,
            proxy.dns_override.as_deref(),
            fingerprint.as_ref(),
            expected_peer,
            None,
            None,
            &pool_config,
            |key| self.try_cached_sender_read(key),
        );

        let sender = if let Some(sender) = fast_sender {
            sender
        } else {
            let key = with_hbone_pool_key(
                dial_host,
                app_port,
                hbone_port,
                proxy.dns_override.as_deref(),
                fingerprint.as_ref(),
                expected_peer,
                None,
                None,
                &pool_config,
                |key| key.to_string(),
            );
            self.get_or_create_sender(
                proxy,
                dial_host,
                app_host,
                app_port,
                app_policy_port,
                hbone_port,
                expected_peer,
                None,
                None,
                &key,
                &pool_config,
                Some(connect_timeout),
            )
            .await?
        };
        tokio::time::timeout(
            connect_timeout,
            self.open_connect_stream(sender, app_host, app_port, &source_identity),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority_for_host_port(app_host, app_port),
            message: format!(
                "timed out after {}ms waiting for HBONE CONNECT probe response",
                effective_connect_timeout_ms
            ),
        })??;
        Ok(())
    }

    pub fn pool_size(&self) -> usize {
        self.entries.iter().map(|entry| entry.value().len()).sum()
    }

    fn current_svid_identity_cached(
        &self,
    ) -> Result<(crate::identity::SpiffeId, Arc<str>), HbonePoolError> {
        let snapshot = self.gateway_svid.load_full();
        let cached = self.svid_identity_cache.load_full();
        if let Some(cache) = cached.as_ref()
            && Arc::ptr_eq(&cache.source, &snapshot)
        {
            return Ok((cache.identity.clone(), cache.fingerprint.clone()));
        }

        let bundle = snapshot.as_ref().as_ref().ok_or(HbonePoolError::NoSvid)?;
        let identity = bundle.spiffe_id.clone();
        let fingerprint: Arc<str> = Arc::from(svid_fingerprint(bundle)?);
        if let Some(previous) = cached.as_ref() {
            // The SVID slot rotated: file the outgoing fingerprint under the
            // generation it was current for, so the delayed drain task can
            // resolve `force_drain_svid_generation(old_gen)` to it. Slot
            // stores are change-gated by the rotation watcher, so EVERY
            // rebuild is a genuine material change — record even when the
            // fingerprint is unchanged (a trust-bundle-only rotation keeps
            // the leaf, but sessions verified against the previous bundle
            // must still not outlive the drain window). A same-as-current
            // fingerprint record makes that drain force a one-time reconnect
            // wave for keys that are also current; that churn is the intent.
            self.record_retired_fingerprint(previous.svid_generation, previous.fingerprint.clone());
        }
        self.svid_identity_cache
            .store(Arc::new(Some(HboneSvidIdentityCache {
                source: snapshot,
                identity: identity.clone(),
                fingerprint: fingerprint.clone(),
                svid_generation: self.backend_svid_generation.load(Ordering::Acquire),
            })));
        Ok((identity, fingerprint))
    }

    fn record_retired_fingerprint(&self, generation: u64, fingerprint: Arc<str>) {
        // Bound the per-generation list as well as the generation count: when
        // the rotation consumer is starved or dead, every rotation stamps the
        // same frozen generation and would grow one Vec unbounded while the
        // key-count cap below never trips. Overflow is drained immediately
        // (early is safe, never is not). Drains happen after the shard guard
        // is released.
        let mut overflowed: Vec<Arc<str>> = Vec::new();
        {
            let mut retired = self
                .retired_svid_fingerprints
                .entry(generation)
                .or_default();
            if !retired
                .iter()
                .any(|existing| existing.as_ref() == fingerprint.as_ref())
            {
                retired.push(fingerprint);
            }
            while retired.len() > MAX_RETIRED_FINGERPRINTS_PER_GENERATION {
                overflowed.push(retired.remove(0));
            }
        }
        if !overflowed.is_empty() {
            self.drain_retired_fingerprints(&overflowed);
        }
        // Cap the registry: with the drain window disabled nothing consumes
        // these records, and a rotation storm must not grow them unbounded.
        // An evicted record's drain timer may not have fired yet (or drains
        // may be disabled entirely) — dropping it silently would leak its
        // sessions past the configured drain window, so drain the evicted
        // fingerprints immediately: early is safe, never is not. Cold path
        // (rotation only), so the min-scan eviction is fine.
        while self.retired_svid_fingerprints.len() > MAX_RETIRED_SVID_GENERATIONS {
            let Some(oldest) = self
                .retired_svid_fingerprints
                .iter()
                .map(|entry| *entry.key())
                .min()
            else {
                break;
            };
            if let Some((_, evicted)) = self.retired_svid_fingerprints.remove(&oldest) {
                self.drain_retired_fingerprints(&evicted);
            }
        }
    }

    /// Remove every pool entry and creation lock whose key embeds one of the
    /// `retired` SVID fingerprints.
    fn drain_retired_fingerprints(&self, retired: &[Arc<str>]) {
        let fingerprint_retired = |key: &str| {
            hbone_key_svid_fingerprint(key)
                .is_some_and(|fingerprint| retired.iter().any(|fp| fp.as_ref() == fingerprint))
        };
        let mut evicted = 0usize;
        self.entries.retain(|key, entries| {
            let drain = fingerprint_retired(key);
            if drain {
                evicted = evicted.saturating_add(entries.len());
            }
            !drain
        });
        self.creation_locks
            .retain(|key, _| !fingerprint_retired(key));
        record_hbone_evictions(evicted);
    }

    /// Drain pool entries belonging to the retired SVID `generation` — and to
    /// any older generation whose record is still pending.
    ///
    /// Mirrors the `SvidGenerationMatcher` semantics of the HTTP/H2/gRPC/H3
    /// pools: generations NEWER than the passed one are never touched, so
    /// overlapping rotation drain windows (A→B→C within one
    /// `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` window) never drain a newer
    /// generation's connections before that generation's own timer fires.
    /// HBONE keys embed the SVID *fingerprint* rather than the generation, so
    /// the identity cache records which fingerprint was current under each
    /// generation and this method resolves the passed generation through that
    /// registry.
    ///
    /// The sweep is `<= generation` rather than `== generation` to close the
    /// slot-swap/generation-store race: the rotation watcher swaps the SVID
    /// slot BEFORE the async rotation consumer advances
    /// `backend_svid_generation`, so traffic landing in that window stamps the
    /// incoming fingerprint with the outgoing generation and the next rotation
    /// files it one generation too low. Drain timers fire in rotation order
    /// with equal delays, so a record misfiled under an already-drained older
    /// generation is picked up by the next drain instead of leaking until idle
    /// pruning.
    pub fn force_drain_svid_generation(&self, generation: u64) {
        // Refresh the identity cache first so a rotation with no HBONE traffic
        // since the SVID slot swap still records the outgoing fingerprint.
        if self.current_svid_identity_cached().is_err() {
            // No SVID in the slot: every pooled connection is stale.
            self.force_drain_all();
            return;
        }

        let stale_generations: Vec<u64> = self
            .retired_svid_fingerprints
            .iter()
            .map(|entry| *entry.key())
            .filter(|recorded| *recorded <= generation)
            .collect();
        let mut retired: Vec<Arc<str>> = Vec::new();
        for stale in stale_generations {
            if let Some((_, fingerprints)) = self.retired_svid_fingerprints.remove(&stale) {
                retired.extend(fingerprints);
            }
        }
        if retired.is_empty() {
            // Nothing was retired at or before this generation: either its
            // fingerprint is still current or it never carried pool entries.
            return;
        }

        self.drain_retired_fingerprints(&retired);
    }

    pub fn force_drain_all(&self) {
        let evicted = self.pool_size();
        self.entries.clear();
        self.creation_locks.clear();
        self.retired_svid_fingerprints.clear();
        record_hbone_evictions(evicted);
    }

    /// The effective pool configuration for `proxy`.
    ///
    /// Exposed for the nested-HTTP/2 gRPC transport (issue #3284), which builds
    /// its INNER hyper HTTP/2 client over a byte tunnel this pool opened and
    /// must apply the same per-proxy flow-control / frame-size settings the
    /// outer HBONE connection uses.
    pub(crate) fn pool_config_for(&self, proxy: &Proxy) -> PoolConfig {
        self.pool_config.for_proxy(proxy)
    }

    /// Open a pooled bare HBONE CONNECT byte tunnel. The HTTP/2 connection is
    /// dialed to `dial_host:hbone_port`; the CONNECT `:authority` is
    /// `app_host:app_port`. The ordinary Ambient path passes the same host for
    /// both. NodeWaypoint secured egress passes the destination NodeWaypoint as
    /// `dial_host` while preserving the selected workload IP/DNS as `app_host`.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_tunnel_via(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        app_host: &str,
        app_port: u16,
        app_policy_port: u16,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
        // CROSS-CLUSTER east-west scope: `expected_trust_domain` scopes the
        // server-cert verifier to a single remote trust domain and `sni_override`
        // sets the outer-TLS SNI to the destination service FQDN so the remote
        // east-west gateway's SNI passthrough routes the dial. Both `None` for
        // the in-cluster Ambient/Waypoint/NodeWaypoint egress callers (the pinned
        // peer constrains the domain; SNI = dial host). They are part of the pool
        // KEY so a cross-cluster session (verified against TD-B for service-X) is
        // never reused for a different TD / SNI.
        expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
        sni_override: Option<&str>,
        asserted_source_identity: Option<&crate::identity::SpiffeId>,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        let (source_identity, fingerprint) = match self.current_svid_identity_cached() {
            Ok(identity) => identity,
            Err(error) => {
                crate::modes::mesh::node_waypoint_observability::record_hbone_handshake(
                    crate::modes::mesh::node_waypoint_observability::NodeWaypointHboneHandshakePhase::OutboundDial,
                    false,
                );
                return Err(error);
            }
        };
        let hbone_source_identity = asserted_source_identity.unwrap_or(&source_identity);
        let pool_config = self.pool_config.for_proxy(proxy);
        let effective_connect_timeout_ms =
            effective_connect_timeout_ms_for_policy_port(proxy, app_policy_port);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);

        let dial_result = async {
            let fast_sender = with_hbone_pool_key(
                dial_host,
                app_port,
                hbone_port,
                proxy.dns_override.as_deref(),
                fingerprint.as_ref(),
                expected_peer,
                sni_override,
                expected_trust_domain,
                &pool_config,
                |key| self.try_cached_sender_read(key),
            );

            let sender = if let Some(sender) = fast_sender {
                sender
            } else {
                let key = with_hbone_pool_key(
                    dial_host,
                    app_port,
                    hbone_port,
                    proxy.dns_override.as_deref(),
                    fingerprint.as_ref(),
                    expected_peer,
                    sni_override,
                    expected_trust_domain,
                    &pool_config,
                    |key| key.to_string(),
                );
                self.get_or_create_sender(
                    proxy,
                    dial_host,
                    app_host,
                    app_port,
                    app_policy_port,
                    hbone_port,
                    expected_peer,
                    expected_trust_domain,
                    sni_override,
                    &key,
                    &pool_config,
                    Some(connect_timeout),
                )
                .await?
            };
            tokio::time::timeout(
                connect_timeout,
                self.open_connect_stream(sender, app_host, app_port, hbone_source_identity),
            )
            .await
            .map_err(|_| HbonePoolError::ConnectStream {
                authority: authority_for_host_port(app_host, app_port),
                message: format!(
                    "timed out after {}ms waiting for HBONE CONNECT response",
                    effective_connect_timeout_ms
                ),
            })?
        }
        .await;

        match &dial_result {
            Ok(_) => {
                crate::modes::mesh::node_waypoint_observability::record_hbone_handshake(
                    crate::modes::mesh::node_waypoint_observability::NodeWaypointHboneHandshakePhase::OutboundDial,
                    true,
                );
            }
            Err(_) => {
                crate::modes::mesh::node_waypoint_observability::record_hbone_handshake(
                    crate::modes::mesh::node_waypoint_observability::NodeWaypointHboneHandshakePhase::OutboundDial,
                    false,
                );
            }
        }
        dial_result
    }

    /// Open a **bare** HBONE CONNECT byte tunnel to a peer's HBONE listener over
    /// a FRESH SVID-mTLS H2 connection for a WebSocket egress session, carrying
    /// the HBONE protocol marker and the W3C source-identity baggage just like
    /// [`Self::get_tunnel`]. The connection is DIALED to `dial_host:hbone_port`
    /// (the peer's pod address + `:15008`/`mesh.hbone_port`); the bare CONNECT
    /// `:authority` is `app_host:app_port` — the destination workload's app
    /// address+port the peer's transparent HBONE relay byte-copies to locally.
    ///
    /// This is the WebSocket analogue of [`Self::get_tunnel`] / the raw-TCP HBONE
    /// egress path, NOT an Extended CONNECT. Ambient/Waypoint materialize NO
    /// inbound routes, and the route-miss transparent-relay fallback
    /// (`build_inbound_hbone_relay_proxy`) is gated on a BARE CONNECT
    /// (`is_connect_request` requires `:protocol` to be ABSENT) — so an Extended
    /// CONNECT carrying `:protocol=websocket` to `:15008` would 404 before any WS
    /// handler runs. Instead the caller dials this bare byte tunnel to the app
    /// addr:port and speaks the WebSocket (inner H1 upgrade) THROUGH it: the
    /// relay byte-copies the upgrade to the loopback app, which performs the WS
    /// handshake — no destination-side change.
    ///
    /// Unlike HTTP-family Ambient egress (which multiplexes over the pooled HBONE
    /// connections) this dials its OWN H2 connection carrying exactly ONE CONNECT
    /// stream (1:1, dropped when the WebSocket session closes) — the same model
    /// the Sidecar raw-TCP / Sidecar WebSocket egress paths use. A proxied
    /// WebSocket already opens one dedicated backend connection (its lifetime is
    /// bounded by `DestinationRule.maxConnections` via `BackendConnectionGuard`),
    /// so a per-session H2 connection keeps long-lived WebSocket sessions off the
    /// multiplexed HTTP pool and amortizes the handshake over the session.
    /// SVID rotation is automatic because every new session dials with the
    /// current SVID. The dial PINS `expected_peer`; a missing gateway SVID fails
    /// closed before the dial.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn get_ws_byte_tunnel(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        hbone_port: u16,
        app_host: &str,
        app_port: u16,
        app_policy_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
        // CROSS-CLUSTER east-west (issue #2010): `expected_trust_domain` scopes
        // the peer-cert verifier to a single remote trust domain (`expected_peer =
        // None`, since the SNI-passthrough gateway LB-picks the destination) and
        // `sni_override` sets the ClientHello SNI to the destination service FQDN.
        // Both `None` for the in-cluster byte-tunnel (SNI = dial host, pinned peer).
        expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
        sni_override: Option<&str>,
        // The ASSERTED SOURCE identity to stamp into the HBONE baggage (the W3C
        // source-identity header the destination's AuthorizationPolicy / telemetry
        // read). For a WS request forwarded from an authenticated mesh peer this
        // is the ORIGINAL workload SPIFFE (`ctx.peer_spiffe_id`), so the remote
        // sees the source workload — not the gateway's own SVID. `None` (the
        // ambient egress default) falls back to the gateway SVID, exactly like the
        // HTTP HBONE path (`get_tunnel_via`).
        asserted_source_identity: Option<&crate::identity::SpiffeId>,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        // This is a secured source-side HBONE dial, so it owns the same
        // `outbound_dial` NodeWaypoint ADR phase as `get_tunnel_via` (issue
        // #3334). WebSocket egress dials its own 1:1 connection rather than
        // reusing the pooled HTTP senders, so without this the phase would be
        // blind to every WebSocket session on the topology.
        let (source_identity, _fingerprint) = match self.current_svid_identity_cached() {
            Ok(identity) => identity,
            Err(error) => {
                crate::modes::mesh::node_waypoint_observability::record_hbone_handshake(
                    crate::modes::mesh::node_waypoint_observability::NodeWaypointHboneHandshakePhase::OutboundDial,
                    false,
                );
                return Err(error);
            }
        };
        let hbone_source_identity = asserted_source_identity.unwrap_or(&source_identity);
        let pool_config = self.pool_config.for_proxy(proxy);
        // DR keepalive override resolved for the destination's APP port, not
        // the transport `hbone_port`.
        let keepalive_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&app_policy_port))
            .and_then(|o| o.tcp_keepalive.as_ref());
        // Each WebSocket-over-HBONE session dials its OWN 1:1 tunnel, and that
        // tunnel's `maxConnections` slot is ALREADY held by the caller: the
        // WebSocket connect loop (`src/proxy/mod.rs`) reserves a session guard
        // on the caller's logical `(backend host, policy port)` lane before this
        // dial and holds it for the whole session. Admitting again here would charge the one
        // socket twice — and at `maxConnections: 1` the dial would refuse
        // itself, making every WebSocket upgrade to a capped mesh destination
        // fail. The session guard is the single owner; do NOT re-admit.
        let dial_result: Result<H2ConnectTunnel, HbonePoolError> = async {
            // Registered like every pooled transport (issue #3859): a 1:1
            // WebSocket bridge never enters the pool map, so pool clearing could
            // not cover it — the registry is what reaches it.
            let transport = dial_h2_connect_sender(
                &self.dns_cache,
                &self.gateway_svid,
                self.crls.load_full(),
                proxy,
                dial_host,
                hbone_port,
                expected_peer,
                expected_trust_domain,
                sni_override,
                &pool_config,
                keepalive_override,
                None,
                // Caller-owned admission (see above).
                None,
                self.trust_registry(),
                MeshTransportKind::Hbone,
                None,
                self.effective_max_header_list_size(),
            )
            .await?;
            let baggage = baggage_header_for_source(hbone_source_identity);
            tokio::time::timeout(
                Duration::from_millis(proxy.backend_connect_timeout_ms),
                open_h2_connect_stream(
                    transport,
                    app_host,
                    app_port,
                    Some(&baggage),
                    Some("hbone"),
                ),
            )
            .await
            .map_err(|_| HbonePoolError::ConnectStream {
                authority: authority_for_host_port(app_host, app_port),
                message: format!(
                    "timed out after {}ms waiting for HBONE WebSocket byte-tunnel CONNECT response",
                    proxy.backend_connect_timeout_ms
                ),
            })?
        }
        .await;

        crate::modes::mesh::node_waypoint_observability::record_hbone_handshake(
            crate::modes::mesh::node_waypoint_observability::NodeWaypointHboneHandshakePhase::OutboundDial,
            dial_result.is_ok(),
        );
        dial_result
    }

    /// Open a datagram-over-HBONE CONNECT tunnel to a peer's HBONE listener over
    /// a FRESH SVID-mTLS H2 connection (F3 §3.3 Stage 4), stamping the `udp`
    /// protocol marker (NOT `hbone`) and the W3C source-identity baggage. The
    /// connection is DIALED to `dial_host:hbone_port` (the peer's pod address +
    /// `:15008`/`mesh.hbone_port`); the CONNECT `:authority` is `app_host:app_port`
    /// — the destination workload's UDP app address+port the peer unframes the
    /// tunnel into a local `UdpSocket` toward. The returned [`H2ConnectTunnel`]
    /// carries length-delimited datagrams (see `crate::proxy::mesh_udp_frame`),
    /// NOT a raw byte stream.
    ///
    /// Like [`Self::get_ws_byte_tunnel`] this dials its OWN H2 connection carrying
    /// exactly ONE CONNECT stream (1:1, dropped when the UDP session ends) rather
    /// than multiplexing over the pooled HBONE connections. A dedicated connection
    /// per UDP session is deliberate: it keeps the wire-visible `udp` marker on a
    /// stream that is unambiguously a datagram tunnel (no risk of a pooled
    /// connection caching a per-connection `hbone`-vs-`udp` verdict by its first
    /// marker), and a captured UDP flow is already a distinct session with its own
    /// lifetime. SVID rotation is automatic (each session dials with the current
    /// SVID). In-cluster dials pin `expected_peer`; cross-cluster dials use the
    /// supplied trust-domain scope and SNI override. A missing gateway SVID fails
    /// closed before the dial. Distinct from [`Self::get_tunnel`], which hardcodes the
    /// `hbone` marker on the pooled byte-stream path.
    //
    // Callers: the mesh UDP capture egress datapath (Linux-only, `IP_TRANSPARENT`)
    // AND the cross-platform UDP capability probe ([`Self::warmup_datagram_connection`]),
    // so this is reachable on every platform.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_datagram_tunnel(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        hbone_port: u16,
        app_host: &str,
        app_port: u16,
        app_policy_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
        expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
        sni_override: Option<&str>,
        asserted_source: Option<&UdpSourceIdentity>,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        let (source_identity, _fingerprint) = self.current_svid_identity_cached()?;
        let pool_config = self.pool_config.for_proxy(proxy);
        // Per-port DestinationRule overrides (`portLevelSettings`) are stored on
        // the UDP upstream's `port_overrides` and precomputed onto
        // `dispatch_port_overrides`. Resolve them for the destination's APP port
        // (the DR keying port), NOT the transport `hbone_port`, mirroring the
        // WS byte-tunnel path and the byte-stream inbound relay's
        // `effective_connect_timeout_ms` (codex r5 P2):
        // - `tcpKeepalive` flows into the dial's socket keepalive;
        // - `connectTimeout` bounds the WHOLE dial (TCP + TLS + H2 handshake)
        //   AND the CONNECT-stream response wait.
        let port_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&app_policy_port));
        let keepalive_override = port_override.and_then(|o| o.tcp_keepalive.as_ref());
        let effective_connect_timeout_ms =
            effective_connect_timeout_ms_for_policy_port(proxy, app_policy_port);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        let udp_conn_admission = self.conn_admission(proxy, dial_host, app_policy_port);
        // Registered like every pooled transport (issue #3859): a 1:1 datagram
        // bridge never enters the pool map either.
        let transport = dial_h2_connect_sender(
            &self.dns_cache,
            &self.gateway_svid,
            self.crls.load_full(),
            proxy,
            dial_host,
            hbone_port,
            expected_peer,
            expected_trust_domain,
            sni_override,
            &pool_config,
            keepalive_override,
            Some(connect_timeout),
            udp_conn_admission.as_ref(),
            self.trust_registry(),
            MeshTransportKind::Hbone,
            None,
            self.effective_max_header_list_size(),
        )
        .await?;
        let baggage = asserted_source.map_or_else(
            || baggage_header_for_source(&source_identity),
            baggage_header_for_udp_source,
        );
        tokio::time::timeout(
            connect_timeout,
            open_h2_connect_stream(
                transport,
                app_host,
                app_port,
                Some(&baggage),
                Some(crate::modes::mesh::hbone::UDP_PROTOCOL),
            ),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority_for_host_port(app_host, app_port),
            message: format!(
                "timed out after {}ms waiting for datagram-over-HBONE CONNECT response",
                effective_connect_timeout_ms
            ),
        })?
    }

    /// Capability probe for a UDP egress target: open a `udp`-marked
    /// datagram-over-HBONE CONNECT exactly as [`Self::get_datagram_tunnel`]
    /// would, then DROP the tunnel. A UDP egress target's destination relay
    /// branches on the `udp` marker (`is_udp_hbone_connect`) and unframes the
    /// stream into a local `UdpSocket`; probing it with the byte-stream
    /// [`Self::warmup_connection`] (which stamps the `hbone` marker) hits the
    /// WRONG relay on the destination — the byte-stream path that TCP-connects
    /// to the app port — so the probe must carry the SAME `udp` marker the
    /// dispatch datapath uses, or it would prove the wrong capability (codex r1
    /// P1). Like the dispatch path this dials its OWN H2 connection (no pooled
    /// `hbone`-vs-`udp` marker ambiguity); the connection is dropped with the
    /// tunnel when the probe returns.
    #[allow(clippy::too_many_arguments)]
    pub async fn warmup_datagram_connection_via(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        app_host: &str,
        app_port: u16,
        app_policy_port: u16,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
    ) -> Result<(), HbonePoolError> {
        let _tunnel = self
            .get_datagram_tunnel(
                proxy,
                dial_host,
                hbone_port,
                app_host,
                app_port,
                app_policy_port,
                expected_peer,
                None,
                None,
                None,
            )
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_or_create_sender(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        app_host: &str,
        app_port: u16,
        app_policy_port: u16,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
        // CROSS-CLUSTER scope, threaded into the dial. `None`/`None` in-cluster.
        expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
        sni_override: Option<&str>,
        key: &str,
        pool_config: &PoolConfig,
        connect_timeout_override: Option<Duration>,
    ) -> Result<MeshH2Transport, HbonePoolError> {
        self.maybe_prune_idle_entries();
        let max_entries = pool_config.http2_connections_per_host.max(1);
        let effective_connect_timeout_ms = connect_timeout_override
            .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(proxy.backend_connect_timeout_ms);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        match self.cached_sender(key, max_entries) {
            Some(CachedSender::Ready(transport)) => return Ok(transport),
            Some(CachedSender::Pending(transport)) => {
                let authority = authority_for_host_port(app_host, app_port);
                let MeshH2Transport { sender, gate } = transport;
                match tokio::time::timeout(connect_timeout, sender.ready()).await {
                    Ok(Ok(sender)) => {
                        let transport = MeshH2Transport { sender, gate };
                        if !transport.is_retired() && !transport.keepalive_failed() {
                            return Ok(transport);
                        }
                        debug!(
                            dial_host,
                            app_host,
                            app_port,
                            hbone_port,
                            "Cached HBONE HTTP/2 transport became unusable while waiting for readiness; creating a replacement"
                        );
                    }
                    Ok(Err(err)) => {
                        debug!(
                            dial_host,
                            app_host,
                            app_port,
                            hbone_port,
                            error = %err,
                            "Cached HBONE HTTP/2 sender closed while waiting for readiness; creating a replacement"
                        );
                    }
                    Err(_) => {
                        return Err(HbonePoolError::ConnectStream {
                            authority,
                            message: format!(
                                "timed out after {}ms waiting for cached HBONE HTTP/2 sender readiness",
                                effective_connect_timeout_ms
                            ),
                        });
                    }
                }
            }
            None => {}
        }

        let creation_started = Instant::now();
        let authority = authority_for_host_port(app_host, app_port);
        let creation_slot = self
            .creation_locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(HboneCreationSlot::new()))
            .clone();
        // Join the cohort BEFORE awaiting the lock: subscribing is what scopes
        // this caller to the attempt that is in flight right now, so it can be
        // released by that attempt's failure instead of repeating the dial
        // (issue #5046). Every waiter keeps its OWN `connect_timeout` here.
        let cohort = creation_slot.join();
        let joined = tokio::time::timeout(connect_timeout, cohort.wait()).await;
        let mut creation_lease = match joined {
            Ok(SharedCreationRole::Creator(lease)) => lease,
            Ok(SharedCreationRole::Failed(shared)) => return Err(shared.clone_for_broadcast()),
            Err(_) => {
                return Err(HbonePoolError::ConnectStream {
                    authority: authority.clone(),
                    message: format!(
                        "timed out after {}ms waiting to coalesce HBONE HTTP/2 sender creation",
                        effective_connect_timeout_ms
                    ),
                });
            }
        };
        match self.cached_sender(key, max_entries) {
            Some(CachedSender::Ready(transport)) => {
                return Ok(transport);
            }
            Some(CachedSender::Pending(transport)) => {
                let remaining = crate::pool::remaining_connect_timeout(
                    creation_started,
                    connect_timeout,
                )
                .ok_or_else(|| HbonePoolError::ConnectStream {
                    authority: authority.clone(),
                    message: format!(
                        "timed out after {}ms waiting for coalesced HBONE HTTP/2 sender creation",
                        effective_connect_timeout_ms
                    ),
                })?;
                let MeshH2Transport { sender, gate } = transport;
                match tokio::time::timeout(remaining, sender.ready()).await {
                    Ok(Ok(sender)) => {
                        let transport = MeshH2Transport { sender, gate };
                        if !transport.is_retired() && !transport.keepalive_failed() {
                            return Ok(transport);
                        }
                        debug!(
                            dial_host,
                            app_host,
                            app_port,
                            hbone_port,
                            "Coalesced HBONE HTTP/2 transport became unusable; creating a replacement"
                        );
                    }
                    Ok(Err(err)) => {
                        debug!(
                            dial_host,
                            app_host,
                            app_port,
                            hbone_port,
                            error = %err,
                            "Cached HBONE HTTP/2 sender closed after coalesced creation wait; creating a replacement"
                        );
                    }
                    Err(_) => {
                        return Err(HbonePoolError::ConnectStream {
                            authority,
                            message: format!(
                                "timed out after {}ms waiting for coalesced HBONE HTTP/2 sender readiness",
                                effective_connect_timeout_ms
                            ),
                        });
                    }
                }
            }
            None => {}
        }

        // A concurrent creator for this key failed while this caller was queued
        // for the creation lock: adopt that cohort's typed outcome instead of
        // repeating the same dial (issue #5046). Checked AFTER the cache
        // re-check above so a usable connection always wins over a shared
        // failure, and before any budget is spent on a dial.
        if let Some(shared) = creation_lease.take_broadcast_failure() {
            return Err(shared.clone_for_broadcast());
        }

        let remaining = match crate::pool::remaining_connect_timeout(
            creation_started,
            connect_timeout,
        ) {
            Some(remaining) => remaining,
            None => {
                return Err(HbonePoolError::ConnectStream {
                    authority: authority.clone(),
                    message: format!(
                        "timed out after {}ms waiting for coalesced HBONE HTTP/2 sender creation",
                        effective_connect_timeout_ms
                    ),
                });
            }
        };
        // Snapshot the SVID and CRL slots before dialing: the SPIFFE TLS
        // resolver/verifier use these snapshots for the handshake, so an
        // unchanged slot across the dial proves the session was built from the
        // material that is still current when it is pooled.
        let svid_slot_before_dial = self.gateway_svid.load_full();
        let crls_before_dial = self.crls.load_full();
        // Resolve the DR `connectionPool.tcp.tcpKeepalive` per-port override for
        // the destination's APP port (`target_port`), NOT the transport
        // `hbone_port` (always `:15008`). Falls back to the global pool
        // keepalive inside the dialer when absent.
        let keepalive_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&app_policy_port))
            .and_then(|o| o.tcp_keepalive.as_ref());
        let pooled_conn_admission = self.conn_admission(proxy, dial_host, app_policy_port);
        let transport = match tokio::time::timeout(
            remaining,
            self.create_sender(
                proxy,
                dial_host,
                hbone_port,
                expected_peer,
                expected_trust_domain,
                sni_override,
                pool_config,
                keepalive_override,
                Some(remaining),
                crls_before_dial.clone(),
                pooled_conn_admission.as_ref(),
                key,
            ),
        )
        .await
        {
            Ok(Ok(transport)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_handshake(crate::runtime_metrics::PoolKind::Hbone);
                transport
            }
            Ok(Err(err)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::Hbone);
                // Release the whole cohort on this one physical dial: every
                // caller that joined while it was in flight gets the same typed
                // outcome rather than taking the lock and repeating it (issue
                // #5046). Published while the lock is still held, so no waiter
                // can slip past the broadcast. `record_pool_failure` stays on
                // the creator alone — one physical dial, one pool failure —
                // while each waiter still reports its own logical outcome.
                creation_lease.publish_failure(Arc::new(err.clone_for_broadcast()));
                return Err(err);
            }
            Err(_) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::Hbone);
                // Deliberately NOT broadcast: this is the CREATOR's own connect
                // budget expiring, not evidence about the peer. A waiter may
                // have a longer deadline (per-port `connect_timeout_ms`
                // overrides are not part of the pool key), and #5046 requires
                // each waiter's original deadline to survive — so the lease
                // drops without publishing and the next waiter is elected as a
                // fresh creator with its own remaining budget.
                return Err(HbonePoolError::ConnectStream {
                    authority,
                    message: format!(
                        "timed out after {}ms creating coalesced HBONE HTTP/2 sender",
                        effective_connect_timeout_ms
                    ),
                });
            }
        };
        // An SVID rotation or CRL reload drain may have fired while this dial was in
        // flight: pooling the sender under a retired-fingerprint key would
        // resurrect it AFTER its one-shot drain already ran, leaving an
        // old-identity session alive until idle pruning (forever with
        // `idle_timeout_seconds=0`). Serve the triggering request on the
        // connection, but only pool it while (a) the slot is unchanged across
        // the dial — catches same-leaf trust-bundle rotations the fingerprint
        // cannot see — (b) the CRL slot is unchanged across the dial, and (c)
        // the key's fingerprint is still the current one
        // — catches rotations between key construction and the slot snapshot.
        // Pre-drain inserts under a retired-but-undrained key are also
        // skipped, which merely costs those stragglers pooling during the
        // drain window.
        let svid_slot_unchanged =
            Arc::ptr_eq(&svid_slot_before_dial, &self.gateway_svid.load_full());
        let crls_unchanged = Arc::ptr_eq(&crls_before_dial, &self.crls.load_full());
        let key_fingerprint_is_current = self
            .current_svid_identity_cached()
            .ok()
            .is_some_and(|(_, current)| hbone_key_svid_fingerprint(key) == Some(current.as_ref()));
        // A gateway trust withdrawal that landed between registration and here
        // already retired this transport. Registration is the fence for the
        // common case, but the window between `register` releasing the fence and
        // this insert is real, so re-check and fail closed: the connection is
        // neither pooled nor served (issue #3859).
        if transport.is_retired() {
            return Err(HbonePoolError::TrustWithdrawn);
        }
        if transport.keepalive_failed() {
            // Keepalive already tore this dial down; serve without pooling so
            // the next request redials (issue #4162).
            return Ok(transport);
        }
        if !svid_slot_unchanged || !crls_unchanged || !key_fingerprint_is_current {
            debug!(
                dial_host,
                app_host,
                app_port,
                hbone_port,
                "HBONE HTTP/2 connection completed under rotated TLS material; serving without pooling"
            );
            return Ok(transport);
        }
        self.entries
            .entry(key.to_string())
            .and_modify(|entries| {
                record_hbone_evictions(prune_pool_entries(entries));
                entries.push(HbonePoolEntry {
                    transport: transport.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                });
                let max_entries = pool_config.http2_connections_per_host.max(1);
                if entries.len() > max_entries {
                    let overflow = entries.len() - max_entries;
                    entries.drain(0..overflow);
                    record_hbone_evictions(overflow);
                }
            })
            .or_insert_with(|| {
                vec![HbonePoolEntry {
                    transport: transport.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                }]
            });
        // Keepalive may have failed between the check above and insert, or
        // between insert and this recheck. Evict by gate identity so a newer
        // replacement under the same key is not removed (issue #4162).
        if transport.keepalive_failed() {
            evict_hbone_entry_for_gate(&self.entries, key, &transport.gate);
        }
        debug!(
            dial_host,
            app_host, app_port, hbone_port, "Created gateway HBONE HTTP/2 connection"
        );
        Ok(transport)
    }

    fn cached_sender(&self, key: &str, max_entries: usize) -> Option<CachedSender> {
        let mut entries = self.entries.get_mut(key)?;
        record_hbone_evictions(prune_pool_entries(&mut entries));
        let mut pending = None;
        let mut pending_idx = None;
        let mut idx = 0;
        while idx < entries.len() {
            let entry = &mut entries[idx];
            // A retired or keepalive-failed transport is never handed out
            // again, even before its socket has finished closing. One relaxed
            // load each (issues #3859 / #4162).
            if entry.transport.is_retired() || entry.transport.keepalive_failed() {
                entries.remove(idx);
                record_hbone_evictions(1);
                continue;
            }
            let transport = entry.transport.clone();
            match transport.sender.clone().ready().now_or_never() {
                Some(Ok(ready)) => {
                    entry.last_used_at.store(unix_secs(), Ordering::Relaxed);
                    return Some(CachedSender::Ready(MeshH2Transport {
                        sender: ready,
                        gate: transport.gate,
                    }));
                }
                Some(Err(_)) => {
                    entries.remove(idx);
                    record_hbone_evictions(1);
                    continue;
                }
                None => {
                    if pending.is_none() {
                        pending = Some(transport);
                        pending_idx = Some(idx);
                    }
                }
            }
            idx += 1;
        }
        if entries.len() >= max_entries {
            if let Some(idx) = pending_idx
                && let Some(entry) = entries.get_mut(idx)
            {
                entry.last_used_at.store(unix_secs(), Ordering::Relaxed);
            }
            pending.map(CachedSender::Pending)
        } else {
            None
        }
    }

    /// Shared-lock fast path: scan for a ready sender and refresh its
    /// `last_used_at` via a relaxed atomic store, avoiding the exclusive shard
    /// write lock that `cached_sender` holds during prune + scan + clone.
    /// Refreshing recency here keeps a connection served only by this path from
    /// being pruned as idle. Expired entries are skipped (not removed); dead
    /// senders fall through to the write path.
    fn try_cached_sender_read(&self, key: &str) -> Option<MeshH2Transport> {
        let entries = self.entries.get(key)?;
        let now = unix_secs();
        for entry in entries.value().iter() {
            let last_used = entry.last_used_at.load(Ordering::Relaxed);
            if entry_idle_expired(last_used, entry.idle_timeout_seconds, now) {
                continue;
            }
            // Retired or keepalive-failed transports are skipped here and
            // removed by the write path (this path holds only a shared lock).
            if entry.transport.is_retired() || entry.transport.keepalive_failed() {
                continue;
            }
            let transport = entry.transport.clone();
            match transport.sender.clone().ready().now_or_never() {
                Some(Ok(ready)) => {
                    // Refresh recency on the shared-lock fast path so a busy
                    // connection is not pruned as idle. This is the whole point
                    // of this path existing: avoid the exclusive write lock.
                    entry.last_used_at.store(now, Ordering::Relaxed);
                    return Some(MeshH2Transport {
                        sender: ready,
                        gate: transport.gate,
                    });
                }
                _ => continue,
            }
        }
        None
    }

    fn maybe_prune_idle_entries(&self) {
        let now = unix_secs();
        let interval = if self.pool_config.idle_timeout_seconds == 0 {
            60
        } else {
            self.pool_config.idle_timeout_seconds.clamp(1, 60)
        };
        let last = self.last_idle_prune_unix_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) < interval {
            return;
        }
        if self
            .last_idle_prune_unix_secs
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        self.entries.retain(|_, entries| {
            record_hbone_evictions(prune_pool_entries(entries));
            !entries.is_empty()
        });
        self.creation_locks.retain(|key, lock| {
            self.entries.contains_key(key.as_str()) || Arc::strong_count(lock) > 1
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
        // CROSS-CLUSTER scope: `expected_trust_domain` scopes the verifier and
        // `sni_override` sets the outer-TLS SNI. `None`/`None` for every
        // in-cluster pooled dial (the pinned peer constrains the domain; SNI =
        // dial host). These are part of the pool key (the byte-stream path is
        // pooled), so a cross-cluster session is never shared with an in-cluster
        // one to the same `(host, port)`.
        expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
        sni_override: Option<&str>,
        pool_config: &PoolConfig,
        keepalive_override: Option<&crate::config::types::TcpKeepaliveCfg>,
        connect_timeout_override: Option<Duration>,
        crls: crate::tls::CrlList,
        conn_admission: Option<&crate::backend_conn_limit::PooledConnectionAdmission<'_>>,
        pool_key: &str,
    ) -> Result<MeshH2Transport, HbonePoolError> {
        // The raw-`h2` dial over SVID-mTLS is the transport primitive shared
        // with the Sidecar mesh-mTLS raw-TCP egress path; only the dial port
        // (`:15008` here) and the CONNECT request differ. `keepalive_override`
        // is resolved by the caller for the destination's app port (the DR
        // keying port), not this transport `hbone_port`.
        dial_h2_connect_sender(
            &self.dns_cache,
            &self.gateway_svid,
            crls,
            proxy,
            target_host,
            hbone_port,
            expected_peer,
            expected_trust_domain,
            sni_override,
            pool_config,
            keepalive_override,
            connect_timeout_override,
            conn_admission,
            self.trust_registry(),
            MeshTransportKind::Hbone,
            Some(HboneKeepalivePoolHandle {
                entries: Arc::clone(&self.entries),
                key: pool_key.to_string(),
            }),
            self.effective_max_header_list_size(),
        )
        .await
    }

    async fn open_connect_stream(
        &self,
        transport: MeshH2Transport,
        target_host: &str,
        target_port: u16,
        source_identity: &crate::identity::SpiffeId,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        // HBONE stamps the `hbone` protocol marker and a W3C baggage header
        // carrying the source workload identity; the shared opener handles the
        // rest of the CONNECT exchange.
        let baggage = baggage_header_for_source(source_identity);
        open_h2_connect_stream(
            transport,
            target_host,
            target_port,
            Some(&baggage),
            Some("hbone"),
        )
        .await
    }
}

/// A bidirectional byte tunnel over one HTTP/2 CONNECT stream.
///
/// This is the transport primitive shared by every mesh CONNECT tunnel,
/// regardless of topology: HBONE (Ambient/Waypoint, `:15008`, with the
/// `x-ferrum-mesh-protocol: hbone` marker) and Sidecar SVID-mTLS raw-TCP
/// egress (`:15006`, a bare CONNECT). Both ride raw `h2` streams; the only
/// wire difference is the dial port and the optional marker/baggage on the
/// CONNECT request (see [`open_h2_connect_stream`]).
pub struct H2ConnectTunnel {
    recv_stream: RecvStream,
    send_stream: SendStream<Bytes>,
    read_buf: Bytes,
    write_closed: bool,
    write_reservation: usize,
    /// Retirement gate of the HTTP/2 transport this stream rides (issue #3859).
    ///
    /// The tunnel owns its `RecvStream`/`SendStream` directly, so a pool drain
    /// cannot reach it once it has been handed to a relay. Carrying the gate is
    /// what makes an already-issued tunnel reachable by a trust withdrawal: both
    /// poll halves consult it, so the relay stops forwarding on its very next
    /// poll instead of waiting for the socket close to propagate through h2.
    gate: MeshTransportGate,
}

impl AsyncRead for H2ConnectTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // One relaxed atomic load; no lock, no allocation. Checked before the
        // `dst.remaining() == 0` shortcut so a retired tunnel reports the
        // failure even on a zero-length read.
        if self.gate.is_retired() {
            return Poll::Ready(Err(self.gate.retired_io_error()));
        }
        if self.gate.keepalive_failed() {
            return Poll::Ready(Err(self.gate.keepalive_io_error()));
        }
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !self.read_buf.is_empty() {
                let to_copy = self.read_buf.len().min(dst.remaining());
                if let Err(e) = self.recv_stream.flow_control().release_capacity(to_copy) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )));
                }
                dst.put_slice(&self.read_buf[..to_copy]);
                self.read_buf.advance(to_copy);
                return Poll::Ready(Ok(()));
            }

            match self.recv_stream.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    self.read_buf = chunk;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        e.to_string(),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2ConnectTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.gate.is_retired() {
            return Poll::Ready(Err(self.gate.retired_io_error()));
        }
        if self.gate.keepalive_failed() {
            return Poll::Ready(Err(self.gate.keepalive_io_error()));
        }
        if self.write_closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HBONE tunnel write half already closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_reservation == 0 {
            let desired = buf.len().min(MAX_HBONE_WRITE_CHUNK);
            self.send_stream.reserve_capacity(desired);
            self.write_reservation = desired;
        }

        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) if capacity > 0 => {
                let to_write = capacity.min(self.write_reservation).min(buf.len());
                self.send_stream
                    .send_data(Bytes::copy_from_slice(&buf[..to_write]), false)
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())
                    })?;
                self.write_reservation = self.write_reservation.saturating_sub(to_write);
                Poll::Ready(Ok(to_write))
            }
            Poll::Ready(Some(Ok(_))) | Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HBONE tunnel write half closed",
            ))),
        }
    }

    // h2 send_data queues into the connection driver which flushes to
    // TCP independently; no explicit flush API on SendStream.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // A retired tunnel has no orderly half-close to perform: the transport
        // is being torn down, so report completion rather than pushing an
        // END_STREAM onto a stream whose connection is closing. Dropping the
        // tunnel afterwards resets the stream through h2's own teardown.
        if self.gate.is_retired() {
            self.write_closed = true;
            return Poll::Ready(Ok(()));
        }
        if self.gate.keepalive_failed() {
            self.write_closed = true;
            return Poll::Ready(Ok(()));
        }
        if !self.write_closed {
            self.send_stream
                .send_data(Bytes::new(), true)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Unpin for H2ConnectTunnel {}

/// Dial a fresh raw-`h2` client connection to `target_host:dial_port` over an
/// SVID-mTLS session (ALPN `h2`), pinned to `expected_peer` when present, and
/// complete the HTTP/2 handshake. Shared by the HBONE pool (dialing the peer's
/// `:15008`) and the Sidecar mesh-mTLS raw-TCP egress path (dialing the peer's
/// `:15006`) — the transport is identical at this layer; only the dial port and
/// the CONNECT request itself differ (see [`open_h2_connect_stream`]). The whole
/// dial (DNS + TCP + TLS + H2 handshake) is bounded by
/// `proxy.backend_connect_timeout_ms`. Advertising `h2` only lets a peer reject
/// non-mesh clients at ALPN; pinning the peer identity means a same-trust-domain
/// workload at a reused pod IP cannot impersonate the destination.
///
/// `keepalive_override` carries the DestinationRule `connectionPool.tcp.tcpKeepalive`
/// resolved by the caller for the destination's APP/service port (NOT this
/// transport `dial_port`, which is always `:15008`/`:15006`). When `Some` it is
/// applied with full time/interval/probes; otherwise the connection falls back
/// to the global pool keepalive. NOTE: keepalive is NOT in the pool key
/// (forbidden by `.claude/rules/proxy-protocols.md`), and HBONE / mesh-mTLS
/// pool connections are shared across dispatchers, so the first dispatcher to
/// materialize the connection wins (same first-materializer tradeoff as
/// `idleTimeout` / `maxRequestsPerConnection`). WebSocket-over-HBONE /
/// -mesh-mTLS rides this same dialer (`get_ws_byte_tunnel` /
/// `open_ws_connect_tunnel`), so it inherits the resolved keepalive too.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dial_h2_connect_sender(
    dns_cache: &DnsCache,
    gateway_svid: &SharedSvidBundle,
    crls: crate::tls::CrlList,
    proxy: &Proxy,
    target_host: &str,
    dial_port: u16,
    expected_peer: Option<&crate::identity::SpiffeId>,
    // Scopes the server-cert verifier to a single remote trust domain for the
    // CROSS-CLUSTER east-west path (`expected_peer = None`, the SNI-passthrough
    // gateway LB-picks the destination so no pod SPIFFE can be pinned, but the
    // server SVID MUST be in exactly this trust domain). `None` for every
    // in-cluster dial (the pinned peer already constrains the domain), matching
    // the prior hardcoded `None`.
    expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
    // Overrides the ClientHello SNI when `Some` (CROSS-CLUSTER: the destination
    // service FQDN, so the remote east-west gateway's SNI passthrough routes to
    // a destination terminator). `None` keeps the current behavior — SNI = the
    // dial host `target_host` — so the in-cluster HBONE / raw-TCP / UDP /
    // WebSocket-over-HBONE callers are byte-identical.
    sni_override: Option<&str>,
    pool_config: &PoolConfig,
    keepalive_override: Option<&crate::config::types::TcpKeepaliveCfg>,
    // Per-port DestinationRule `connectTimeout` override (resolved by the caller
    // for the destination APP port, the DR keying port — NOT the transport dial
    // port). `None` keeps the proxy-level `backend_connect_timeout_ms`. Bounds
    // the WHOLE dial (TCP + TLS + H2 handshake), mirroring the byte-stream
    // inbound relay's `effective_connect_timeout_ms` (codex r5 P2).
    connect_timeout_override: Option<Duration>,
    // DestinationRule `connectionPool.tcp.maxConnections` admission lane for the
    // destination's APP/service policy port (again NOT the transport dial port).
    // `None` means the destination carries no cap and the dial proceeds
    // unconditionally. When `Some`, one physical-connection slot is reserved
    // before dialing and handed to the spawned H2 connection driver, so it is
    // released exactly when this tunnel connection closes — idle prune, pool
    // drain, SVID rotation drain on reload/update/delete, or shutdown. Reuse of
    // a pooled tunnel takes no slot, so any number of multiplexed CONNECT
    // streams ride one admitted connection.
    conn_admission: Option<&crate::backend_conn_limit::PooledConnectionAdmission<'_>>,
    // Gateway trust ownership registry (issue #3859). `Some` in every
    // `ProxyState`-backed path; `None` only for focused tests and standalone
    // callers, where no trust publication path exists either. `kind` is the
    // closed transport class the retirement metrics label by.
    trust_registry: Option<&Arc<MeshTrustRegistry>>,
    kind: MeshTransportKind,
    // Pooled HBONE only (issue #4162): identity-safe eviction handle so a
    // keepalive failure removes *this* transport and not a newer replacement
    // under the same key. `None` for 1:1 WS/datagram and mesh-mTLS CONNECT.
    keepalive_pool: Option<HboneKeepalivePoolHandle>,
    // Receive-side `SETTINGS_MAX_HEADER_LIST_SIZE` advertised on the h2
    // handshake, bounding the response header block the peer may push back.
    // Callers without an operator policy pass
    // [`HBONE_DEFAULT_MAX_HEADER_LIST_SIZE`] (hyper's own 16 KiB), never `h2`'s
    // 16 MiB default.
    max_header_list_size: u32,
) -> Result<MeshH2Transport, HbonePoolError> {
    // Stamp the accepted trust generation BEFORE dialing. If a withdrawal
    // publishes a new generation while this dial is in flight, registration
    // below refuses the ticket and the connection is dropped instead of being
    // pooled or returned — that is the creation race, closed.
    let admission_ticket = trust_registry.map(|registry| registry.admission_ticket());
    let trust_registry = trust_registry.cloned();
    let conn_slot = match conn_admission {
        Some(admission) => match admission.acquire() {
            Ok(slot) => Some(slot),
            Err(limit) => {
                return Err(HbonePoolError::MaxConnectionsExceeded {
                    host: admission.host().to_string(),
                    port: admission.policy_port(),
                    current: limit.current,
                    cap: limit.cap,
                });
            }
        },
        None => None,
    };
    let candidates = dns_cache
        .resolve_candidates(
            target_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .map_err(|e| HbonePoolError::DnsLookup {
            host: target_host.to_string(),
            message: e.to_string(),
        })?;
    let effective_connect_timeout_ms = connect_timeout_override
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(proxy.backend_connect_timeout_ms);
    let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);

    // `dial_h2_connect_sender` backs in-cluster HBONE egress (any-federated when
    // the operator target carries no pin, else pinned), the PINNED Sidecar
    // mesh-mTLS CONNECT tunnels (raw-TCP / UDP / WebSocket egress, all
    // `expected_peer = Some`), AND the CROSS-CLUSTER Ambient HBONE east-west path
    // (`expected_peer = None`, `expected_trust_domain = Some(remote TD)`,
    // `sni_override = Some(service FQDN)`). For the in-cluster callers both
    // `expected_trust_domain` and `sni_override` are `None` so behavior is
    // unchanged.
    let tls_config = build_spiffe_outbound_config(
        gateway_svid.clone(),
        expected_peer.cloned(),
        expected_trust_domain.cloned(),
        vec![b"h2".to_vec()],
        crls,
    )?;
    let connector = TlsConnector::from(tls_config);
    // SNI = the `sni_override` when present (cross-cluster: the destination
    // service FQDN the remote east-west gateway routes passthrough on), else the
    // dial host (every in-cluster path — byte-identical to the prior hardcode).
    let sni_host = sni_override.unwrap_or(target_host);
    let server_name =
        rustls::pki_types::ServerName::try_from(sni_host.to_string()).map_err(|e| {
            HbonePoolError::InvalidServerName {
                host: sni_host.to_string(),
                message: e.to_string(),
            }
        })?;

    crate::dns::connect_candidates(&candidates, dial_port, connect_timeout, |sock_addr| {
        let connector = connector.clone();
        let server_name = server_name.clone();
        // One reservation, cloned per DNS candidate: a failed attempt drops its
        // clone, so only an established tunnel keeps the slot.
        let conn_slot = conn_slot.clone();
        let trust_registry = trust_registry.clone();
        let keepalive_pool = keepalive_pool.clone();
        async move {
            let tcp = crate::socket_opts::connect_with_socket_opts(sock_addr)
                .await
                .map_err(|source| HbonePoolError::Connect {
                    addr: sock_addr.to_string(),
                    source,
                })?;
            let _ = tcp.set_nodelay(true);
            crate::socket_opts::apply_pooled_tcp_keepalive(
                "hbone_pool",
                &tcp,
                keepalive_override,
                pool_config.enable_http_keep_alive,
                pool_config.tcp_keepalive_seconds,
            );

            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|source| HbonePoolError::TlsHandshake {
                    host: target_host.to_string(),
                    source,
                })?;
            if !matches!(tls_stream.get_ref().1.alpn_protocol(), Some(b"h2")) {
                return Err(HbonePoolError::TlsHandshake {
                    host: target_host.to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "peer did not negotiate ALPN h2",
                    ),
                });
            }

            let (stream_window_size, connection_window_size) = h2_window_sizes(pool_config);
            let mut builder = h2::client::Builder::new();
            // Bound the response header block a peer may push at us. An HBONE
            // peer holds a valid SVID, but a valid SVID is not a promise to
            // bound its own HEADERS/CONTINUATION block: a compromised in-mesh
            // workload or any waypoint the mesh routes through can answer a
            // CONNECT with a multi-megabyte block, and `h2` only installs a
            // receive-side cap when this setting is `Some` (its default is
            // 16 MiB). Every sibling backend transport already carries a bound —
            // `http2_pool.rs` and `grpc_proxy.rs` ride hyper's 16 KiB default and
            // `src/http3/client.rs` carries its own field-section ceiling — so
            // the mesh data path must not be the one unbounded reader. This dial
            // also backs the Sidecar mesh-mTLS CONNECT pool, which passes the
            // same 16 KiB default. Enforcement is stream-level: `h2` refuses the
            // oversized stream and the connection survives.
            builder
                .initial_window_size(stream_window_size)
                .initial_connection_window_size(connection_window_size)
                .max_frame_size(pool_config.http2_max_frame_size)
                .max_header_list_size(max_header_list_size)
                .max_concurrent_reset_streams(4096);
            if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
                builder.max_concurrent_streams(max_streams);
            }

            let (sender, mut connection) =
                builder
                    .handshake(tls_stream)
                    .await
                    .map_err(|e| HbonePoolError::H2Handshake {
                        host: target_host.to_string(),
                        message: e.to_string(),
                    })?;

            // Admit the established transport under the generation it was
            // dialed with. A withdrawal that landed mid-dial refuses it here,
            // BEFORE the driver is spawned and before the sender can be pooled
            // or served, so an old-generation connection can neither escape
            // retirement nor repopulate the pool.
            let gate = MeshTransportGate::new();
            if pool_config.enable_http2
                && let Some(ping_pong) = connection.ping_pong()
            {
                spawn_h2_keepalive(
                    ping_pong,
                    pool_config.http2_keep_alive_interval_seconds,
                    pool_config.http2_keep_alive_timeout_seconds,
                    gate.clone(),
                    keepalive_pool,
                );
            }

            let registration: Option<Arc<MeshTransportRegistration>> =
                match (trust_registry.as_ref(), admission_ticket) {
                    (Some(registry), Some(ticket)) => Some(
                        registry
                            .register(ticket, kind, gate.clone())
                            .map_err(|_| HbonePoolError::TrustWithdrawn)?,
                    ),
                    _ => None,
                };

            // TLS ALPN already proved H2 for this candidate. Drive it without
            // blocking healthy HBONE peers on a SETTINGS-derived sentinel.
            let driver_gate = gate.clone();
            tokio::spawn(async move {
                // The `maxConnections` slot lives exactly as long as the
                // connection driver, i.e. as long as the tunnel socket is open.
                let _conn_slot = conn_slot;
                // The registration lives exactly as long as the driver, so the
                // registry's live set IS the set of open mesh transports.
                let _registration = registration;
                tokio::pin!(connection);
                tokio::select! {
                    biased;
                    // Trust withdrawal. Returning here drops the HTTP/2
                    // connection, which closes the TLS socket and errors every
                    // CONNECT stream multiplexed on it — including tunnels that
                    // already left the pool and senders callers have cloned.
                    () = driver_gate.cancelled() => {
                        debug!(
                            "mesh h2 connect pool: HTTP/2 connection retired after gateway trust withdrawal"
                        );
                    }
                    // Keepalive PING failure (issue #4162). Distinct from trust
                    // withdrawal so a dead peer is never labeled as a withdrawn
                    // authority. Dropping the connection here makes the pooled
                    // SendRequest unusable for the next checkout.
                    () = driver_gate.keepalive_cancelled() => {
                        debug!(
                            "mesh h2 connect pool: HTTP/2 connection closed after keepalive failure"
                        );
                    }
                    result = &mut connection => {
                        if let Err(e) = result {
                            debug!("mesh h2 connect pool: HTTP/2 connection closed: {}", e);
                        }
                    }
                }
            });
            Ok(MeshH2Transport { sender, gate })
        }
    })
    .await
    .map(|(transport, _)| transport)
    .map_err(|error| match error {
        crate::dns::CandidateConnectError::TimedOut { last_addr } => {
            HbonePoolError::ConnectTimeout {
                addr: last_addr.to_string(),
                timeout_ms: effective_connect_timeout_ms,
            }
        }
        crate::dns::CandidateConnectError::Failed { source, .. } => source,
    })
}

/// Open one HTTP/2 CONNECT stream to `target_host:target_port` over `sender`,
/// returning the bidirectional byte tunnel. `marker` stamps the optional
/// `x-ferrum-mesh-protocol` header (`Some("hbone")` for HBONE; `None` for a bare
/// Sidecar mesh-mTLS CONNECT), and `baggage` carries the optional W3C baggage
/// source identity (HBONE only — Sidecar mTLS authenticates the peer via its
/// client certificate and needs no baggage). A non-200 CONNECT response fails
/// closed.
pub(crate) async fn open_h2_connect_stream(
    transport: MeshH2Transport,
    target_host: &str,
    target_port: u16,
    baggage: Option<&str>,
    marker: Option<&'static str>,
) -> Result<H2ConnectTunnel, HbonePoolError> {
    let authority = authority_for_host_port(target_host, target_port);
    // Synchronous refusal: a transport retired between checkout and CONNECT may
    // not open a new stream, even though its socket has not finished closing.
    if transport.is_retired() {
        return Err(HbonePoolError::TrustWithdrawn);
    }
    if transport.keepalive_failed() {
        return Err(HbonePoolError::ConnectStream {
            authority: authority.clone(),
            message: MESH_KEEPALIVE_FAILED_MESSAGE.to_string(),
        });
    }
    let MeshH2Transport { sender, gate } = transport;

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(authority.as_str())
        .body(())
        .map_err(|e| HbonePoolError::InvalidConnectRequest {
            authority: authority.clone(),
            message: e.to_string(),
        })?;
    if let Some(baggage) = baggage {
        request.headers_mut().insert(
            BAGGAGE_HEADER,
            http::HeaderValue::from_str(baggage).map_err(|e| {
                HbonePoolError::InvalidConnectRequest {
                    authority: authority.clone(),
                    message: e.to_string(),
                }
            })?,
        );
    }
    if let Some(marker) = marker {
        request.headers_mut().insert(
            "x-ferrum-mesh-protocol",
            http::HeaderValue::from_static(marker),
        );
    }

    let mut sender = sender
        .ready()
        .await
        .map_err(|e| HbonePoolError::ConnectStream {
            authority: authority.clone(),
            message: e.to_string(),
        })?;
    // `ready()` yields to the connection driver. A withdrawal can land after
    // the checkout-time check above but before readiness resolves; refuse at
    // the final pre-wire boundary so a retained sender cannot open a fresh
    // CONNECT stream during that interval.
    if gate.is_retired() {
        return Err(HbonePoolError::TrustWithdrawn);
    }
    if gate.keepalive_failed() {
        return Err(HbonePoolError::ConnectStream {
            authority: authority.clone(),
            message: MESH_KEEPALIVE_FAILED_MESSAGE.to_string(),
        });
    }
    let (response_fut, send_stream) =
        sender
            .send_request(request, false)
            .map_err(|e| HbonePoolError::ConnectStream {
                authority: authority.clone(),
                message: e.to_string(),
            })?;
    let response = response_fut
        .await
        .map_err(|e| HbonePoolError::ConnectStream {
            authority: authority.clone(),
            message: e.to_string(),
        })?;
    if response.status() != StatusCode::OK {
        return Err(HbonePoolError::ConnectRejected {
            authority,
            status: response.status().as_u16(),
        });
    }
    Ok(H2ConnectTunnel {
        recv_stream: response.into_body(),
        send_stream,
        read_buf: Bytes::new(),
        write_closed: false,
        write_reservation: 0,
        gate,
    })
}

/// Outcome of a successful WebSocket Extended CONNECT (RFC 8441) over an H2
/// session: the byte tunnel carrying the raw WebSocket frame stream, plus the
/// subprotocol the peer negotiated (forwarded to the originating client per RFC
/// 6455 §11.3.4 / RFC 8441 §5.2). The tunnel is the wire transport directly —
/// there is NO inner HTTP/1.1 upgrade handshake and NO `Sec-WebSocket-Key`
/// exchange (those are HTTP/1.1-only); the caller wraps the tunnel as a
/// `Role::Client` WebSocket framer.
pub struct H2WsConnectTunnel {
    pub tunnel: H2ConnectTunnel,
    pub negotiated_subprotocol: Option<http::HeaderValue>,
}

/// Open one HTTP/2 **Extended** CONNECT stream (RFC 8441 — `:method=CONNECT`
/// plus the `:protocol=websocket` pseudo-header) carrying the `:authority`
/// routing key over `sender`, returning the byte tunnel that carries the
/// WebSocket frame stream. This is the WebSocket analogue of
/// [`open_h2_connect_stream`]: the destination's mesh inbound listener (Sidecar
/// `:15006` / Ambient `:15008`, both advertise
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL`) treats the Extended CONNECT exactly as a
/// client-originated WebSocket upgrade and bridges it to the local app — so the
/// source must speak Extended CONNECT, NOT a bare CONNECT carrying an inner H1
/// handshake.
///
/// `authority` is the pre-built `:authority` the peer routes on — the caller
/// computes it with the same preserve-host / multi-port logic as the HTTP-family
/// mesh egress path so parity holds byte-for-byte (e.g. a port-less service
/// Host). It is independent of the connection's dial target (the connection is
/// already established on `sender`). `path_and_query` is the client's request
/// target (`:path`), preserved byte-for-byte so `ws://svc-b/ws?room=1` reaches
/// the destination as `/ws?room=1` (not `/`) — the caller derives it from the
/// computed backend URL and guarantees a leading `/`.
///
/// `ws_handshake_headers` are the forwardable WebSocket request headers (e.g.
/// `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions`, identity headers) that
/// ride the Extended CONNECT request; the RFC 6455 framing headers
/// (`Upgrade`/`Connection`/`Sec-WebSocket-Key`/`Sec-WebSocket-Version`) are NOT
/// sent — they are HTTP/1.1-only and the caller's frontend already stripped
/// them. `marker` stamps the optional `x-ferrum-mesh-protocol` header
/// (`Some("hbone")` for Ambient HBONE; `None` for a Sidecar mesh-mTLS dial), and
/// `baggage` carries the optional W3C baggage source identity (HBONE only).
///
/// Fails closed: if the peer never acknowledged
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL`, sending an Extended CONNECT would be a
/// protocol violation, so we return [`HbonePoolError::ExtendedConnectUnsupported`]
/// before sending anything. A non-200 response also fails closed.
pub(crate) async fn open_h2_ws_connect_stream(
    transport: MeshH2Transport,
    authority: &str,
    path_and_query: &str,
    ws_handshake_headers: &[(String, String)],
    baggage: Option<&str>,
    marker: Option<&'static str>,
) -> Result<H2WsConnectTunnel, HbonePoolError> {
    // Synchronous refusal (issue #3859): a transport retired between checkout
    // and Extended CONNECT may not open a new stream.
    if transport.is_retired() {
        return Err(HbonePoolError::TrustWithdrawn);
    }
    if transport.keepalive_failed() {
        return Err(HbonePoolError::ConnectStream {
            authority: authority.to_string(),
            message: MESH_KEEPALIVE_FAILED_MESSAGE.to_string(),
        });
    }
    let MeshH2Transport { sender, gate } = transport;
    // Owned copy for the error variants (which carry a `String`).
    let authority = authority.to_string();
    // RFC 8441 Extended CONNECT keeps `:scheme` and `:path` (unlike a bare
    // CONNECT, which drops them). h2 derives them from the request URI, so build
    // a full `https://<authority><path_and_query>` URI rather than a bare
    // authority. `path_and_query` is the CLIENT's request target (e.g.
    // `/ws?room=1`), preserved byte-for-byte so the destination routes + builds
    // the local backend WebSocket URL on the same path the client requested
    // (parity with direct WS forwarding and the HTTP mesh paths). Callers
    // normalize it to start with `/`; an empty/relative value would make
    // `https://authority` parse as an opaque URI with no path, so the caller
    // guarantees a leading `/`.
    let uri = format!("https://{authority}{path_and_query}");
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(uri.as_str())
        .body(())
        .map_err(|e| HbonePoolError::InvalidConnectRequest {
            authority: authority.to_string(),
            message: e.to_string(),
        })?;
    // The `:protocol` pseudo-header is carried as an h2 extension; the h2 client
    // removes it from the request extensions and serializes it on the wire.
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("websocket"));
    if let Some(baggage) = baggage {
        request.headers_mut().insert(
            BAGGAGE_HEADER,
            http::HeaderValue::from_str(baggage).map_err(|e| {
                HbonePoolError::InvalidConnectRequest {
                    authority: authority.clone(),
                    message: e.to_string(),
                }
            })?,
        );
    }
    if let Some(marker) = marker {
        request.headers_mut().insert(
            "x-ferrum-mesh-protocol",
            http::HeaderValue::from_static(marker),
        );
    }
    for (name, value) in ws_handshake_headers {
        if let (Ok(header_name), Ok(header_value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            request.headers_mut().append(header_name, header_value);
        }
    }

    let mut sender = sender
        .ready()
        .await
        .map_err(|e| HbonePoolError::ConnectStream {
            authority: authority.clone(),
            message: e.to_string(),
        })?;
    // Fail closed before sending: a peer that never acknowledged
    // `SETTINGS_ENABLE_CONNECT_PROTOCOL` would reset an Extended CONNECT stream.
    // The setting is learned from the peer's initial SETTINGS frame, which the
    // connection driver processes asynchronously — on a freshly handshaked
    // connection it may not be observed at the instant `ready()` first resolves.
    // Poll it with a short bounded wait (yielding so the driver can read the
    // frame) before declaring the peer incapable, so a healthy peer that simply
    // hasn't had its SETTINGS processed yet is not falsely rejected.
    if !sender.is_extended_connect_protocol_enabled() {
        let mut negotiated = false;
        for attempt in 0..EXTENDED_CONNECT_SETTINGS_POLL_ATTEMPTS {
            if attempt == 0 {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(EXTENDED_CONNECT_SETTINGS_POLL_INTERVAL).await;
            }
            if sender.is_extended_connect_protocol_enabled() {
                negotiated = true;
                break;
            }
        }
        if !negotiated {
            return Err(HbonePoolError::ExtendedConnectUnsupported { authority });
        }
    }
    // The bounded SETTINGS wait above yields. Re-check immediately before
    // `send_request` so a trust withdrawal cannot race that wait and enqueue a
    // new Extended CONNECT stream on the retired TLS session.
    if gate.is_retired() {
        return Err(HbonePoolError::TrustWithdrawn);
    }
    if gate.keepalive_failed() {
        return Err(HbonePoolError::ConnectStream {
            authority: authority.clone(),
            message: MESH_KEEPALIVE_FAILED_MESSAGE.to_string(),
        });
    }
    let (response_fut, send_stream) =
        sender
            .send_request(request, false)
            .map_err(|e| HbonePoolError::ConnectStream {
                authority: authority.clone(),
                message: e.to_string(),
            })?;
    let response = response_fut
        .await
        .map_err(|e| HbonePoolError::ConnectStream {
            authority: authority.clone(),
            message: e.to_string(),
        })?;
    if response.status() != StatusCode::OK {
        return Err(HbonePoolError::ConnectRejected {
            authority,
            status: response.status().as_u16(),
        });
    }
    let negotiated_subprotocol = response
        .headers()
        .get(http::header::SEC_WEBSOCKET_PROTOCOL)
        .cloned();
    Ok(H2WsConnectTunnel {
        tunnel: H2ConnectTunnel {
            recv_stream: response.into_body(),
            send_stream,
            read_buf: Bytes::new(),
            write_closed: false,
            write_reservation: 0,
            gate,
        },
        negotiated_subprotocol,
    })
}

pub fn target_hbone_enabled(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(HBONE_TARGET_TAG)
        .is_some_and(|value| matches_boolish_true(value))
}

pub fn target_hbone_port(target: &UpstreamTarget) -> u16 {
    target
        .tags
        .get(HBONE_PORT_TAG)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(ISTIO_HBONE_PORT)
}

/// The outer TCP/TLS host to dial for an HBONE target. Defaults to the target
/// host. A present-but-empty override fails closed so a malformed waypoint
/// target cannot silently downgrade to a direct workload dial.
pub fn target_hbone_dial_host(target: &UpstreamTarget) -> Result<&str, HbonePoolError> {
    match target.tags.get(HBONE_DIAL_HOST_TAG) {
        None => Ok(target.host.as_str()),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(HbonePoolError::InvalidDialHostTag {
                    value: value.clone(),
                    message: "dial host must not be empty".to_string(),
                })
            } else {
                Ok(trimmed)
            }
        }
    }
}

/// The inner HBONE CONNECT `:authority` HOST for this target — the real
/// destination pod address the dest relay dials under the open-relay guard.
/// Reads [`HBONE_AUTHORITY_HOST_TAG`] when present (AMBIENT CROSS-CLUSTER, whose
/// `target.host` is a scoped synthetic identity, NOT a dialable address), else
/// falls back to `target.host` (every in-cluster target, byte-identical to the
/// prior behavior). A present-but-empty override fails closed so a corrupt tag
/// can never produce a `:0`/empty CONNECT authority — the dispatch path treats
/// this as a fatal cross-cluster misconfiguration (502), never dialing the
/// synthetic identity as the authority.
pub fn target_hbone_authority_host(target: &UpstreamTarget) -> Result<&str, HbonePoolError> {
    match target.tags.get(HBONE_AUTHORITY_HOST_TAG) {
        None => Ok(target.host.as_str()),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(HbonePoolError::InvalidAuthorityHostTag {
                    value: value.clone(),
                    message: "HBONE CONNECT authority host must not be empty".to_string(),
                })
            } else {
                Ok(trimmed)
            }
        }
    }
}

/// The destination identity an outbound mesh dial must PIN, read from the
/// target's [`HBONE_PEER_SPIFFE_ID_TAG`] override, or else
/// [`MESH_SPIFFE_ID_TAG`]. `Ok(None)` when both are absent — operator-supplied
/// targets without a declared peer identity keep trust-domain-only
/// verification. A PRESENT but unparseable tag is an error so a corrupted
/// identity fails the dial closed instead of silently downgrading to unpinned
/// verification.
pub fn target_expected_peer_spiffe(
    target: &UpstreamTarget,
) -> Result<Option<crate::identity::SpiffeId>, HbonePoolError> {
    let value = target
        .tags
        .get(HBONE_PEER_SPIFFE_ID_TAG)
        .or_else(|| target.tags.get(MESH_SPIFFE_ID_TAG));
    match value {
        None => Ok(None),
        Some(value) => crate::identity::SpiffeId::new(value)
            .map(Some)
            .map_err(|e| HbonePoolError::InvalidPeerSpiffeTag {
                value: value.clone(),
                message: e.to_string(),
            }),
    }
}

/// Whether an HBONE target is a CROSS-CLUSTER east-west target (carries the
/// transport-agnostic [`crate::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG`] =
/// boolish-true). Such a target dials the REMOTE east-west gateway
/// (`mesh.hbone_dial_host` / `mesh.hbone_port`) with the destination workload's
/// pod addr:app-port as the inner CONNECT `:authority` (= `target.host:port`)
/// and the destination service FQDN as the outer-TLS SNI override
/// (`mesh.eastwest_sni`), using TRUST-DOMAIN-ONLY peer verification scoped to the
/// remote trust domain (`mesh.trust_domain`). The cross-cluster / SNI / trust
/// domain tags are shared with the Sidecar mesh-mTLS cross-cluster path (one
/// set of tag constants, defined in `mesh_mtls_pool`); the HBONE path layers the
/// HBONE transport tags (`mesh.hbone*`) on top.
pub fn target_hbone_cross_cluster(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(crate::proxy::mesh_mtls_pool::MESH_CROSS_CLUSTER_TAG)
        .is_some_and(|value| matches_boolish_true(value))
}

/// The destination-service-FQDN outer-TLS SNI override a CROSS-CLUSTER HBONE
/// target MUST carry ([`crate::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG`]).
/// `None` when absent OR empty so the dispatch path can FAIL CLOSED — a
/// cross-cluster HBONE dial without a usable SNI must be refused, never fall
/// back to the gateway address as SNI (which would break the passthrough route).
pub fn target_hbone_eastwest_sni(target: &UpstreamTarget) -> Option<&str> {
    target
        .tags
        .get(crate::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG)
        .map(String::as_str)
        .filter(|sni| !sni.is_empty())
}

/// The remote trust domain a CROSS-CLUSTER HBONE target scopes verification to
/// ([`crate::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG`]). `None` when absent,
/// empty, or unparseable so the dispatch path can FAIL CLOSED — a cross-cluster
/// HBONE dial with no usable trust domain must be refused, never fall back to
/// any-federated verification (which would let a federated cert from a DIFFERENT
/// trust domain complete the handshake). Cross-cluster HBONE targets carry NO
/// `mesh.spiffe_id`, so this remote trust domain is the only identity constraint.
pub fn target_hbone_cross_cluster_trust_domain(
    target: &UpstreamTarget,
) -> Option<crate::identity::spiffe::TrustDomain> {
    target
        .tags
        .get(crate::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG)
        .filter(|value| !value.is_empty())
        .and_then(|value| crate::identity::spiffe::TrustDomain::new(value.as_str()).ok())
}

/// Resolved dial parameters for an Ambient HBONE CONNECT, derived ONCE from a
/// target's mesh tags — the HBONE counterpart of
/// [`crate::proxy::mesh_mtls_pool::MeshMtlsDialPlan`] (issue #3284).
///
/// The inline resolution in `proxy_to_backend_hbone` remains the HTTP path's
/// own (it maps each failure to its own 502 shape); this type exists so the
/// nested-HTTP/2 gRPC transport resolves the SAME tags with the SAME
/// fail-closed rules instead of re-deriving them, and every failure is an
/// ordinary [`HbonePoolError`] so callers keep one error mapping.
///
/// The two shapes:
/// - **In-cluster** (default): dial the workload/waypoint directly and PIN the
///   destination identity from `mesh.hbone_peer_spiffe_id` / `mesh.spiffe_id`.
///   A present-but-corrupt tag fails closed; an absent one keeps the
///   trust-domain-only verification operator-supplied targets have always had.
/// - **Cross-cluster** (`mesh.cross_cluster`): dial the REMOTE east-west
///   gateway (`mesh.hbone_dial_host`), override the ClientHello SNI to the
///   destination service FQDN (`mesh.eastwest_sni`), and scope verification to
///   the remote trust domain (`mesh.trust_domain`). Both are mandatory — a
///   missing one fails closed rather than dialing the gateway address as SNI or
///   falling back to any-federated verification.
#[derive(Debug)]
pub struct HboneDialPlan<'a> {
    /// Outer TCP/TLS host: the workload/waypoint in-cluster, the remote
    /// east-west gateway cross-cluster.
    pub dial_host: &'a str,
    /// Inner CONNECT `:authority` HOST — the REAL destination pod address the
    /// destination relay dials under the open-relay guard.
    pub app_host: &'a str,
    /// Peer HBONE listener port (`mesh.hbone_port`, default `:15008`).
    pub hbone_port: u16,
    /// Pinned destination workload identity (in-cluster), or `None`.
    pub expected_peer: Option<crate::identity::SpiffeId>,
    /// Remote trust domain verification is scoped to (cross-cluster only).
    pub expected_trust_domain: Option<crate::identity::spiffe::TrustDomain>,
    /// ClientHello SNI override (cross-cluster only). Borrowed from the target
    /// tag to avoid a per-dispatch allocation.
    pub sni_override: Option<&'a str>,
}

impl<'a> HboneDialPlan<'a> {
    /// Resolve the dial plan for `target`, or a fail-closed [`HbonePoolError`].
    /// Callers map the error to their own protocol-appropriate refusal — never
    /// a plaintext or non-HBONE fallback.
    pub fn resolve(target: &'a UpstreamTarget) -> Result<Self, HbonePoolError> {
        let dial_host = target_hbone_dial_host(target)?;
        if target_hbone_cross_cluster(target) && !target.tags.contains_key(HBONE_AUTHORITY_HOST_TAG)
        {
            return Err(HbonePoolError::MissingCrossClusterAuthorityHost);
        }
        let app_host = target_hbone_authority_host(target)?;
        let hbone_port = target_hbone_port(target);
        if target_hbone_cross_cluster(target) {
            // SNI override THEN trust domain, both mandatory — the same order
            // the HTTP dispatch path checks them inline.
            let sni_override =
                target_hbone_eastwest_sni(target).ok_or(HbonePoolError::MissingCrossClusterSni)?;
            let trust_domain = target_hbone_cross_cluster_trust_domain(target)
                .ok_or(HbonePoolError::MissingCrossClusterTrustDomain)?;
            Ok(Self {
                dial_host,
                app_host,
                hbone_port,
                expected_peer: None,
                expected_trust_domain: Some(trust_domain),
                sni_override: Some(sni_override),
            })
        } else {
            Ok(Self {
                dial_host,
                app_host,
                hbone_port,
                expected_peer: target_expected_peer_spiffe(target)?,
                expected_trust_domain: None,
                sni_override: None,
            })
        }
    }
}

pub(crate) fn authority_for_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The inner HTTP/1.1 WebSocket handshake `Host` for an Ambient HBONE WS egress
/// spoken THROUGH the byte tunnel.
///
/// When the route preserves the client Host (`preserve_host_header`) and the
/// client actually sent a non-empty Host, that Host rides through (mirroring the
/// HTTP HBONE relay, which forwards the client Host). Otherwise the fallback is
/// `authority_for_host_port(app_host, port)` — the REAL destination pod addr
/// (`mesh.hbone_authority_host`), NOT `target.host`.
///
/// This distinction is load-bearing for CROSS-CLUSTER targets: their
/// `target.host` is the scoped synthetic `mesh-xc-hbone|...` identity, which is
/// not a valid URI authority. Falling back to it would make
/// `ws://{target.host}...` an invalid WS URI that `into_client_request()`
/// rejects AFTER the tunnel is already established (issue #2010 codex). For
/// IN-CLUSTER targets `app_host == target.host` (the authority-host tag is
/// absent), so the fallback is byte-identical to the pre-fix behavior. Mirrors
/// `proxy_to_backend_hbone`, whose backend `Host` header is
/// `authority_for_host_port(app_host, port)` when the client Host is not
/// preserved.
pub fn hbone_ws_inner_host(
    client_host: Option<&str>,
    preserve_host_header: bool,
    app_host: &str,
    port: u16,
) -> String {
    match client_host {
        Some(host) if preserve_host_header && !host.is_empty() => host.to_string(),
        _ => authority_for_host_port(app_host, port),
    }
}

fn h2_window_sizes(pool_config: &PoolConfig) -> (u32, u32) {
    if pool_config.http2_adaptive_window {
        (
            pool_config
                .http2_initial_stream_window_size
                .max(ADAPTIVE_STREAM_WINDOW_SIZE),
            pool_config
                .http2_initial_connection_window_size
                .max(ADAPTIVE_CONNECTION_WINDOW_SIZE),
        )
    } else {
        (
            pool_config.http2_initial_stream_window_size,
            pool_config.http2_initial_connection_window_size,
        )
    }
}

pub fn svid_fingerprint(bundle: &SvidBundle) -> Result<String, HbonePoolError> {
    let leaf = bundle
        .cert_chain_der
        .first()
        .ok_or(HbonePoolError::NoLeafCert)?;
    let digest = Sha256::digest(leaf);
    let mut out = String::with_capacity(16);
    for byte in digest[..8].iter() {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

fn hbone_key_svid_fingerprint(key: &str) -> Option<&str> {
    key.split('|').nth(5)
}

fn prune_pool_entries(entries: &mut Vec<HbonePoolEntry>) -> usize {
    let before = entries.len();
    let now = unix_secs();
    entries.retain(|entry| {
        // Retired by a gateway trust withdrawal: evict without consulting the
        // socket at all (issue #3859). Keepalive-failed transports are evicted
        // the same way so a black-holed peer cannot stay "healthy" (issue #4162).
        if entry.transport.is_retired() || entry.transport.keepalive_failed() {
            return false;
        }
        let sender = entry.transport.sender.clone();
        if matches!(sender.ready().now_or_never(), Some(Err(_))) {
            return false;
        }
        !entry_idle_expired(
            entry.last_used_at.load(Ordering::Relaxed),
            entry.idle_timeout_seconds,
            now,
        )
    });
    before.saturating_sub(entries.len())
}

fn record_hbone_evictions(count: usize) {
    crate::runtime_metrics::global_ref()
        .record_pool_evictions(crate::runtime_metrics::PoolKind::Hbone, count as u64);
}

/// Remove the pool entry whose gate is `gate`. Identity match (not key-only)
/// so a concurrent checkout that replaced this transport under the same key
/// is not evicted (issue #4162). Mirrors `DashMap::remove_if` + `Arc::ptr_eq`
/// used by `GenericPool` pending-creation cleanup and the HTTP/3 / HTTP/2
/// pool invalidation pattern.
fn evict_hbone_entry_for_gate(
    entries: &DashMap<String, Vec<HbonePoolEntry>>,
    key: &str,
    gate: &MeshTransportGate,
) {
    let mut removed = 0;
    {
        if let Some(mut shard) = entries.get_mut(key) {
            let before = shard.len();
            shard.retain(|entry| !entry.transport.gate.ptr_eq(gate));
            removed = before.saturating_sub(shard.len());
        }
    }
    entries.remove_if(key, |_, remaining| remaining.is_empty());
    record_hbone_evictions(removed);
}

// `last_used_secs`/`now_secs` are wall-clock `unix_secs()`. `GenericPool` no
// longer shares that convention: issue #4517 moved `PoolEntry.last_used_tick_ms`
// onto the process-monotonic tick, and this pool is the remaining wall-clock
// idle scheduler. A backward wall-clock step (NTP correction, VM resume) makes
// `saturating_sub` under-count idle time, so an idle entry may survive a few
// extra prune cycles until the clock catches up — never unbounded, since dead
// senders are still culled by the `ready()` health probe on both the read and
// write paths. A forward step larger than the timeout can evict one fresh
// entry, after which it self-heals. Migrating this pool's prune scheduler and
// this field together is the right place to remove that residual, not a
// piecemeal switch of this one field that would desync it from the rest of the
// pool's timing.
pub(crate) fn entry_idle_expired(
    last_used_secs: u64,
    idle_timeout_seconds: u64,
    now_secs: u64,
) -> bool {
    idle_timeout_seconds > 0 && now_secs.saturating_sub(last_used_secs) > idle_timeout_seconds
}

pub(crate) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn matches_boolish_true(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
        || value == "1"
}

#[allow(clippy::too_many_arguments)]
fn with_hbone_pool_key<R>(
    host: &str,
    target_port: u16,
    hbone_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&crate::identity::SpiffeId>,
    sni_override: Option<&str>,
    expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
    pool_config: &PoolConfig,
    f: impl FnOnce(&str) -> R,
) -> R {
    HBONE_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_hbone_pool_key(
            &mut buf,
            host,
            target_port,
            hbone_port,
            dns_override,
            svid_fingerprint,
            expected_peer,
            sni_override,
            expected_trust_domain,
            pool_config,
        );
        f(&buf)
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn pool_key_owned(
    host: &str,
    target_port: u16,
    hbone_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&crate::identity::SpiffeId>,
    sni_override: Option<&str>,
    expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
    pool_config: &PoolConfig,
) -> String {
    with_hbone_pool_key(
        host,
        target_port,
        hbone_port,
        dns_override,
        svid_fingerprint,
        expected_peer,
        sni_override,
        expected_trust_domain,
        pool_config,
        |key| key.to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_hbone_pool_key(
    buf: &mut String,
    host: &str,
    target_port: u16,
    hbone_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&crate::identity::SpiffeId>,
    sni_override: Option<&str>,
    expected_trust_domain: Option<&crate::identity::spiffe::TrustDomain>,
    pool_config: &PoolConfig,
) {
    buf.clear();
    // The pinned peer identity is connection identity, not policy: a pooled
    // mTLS connection verified against one expected SVID must never be reused
    // for a target that pins a different (or no) identity. The ClientHello SNI
    // override (the destination FQDN on cross-cluster east-west dials; empty
    // otherwise) follows the peer field so two cross-cluster targets to the
    // SAME gateway endpoint for DIFFERENT destination services keep isolated
    // connections (each needs its own outer-TLS SNI / passthrough route). The
    // expected trust domain (the remote TD a cross-cluster session was VERIFIED
    // against; empty otherwise) follows the SNI so a session verified against
    // remote trust domain B is never reused for C. `sni` and `td` are appended
    // AFTER `svid_fingerprint` so `hbone_key_svid_fingerprint`'s positional
    // parse (index 5) is unchanged — mirroring `write_mesh_mtls_pool_key`. With
    // `sni_override = None` and `expected_trust_domain = None` the two trailing
    // fields are empty, so the in-cluster HBONE / raw-TCP / UDP / WS keys are
    // byte-identical to the pre-cross-cluster format (`...|{peer}||`).
    let _ = write!(
        buf,
        "hbone|{host}|{target_port}|{hbone_port}|{}|{svid_fingerprint}|{}|{}|{}",
        dns_override.unwrap_or_default(),
        expected_peer.map(|peer| peer.as_str()).unwrap_or_default(),
        sni_override.unwrap_or_default(),
        expected_trust_domain
            .map(crate::identity::spiffe::TrustDomain::as_str)
            .unwrap_or_default()
    );
    write_pool_config_key(buf, pool_config);
}

pub(crate) fn write_pool_config_key(buf: &mut String, pool_config: &PoolConfig) {
    // Pool-MANAGEMENT policy is intentionally excluded from the key: it does
    // not change the h2-over-mTLS connection's identity or wire behavior, and
    // including it fragmented the pool (two proxies targeting the same sidecar
    // with the same SVID but different idle-timeout / per-host caps could not
    // share an established mTLS connection). Specifically:
    //   - idle_timeout_seconds is tracked per HbonePoolEntry for idle pruning;
    //   - http2_connections_per_host is applied as a max-entries cap at insert.
    // Only fields that affect the actual connection (protocol selection,
    // keepalive, and h2 SETTINGS) remain — mirroring the direct-H2 pool key,
    // per the "never add policy fields to pool keys" invariant.
    let _ = write!(
        buf,
        "|pool={},{},{},{},{},{},{},{},{}",
        u8::from(pool_config.enable_http_keep_alive),
        u8::from(pool_config.enable_http2),
        pool_config.tcp_keepalive_seconds,
        pool_config.http2_keep_alive_interval_seconds,
        pool_config.http2_keep_alive_timeout_seconds,
        pool_config.http2_initial_stream_window_size,
        pool_config.http2_initial_connection_window_size,
        u8::from(pool_config.http2_adaptive_window),
        pool_config.http2_max_frame_size
    );
    buf.push(',');
    match pool_config.http2_max_concurrent_streams {
        Some(value) => {
            let _ = write!(buf, "{value}");
        }
        None => buf.push_str("none"),
    }
}

fn spawn_h2_keepalive(
    mut ping_pong: h2::PingPong,
    interval_seconds: u64,
    timeout_seconds: u64,
    gate: MeshTransportGate,
    keepalive_pool: Option<HboneKeepalivePoolHandle>,
) {
    let interval_seconds = interval_seconds.max(1);
    let timeout_seconds = timeout_seconds.max(1);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        let mut keepalive_pool = keepalive_pool;
        loop {
            ticker.tick().await;
            let ping_failed = match tokio::time::timeout(
                Duration::from_secs(timeout_seconds),
                ping_pong.ping(h2::Ping::opaque()),
            )
            .await
            {
                Ok(Ok(_)) => false,
                Ok(Err(e)) => {
                    debug!("hbone_pool: HTTP/2 keepalive ping failed: {}", e);
                    true
                }
                Err(_) => {
                    debug!("hbone_pool: HTTP/2 keepalive ping timed out");
                    true
                }
            };
            if ping_failed {
                let _ = gate.abort_keepalive();
                if let Some(handle) = keepalive_pool.take() {
                    handle.evict(&gate);
                }
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, ResolvedPortOverride,
        ResponseBodyMode,
    };
    use crate::dns::DnsConfig;
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::identity::{TrustBundle, TrustBundleSet};
    use arc_swap::ArcSwap;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn target_with_tags(tags: &[(&str, &str)]) -> UpstreamTarget {
        UpstreamTarget {
            host: "orders.default.svc.cluster.local".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<HashMap<_, _>>(),
            locality: None,
            path: None,
        }
    }

    fn test_proxy(connect_timeout_ms: u64) -> Proxy {
        let now = Utc::now();
        Proxy {
            id: "hbone-test".to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/hbone".to_string()),
            backend_scheme: Some(BackendScheme::Http),
            dispatch_kind: DispatchKind::from(BackendScheme::Http),
            backend_host: "orders.default.svc.cluster.local".to_string(),
            backend_port: 8080,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: connect_timeout_ms,
            backend_read_timeout_ms: 30_000,
            backend_write_timeout_ms: 30_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dispatch_port_overrides: None,
            dispatch_port_override_fallback: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            h2_upgrade_policy: None,
            pool_max_requests_per_connection: None,
            pool_http1_max_pending_requests: None,
            upstream_id: None,
            upstream_subset: None,
            api_spec_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: ResponseBodyMode::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            websocket_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            stream_proxy_protocol: None,
            backend_proxy_protocol: None,
            stream_match: None,
            compiled_stream_match: None,
            created_at: now,
            updated_at: now,
            pending_limit_scope: None,
        }
    }

    #[test]
    fn effective_connect_timeout_uses_policy_port_override() {
        let mut proxy = test_proxy(5_000);
        proxy.dispatch_port_overrides = Some(HashMap::from([(
            8080,
            ResolvedPortOverride {
                connect_timeout_ms: Some(30_000),
                ..ResolvedPortOverride::default()
            },
        )]));

        assert_eq!(
            effective_connect_timeout_ms_for_policy_port(&proxy, 8080),
            30_000
        );
        assert_eq!(
            effective_connect_timeout_ms_for_policy_port(&proxy, 9090),
            5_000
        );
    }

    #[test]
    fn hbone_tag_accepts_boolish_true_values() {
        for value in ["true", "TRUE", "1", "yes", "on"] {
            let target = target_with_tags(&[(HBONE_TARGET_TAG, value)]);
            assert!(target_hbone_enabled(&target), "{value} should enable HBONE");
        }
    }

    #[test]
    fn hbone_tag_rejects_absent_or_false_values() {
        assert!(!target_hbone_enabled(&target_with_tags(&[])));
        for value in ["false", "0", "off", "no", ""] {
            let target = target_with_tags(&[(HBONE_TARGET_TAG, value)]);
            assert!(
                !target_hbone_enabled(&target),
                "{value} should not enable HBONE"
            );
        }
    }

    #[test]
    fn hbone_port_defaults_and_overrides() {
        assert_eq!(target_hbone_port(&target_with_tags(&[])), ISTIO_HBONE_PORT);
        assert_eq!(
            target_hbone_port(&target_with_tags(&[(HBONE_PORT_TAG, "16008")])),
            16008
        );
        assert_eq!(
            target_hbone_port(&target_with_tags(&[(HBONE_PORT_TAG, "0")])),
            ISTIO_HBONE_PORT
        );
        assert_eq!(
            target_hbone_port(&target_with_tags(&[(HBONE_PORT_TAG, "not-a-port")])),
            ISTIO_HBONE_PORT
        );
    }

    #[test]
    fn hbone_dial_host_defaults_and_rejects_empty_override() {
        assert_eq!(
            target_hbone_dial_host(&target_with_tags(&[])).unwrap(),
            "orders.default.svc.cluster.local"
        );
        assert_eq!(
            target_hbone_dial_host(&target_with_tags(&[(HBONE_DIAL_HOST_TAG, "10.9.0.7")]))
                .unwrap(),
            "10.9.0.7"
        );
        assert!(matches!(
            target_hbone_dial_host(&target_with_tags(&[(HBONE_DIAL_HOST_TAG, " ")])),
            Err(HbonePoolError::InvalidDialHostTag { .. })
        ));
    }

    /// The inner-CONNECT `:authority` host falls back to `target.host` for an
    /// in-cluster target (no override tag) and reads the override for a
    /// cross-cluster target whose `target.host` is a scoped synthetic identity.
    /// A present-but-empty override fails CLOSED so dispatch never dials the
    /// synthetic identity as the CONNECT authority.
    #[test]
    fn hbone_authority_host_defaults_to_target_host_else_override() {
        // In-cluster: no tag ⇒ authority host = target.host (byte-identical to
        // the prior behavior).
        assert_eq!(
            target_hbone_authority_host(&target_with_tags(&[])).unwrap(),
            "orders.default.svc.cluster.local"
        );
        // Cross-cluster: the synthetic identity lives in `target.host`, the REAL
        // pod addr lives in the override tag, which is what the authority reads.
        let mut xc = target_with_tags(&[(HBONE_AUTHORITY_HOST_TAG, "10.244.5.5")]);
        xc.host = "mesh-xc-hbone|10.9.9.9|15443|10.244.5.5".to_string();
        assert_eq!(
            target_hbone_authority_host(&xc).unwrap(),
            "10.244.5.5",
            "the CONNECT authority must be the real pod addr, never the synthetic host"
        );
        // A present-but-empty override fails closed.
        assert!(matches!(
            target_hbone_authority_host(&target_with_tags(&[(HBONE_AUTHORITY_HOST_TAG, "  ")])),
            Err(HbonePoolError::InvalidAuthorityHostTag { .. })
        ));
    }

    #[test]
    fn hbone_peer_spiffe_override_takes_precedence_over_workload_spiffe() {
        let target = target_with_tags(&[
            (
                MESH_SPIFFE_ID_TAG,
                "spiffe://cluster.local/ns/default/sa/orders",
            ),
            (
                HBONE_PEER_SPIFFE_ID_TAG,
                "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
            ),
        ]);

        let expected = target_expected_peer_spiffe(&target)
            .expect("valid peer spiffe")
            .expect("peer spiffe present");
        assert_eq!(
            expected.as_str(),
            "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a"
        );
    }

    #[test]
    fn authority_for_host_port_brackets_ipv6_literals() {
        assert_eq!(
            authority_for_host_port("orders.default.svc.cluster.local", 8080),
            "orders.default.svc.cluster.local:8080"
        );
        assert_eq!(
            authority_for_host_port("2001:db8::10", 8080),
            "[2001:db8::10]:8080"
        );
        assert_eq!(
            authority_for_host_port("[2001:db8::10]", 8080),
            "[2001:db8::10]:8080"
        );
    }

    #[test]
    fn adaptive_window_lifts_hbone_initial_window_sizes() {
        let fixed = PoolConfig {
            http2_initial_stream_window_size: 65_535,
            http2_initial_connection_window_size: 131_072,
            http2_adaptive_window: false,
            ..PoolConfig::default()
        };
        assert_eq!(h2_window_sizes(&fixed), (65_535, 131_072));

        let adaptive = PoolConfig {
            http2_initial_stream_window_size: 65_535,
            http2_initial_connection_window_size: 131_072,
            http2_adaptive_window: true,
            ..PoolConfig::default()
        };
        assert_eq!(
            h2_window_sizes(&adaptive),
            (ADAPTIVE_STREAM_WINDOW_SIZE, ADAPTIVE_CONNECTION_WINDOW_SIZE)
        );
    }

    #[test]
    fn pool_key_includes_ports_dns_svid_and_effective_pool_config() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 12,
            enable_http_keep_alive: false,
            enable_http2: true,
            http2_connections_per_host: 3,
            tcp_keepalive_seconds: 22,
            http2_keep_alive_interval_seconds: 33,
            http2_keep_alive_timeout_seconds: 44,
            http2_initial_stream_window_size: 65_535,
            http2_initial_connection_window_size: 131_072,
            http2_adaptive_window: false,
            http2_max_frame_size: 16_384,
            http2_max_concurrent_streams: None,
            ..PoolConfig::default()
        };
        let pinned_peer =
            crate::identity::SpiffeId::new("spiffe://cluster.local/ns/default/sa/orders")
                .expect("valid spiffe id");
        let key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            Some("10.0.0.2"),
            "0123456789abcdef",
            Some(&pinned_peer),
            None,
            None,
            &pool_config,
        );
        // No cross-cluster SNI / trust-domain ⇒ two empty trailing fields after
        // the peer (byte-identical to the pre-cross-cluster format's tail except
        // for the two appended `||`).
        assert_eq!(
            key,
            "hbone|orders.default.svc.cluster.local|8080|15008|10.0.0.2|0123456789abcdef|spiffe://cluster.local/ns/default/sa/orders||"
                .to_string()
                + "|pool=0,1,22,33,44,65535,131072,0,16384,none"
        );
        // An unpinned dial must not share a connection with a pinned one.
        let unpinned_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            Some("10.0.0.2"),
            "0123456789abcdef",
            None,
            None,
            None,
            &pool_config,
        );
        assert_ne!(
            key, unpinned_key,
            "pinned-peer identity is connection identity and must partition the pool"
        );
    }

    #[test]
    fn hbone_key_svid_fingerprint_reads_fingerprint_field() {
        // The fingerprint must stay at positional index 5 even with a
        // cross-cluster SNI + trust domain appended after it.
        let key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            Some("10.0.0.2"),
            "0123456789abcdef",
            None,
            Some("svc-b.default.svc.cluster.local"),
            Some(&TrustDomain::new("cluster-b.local").unwrap()),
            &PoolConfig::default(),
        );

        assert_eq!(hbone_key_svid_fingerprint(&key), Some("0123456789abcdef"));
        assert_eq!(hbone_key_svid_fingerprint("not-a-pool-key"), None);
    }

    #[test]
    fn pool_key_changes_when_per_proxy_pool_overrides_change() {
        let base_config = PoolConfig::default();
        let overridden_config = PoolConfig {
            // A genuine connection-affecting H2 setting (still part of the key
            // after pool-management policy was dropped from it).
            http2_initial_stream_window_size: base_config.http2_initial_stream_window_size + 1,
            ..base_config.clone()
        };

        let base_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            None,
            None,
            &base_config,
        );
        let overridden_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            None,
            None,
            &overridden_config,
        );

        assert_ne!(
            base_key, overridden_key,
            "HBONE pools with different effective per-proxy H2 sizing must not share senders"
        );
    }

    #[test]
    fn pool_key_ignores_pool_management_policy() {
        // F19: idle_timeout_seconds and http2_connections_per_host are
        // pool-management policy, not connection identity. Two proxies that
        // differ ONLY in those must produce the SAME key so they can share an
        // established mTLS connection to the same sidecar.
        let base_config = PoolConfig::default();
        let policy_only_config = PoolConfig {
            idle_timeout_seconds: base_config.idle_timeout_seconds + 100,
            http2_connections_per_host: base_config.http2_connections_per_host + 5,
            ..base_config.clone()
        };
        let base_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            None,
            None,
            &base_config,
        );
        let policy_only_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            None,
            None,
            &policy_only_config,
        );
        assert_eq!(
            base_key, policy_only_key,
            "HBONE pool key must not be fragmented by idle-timeout / per-host-cap policy"
        );
    }

    #[test]
    fn idle_maintenance_removes_unreachable_empty_keys() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 1,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config,
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );

        pool.entries.insert(
            "hbone|old|8080|15008||oldfingerprint".to_string(),
            Vec::new(),
        );

        pool.maybe_prune_idle_entries();

        assert!(
            pool.entries.is_empty(),
            "map-level idle maintenance should drop keys with no live senders"
        );
    }

    #[test]
    fn idle_maintenance_prunes_orphaned_creation_locks() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 1,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config,
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let stale_key = "hbone|stale|8080|15008||oldfingerprint".to_string();
        let active_key = "hbone|active|8080|15008||oldfingerprint".to_string();
        let active_lock = Arc::new(HboneCreationSlot::new());
        let active_ref = active_lock.clone();

        pool.creation_locks
            .insert(stale_key.clone(), Arc::new(HboneCreationSlot::new()));
        pool.creation_locks
            .insert(active_key.clone(), active_lock.clone());

        pool.maybe_prune_idle_entries();

        assert!(!pool.creation_locks.contains_key(&stale_key));
        assert!(
            pool.creation_locks.contains_key(&active_key),
            "in-flight creation locks with external references must survive pruning"
        );

        drop(active_ref);
        drop(active_lock);
        pool.last_idle_prune_unix_secs.store(0, Ordering::Relaxed);
        pool.maybe_prune_idle_entries();

        assert!(!pool.creation_locks.contains_key(&active_key));
    }

    fn svid_bundle(leaf: &[u8]) -> SvidBundle {
        let td = TrustDomain::new("cluster.local").unwrap();
        SvidBundle {
            spiffe_id: SpiffeId::from_parts(&td, "ns/default/sa/gateway").unwrap(),
            cert_chain_der: vec![leaf.to_vec()],
            private_key_pkcs8_der: Vec::new().into(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: td,
                x509_authorities: vec![],
                jwt_authorities: vec![],
                refresh_hint_seconds: None,
            }),
        }
    }

    fn key_for_fingerprint(host: &str, fingerprint: &str) -> String {
        pool_key_owned(
            host,
            8080,
            ISTIO_HBONE_PORT,
            None,
            fingerprint,
            None,
            None,
            None,
            &PoolConfig::default(),
        )
    }

    fn insert_empty_entry(pool: &HboneConnectionPool, key: &str) {
        pool.entries.insert(key.to_string(), Vec::new());
        pool.creation_locks
            .insert(key.to_string(), Arc::new(HboneCreationSlot::new()));
    }

    #[test]
    fn force_drain_svid_generation_removes_only_passed_generation() {
        let bundle_a = svid_bundle(b"generation-a-leaf");
        let fingerprint_a = svid_fingerprint(&bundle_a).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(7));
        let pool = HboneConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );

        // Traffic under generation 7 builds the identity cache for A.
        let (_, cached_fp) = pool.current_svid_identity_cached().unwrap();
        assert_eq!(cached_fp.as_ref(), fingerprint_a);
        let key_a = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_a);
        insert_empty_entry(&pool, &key_a);

        // Rotation A -> B: slot swap, then the rotation consumer bumps the
        // generation. Traffic under generation 8 builds B entries.
        let bundle_b = svid_bundle(b"generation-b-leaf");
        let fingerprint_b = svid_fingerprint(&bundle_b).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_b)));
        generation.store(8, Ordering::Release);
        let (_, cached_fp) = pool.current_svid_identity_cached().unwrap();
        assert_eq!(cached_fp.as_ref(), fingerprint_b);
        let key_b = key_for_fingerprint("b.default.svc.cluster.local", &fingerprint_b);
        insert_empty_entry(&pool, &key_b);

        // Rotation B -> C before A's drain timer fires.
        let bundle_c = svid_bundle(b"generation-c-leaf");
        let fingerprint_c = svid_fingerprint(&bundle_c).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_c)));
        generation.store(9, Ordering::Release);
        let key_c = key_for_fingerprint("c.default.svc.cluster.local", &fingerprint_c);
        insert_empty_entry(&pool, &key_c);

        // A's delayed drain must remove only generation-7 (fingerprint A)
        // entries: B's own drain window has not elapsed yet.
        pool.force_drain_svid_generation(7);
        assert!(!pool.entries.contains_key(&key_a));
        assert!(pool.entries.contains_key(&key_b));
        assert!(pool.entries.contains_key(&key_c));
        assert!(!pool.creation_locks.contains_key(&key_a));
        assert!(pool.creation_locks.contains_key(&key_b));
        assert!(pool.creation_locks.contains_key(&key_c));

        // B's drain removes B; C (current) stays.
        pool.force_drain_svid_generation(8);
        assert!(!pool.entries.contains_key(&key_b));
        assert!(pool.entries.contains_key(&key_c));
        assert!(!pool.creation_locks.contains_key(&key_b));
        assert!(pool.creation_locks.contains_key(&key_c));
    }

    #[test]
    fn force_drain_svid_generation_records_rotation_with_no_traffic() {
        // No HBONE request runs between the slot swap and the drain timer:
        // the drain itself must refresh the identity cache, record the
        // outgoing fingerprint, and still drain the old generation.
        let bundle_a = svid_bundle(b"idle-generation-a");
        let fingerprint_a = svid_fingerprint(&bundle_a).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(3));
        let pool = HboneConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );

        let (_, cached_fp) = pool.current_svid_identity_cached().unwrap();
        assert_eq!(cached_fp.as_ref(), fingerprint_a);
        let key_a = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_a);
        insert_empty_entry(&pool, &key_a);

        let bundle_b = svid_bundle(b"idle-generation-b");
        let fingerprint_b = svid_fingerprint(&bundle_b).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_b)));
        generation.store(4, Ordering::Release);
        let key_b = key_for_fingerprint("b.default.svc.cluster.local", &fingerprint_b);
        insert_empty_entry(&pool, &key_b);

        pool.force_drain_svid_generation(3);
        assert!(!pool.entries.contains_key(&key_a));
        assert!(pool.entries.contains_key(&key_b));

        // Draining the current generation is a no-op: nothing was retired
        // under it.
        pool.force_drain_svid_generation(4);
        assert!(pool.entries.contains_key(&key_b));
    }

    #[test]
    fn force_drain_svid_generation_drains_all_without_svid() {
        let pool = HboneConnectionPool::new(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let key = key_for_fingerprint("a.default.svc.cluster.local", "anyfingerprint");
        insert_empty_entry(&pool, &key);

        pool.force_drain_svid_generation(1);

        assert!(pool.entries.is_empty());
        assert!(pool.creation_locks.is_empty());
    }

    #[test]
    fn force_drain_sweeps_generations_at_or_below_passed() {
        // The slot-swap → generation-store race can file a fingerprint one
        // generation too low (see `force_drain_svid_generation` docs). A
        // record misfiled under an already-drained generation must be picked
        // up by the next drain rather than leaking until idle pruning.
        let bundle_a = svid_bundle(b"sweep-generation-a");
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(7));
        let pool = HboneConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_identity_cached().unwrap();

        // Race: the slot swaps to B and traffic rebuilds the cache while the
        // rotation consumer has not stored generation 8 yet, so B is stamped
        // with generation 7.
        let bundle_b = svid_bundle(b"sweep-generation-b");
        let fingerprint_b = svid_fingerprint(&bundle_b).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_b)));
        pool.current_svid_identity_cached().unwrap();
        // Generation 7's drain fires and consumes A's record.
        pool.force_drain_svid_generation(7);
        generation.store(8, Ordering::Release);
        let key_b = key_for_fingerprint("b.default.svc.cluster.local", &fingerprint_b);
        insert_empty_entry(&pool, &key_b);

        // Rotation B -> C files B's fingerprint under its (stale) stamped
        // generation 7 — a generation whose drain already ran.
        let bundle_c = svid_bundle(b"sweep-generation-c");
        let fingerprint_c = svid_fingerprint(&bundle_c).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_c)));
        generation.store(9, Ordering::Release);
        pool.current_svid_identity_cached().unwrap();
        let key_c = key_for_fingerprint("c.default.svc.cluster.local", &fingerprint_c);
        insert_empty_entry(&pool, &key_c);

        // Generation 8's drain must sweep the misfiled record; C (newer)
        // stays untouched.
        pool.force_drain_svid_generation(8);
        assert!(
            !pool.entries.contains_key(&key_b),
            "record misfiled under an already-drained generation must be swept by the next drain"
        );
        assert!(pool.entries.contains_key(&key_c));
    }

    #[test]
    fn trust_bundle_only_rotation_retires_current_fingerprint() {
        // A trust-bundle-only reload keeps the leaf (and thus the
        // fingerprint) but still publishes a rotation: sessions verified
        // against the previous bundle must not outlive the drain window even
        // though their keys collide with current ones.
        let bundle_a = svid_bundle(b"bundle-rotation-leaf");
        let fingerprint = svid_fingerprint(&bundle_a).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(5));
        let pool = HboneConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_identity_cached().unwrap();
        let key = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint);
        insert_empty_entry(&pool, &key);

        // Same leaf, fresh slot store (the rotation watcher is change-gated,
        // so any store is a genuine material change — here: new trust
        // bundle). No traffic runs before the drain.
        gateway_svid.store(Arc::new(Some(svid_bundle(b"bundle-rotation-leaf"))));
        generation.store(6, Ordering::Release);

        pool.force_drain_svid_generation(5);
        assert!(
            !pool.entries.contains_key(&key),
            "old-trust-bundle sessions must drain even when the leaf fingerprint is unchanged"
        );
    }

    #[test]
    fn capped_registry_eviction_drains_evicted_generations() {
        let bundle_0 = svid_bundle(b"evict-leaf-0");
        let fingerprint_0 = svid_fingerprint(&bundle_0).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_0))));
        let generation = Arc::new(AtomicU64::new(0));
        let pool = HboneConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_identity_cached().unwrap();
        let key_0 = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_0);
        insert_empty_entry(&pool, &key_0);

        // Rotation storm overflows the registry; generation 0's record is
        // evicted before any drain timer fires — its entries must drain at
        // eviction instead of leaking until idle pruning.
        for revision in 1..=(MAX_RETIRED_SVID_GENERATIONS as u64 + 2) {
            let leaf = format!("evict-leaf-{revision}");
            gateway_svid.store(Arc::new(Some(svid_bundle(leaf.as_bytes()))));
            generation.store(revision, Ordering::Release);
            pool.current_svid_identity_cached().unwrap();
        }

        assert!(
            !pool.entries.contains_key(&key_0),
            "registry cap eviction must drain the evicted generation's entries"
        );
        assert!(pool.retired_svid_fingerprints.len() <= MAX_RETIRED_SVID_GENERATIONS);
    }

    #[test]
    fn per_generation_retired_list_is_capped_and_drains_overflow() {
        let bundle_0 = svid_bundle(b"frozen-leaf-0");
        let fingerprint_0 = svid_fingerprint(&bundle_0).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_0))));
        // Frozen generation counter: a starved rotation consumer stamps every
        // rotation with the same generation, funnelling all retirements into
        // one bucket.
        let generation = Arc::new(AtomicU64::new(3));
        let pool = HboneConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_identity_cached().unwrap();
        let key_0 = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_0);
        insert_empty_entry(&pool, &key_0);

        for revision in 1..=(MAX_RETIRED_FINGERPRINTS_PER_GENERATION as u64 * 2) {
            let leaf = format!("frozen-leaf-{revision}");
            gateway_svid.store(Arc::new(Some(svid_bundle(leaf.as_bytes()))));
            pool.current_svid_identity_cached().unwrap();
        }

        let bucket_len = pool
            .retired_svid_fingerprints
            .get(&3)
            .map(|bucket| bucket.len())
            .unwrap_or(0);
        assert!(
            bucket_len <= MAX_RETIRED_FINGERPRINTS_PER_GENERATION,
            "per-generation bucket must stay bounded under a frozen generation counter"
        );
        assert!(
            !pool.entries.contains_key(&key_0),
            "fingerprints evicted from a full bucket must drain their entries"
        );
    }

    #[test]
    fn retired_fingerprint_registry_is_capped() {
        let bundle = svid_bundle(b"cap-initial-leaf");
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle))));
        let generation = Arc::new(AtomicU64::new(0));
        let pool = HboneConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_identity_cached().unwrap();

        // Rotation storm with the drain window disabled: nothing consumes the
        // retired records, so the registry must stay capped.
        for revision in 1..=(MAX_RETIRED_SVID_GENERATIONS as u64 * 3) {
            let leaf = format!("cap-leaf-{revision}");
            gateway_svid.store(Arc::new(Some(svid_bundle(leaf.as_bytes()))));
            generation.store(revision, Ordering::Release);
            pool.current_svid_identity_cached().unwrap();
        }

        assert!(pool.retired_svid_fingerprints.len() <= MAX_RETIRED_SVID_GENERATIONS);
    }

    #[tokio::test]
    async fn coalesced_creation_lock_wait_obeys_connect_timeout() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 60,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config.clone(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let proxy = test_proxy(10);
        let key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            ISTIO_HBONE_PORT,
            None,
            "fingerprint",
            None,
            None,
            None,
            &pool_config,
        );
        let creation_lock = Arc::new(HboneCreationSlot::new());
        let _held_guard = match creation_lock.join().wait().await {
            SharedCreationRole::Creator(lease) => lease,
            SharedCreationRole::Failed(_) => panic!("a fresh slot must elect a creator"),
        };
        pool.creation_locks
            .insert(key.clone(), creation_lock.clone());

        let started = Instant::now();
        let err = pool
            .get_or_create_sender(
                &proxy,
                "orders.default.svc.cluster.local",
                "orders.default.svc.cluster.local",
                8080,
                8080,
                ISTIO_HBONE_PORT,
                None,
                None,
                None,
                &key,
                &pool_config,
                None,
            )
            .await
            .expect_err("coalesced lock wait should time out");

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "lock wait must respect backend_connect_timeout_ms instead of queueing indefinitely"
        );
        match err {
            HbonePoolError::ConnectStream { authority, message } => {
                assert_eq!(authority, "orders.default.svc.cluster.local:8080");
                assert!(message.contains("waiting to coalesce HBONE HTTP/2 sender creation"));
            }
            other => panic!("expected ConnectStream timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn coalesced_creation_lock_wait_obeys_connect_timeout_override() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 60,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config.clone(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let proxy = test_proxy(2_000);
        let key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            ISTIO_HBONE_PORT,
            None,
            "fingerprint",
            None,
            None,
            None,
            &pool_config,
        );
        let creation_lock = Arc::new(HboneCreationSlot::new());
        let _held_guard = match creation_lock.join().wait().await {
            SharedCreationRole::Creator(lease) => lease,
            SharedCreationRole::Failed(_) => panic!("a fresh slot must elect a creator"),
        };
        pool.creation_locks
            .insert(key.clone(), creation_lock.clone());

        let started = Instant::now();
        let err = pool
            .get_or_create_sender(
                &proxy,
                "orders.default.svc.cluster.local",
                "orders.default.svc.cluster.local",
                8080,
                8080,
                ISTIO_HBONE_PORT,
                None,
                None,
                None,
                &key,
                &pool_config,
                Some(Duration::from_millis(25)),
            )
            .await
            .expect_err("coalesced lock wait should time out");

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "lock wait must respect the connect timeout override instead of the proxy default"
        );
        match err {
            HbonePoolError::ConnectStream { authority, message } => {
                assert_eq!(authority, "orders.default.svc.cluster.local:8080");
                assert!(message.contains("timed out after 25ms"));
            }
            other => panic!("expected ConnectStream timeout, got {other:?}"),
        }
    }

    #[test]
    fn idle_expiration_uses_last_used_time() {
        let now: u64 = 1_000_000;

        assert!(
            entry_idle_expired(now - 2, 1, now),
            "entries idle longer than the timeout should expire"
        );
        assert!(
            !entry_idle_expired(now, 1, now),
            "freshly used entries should stay in the pool"
        );
        assert!(
            !entry_idle_expired(now - 60, 0, now),
            "zero idle timeout disables idle pruning"
        );
    }

    #[test]
    fn fingerprint_uses_first_eight_sha256_bytes_of_leaf_cert() {
        let td = TrustDomain::new("cluster.local").unwrap();
        let bundle = SvidBundle {
            spiffe_id: SpiffeId::from_parts(&td, "ns/default/sa/gateway").unwrap(),
            cert_chain_der: vec![b"leaf-cert".to_vec(), b"intermediate".to_vec()],
            private_key_pkcs8_der: Vec::new().into(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: td,
                x509_authorities: vec![],
                jwt_authorities: vec![],
                refresh_hint_seconds: None,
            }),
        };

        let expected_digest = Sha256::digest(b"leaf-cert");
        let mut expected = String::new();
        for byte in expected_digest[..8].iter() {
            let _ = write!(expected, "{byte:02x}");
        }

        assert_eq!(svid_fingerprint(&bundle).unwrap(), expected);
    }

    #[test]
    fn capability_failure_requires_protocol_or_configuration_evidence() {
        let dns_failure = HbonePoolError::DnsLookup {
            host: "orders.default.svc.cluster.local".to_string(),
            message: "temporary resolver failure".to_string(),
        };
        assert!(
            !dns_failure.is_capability_failure(),
            "a DNS outage must fail the request without permanently disabling HBONE"
        );

        let timeout = HbonePoolError::ConnectTimeout {
            addr: "10.0.0.8:15008".to_string(),
            timeout_ms: 1_000,
        };
        assert!(
            !timeout.is_capability_failure(),
            "a peer startup timeout must remain retryable after the peer recovers"
        );

        let refused = HbonePoolError::Connect {
            addr: "10.0.0.8:15008".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "peer is restarting",
            ),
        };
        assert!(
            !refused.is_capability_failure(),
            "connection refusal during a rolling restart must not poison the capability cache"
        );

        let rejected = HbonePoolError::ConnectRejected {
            authority: "orders.default.svc.cluster.local:8080".to_string(),
            status: 403,
        };
        assert!(
            !rejected.is_capability_failure(),
            "policy or workload-level CONNECT rejection must not downgrade HBONE support"
        );

        let stream_failure = HbonePoolError::ConnectStream {
            authority: "orders.default.svc.cluster.local:8080".to_string(),
            message: "stream reset".to_string(),
        };
        assert!(
            !stream_failure.is_capability_failure(),
            "a single CONNECT stream failure should not mark the sidecar HBONE-unsupported"
        );

        let h2_failure = HbonePoolError::H2Handshake {
            host: "orders.default.svc.cluster.local".to_string(),
            message: "peer reset connection during HTTP/2 preface".to_string(),
        };
        assert!(
            !h2_failure.is_capability_failure(),
            "post-TLS H2 handshake loss during peer restart must preserve prior capability"
        );

        let tls_reset_error = std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "peer reset during handshake",
        );
        let tls_reset = HbonePoolError::TlsHandshake {
            host: "orders.default.svc.cluster.local".to_string(),
            source: tls_reset_error,
        };
        assert!(
            !tls_reset.is_capability_failure(),
            "TLS transport interruption during peer restart must preserve prior capability"
        );

        let tls_protocol_error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer certificate or protocol rejected",
        );
        let alpn_rejection = HbonePoolError::TlsHandshake {
            host: "orders.default.svc.cluster.local".to_string(),
            source: tls_protocol_error,
        };
        assert!(
            alpn_rejection.is_capability_failure(),
            "explicit HBONE TLS/ALPN rejection remains capability evidence"
        );
    }

    #[test]
    fn with_hbone_pool_key_matches_pool_key_owned() {
        let pool_config = PoolConfig::default();
        let owned = pool_key_owned(
            "host",
            8080,
            15008,
            None,
            "fp",
            None,
            None,
            None,
            &pool_config,
        );
        let via_callback = with_hbone_pool_key(
            "host",
            8080,
            15008,
            None,
            "fp",
            None,
            None,
            None,
            &pool_config,
            |key| key.to_string(),
        );
        assert_eq!(owned, via_callback);
    }

    /// CROSS-CLUSTER pool-key isolation: a `sni_override` and/or an
    /// `expected_trust_domain` MUST partition the pool — a session verified
    /// against trust domain B and routed by SNI for service-X is never reused for
    /// a different SNI / trust domain on the SAME `(host, port)` gateway endpoint.
    /// `None`/`None` (in-cluster) stays byte-identical to the prior format.
    #[test]
    fn cross_cluster_sni_and_trust_domain_partition_the_pool_key() {
        let pool_config = PoolConfig::default();
        let td_b = TrustDomain::new("cluster-b.local").unwrap();
        let td_c = TrustDomain::new("cluster-c.local").unwrap();

        // In-cluster baseline (no SNI / TD override).
        let in_cluster = pool_key_owned(
            "10.9.9.9",
            8080,
            15443,
            None,
            "fp",
            None,
            None,
            None,
            &pool_config,
        );
        // Cross-cluster to service-X in TD-B over the SAME gateway endpoint.
        let xc_b_svc_x = pool_key_owned(
            "10.9.9.9",
            8080,
            15443,
            None,
            "fp",
            None,
            Some("svc-x.default.svc.cluster.local"),
            Some(&td_b),
            &pool_config,
        );
        // Same gateway endpoint + same TD-B but a DIFFERENT destination service
        // (different SNI) — distinct passthrough route, must not share.
        let xc_b_svc_y = pool_key_owned(
            "10.9.9.9",
            8080,
            15443,
            None,
            "fp",
            None,
            Some("svc-y.default.svc.cluster.local"),
            Some(&td_b),
            &pool_config,
        );
        // Same gateway endpoint + same SNI but a DIFFERENT trust domain — a
        // session verified against TD-C must never be reused as TD-B.
        let xc_c_svc_x = pool_key_owned(
            "10.9.9.9",
            8080,
            15443,
            None,
            "fp",
            None,
            Some("svc-x.default.svc.cluster.local"),
            Some(&td_c),
            &pool_config,
        );

        assert_ne!(
            in_cluster, xc_b_svc_x,
            "a cross-cluster SNI/TD session must not share with an in-cluster one"
        );
        assert_ne!(
            xc_b_svc_x, xc_b_svc_y,
            "different destination SNIs on the same gateway endpoint must partition the pool"
        );
        assert_ne!(
            xc_b_svc_x, xc_c_svc_x,
            "different trust domains on the same gateway endpoint must partition the pool"
        );
    }

    /// The outer-TLS SNI resolution `dial_h2_connect_sender` applies: `None`
    /// keeps the dial host (byte-identical to the prior hardcoded
    /// `ServerName::try_from(target_host)`); `Some(x)` overrides to `x` (the
    /// cross-cluster destination FQDN). Pins the exact expression so the
    /// in-cluster callers can never silently change SNI.
    #[test]
    fn sni_override_resolves_to_dial_host_when_none_else_the_override() {
        // Mirrors the resolution inside `dial_h2_connect_sender`:
        //   let sni_host = sni_override.unwrap_or(target_host);
        let resolve = |target_host: &str, sni_override: Option<&str>| -> String {
            let sni_host = sni_override.unwrap_or(target_host);
            let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
                .expect("valid server name");
            match server_name {
                rustls::pki_types::ServerName::DnsName(dns) => dns.as_ref().to_string(),
                rustls::pki_types::ServerName::IpAddress(ip) => {
                    let ip: std::net::IpAddr = ip.into();
                    ip.to_string()
                }
                _ => unreachable!("unexpected server name variant"),
            }
        };

        // None ⇒ SNI = the dial host (unchanged in-cluster behavior).
        assert_eq!(resolve("10.9.9.9", None), "10.9.9.9");
        assert_eq!(
            resolve("svc-b.default.svc.cluster.local", None),
            "svc-b.default.svc.cluster.local"
        );
        // Some(x) ⇒ SNI = x even though the dial host is the gateway IP.
        assert_eq!(
            resolve("10.9.9.9", Some("svc-b.default.svc.cluster.local")),
            "svc-b.default.svc.cluster.local"
        );
    }

    #[test]
    fn read_path_returns_none_on_empty_and_missing_keys() {
        let pool = HboneConnectionPool::new(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        assert!(pool.try_cached_sender_read("missing").is_none());
        pool.entries.insert("empty".to_string(), Vec::new());
        assert!(pool.try_cached_sender_read("empty").is_none());
    }

    #[test]
    fn connect_phase_reset_classifies_as_refused() {
        let reset = HbonePoolError::Connect {
            addr: "127.0.0.1:15008".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset"),
        };
        assert_eq!(reset.error_class(), ErrorClass::ConnectionRefused);

        let timed_out = HbonePoolError::Connect {
            addr: "127.0.0.1:15008".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"),
        };
        assert_eq!(timed_out.error_class(), ErrorClass::ConnectionTimeout);
    }

    // Establish a raw (plaintext) h2 client connection to an in-process h2
    // server listening on loopback, returning the client `SendRequest`. No TLS:
    // these tests exercise the Extended CONNECT request shape + fail-closed
    // gate, which are independent of the SVID-mTLS transport the production dial
    // wraps it in.
    async fn h2_client_to(addr: std::net::SocketAddr) -> MeshH2Transport {
        let tcp = TcpStream::connect(addr).await.expect("client tcp connect");
        let (sender, connection) = h2::client::handshake(tcp)
            .await
            .expect("client h2 handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        MeshH2Transport::ungoverned(sender.ready().await.expect("client sender ready"))
    }

    #[tokio::test]
    async fn ws_extended_connect_fails_closed_when_peer_lacks_connect_protocol() {
        // Server does NOT call `enable_connect_protocol`, so an Extended CONNECT
        // would be a protocol violation. The opener must fail closed BEFORE
        // sending a request rather than dialing the peer regardless.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind h2 server");
        let addr = listener.local_addr().expect("server addr");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("server accept");
            // Default builder: SETTINGS_ENABLE_CONNECT_PROTOCOL is NOT advertised.
            let mut conn = h2::server::handshake(tcp).await.expect("server handshake");
            // Drive the connection so SETTINGS are exchanged; the client should
            // reject before sending any request, so no stream is expected.
            let _ = conn.accept().await;
        });

        let sender = h2_client_to(addr).await;
        let result = open_h2_ws_connect_stream(
            sender,
            "orders.default.svc.cluster.local:8080",
            "/",
            &[],
            None,
            None,
        )
        .await;
        match result {
            Err(HbonePoolError::ExtendedConnectUnsupported { authority }) => {
                assert_eq!(authority, "orders.default.svc.cluster.local:8080");
            }
            Err(other) => panic!("expected ExtendedConnectUnsupported, got error {other:?}"),
            Ok(_) => panic!("expected ExtendedConnectUnsupported, got an open tunnel"),
        }
        server.abort();
    }

    #[tokio::test]
    async fn ws_extended_connect_opens_tunnel_and_relays_bytes() {
        // Server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL, accepts the
        // Extended CONNECT (200) echoing a negotiated subprotocol, then echoes
        // payload bytes back over the stream body — proving the opener produces
        // a working bidirectional tunnel and surfaces the subprotocol.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind h2 server");
        let addr = listener.local_addr().expect("server addr");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("server accept");
            let mut builder = h2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut conn = builder
                .handshake::<_, Bytes>(tcp)
                .await
                .expect("server handshake");
            let (request, mut respond) = conn
                .accept()
                .await
                .expect("server has a stream")
                .expect("accepted request");
            // The request must be an Extended CONNECT carrying :protocol=websocket.
            assert_eq!(request.method(), &Method::CONNECT);
            assert_eq!(
                request
                    .extensions()
                    .get::<h2::ext::Protocol>()
                    .map(|p| p.as_str().to_string()),
                Some("websocket".to_string())
            );
            // The client's non-root `:path` must be preserved byte-for-byte
            // (codex finding #2): a hard-coded `/` would drop `?room=1` and the
            // destination would route + build the local WS backend URL wrong.
            assert_eq!(
                request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string()),
                Some("/ws?room=1".to_string()),
                "the WebSocket :path+query must survive the Extended CONNECT"
            );
            assert_eq!(
                request
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|v| v.to_str().ok()),
                Some("chat")
            );
            // Echo the stream body in its OWN task and keep polling the
            // connection below: `SendStream::send_data` only QUEUES frames; the
            // h2 connection future is what flushes them to the socket. If the
            // echo ran inline here, the task would park on the next
            // `body.data().await` (Pending) after echoing the first frame and
            // never drive the connection, so the echoed bytes would sit unflushed
            // and the client's read would hang. This mirrors the working
            // server pattern in `tests/integration/gateway_hbone_pool_tests.rs`.
            tokio::spawn(async move {
                let mut body = request.into_body();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header("sec-websocket-protocol", "chat")
                    .body(())
                    .expect("build response");
                let mut send = respond
                    .send_response(response, false)
                    .expect("send response");
                // Echo each inbound data chunk back over the response body.
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("server recv chunk");
                    let _ = body.flow_control().release_capacity(chunk.len());
                    if chunk.is_empty() {
                        continue;
                    }
                    if send.send_data(chunk, false).is_err() {
                        return;
                    }
                }
                let _ = send.send_data(Bytes::new(), true);
            });
            // Drive the connection so queued response frames flush and the client
            // can read the echo; this returns once the connection closes.
            while let Some(next) = conn.accept().await {
                if next.is_err() {
                    break;
                }
            }
        });

        let sender = h2_client_to(addr).await;
        let ws = open_h2_ws_connect_stream(
            sender,
            "orders.default.svc.cluster.local:8080",
            "/ws?room=1",
            &[("Sec-WebSocket-Protocol".to_string(), "chat".to_string())],
            None,
            None,
        )
        .await
        .expect("extended connect tunnel opens");

        assert_eq!(
            ws.negotiated_subprotocol
                .as_ref()
                .and_then(|v| v.to_str().ok()),
            Some("chat"),
            "the negotiated subprotocol must be surfaced to the caller"
        );

        // Round-trip bytes over the raw tunnel (the WebSocket frame transport).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tunnel = ws.tunnel;
        tunnel
            .write_all(b"frame-bytes")
            .await
            .expect("tunnel write");
        tunnel.flush().await.expect("tunnel flush");
        let mut buf = [0u8; 11];
        tunnel.read_exact(&mut buf).await.expect("tunnel read echo");
        assert_eq!(&buf, b"frame-bytes");
        server.abort();
    }
}
