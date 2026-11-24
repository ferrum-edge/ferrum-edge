//! Datagram-safe client-address metadata (PROXY protocol v2 DGRAM envelope).
//!
//! UDP and DTLS listeners behind a datagram load balancer only ever observe the
//! balancer's own socket address, so the original client identity is lost for
//! authorization, rate limiting, and audit. TCP solves this with the PROXY
//! protocol, but that framing is connection-borne: it is written once, ahead of
//! the byte stream, and nothing in it survives datagram boundaries.
//!
//! This module defines the datagram equivalent Ferrum accepts (issue #3289):
//! a PROXY protocol v2 header carrying the `DGRAM` transport byte, prepended to
//! **every** datagram, with the application payload following the declared
//! address block.
//!
//! ```text
//!  0                12      13      14          16
//!  +----------------+-------+-------+-----------+----------------+---------+
//!  | v2 signature   |ver_cmd|fam_tp | addr_len  |  address block | payload |
//!  |   (12 bytes)   |  1 B  |  1 B  |  u16 BE   |  addr_len B    |    …    |
//!  +----------------+-------+-------+-----------+----------------+---------+
//! ```
//!
//! Per-datagram (rather than first-datagram-only) framing is deliberate. A
//! session-scoped header would let any later datagram from the same 4-tuple
//! inherit an identity it never proved, and datagram delivery is unordered and
//! lossy, so there is no "first" datagram to rely on.
//!
//! # Three separate properties
//!
//! The authenticated envelope provides three *distinct* guarantees. Do not
//! conflate them, and do not weaken one on the strength of another:
//!
//! 1. **Authenticity** — the tag proves the envelope and payload were minted by
//!    a holder of `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`.
//! 2. **Listener-domain binding** (issue #3856) — the tag is computed over a
//!    versioned domain-separation prefix naming the *exact receiving listener*,
//!    so an envelope minted for listener A can never authenticate on listener B
//!    even though both key from one process-global root secret. This holds for
//!    every command and family, `LOCAL` and `AF_UNSPEC` included.
//! 3. **Freshness / anti-replay** (issue #3862) — an authenticated envelope
//!    carries a bounded, authenticated freshness record, and the receiver keeps
//!    a bounded sliding replay window per sender so each `(sender, epoch,
//!    sequence)` is admitted at most once.
//!
//! # Security model
//!
//! The mechanism is off unless an operator sets `stream_proxy_protocol: true`
//! on the `udp` / `dtls` proxy. When it is on:
//!
//! - The socket peer must be inside `FERRUM_TRUSTED_PROXIES`. An untrusted peer
//!   is dropped outright — the datagram is never parsed and never forwarded.
//! - The socket peer remains `source.ip` / `direct_client_ip` **always**. Only
//!   the authenticated envelope may set `remote.ip` / `client_ip`.
//! - When `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET` is configured, every datagram
//!   must additionally carry a valid HMAC-SHA-256 tag ([`AUTH_TLV_TYPE`]) and a
//!   valid freshness record ([`FRESHNESS_TLV_TYPE`]). Source addresses are
//!   trivially spoofable on UDP, so this is the only thing that makes trust in
//!   a datagram peer meaningful on a network the operator does not fully
//!   control.
//! - Anything else fails closed: no signature, truncated header, oversized
//!   address block, wrong address family, any transport but `DGRAM` on a
//!   `PROXY` command (`STREAM` — i.e. a TCP header replayed onto the datagram
//!   path — is refused whatever family it declares, `AF_UNSPEC` included),
//!   malformed TLVs, a missing or invalid authentication tag, a missing or
//!   malformed freshness record, a duplicate/stale sequence, a declared
//!   destination port that does not match the receiving listener, or replay
//!   state exhaustion. There is no fallback to the socket peer, because that
//!   would silently downgrade a spoofed datagram into an accepted one.
//!
//! ## Listener-domain binding
//!
//! The MAC input is
//!
//! ```text
//!   DOMAIN_LABEL || binding_version || protocol_tag
//!                || family_tag || bind_addr octets || listen_port
//!                || <the complete datagram with the 32 tag bytes elided>
//! ```
//!
//! The binding half is [`DatagramListenerBinding`], serialized once at gate
//! construction into a fixed-size inline buffer, so the receive path absorbs it
//! without re-serializing and without allocating. It is derived entirely from
//! *configured/bound listener properties* — never from envelope bytes:
//!
//! - `protocol_tag` distinguishes the plain-UDP receive boundary from the
//!   DTLS-terminating one, so the same numeric port cannot be crossed between a
//!   `udp` and a `dtls` frontend.
//! - `family_tag` + `bind_addr` is the listener's **canonical bind address**
//!   (IPv4-mapped IPv6 folded to IPv4), so a wildcard bind (`0.0.0.0` / `::`)
//!   and a specific-address bind on the same numeric port are different domains
//!   and cannot be crossed either.
//! - `listen_port` is the exact receiving port.
//!
//! Because the binding is inside the MAC input, a cross-listener replay fails
//! as [`DatagramMetadataError::AuthenticationTagMismatch`] for every envelope
//! form. The envelope's own declared destination port is *also* compared to the
//! listener's port as defense in depth; that check runs first, so an
//! address-bearing cross-listener envelope reports the more specific
//! [`DatagramMetadataError::ListenerBindingMismatch`]. Neither check is
//! sufficient alone: the declared destination cannot cover `LOCAL` /
//! `AF_UNSPEC` (they carry no address), and the MAC alone cannot produce a
//! distinguishable reason.
//!
//! The root secret is read once at startup, so it does not rotate under a live
//! listener; a listener reload reconstructs the binding from the live bind
//! address, protocol, and port rather than inheriting the previous listener's.
//!
//! ## Freshness and anti-replay
//!
//! An authenticated envelope carries exactly one [`FRESHNESS_TLV_TYPE`] TLV
//! whose 29-byte value is
//!
//! ```text
//!   version u8 | sender_id u32 BE | epoch u64 BE | sequence u64 BE
//!              | timestamp_ms u64 BE
//! ```
//!
//! Every field is inside the MAC input, so none of it is usable unless the
//! sender holds the root secret and minted it for *this* listener.
//!
//! The receiver keeps one bounded record per authenticated `sender_id`
//! (per listener): the highest admitted sequence for the sender's current
//! epoch, plus a [`REPLAY_WINDOW_BITS`]-bit bitmap of the sequences immediately
//! below it. Check-and-mark happens under a single `DashMap` shard write guard,
//! so it is one synchronization event and two receive workers can never both
//! admit one sequence.
//!
//! - a sequence equal to the highest, or already marked in the window, is a
//!   duplicate;
//! - a sequence more than [`REPLAY_WINDOW_BITS`] behind the highest is stale;
//! - `u64::MAX` is reserved so a sender must roll its epoch before the sequence
//!   space wraps;
//! - an epoch below the sender's current one is stale; a higher epoch is a
//!   sender restart/rotation and reseeds the window at that sequence.
//!
//! `timestamp_ms` is checked against the receiver's clock with a fixed
//! [`FRESHNESS_HORIZON_MS`] tolerance in both directions. That is what makes
//! the *lifecycle* guarantees statable, and what makes bounded eviction safe.
//!
//! ### What is guaranteed, and what is not
//!
//! - **Within one Ferrum process, per listener**: every authenticated envelope
//!   is admitted **at most once**. A byte-for-byte replay is refused before any
//!   session, DTLS allocation, plugin hook, backend send, or idle refresh.
//! - **Across a listener reload, a receiver process restart, or another Ferrum
//!   replica**: replay protection is process-local, so exposure is *bounded to
//!   [`FRESHNESS_HORIZON_MS`]* by the authenticated timestamp horizon — an
//!   envelope older than that is refused by any receiver, restarted or not.
//!   Ferrum does **not** claim cluster-wide anti-replay; the supported
//!   deployment contract is per-flow sender stickiness (a datagram balancer
//!   already pins one client flow to one Ferrum socket) plus that horizon.
//! - **Sender restart**: the sender must publish a strictly higher `epoch`.
//!   Reusing an old epoch with restarted sequence numbers is refused as stale.
//!
//! State is bounded at [`MAX_REPLAY_SENDERS`] senders per listener. At capacity
//! the guard first reclaims entries idle longer than `4 ×
//! FRESHNESS_HORIZON_MS` and, if that frees nothing, refuses with
//! [`DatagramMetadataError::ReplayStateCapacity`] rather than evicting live
//! protection. The idle threshold exceeds `2 × FRESHNESS_HORIZON_MS` on
//! purpose: an envelope that could still be inside the horizon after the
//! reclaim would need a timestamp newer than the entry's last activity plus
//! `2 × FRESHNESS_HORIZON_MS`, so reclaiming can never make an old sequence
//! valid again.
//!
//! Diagnostics are field-specific but bounded: they name the field and, at
//! most, the offending numeric code or length. Payload bytes, tag bytes,
//! secrets, sequence-cache contents, and addresses asserted inside the envelope
//! never appear in a log record.
//!
//! # Relationship to the TCP PROXY parser
//!
//! [`crate::proxy::proxy_protocol`] is the connection-borne TCP parser (v1
//! text and v2 binary, STREAM transport, one header per connection). This
//! module is a separate per-datagram parser: it requires `DGRAM` transport,
//! walks the auth/freshness TLV region, binds the MAC to the receiving
//! listener, enforces freshness, and never allocates on the receive path.
//! Signature, version, family codes, and the 512-byte address-block cap MUST
//! stay aligned with that parser; a spec-level fix must update both. Do not
//! collapse them into one abstraction — the datagram path's transport,
//! auth-TLV, listener-binding, freshness, and hot-path checks would be lost.
//!
//! # Spec references
//!
//! - PROXY protocol v2: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//!   (section 2.2; `0x02` is the spec's `DGRAM` transport, and TLV type
//!   `0xE0`.. is reserved for application use.)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;

use crate::fips::approved::HmacSha256Key;
use crate::proxy::client_ip::TrustedProxies;

/// PROXY protocol v2 12-byte signature.
///
/// Keep byte-identical to [`crate::proxy::proxy_protocol`]'s `V2_SIG`. The
/// parsers are deliberately separate; this constant is the shared spec token.
const V2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
/// Signature + `ver_cmd` + `fam_transport` + `addr_len`.
const FIXED_HEADER_LEN: usize = 16;
/// Maximum accepted address-block length (fixed addresses plus TLVs). Matches
/// the TCP parser's `V2_MAX_ADDR_LEN` so one deployment cannot need two
/// different budgets.
const MAX_ADDR_BLOCK_LEN: u16 = 512;
/// `AF_INET` fixed address block: 4 + 4 + 2 + 2. Matches the TCP parser.
const INET_ADDR_LEN: usize = 12;
/// `AF_INET6` fixed address block: 16 + 16 + 2 + 2. Matches the TCP parser.
const INET6_ADDR_LEN: usize = 36;

/// TLV type carrying the HMAC-SHA-256 authentication tag.
///
/// `0xE0`..`0xEF` is the PROXY v2 application-reserved TLV range, so this
/// cannot collide with a registered TLV.
pub const AUTH_TLV_TYPE: u8 = 0xE0;
/// Length of the authentication tag value.
pub const AUTH_TAG_LEN: usize = 32;

/// TLV type carrying the authenticated freshness record (issue #3862).
///
/// Also inside the `0xE0`..`0xEF` application-reserved range.
pub const FRESHNESS_TLV_TYPE: u8 = 0xE1;
/// Version byte of the freshness record. A different value is refused rather
/// than best-effort parsed, so the extension can be revised without a receiver
/// ever guessing at an unknown layout.
pub const FRESHNESS_VERSION: u8 = 0x01;
/// Exact length of a [`FRESHNESS_TLV_TYPE`] value: version(1) + sender_id(4) +
/// epoch(8) + sequence(8) + timestamp_ms(8).
pub const FRESHNESS_VALUE_LEN: usize = 29;
/// Full on-wire size of the freshness TLV, header included.
pub const FRESHNESS_TLV_LEN: usize = 3 + FRESHNESS_VALUE_LEN;

/// Accepted skew, in either direction, between an envelope's authenticated
/// `timestamp_ms` and the receiver's clock.
///
/// This is deliberately a compile-time constant rather than an operator knob:
/// it is the *security horizon* the lifecycle guarantees are stated in terms
/// of, and a deployment that could widen it could silently widen the
/// cross-restart / cross-replica replay window. Senders and receivers must
/// therefore agree on wall-clock time to within this tolerance (ordinary NTP
/// synchronization is orders of magnitude tighter).
pub const FRESHNESS_HORIZON_MS: u64 = 30_000;

/// Width of the per-sender sliding replay window, in sequence numbers below the
/// highest admitted one. Unique reordering inside this range is admitted once
/// each; anything further behind is stale.
pub const REPLAY_WINDOW_BITS: u64 = 64;

/// Maximum number of distinct authenticated senders one listener keeps replay
/// state for. Reached only by a sender population this large or by a
/// compromised sender minting `sender_id`s (an off-path attacker cannot: the
/// field is inside the MAC).
pub const MAX_REPLAY_SENDERS: usize = 1024;

/// Idle threshold for reclaiming a sender's replay record.
///
/// Strictly greater than `2 × FRESHNESS_HORIZON_MS`, which is what makes
/// reclaiming safe: for a previously admitted envelope to be accepted again
/// after its record is reclaimed, its authenticated timestamp would have to be
/// no older than `now − FRESHNESS_HORIZON_MS` while also being no newer than
/// `last_activity + FRESHNESS_HORIZON_MS`. With `now ≥ last_activity + 4 ×
/// FRESHNESS_HORIZON_MS` those two ranges cannot overlap, so the horizon check
/// refuses it before the (now absent) window ever matters.
const REPLAY_ENTRY_IDLE_MS: u64 = 4 * FRESHNESS_HORIZON_MS;

/// Minimum interval between idle-reclaim sweeps, so a hostile flood of new
/// `sender_id`s at capacity cannot turn every datagram into a full map scan.
const REPLAY_RECLAIM_MIN_INTERVAL_MS: u64 = 250;

/// Versioned domain-separation label absorbed ahead of every MAC input.
const DOMAIN_LABEL: &[u8] = b"ferrum-datagram-proxy-v1";
/// Version of the binding serialization that follows [`DOMAIN_LABEL`].
const DOMAIN_BINDING_VERSION: u8 = 0x01;
/// Upper bound on the serialized domain prefix: label + version + protocol +
/// family tag + 16 address bytes + 2 port bytes.
const DOMAIN_PREFIX_MAX: usize = 48;

/// Minimum accepted length of `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`.
pub const MIN_DATAGRAM_SECRET_BYTES: usize = 32;

/// Canonical protocol half of a listener's domain identity.
///
/// This is the *receive boundary*, not the backend scheme: a `udp` proxy with
/// `frontend_tls: true` terminates DTLS and therefore validates envelopes in
/// [`crate::dtls::DtlsServer::run`], while every other udp/dtls listener
/// validates them in `udp_proxy::process_datagram`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramListenerProtocol {
    /// Plain UDP receive boundary.
    Udp,
    /// DTLS-terminating frontend receive boundary (pre-demux).
    Dtls,
}

impl DatagramListenerProtocol {
    /// Stable wire tag. Never renumber: it is inside the MAC input, so a
    /// renumbering would invalidate every sender's envelopes.
    const fn tag(self) -> u8 {
        match self {
            Self::Udp => 0x01,
            Self::Dtls => 0x02,
        }
    }
}

/// The exact receiving listener an authenticated envelope is bound to.
///
/// Built from configured/bound listener properties only. Two listeners in one
/// process that differ in *any* of protocol, canonical bind address, or port
/// are different cryptographic domains, so a valid envelope for one can never
/// authenticate on the other (issue #3856).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramListenerBinding {
    protocol: DatagramListenerProtocol,
    /// Canonical bind address: exactly what the listener bound, with an
    /// IPv4-mapped IPv6 form folded to IPv4 so `::ffff:10.0.0.5` and `10.0.0.5`
    /// are one domain rather than two.
    bind_addr: IpAddr,
    port: u16,
}

impl DatagramListenerBinding {
    /// Canonicalize and capture a listener's domain identity.
    pub fn new(protocol: DatagramListenerProtocol, bind_addr: IpAddr, port: u16) -> Self {
        Self {
            protocol,
            bind_addr: crate::util::client_identity::canonical_ip(bind_addr),
            port,
        }
    }

    /// Receive-boundary protocol.
    #[inline]
    pub fn protocol(&self) -> DatagramListenerProtocol {
        self.protocol
    }

    /// Canonical bind address.
    #[inline]
    pub fn bind_addr(&self) -> IpAddr {
        self.bind_addr
    }

    /// Receiving port.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Serialize the canonical domain prefix into `out`, returning its length.
    ///
    /// The encoding is unambiguous without explicit lengths because the family
    /// tag precedes the address and fixes its width, and the port is a fixed
    /// two bytes at the end.
    fn write_domain(&self, out: &mut [u8; DOMAIN_PREFIX_MAX]) -> usize {
        let mut at = 0usize;
        out[at..at + DOMAIN_LABEL.len()].copy_from_slice(DOMAIN_LABEL);
        at += DOMAIN_LABEL.len();
        out[at] = DOMAIN_BINDING_VERSION;
        at += 1;
        out[at] = self.protocol.tag();
        at += 1;
        match self.bind_addr {
            IpAddr::V4(v4) => {
                out[at] = 0x04;
                at += 1;
                out[at..at + 4].copy_from_slice(&v4.octets());
                at += 4;
            }
            IpAddr::V6(v6) => {
                out[at] = 0x06;
                at += 1;
                out[at..at + 16].copy_from_slice(&v6.octets());
                at += 16;
            }
        }
        out[at..at + 2].copy_from_slice(&self.port.to_be_bytes());
        at + 2
    }

    /// The canonical domain bytes this binding contributes to every MAC input.
    ///
    /// Exposed so the sender-side encoder and the conformance tests can pin the
    /// exact identity rather than re-deriving it.
    pub fn canonical_domain(&self) -> Vec<u8> {
        let mut buf = [0u8; DOMAIN_PREFIX_MAX];
        let len = self.write_domain(&mut buf);
        buf[..len].to_vec()
    }
}

/// Authenticated freshness record carried by every authenticated envelope.
///
/// All four fields are inside the MAC input, so an off-path attacker can
/// neither mint nor edit them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramFreshness {
    /// Stable, bounded sender/key identity. One datagram balancer instance
    /// picks one value and keeps it for the life of an epoch.
    pub sender_id: u32,
    /// Sender boot / key-rotation epoch. Must strictly increase across a
    /// sender restart; a lower value than the receiver has seen is refused.
    pub epoch: u64,
    /// Monotonic sequence within `(sender_id, epoch)`. `u64::MAX` is reserved.
    pub sequence: u64,
    /// Unix milliseconds at send time, checked against
    /// [`FRESHNESS_HORIZON_MS`].
    pub timestamp_ms: u64,
}

impl DatagramFreshness {
    /// Serialize the 29-byte TLV value.
    pub fn encode_value(&self) -> [u8; FRESHNESS_VALUE_LEN] {
        let mut out = [0u8; FRESHNESS_VALUE_LEN];
        out[0] = FRESHNESS_VERSION;
        out[1..5].copy_from_slice(&self.sender_id.to_be_bytes());
        out[5..13].copy_from_slice(&self.epoch.to_be_bytes());
        out[13..21].copy_from_slice(&self.sequence.to_be_bytes());
        out[21..29].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        out
    }

    /// Serialize the complete freshness TLV (type, length, value).
    pub fn encode_tlv(&self) -> [u8; FRESHNESS_TLV_LEN] {
        let mut out = [0u8; FRESHNESS_TLV_LEN];
        out[0] = FRESHNESS_TLV_TYPE;
        out[1..3].copy_from_slice(&(FRESHNESS_VALUE_LEN as u16).to_be_bytes());
        out[3..].copy_from_slice(&self.encode_value());
        out
    }

    /// Strictly parse a freshness TLV value. Length and version are exact; no
    /// short, long, or unknown-version value is best-effort accepted.
    fn decode_value(value: &[u8]) -> Result<Self, DatagramMetadataError> {
        if value.len() != FRESHNESS_VALUE_LEN {
            return Err(DatagramMetadataError::MalformedFreshness);
        }
        let version = value[0];
        if version != FRESHNESS_VERSION {
            return Err(DatagramMetadataError::UnsupportedFreshnessVersion(version));
        }
        let mut sender_id = [0u8; 4];
        sender_id.copy_from_slice(&value[1..5]);
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&value[5..13]);
        let mut sequence = [0u8; 8];
        sequence.copy_from_slice(&value[13..21]);
        let mut timestamp_ms = [0u8; 8];
        timestamp_ms.copy_from_slice(&value[21..29]);
        Ok(Self {
            sender_id: u32::from_be_bytes(sender_id),
            epoch: u64::from_be_bytes(epoch),
            sequence: u64::from_be_bytes(sequence),
            timestamp_ms: u64::from_be_bytes(timestamp_ms),
        })
    }
}

/// Unix milliseconds for the freshness horizon check.
///
/// Fails closed on a clock the platform cannot place after the Unix epoch: the
/// resulting `0` puts every real timestamp outside the horizon, so datagrams
/// are refused rather than admitted with an unverifiable freshness claim.
pub fn unix_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Why a datagram's client-address metadata was refused.
///
/// Every variant is a fail-closed drop. Values are bounded: a code or a length,
/// never payload bytes, addresses under construction, sequence-cache contents,
/// or tag material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramMetadataError {
    /// The socket peer is not inside `FERRUM_TRUSTED_PROXIES`.
    UntrustedPeer,
    /// Fewer bytes than the fixed 16-byte header.
    TruncatedHeader { len: usize },
    /// The datagram did not begin with the PROXY v2 signature.
    InvalidSignature,
    /// Version nibble was not `2`.
    UnsupportedVersion(u8),
    /// Command nibble was neither `LOCAL` (0x0) nor `PROXY` (0x1).
    UnsupportedCommand(u8),
    /// Declared address block exceeds [`MAX_ADDR_BLOCK_LEN`].
    AddressBlockTooLong(u16),
    /// The datagram ended before the declared address block did.
    TruncatedAddressBlock { declared: u16, available: usize },
    /// Address family is neither `AF_UNSPEC`, `AF_INET`, nor `AF_INET6`.
    UnsupportedAddressFamily(u8),
    /// Transport byte is not `DGRAM`. A `STREAM` header on this path is a TCP
    /// PROXY header replayed onto a datagram listener.
    NonDatagramTransport(u8),
    /// The declared family needs more fixed address bytes than were supplied.
    AddressBlockTooShortForFamily { family: u8, len: usize },
    /// A TLV ran past the end of the address block, or declared a length the
    /// block cannot hold.
    MalformedTlv,
    /// More than one authentication TLV was present.
    DuplicateAuthenticationTag,
    /// The listener requires an authentication tag and none was present.
    MissingAuthenticationTag,
    /// The authentication TLV did not carry [`AUTH_TAG_LEN`] bytes.
    InvalidAuthenticationTagLength(usize),
    /// The authentication tag did not verify under the configured secret and
    /// this listener's domain binding. A valid envelope minted for another
    /// listener lands here.
    AuthenticationTagMismatch,
    /// A secret is configured but no key could be derived from it, so nothing
    /// can be verified. Fail-closed rather than silently unauthenticated.
    AuthenticationKeyUnavailable,
    /// A later datagram on an established session carried a different
    /// forwarded client than the one the session was admitted with.
    ForwardedClientChanged,
    /// The envelope's declared destination port is not this listener's
    /// `listen_port`. Defense in depth ahead of the cryptographic listener
    /// binding, and the specific reason for an address-bearing cross-listener
    /// envelope.
    ListenerBindingMismatch,
    /// Authentication is required but the datagram carried no freshness TLV.
    /// The pre-freshness authenticated format is deliberately not accepted.
    MissingFreshness,
    /// More than one freshness TLV was present, so the record is ambiguous.
    DuplicateFreshness,
    /// The freshness TLV value was not exactly [`FRESHNESS_VALUE_LEN`] bytes.
    MalformedFreshness,
    /// The freshness record declared a version this build does not implement.
    UnsupportedFreshnessVersion(u8),
    /// The authenticated timestamp is further than [`FRESHNESS_HORIZON_MS`]
    /// from the receiver's clock, in either direction.
    FreshnessOutsideHorizon,
    /// This `(sender, epoch, sequence)` was already admitted.
    ReplayDuplicate,
    /// The sequence is further behind the sender's highest admitted one than
    /// the replay window can prove anything about.
    ReplayStale,
    /// The sender declared an epoch below the one the receiver has admitted, so
    /// this is state from before a restart/rotation.
    ReplayEpochStale,
    /// `u64::MAX` is reserved: the sender must roll its epoch rather than let
    /// the sequence space wrap.
    ReplaySequenceExhausted,
    /// Replay state is at capacity and nothing was reclaimable, so freshness
    /// cannot be proven for a new sender. Refused rather than evicting live
    /// protection.
    ReplayStateCapacity,
}

impl DatagramMetadataError {
    /// Fixed-cardinality label for metrics and log fields.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::UntrustedPeer => "untrusted_peer",
            Self::TruncatedHeader { .. } => "truncated_header",
            Self::InvalidSignature => "invalid_signature",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::UnsupportedCommand(_) => "unsupported_command",
            Self::AddressBlockTooLong(_) => "address_block_too_long",
            Self::TruncatedAddressBlock { .. } => "truncated_address_block",
            Self::UnsupportedAddressFamily(_) => "unsupported_address_family",
            Self::NonDatagramTransport(_) => "non_datagram_transport",
            Self::AddressBlockTooShortForFamily { .. } => "address_block_too_short",
            Self::MalformedTlv => "malformed_tlv",
            Self::DuplicateAuthenticationTag => "duplicate_authentication_tag",
            Self::MissingAuthenticationTag => "missing_authentication_tag",
            Self::InvalidAuthenticationTagLength(_) => "invalid_authentication_tag_length",
            Self::AuthenticationTagMismatch => "authentication_tag_mismatch",
            Self::AuthenticationKeyUnavailable => "authentication_key_unavailable",
            Self::ForwardedClientChanged => "forwarded_client_changed",
            Self::ListenerBindingMismatch => "listener_binding_mismatch",
            Self::MissingFreshness => "missing_freshness",
            Self::DuplicateFreshness => "duplicate_freshness",
            Self::MalformedFreshness => "malformed_freshness",
            Self::UnsupportedFreshnessVersion(_) => "unsupported_freshness_version",
            Self::FreshnessOutsideHorizon => "freshness_outside_horizon",
            Self::ReplayDuplicate => "replay_duplicate",
            Self::ReplayStale => "replay_stale",
            Self::ReplayEpochStale => "replay_epoch_stale",
            Self::ReplaySequenceExhausted => "replay_sequence_exhausted",
            Self::ReplayStateCapacity => "replay_state_capacity",
        }
    }
}

impl std::fmt::Display for DatagramMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedPeer => f.write_str(
                "socket peer is not in FERRUM_TRUSTED_PROXIES, so its datagram client-address \
                 metadata may not set client_ip",
            ),
            Self::TruncatedHeader { len } => write!(
                f,
                "datagram is {len} bytes, shorter than the {FIXED_HEADER_LEN}-byte PROXY v2 header"
            ),
            Self::InvalidSignature => {
                f.write_str("datagram does not begin with the PROXY v2 signature")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported PROXY protocol version {version}")
            }
            Self::UnsupportedCommand(command) => {
                write!(f, "unsupported PROXY v2 command 0x{command:02x}")
            }
            Self::AddressBlockTooLong(len) => write!(
                f,
                "PROXY v2 address block length {len} exceeds the {MAX_ADDR_BLOCK_LEN}-byte cap"
            ),
            Self::TruncatedAddressBlock {
                declared,
                available,
            } => write!(
                f,
                "PROXY v2 header declares a {declared}-byte address block but only {available} \
                 bytes follow the fixed header"
            ),
            Self::UnsupportedAddressFamily(family) => {
                write!(f, "unsupported PROXY v2 address family 0x{family:02x}")
            }
            Self::NonDatagramTransport(transport) => write!(
                f,
                "PROXY v2 transport 0x{transport:02x} is not DGRAM (0x02); a stream header is not \
                 valid on a udp/dtls listener"
            ),
            Self::AddressBlockTooShortForFamily { family, len } => write!(
                f,
                "PROXY v2 address family 0x{family:02x} needs a longer fixed address block than \
                 the {len} bytes supplied"
            ),
            Self::MalformedTlv => f.write_str("malformed TLV in the PROXY v2 address block"),
            Self::DuplicateAuthenticationTag => {
                f.write_str("more than one datagram authentication TLV present")
            }
            Self::MissingAuthenticationTag => f.write_str(
                "FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET is configured but the datagram carried no \
                 authentication TLV",
            ),
            Self::InvalidAuthenticationTagLength(len) => write!(
                f,
                "datagram authentication TLV carries {len} bytes, expected {AUTH_TAG_LEN}"
            ),
            Self::AuthenticationTagMismatch => f.write_str(
                "datagram authentication tag did not verify for this listener's binding",
            ),
            Self::AuthenticationKeyUnavailable => f.write_str(
                "FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET is configured but no authentication key \
                 could be derived from it",
            ),
            Self::ForwardedClientChanged => f.write_str(
                "datagram carried a different forwarded client than the established session was \
                 admitted with",
            ),
            Self::ListenerBindingMismatch => f.write_str(
                "PROXY v2 destination port does not match the receiving listener's binding",
            ),
            Self::MissingFreshness => f.write_str(
                "FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET is configured but the datagram carried no \
                 freshness TLV, so it cannot be proven to be anything but a replay",
            ),
            Self::DuplicateFreshness => f.write_str("more than one datagram freshness TLV present"),
            Self::MalformedFreshness => {
                f.write_str("datagram freshness TLV is not the expected fixed length")
            }
            Self::UnsupportedFreshnessVersion(version) => {
                write!(f, "unsupported datagram freshness record version {version}")
            }
            Self::FreshnessOutsideHorizon => f.write_str(
                "datagram freshness timestamp is outside the accepted horizon from this \
                 receiver's clock",
            ),
            Self::ReplayDuplicate => {
                f.write_str("datagram freshness sequence was already admitted on this listener")
            }
            Self::ReplayStale => f.write_str(
                "datagram freshness sequence is older than this listener's replay window",
            ),
            Self::ReplayEpochStale => f.write_str(
                "datagram freshness epoch is older than the sender's current admitted epoch",
            ),
            Self::ReplaySequenceExhausted => f.write_str(
                "datagram freshness sequence space is exhausted; the sender must roll its epoch",
            ),
            Self::ReplayStateCapacity => f.write_str(
                "this listener's datagram replay state is at capacity, so freshness cannot be \
                 proven for a new sender",
            ),
        }
    }
}

impl std::error::Error for DatagramMetadataError {}

/// The two addresses a datagram listener keeps for one client flow.
///
/// `socket_peer` is what the kernel reported and is the only value that can
/// route a reply. `forwarded` is the authenticated original client, present
/// only when trusted metadata supplied it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramClientIdentity {
    /// Direct socket peer. Always `source.ip` / `direct_client_ip`.
    pub socket_peer: SocketAddr,
    /// Authenticated forwarded client. When present it becomes `remote.ip` /
    /// `client_ip`; otherwise the socket peer serves as both.
    pub forwarded: Option<SocketAddr>,
}

impl DatagramClientIdentity {
    /// Identity for a listener without datagram client-address metadata.
    #[inline]
    pub fn direct(socket_peer: SocketAddr) -> Self {
        Self {
            socket_peer,
            forwarded: None,
        }
    }

    /// The resolved client endpoint: forwarded when authenticated, else the peer.
    #[inline]
    pub fn resolved(&self) -> SocketAddr {
        self.forwarded.unwrap_or(self.socket_peer)
    }

    /// Refuse a datagram whose forwarded client disagrees with the one this
    /// session was admitted with.
    ///
    /// A datagram load balancer that emits this envelope allocates a distinct
    /// source port per client flow, so one Ferrum session maps to one client.
    /// Rather than silently attributing a second client's traffic to the first
    /// session's identity, the mismatch is a fail-closed drop.
    #[inline]
    pub fn matches_session(&self, session_forwarded: Option<SocketAddr>) -> bool {
        self.forwarded == session_forwarded
    }
}

/// A decoded datagram: the authenticated identity plus the application payload.
#[derive(Debug, Clone, Copy)]
pub struct DecodedDatagram<'a> {
    /// Bytes after the metadata header — what the backend or DTLS engine sees.
    pub payload: &'a [u8],
    /// Forwarded client address, `None` for a `LOCAL` / `AF_UNSPEC` envelope
    /// (a balancer's own health probe keeps the socket peer as its identity).
    pub forwarded: Option<SocketAddr>,
}

/// Per-sender sliding replay window for one listener.
#[derive(Debug, Clone, Copy)]
struct SenderReplayState {
    /// Highest sender epoch admitted for this sender.
    epoch: u64,
    /// Highest sequence admitted inside `epoch`.
    highest: u64,
    /// Bit `i` set means sequence `highest - 1 - i` has already been admitted.
    window: u64,
    /// Receiver-clock millis at the last admission, for idle reclaim.
    last_seen_ms: u64,
}

/// Bounded, concurrency-safe replay state for one listener.
///
/// Keyed by the authenticated `sender_id`. The listener/key domain is implicit:
/// the guard lives on the listener's gate, and `sender_id` is only readable
/// after a MAC that already bound both the root secret and this listener.
#[derive(Debug)]
struct DatagramReplayGuard {
    senders: DashMap<u32, SenderReplayState>,
    max_senders: usize,
    /// Receiver-clock millis of the last idle sweep, so sweeps stay rare under
    /// a hostile flood of unseen `sender_id`s.
    last_reclaim_ms: AtomicU64,
    /// Serializes first-seen sender insertion so live cardinality cannot
    /// exceed `max_senders` under concurrent distinct `sender_id`s. Ordinary
    /// established-sender updates never take this lock.
    ///
    /// Lock order: this mutex, then a `DashMap` shard lock. No path acquires
    /// them in reverse.
    admission: Mutex<()>,
}

impl DatagramReplayGuard {
    fn new(shard_amount: usize) -> Self {
        Self {
            // Hot-path concurrent map: shard count comes from the shared
            // sharding helper so one listener's replay checks do not serialize
            // on a single internal lock.
            senders: DashMap::with_capacity_and_shard_amount(
                MAX_REPLAY_SENDERS.min(256),
                crate::util::sharding::pool_shard_amount(shard_amount),
            ),
            max_senders: MAX_REPLAY_SENDERS,
            last_reclaim_ms: AtomicU64::new(0),
            admission: Mutex::new(()),
        }
    }

    /// Number of senders currently tracked. Bounded by [`MAX_REPLAY_SENDERS`].
    fn tracked_senders(&self) -> usize {
        self.senders.len()
    }

    /// Check-and-mark one authenticated freshness record.
    ///
    /// `Ok(())` means this exact `(sender_id, epoch, sequence)` had not been
    /// admitted on this listener and now has been. For an established sender
    /// the mark and the decision happen under one `DashMap` shard write guard,
    /// so concurrent receive workers cannot both admit the same sequence.
    /// First-seen senders additionally serialize on `admission` so concurrent
    /// distinct identities cannot overshoot [`MAX_REPLAY_SENDERS`].
    fn admit(
        &self,
        freshness: &DatagramFreshness,
        now_ms: u64,
    ) -> Result<(), DatagramMetadataError> {
        // The horizon is checked first: it is the bound the cross-restart and
        // cross-replica guarantees are stated in, and it keeps a far-future or
        // ancient timestamp from ever reserving state.
        if now_ms.abs_diff(freshness.timestamp_ms) > FRESHNESS_HORIZON_MS {
            return Err(DatagramMetadataError::FreshnessOutsideHorizon);
        }
        if freshness.sequence == u64::MAX {
            return Err(DatagramMetadataError::ReplaySequenceExhausted);
        }

        // Established sender: one shard write guard covers the whole decision.
        // This path must not take `admission`; ordinary sequence updates stay
        // on the single relevant shard lock.
        if let Some(mut state) = self.senders.get_mut(&freshness.sender_id) {
            return admit_into_window(&mut state, freshness, now_ms);
        }
        // Shard guard released. Everything below is the new-sender path.

        // Serialize first-seen admission. Recheck, reclaim, and insert all
        // happen under this lock so a burst of distinct unseen `sender_id`s
        // cannot each observe a below-cap length and then all insert.
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(mut state) = self.senders.get_mut(&freshness.sender_id) {
            // A peer inserted this sender while we waited for admission.
            return admit_into_window(&mut state, freshness, now_ms);
        }

        // Capacity and reclaim run with no shard lock held: `retain` takes
        // shard locks itself, and lock order is admission then shard.
        if self.senders.len() >= self.max_senders {
            self.reclaim_idle(now_ms);
            if self.senders.len() >= self.max_senders {
                return Err(DatagramMetadataError::ReplayStateCapacity);
            }
        }
        match self.senders.entry(freshness.sender_id) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                // Same sender became visible between the recheck and entry;
                // mark the sequence once under this shard guard.
                admit_into_window(occupied.get_mut(), freshness, now_ms)
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(SenderReplayState {
                    epoch: freshness.epoch,
                    highest: freshness.sequence,
                    window: 0,
                    last_seen_ms: now_ms,
                });
                Ok(())
            }
        }
    }

    /// Drop sender records idle longer than [`REPLAY_ENTRY_IDLE_MS`].
    ///
    /// Safe by construction: an envelope belonging to a reclaimed record is
    /// already outside [`FRESHNESS_HORIZON_MS`], so the horizon check refuses
    /// it whether or not the window still remembers the sequence. Rate-limited
    /// so a flood at capacity cannot make every datagram pay for a scan.
    fn reclaim_idle(&self, now_ms: u64) {
        let last = self.last_reclaim_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < REPLAY_RECLAIM_MIN_INTERVAL_MS {
            return;
        }
        if self
            .last_reclaim_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.senders
            .retain(|_, state| now_ms.saturating_sub(state.last_seen_ms) <= REPLAY_ENTRY_IDLE_MS);
    }
}

/// Decide and mark one sequence against a sender's window.
///
/// Pure and synchronous: the caller holds the shard write guard across it, so
/// nothing here may block, await, or touch the map.
fn admit_into_window(
    state: &mut SenderReplayState,
    freshness: &DatagramFreshness,
    now_ms: u64,
) -> Result<(), DatagramMetadataError> {
    if freshness.epoch < state.epoch {
        return Err(DatagramMetadataError::ReplayEpochStale);
    }
    if freshness.epoch > state.epoch {
        // Sender restart or key rotation. Reseed at this sequence: every
        // sequence from the previous epoch is now refused as an epoch that has
        // been retired, so nothing is reopened.
        state.epoch = freshness.epoch;
        state.highest = freshness.sequence;
        state.window = 0;
        state.last_seen_ms = now_ms;
        return Ok(());
    }

    let sequence = freshness.sequence;
    if sequence == state.highest {
        return Err(DatagramMetadataError::ReplayDuplicate);
    }
    if sequence > state.highest {
        let advance = sequence - state.highest;
        let shifted = if advance >= REPLAY_WINDOW_BITS {
            0
        } else {
            state.window << advance
        };
        // The previous highest is itself an admitted sequence, so it must keep
        // a bit whenever the new window can still represent it.
        let previous_highest = if advance <= REPLAY_WINDOW_BITS {
            1u64 << (advance - 1)
        } else {
            0
        };
        state.window = shifted | previous_highest;
        state.highest = sequence;
        state.last_seen_ms = now_ms;
        return Ok(());
    }

    let behind = state.highest - sequence;
    if behind > REPLAY_WINDOW_BITS {
        return Err(DatagramMetadataError::ReplayStale);
    }
    let bit = 1u64 << (behind - 1);
    if state.window & bit != 0 {
        return Err(DatagramMetadataError::ReplayDuplicate);
    }
    state.window |= bit;
    state.last_seen_ms = now_ms;
    Ok(())
}

/// Per-listener trust gate for datagram client-address metadata.
///
/// Built once per listener at spawn from the process-wide trust boundary, the
/// optional shared secret, and this listener's [`DatagramListenerBinding`].
/// Reload reconstructs the gate — and with it a fresh replay window — from the
/// live binding rather than inheriting another listener's. The receive path only
/// calls [`Self::decode`], which allocates nothing.
pub struct DatagramClientAddressGate {
    trusted_proxies: Arc<TrustedProxies>,
    /// Whether the operator configured a secret. Derived from the exact
    /// configured byte string: any nonempty value means authentication is
    /// mandatory, and only an absent or empty value leaves trust resting on the
    /// peer address alone (documented as the weaker posture). The value is
    /// never trimmed, normalized, or measured — doing so could turn a
    /// configured requirement into no requirement at all.
    authentication_required: bool,
    /// Pre-derived HMAC key over those exact bytes. `None` while
    /// `authentication_required` only if the approved HMAC module refused the
    /// key material, which then fails every datagram closed rather than
    /// downgrading the listener to unauthenticated metadata.
    auth_key: Option<HmacSha256Key>,
    /// Exact receiving listener identity captured at construction.
    binding: DatagramListenerBinding,
    /// Serialized domain prefix for `binding`, absorbed ahead of every MAC
    /// input. Fixed-size and inline, so the receive path neither allocates nor
    /// re-serializes.
    domain: [u8; DOMAIN_PREFIX_MAX],
    domain_len: usize,
    /// Bounded per-sender replay window. Listener-scoped: a fresh gate has a
    /// fresh window, which is why the authenticated timestamp horizon is what
    /// bounds cross-reload and cross-restart exposure.
    replay: DatagramReplayGuard,
}

impl std::fmt::Debug for DatagramClientAddressGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key material or anything derived from it.
        f.debug_struct("DatagramClientAddressGate")
            .field("authenticated", &self.authentication_required)
            .field("binding", &self.binding)
            .finish()
    }
}

impl DatagramClientAddressGate {
    /// Build a gate. `secret` is the raw `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`
    /// value, used verbatim: only an absent or empty value leaves the gate on
    /// peer-address trust. A whitespace-only or whitespace-bearing secret is a
    /// secret like any other — trimming it here would silently key the listener
    /// with different bytes than `EnvConfig` validated, or drop the
    /// authentication requirement entirely.
    ///
    /// `binding` is this listener's exact receive-boundary identity. It is
    /// captured here so every decode both compares the envelope's declared
    /// destination against it and folds it into the MAC input, without ever
    /// consulting a per-datagram caller-supplied identity.
    ///
    /// `shard_amount` carries the operator's `FERRUM_POOL_SHARD_AMOUNT`
    /// intent — either the raw value or the already-resolved one
    /// `StreamListenerManager` holds; `0` selects the auto-derived default. It
    /// sizes the replay map's shards through the shared sharding helper, whose
    /// rounding is idempotent, so passing an already-resolved value is exact.
    pub fn new(
        trusted_proxies: Arc<TrustedProxies>,
        secret: Option<&str>,
        binding: DatagramListenerBinding,
        shard_amount: usize,
    ) -> Self {
        let secret = secret.filter(|value| !value.is_empty());
        let auth_key = match secret {
            Some(value) => HmacSha256Key::new_from_slice(value.as_bytes()).ok(),
            None => None,
        };
        let mut domain = [0u8; DOMAIN_PREFIX_MAX];
        let domain_len = binding.write_domain(&mut domain);
        Self {
            trusted_proxies,
            authentication_required: secret.is_some(),
            auth_key,
            binding,
            domain,
            domain_len,
            replay: DatagramReplayGuard::new(shard_amount),
        }
    }

    /// Whether every datagram must carry a valid authentication tag and
    /// freshness record.
    #[inline]
    pub fn requires_authentication(&self) -> bool {
        self.authentication_required
    }

    /// This listener's canonical domain identity.
    #[inline]
    pub fn binding(&self) -> DatagramListenerBinding {
        self.binding
    }

    /// Senders currently holding replay state on this listener. Bounded by
    /// [`MAX_REPLAY_SENDERS`]; exposed so the bound is assertable.
    #[inline]
    pub fn tracked_replay_senders(&self) -> usize {
        self.replay.tracked_senders()
    }

    /// Whether any peer at all can satisfy the trust boundary.
    ///
    /// An empty `FERRUM_TRUSTED_PROXIES` means no datagram can ever be
    /// admitted; the listener reports that once at startup rather than dropping
    /// every datagram silently.
    #[inline]
    pub fn has_trusted_peers(&self) -> bool {
        !self.trusted_proxies.is_empty()
    }

    /// Decode one datagram received from `socket_peer`, against the receiver's
    /// current wall clock.
    #[inline]
    pub fn decode<'a>(
        &self,
        datagram: &'a [u8],
        socket_peer: &SocketAddr,
    ) -> Result<DecodedDatagram<'a>, DatagramMetadataError> {
        let now_unix_ms = if self.authentication_required {
            unix_now_millis()
        } else {
            0
        };
        self.decode_at(datagram, socket_peer, now_unix_ms)
    }

    /// Decode one datagram against an explicit receiver clock reading.
    ///
    /// Borrows `datagram`; the returned payload is a subslice, so the hot path
    /// performs no copy and no allocation.
    ///
    /// Every refusal happens here, at the single receive boundary, before the
    /// caller can look up or allocate a session, insert a pending-queue entry,
    /// allocate DTLS demux state, run `on_stream_connect` / `on_udp_datagram`,
    /// select or dial a backend, move byte/amplification accounting, or refresh
    /// idle activity.
    pub fn decode_at<'a>(
        &self,
        datagram: &'a [u8],
        socket_peer: &SocketAddr,
        now_unix_ms: u64,
    ) -> Result<DecodedDatagram<'a>, DatagramMetadataError> {
        if !self.trusted_proxies.contains(&socket_peer.ip()) {
            return Err(DatagramMetadataError::UntrustedPeer);
        }
        let parsed = parse_datagram_header_inner(datagram)?;

        // Defense in depth ahead of the cryptographic binding: an
        // address-bearing envelope states which listener it was minted for, and
        // a mismatch is the specific `listener_binding_mismatch` reason. The
        // declared destination is attacker-supplied, so this check can only
        // ever refuse — never admit — and the MAC below is what actually binds
        // every envelope form (including the address-less ones) to this
        // listener.
        if parsed.forwarded.is_some() && parsed.destination_port != Some(self.binding.port) {
            return Err(DatagramMetadataError::ListenerBindingMismatch);
        }

        // With no secret configured, a supplied tag or freshness record is
        // simply not honored: verifying nothing against nothing would present
        // authenticated-looking metadata. Those bytes stay inside the address
        // block either way and never reach the payload.
        if self.authentication_required {
            // A configured secret that produced no key cannot verify anything,
            // so the listener refuses rather than admitting metadata the
            // operator asked to have authenticated.
            let Some(key) = self.auth_key.as_ref() else {
                return Err(DatagramMetadataError::AuthenticationKeyUnavailable);
            };
            self.verify_authentication_tag(key, datagram, &parsed)?;
            // Only now are the freshness bytes trustworthy: the MAC has proven
            // they were minted by a secret holder for this exact listener.
            let Some((start, end)) = parsed.freshness else {
                return Err(DatagramMetadataError::MissingFreshness);
            };
            let freshness = DatagramFreshness::decode_value(&datagram[start..end])?;
            self.replay.admit(&freshness, now_unix_ms)?;
        }
        Ok(DecodedDatagram {
            payload: &datagram[parsed.header_len..],
            forwarded: parsed.forwarded,
        })
    }

    /// Verify the tag over this listener's domain prefix plus everything in the
    /// datagram except the tag value itself.
    ///
    /// The MAC covers the domain binding and the complete datagram with the 32
    /// tag bytes elided, so the receiving listener's protocol/address/port, the
    /// version/command/family/transport bytes, the forwarded addresses, the
    /// freshness record, every other TLV, and the payload are all bound.
    /// Eliding the tag value is the versioned canonical format and avoids
    /// mutating or copying the borrowed datagram on the hot path.
    fn verify_authentication_tag(
        &self,
        key: &HmacSha256Key,
        datagram: &[u8],
        parsed: &ParsedDatagramHeader,
    ) -> Result<(), DatagramMetadataError> {
        let Some((tag_start, tag_end)) = parsed.auth_tag else {
            return Err(DatagramMetadataError::MissingAuthenticationTag);
        };
        let mut mac = key.begin();
        mac.update(&self.domain[..self.domain_len]);
        mac.update(&datagram[..tag_start]);
        mac.update(&datagram[tag_end..]);
        let expected = mac.finalize().into_bytes();
        let verified = crate::plugins::utils::auth_flow::constant_time_eq(
            &expected,
            &datagram[tag_start..tag_end],
        );
        if verified {
            Ok(())
        } else {
            Err(DatagramMetadataError::AuthenticationTagMismatch)
        }
    }
}

/// Byte ranges and decoded fields of one metadata header.
struct ParsedDatagramHeader {
    /// Total metadata length; the payload starts here.
    header_len: usize,
    forwarded: Option<SocketAddr>,
    /// Declared destination port from an `AF_INET` / `AF_INET6` address block.
    /// `None` for `AF_UNSPEC` (no addresses). Not a trust decision; the gate
    /// compares it to the receiving listener as defense in depth.
    destination_port: Option<u16>,
    /// Absolute `[start, end)` of the authentication tag value, when present.
    auth_tag: Option<(usize, usize)>,
    /// Absolute `[start, end)` of the freshness TLV value, when present.
    freshness: Option<(usize, usize)>,
}

/// Parse the metadata header, without any trust, binding, authentication, or
/// freshness decision. Hostile-input entry for the fuzz lane: bounded,
/// allocation-free, and it never returns payload, tag, or secret material.
///
/// Compiled only with `feature = "fuzzing"`, matching the TCP PROXY fuzz
/// entry. The production receive path uses
/// [`DatagramClientAddressGate::decode`].
#[cfg(feature = "fuzzing")]
pub(crate) fn parse_datagram_header(datagram: &[u8]) -> Result<(), DatagramMetadataError> {
    let parsed = parse_datagram_header_inner(datagram)?;
    // Cover the freshness value parser too: it is reachable from hostile wire
    // bytes as soon as a MAC verifies, so it must be bounded and panic-free on
    // its own.
    if let Some((start, end)) = parsed.freshness {
        DatagramFreshness::decode_value(&datagram[start..end])?;
    }
    Ok(())
}

/// Parse the metadata header, without any trust or authentication decision.
fn parse_datagram_header_inner(
    datagram: &[u8],
) -> Result<ParsedDatagramHeader, DatagramMetadataError> {
    if datagram.len() < FIXED_HEADER_LEN {
        return Err(DatagramMetadataError::TruncatedHeader {
            len: datagram.len(),
        });
    }
    if &datagram[..V2_SIG.len()] != V2_SIG {
        return Err(DatagramMetadataError::InvalidSignature);
    }
    let ver_cmd = datagram[12];
    let fam_transport = datagram[13];
    let addr_len = u16::from_be_bytes([datagram[14], datagram[15]]);

    let version = ver_cmd >> 4;
    if version != 2 {
        return Err(DatagramMetadataError::UnsupportedVersion(version));
    }
    if addr_len > MAX_ADDR_BLOCK_LEN {
        return Err(DatagramMetadataError::AddressBlockTooLong(addr_len));
    }
    let available = datagram.len() - FIXED_HEADER_LEN;
    if (addr_len as usize) > available {
        return Err(DatagramMetadataError::TruncatedAddressBlock {
            declared: addr_len,
            available,
        });
    }
    let header_len = FIXED_HEADER_LEN + addr_len as usize;
    let block = &datagram[FIXED_HEADER_LEN..header_len];

    let command = ver_cmd & 0x0f;
    let family = fam_transport >> 4;
    let transport = fam_transport & 0x0f;

    // `LOCAL` is the balancer's own traffic (health probes): no forwarded
    // address, but the envelope is still parsed and authenticated so a bare
    // datagram cannot masquerade as one.
    let is_local = match command {
        0x00 => true,
        0x01 => false,
        other => return Err(DatagramMetadataError::UnsupportedCommand(other)),
    };

    // Every `PROXY` envelope must state that it describes a datagram flow —
    // including the `AF_UNSPEC` shape, which carries no address to check. Doing
    // this only for the address-bearing families would leave a TCP `STREAM`
    // header accepted verbatim on a udp/dtls listener as long as its family
    // nibble were zeroed, which is exactly the replay the module and
    // `docs/tcp_udp_proxy.md` promise to refuse.
    //
    // `LOCAL` keeps the spec's semantics: the sender is speaking for itself,
    // the receiver must ignore the address block, and `fam_transport` is
    // conventionally `0x00`. It never sets a forwarded identity, so it cannot
    // launder a stream header into a client address.
    if !is_local {
        require_datagram_transport(transport)?;
    }

    let (forwarded, fixed_len, destination_port) = match family {
        // AF_UNSPEC — no address is carried.
        0x00 => (None, 0usize, None),
        0x01 => {
            if block.len() < INET_ADDR_LEN {
                return Err(DatagramMetadataError::AddressBlockTooShortForFamily {
                    family,
                    len: block.len(),
                });
            }
            let src = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[8], block[9]]);
            let dest_port = u16::from_be_bytes([block[10], block[11]]);
            (
                Some(SocketAddr::new(IpAddr::V4(src), port)),
                INET_ADDR_LEN,
                Some(dest_port),
            )
        }
        0x02 => {
            if block.len() < INET6_ADDR_LEN {
                return Err(DatagramMetadataError::AddressBlockTooShortForFamily {
                    family,
                    len: block.len(),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let port = u16::from_be_bytes([block[32], block[33]]);
            let dest_port = u16::from_be_bytes([block[34], block[35]]);
            (
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                INET6_ADDR_LEN,
                Some(dest_port),
            )
        }
        // AF_UNIX (0x03) and anything else cannot address a datagram client.
        other => return Err(DatagramMetadataError::UnsupportedAddressFamily(other)),
    };

    let (auth_tag, freshness) =
        walk_envelope_tlvs(&block[fixed_len..], FIXED_HEADER_LEN + fixed_len)?;

    Ok(ParsedDatagramHeader {
        header_len,
        // A LOCAL envelope never sets a client identity even if it carried
        // addresses; the balancer is speaking for itself.
        forwarded: if is_local {
            None
        } else {
            forwarded.map(crate::util::client_identity::canonical_socket_addr)
        },
        destination_port,
        auth_tag,
        freshness,
    })
}

#[inline]
fn require_datagram_transport(transport: u8) -> Result<(), DatagramMetadataError> {
    // 0x02 is DGRAM. UNSPEC (0x00) is refused here on purpose: a `PROXY`
    // envelope must state that it describes a datagram flow, whatever family it
    // declares.
    if transport == 0x02 {
        Ok(())
    } else {
        Err(DatagramMetadataError::NonDatagramTransport(transport))
    }
}

/// Absolute `[start, end)` byte range of a TLV value within the datagram buffer.
type TlvValueByteRange = (usize, usize);

/// Located authentication and freshness TLV value ranges from one envelope walk.
type EnvelopeTlvRanges = (Option<TlvValueByteRange>, Option<TlvValueByteRange>);

/// Walk the TLV region once and locate the single authentication TLV and the
/// single freshness TLV, if present.
///
/// `tlv_base` is the TLV region's absolute offset inside the datagram, so the
/// returned ranges can address the original buffer without a second walk. Both
/// TLVs are capped at exactly one occurrence: a second copy is ambiguous about
/// which one the MAC covered or which sequence was asserted, so it is refused
/// rather than resolved by position.
fn walk_envelope_tlvs(
    tlvs: &[u8],
    tlv_base: usize,
) -> Result<EnvelopeTlvRanges, DatagramMetadataError> {
    let mut offset = 0usize;
    let mut auth: Option<TlvValueByteRange> = None;
    let mut freshness: Option<TlvValueByteRange> = None;
    while offset < tlvs.len() {
        // type (1) + length (2) + value
        if tlvs.len() - offset < 3 {
            return Err(DatagramMetadataError::MalformedTlv);
        }
        let tlv_type = tlvs[offset];
        let value_len = u16::from_be_bytes([tlvs[offset + 1], tlvs[offset + 2]]) as usize;
        let value_start = offset + 3;
        let Some(value_end) = value_start.checked_add(value_len) else {
            return Err(DatagramMetadataError::MalformedTlv);
        };
        if value_end > tlvs.len() {
            return Err(DatagramMetadataError::MalformedTlv);
        }
        match tlv_type {
            AUTH_TLV_TYPE => {
                if auth.is_some() {
                    return Err(DatagramMetadataError::DuplicateAuthenticationTag);
                }
                if value_len != AUTH_TAG_LEN {
                    return Err(DatagramMetadataError::InvalidAuthenticationTagLength(
                        value_len,
                    ));
                }
                auth = Some((tlv_base + value_start, tlv_base + value_end));
            }
            FRESHNESS_TLV_TYPE => {
                if freshness.is_some() {
                    return Err(DatagramMetadataError::DuplicateFreshness);
                }
                if value_len != FRESHNESS_VALUE_LEN {
                    return Err(DatagramMetadataError::MalformedFreshness);
                }
                freshness = Some((tlv_base + value_start, tlv_base + value_end));
            }
            _ => {}
        }
        offset = value_end;
    }
    Ok((auth, freshness))
}

/// Which envelope form the encoder should emit.
///
/// All four forms carry the same authentication, listener-binding, and
/// freshness contract when a key is supplied; the address-less ones simply
/// confer no forwarded identity.
#[derive(Debug, Clone, Copy)]
pub enum DatagramEnvelopeForm {
    /// `LOCAL`, spec-conventional `0x00` `fam_transport`, no addresses. The
    /// balancer speaking for itself (health probes).
    Local,
    /// `PROXY` + `AF_UNSPEC` + `DGRAM`, no addresses.
    Unspec,
    /// `PROXY` + `AF_INET` / `AF_INET6` + `DGRAM`, carrying the forwarded
    /// client and the destination the balancer sent to. `destination`'s port
    /// must be the receiving listener's port.
    Forwarded {
        source: SocketAddr,
        destination: SocketAddr,
    },
}

/// Sender-side authentication material.
///
/// A sender holds the root secret, knows which listener it is addressing, and
/// keeps a `(sender_id, epoch, sequence)` counter. All three are required
/// together: an authenticated envelope without freshness is refused, and a
/// freshness record minted for another listener cannot verify.
///
/// Deliberately not `Debug`: it holds the root HMAC key, and no formatter should
/// ever be able to render it.
#[derive(Clone, Copy)]
pub struct DatagramEnvelopeAuth<'a> {
    /// HMAC-SHA-256 key over the exact configured
    /// `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET` bytes.
    pub key: &'a HmacSha256Key,
    /// The receiving listener this envelope is minted for.
    pub binding: &'a DatagramListenerBinding,
    /// Freshness record for this datagram.
    pub freshness: DatagramFreshness,
}

/// Build a datagram carrying client-address metadata.
///
/// Ferrum never emits this envelope in production — a datagram load balancer
/// does — so this exists for the external conformance tests and for operators
/// generating fixtures. It is the normative encoder for the format above.
///
/// With `auth` set, the envelope carries a freshness TLV and an HMAC-SHA-256
/// tag computed over the listener's canonical domain plus the whole datagram
/// with the tag elided. With `auth` unset, the result carries neither: that is
/// the documented trusted-network posture, which has **no** cryptographic
/// authenticity and **no** freshness — trust rests entirely on the socket peer
/// being inside `FERRUM_TRUSTED_PROXIES`.
pub fn encode_datagram_with_metadata(
    form: DatagramEnvelopeForm,
    payload: &[u8],
    auth: Option<&DatagramEnvelopeAuth<'_>>,
) -> Vec<u8> {
    let (ver_cmd, fam_transport, fixed): (u8, u8, Vec<u8>) = match form {
        DatagramEnvelopeForm::Local => (0x20, 0x00, Vec::new()),
        DatagramEnvelopeForm::Unspec => (0x21, 0x02, Vec::new()),
        DatagramEnvelopeForm::Forwarded {
            source,
            destination,
        } => {
            let source = crate::util::client_identity::canonical_socket_addr(source);
            let destination = crate::util::client_identity::canonical_socket_addr(destination);
            match (source.ip(), destination.ip()) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    let mut fixed = Vec::with_capacity(INET_ADDR_LEN);
                    fixed.extend_from_slice(&src.octets());
                    fixed.extend_from_slice(&dst.octets());
                    fixed.extend_from_slice(&source.port().to_be_bytes());
                    fixed.extend_from_slice(&destination.port().to_be_bytes());
                    (0x21, 0x12, fixed)
                }
                (src, dst) => {
                    let to_v6 = |ip: IpAddr| match ip {
                        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                        IpAddr::V6(v6) => v6,
                    };
                    let mut fixed = Vec::with_capacity(INET6_ADDR_LEN);
                    fixed.extend_from_slice(&to_v6(src).octets());
                    fixed.extend_from_slice(&to_v6(dst).octets());
                    fixed.extend_from_slice(&source.port().to_be_bytes());
                    fixed.extend_from_slice(&destination.port().to_be_bytes());
                    (0x21, 0x22, fixed)
                }
            }
        }
    };

    let tlv_len = if auth.is_some() {
        FRESHNESS_TLV_LEN + 3 + AUTH_TAG_LEN
    } else {
        0
    };
    let addr_len = (fixed.len() + tlv_len) as u16;
    let mut out = Vec::with_capacity(FIXED_HEADER_LEN + addr_len as usize + payload.len());
    out.extend_from_slice(V2_SIG);
    out.push(ver_cmd);
    out.push(fam_transport);
    out.extend_from_slice(&addr_len.to_be_bytes());
    out.extend_from_slice(&fixed);

    match auth {
        None => {
            out.extend_from_slice(payload);
            out
        }
        Some(auth) => {
            out.extend_from_slice(&auth.freshness.encode_tlv());
            out.push(AUTH_TLV_TYPE);
            out.extend_from_slice(&(AUTH_TAG_LEN as u16).to_be_bytes());
            let tag_start = out.len();
            out.extend_from_slice(&[0u8; AUTH_TAG_LEN]);
            out.extend_from_slice(payload);
            let mut domain = [0u8; DOMAIN_PREFIX_MAX];
            let domain_len = auth.binding.write_domain(&mut domain);
            let mut mac = auth.key.begin();
            mac.update(&domain[..domain_len]);
            mac.update(&out[..tag_start]);
            mac.update(&out[tag_start + AUTH_TAG_LEN..]);
            let tag = mac.finalize().into_bytes();
            out[tag_start..tag_start + AUTH_TAG_LEN].copy_from_slice(&tag);
            out
        }
    }
}
