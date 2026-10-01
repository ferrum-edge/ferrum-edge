//! NodeWaypoint UDP/DTLS **reply-source authorization** publication and
//! acknowledgement (issue #3286).
//!
//! # The gap this closes
//!
//! `tc_inbound` admits a datagram to an enrolled pod only when it carries the
//! NodeWaypoint relay's auth mark AND comes from an authorized source. For the
//! relay's *backend dial* the source is a configured node address, so the TCP
//! proof carries over unchanged. For the relay's *reply* it does not: a
//! NodeWaypoint UDP/DTLS reply is not route-selected, it is PINNED (via
//! `IP_PKTINFO`/`IPV6_PKTINFO` on an `IP_TRANSPARENT` socket) to the exact local
//! address the client addressed. On the ordinary Service path that address is
//! the Service ClusterIP — never a node PodCIDR gateway address, and therefore
//! never in `FERRUM_NODE_IPS`/`FERRUM_NODE_IPS6`. So a correctly marked,
//! correctly scoped, correctly attributed reply died in this node's own guard,
//! and only a direct dial to a trusted node address ever completed.
//!
//! Un-pinning the reply is not a fix (a `connect()`ed client — every DTLS client
//! — discards a reply whose source is not the address it dialed), and widening
//! the node-IP set to ClusterIPs would hand every `CAP_NET_ADMIN`/`SO_MARK`
//! capable workload a generic lane to enrolled pods.
//!
//! # What is authorized
//!
//! Exactly the reply's own two-tuple: `(pinned source address, listener port)`.
//! Both are knowable in advance and both are exact — no CIDR, no service range,
//! no port-blind form. `FERRUM_UDP_REPLY_SOURCES`/`FERRUM_UDP_REPLY_SOURCES6`
//! supply only the SOURCE half of the guard's proof; the relay auth mark is
//! still required, TCP never reads these maps, and nothing here admits an
//! unmarked datagram.
//!
//! # The source tuple is not, and never was, a sender proof (issues #3956/#3957)
//!
//! A source address and a socket mark are both chosen by whoever emits the
//! packet. A same-node workload in the HOST network namespace holding only
//! SOCKET-level privilege (`CAP_NET_RAW` suffices for `IP_TRANSPARENT`, and for
//! `SO_MARK` since Linux 5.17) can `SO_MARK` the relay's mark and bind either a
//! configured node address or a published Service ClusterIP, and so present the
//! complete admission this map was originally the second half of.
//! Because the map is listener-wide, that replay works against ANY enrolled
//! destination, not just the one whose Service was named.
//!
//! So the generation carries a THIRD field: the publishing proxy's own
//! Kubernetes pod UID. The node-agent resolves it host-side to the relay pod's
//! cgroup-v2 subtree and writes that into `FERRUM_UDP_RELAY_CGROUPS`, which the
//! tc UDP arms require — via `bpf_skb_cgroup_id()`, the cgroup of the socket
//! that generated the skb — BEFORE they consult a node source or a reply
//! source. That id is assigned by the kernel at socket creation from the
//! creating task's cgroup, so it cannot be presented by a process outside the
//! relay's cgroup.
//!
//! The pod UID is a NAME on this channel, never an authorization. The
//! node-agent resolves it against the real hierarchy and refuses it outright
//! when it names an ENROLLED workload, so nothing published here can authorize
//! one of the pods the guard protects to answer as the relay. A publication
//! that cannot name a relay identity is refused rather than downgraded — except
//! an INACTIVE generation, which authorizes nothing and must stay publishable
//! so withdrawal is always provable. An ACTIVE generation with zero sources
//! still names the relay: that is the bound headless/VIP-less listener whose
//! marked backend dial needs the sender proof and names no ClusterIP tuple.
//!
//! # Ownership: why this is a file channel and not a map write
//!
//! The node-agent is the sole writer of every BPF map, and the mesh proxy's
//! bpffs mount is deliberately **read-only** — a writable one would also let the
//! proxy rewrite the pinned original-destination identity records. So the proxy
//! publishes a DESIRED generation and the node-agent applies it, reusing the
//! established proxy→node-agent channel: the pod registry directory that already
//! carries `.ready4` / `.ready6` markers one way and `.udp-not-ready`
//! acknowledgements the other.
//!
//! # The channel is a generation, not a directory of claims
//!
//! Under `<registry dir>/.udp-reply-src/` there are exactly two well-known
//! files, and nothing else in the directory means anything:
//!
//! * `desired` — written ONLY by the proxy. One bounded, strictly parsed
//!   manifest holding the WHOLE authorized set plus the generation that names
//!   it. Written to a temporary sibling and `rename`d into place, so a reader
//!   observes either the entire previous generation or the entire new one. A
//!   directory of one file per claim could be — and, on the 250 ms node-agent
//!   poll, regularly would be — observed mid-rewrite as a partial set.
//! * `applied` — written ONLY by the node-agent, and only after that exact
//!   generation's COMPLETE IPv4 + IPv6 source set AND its resolved relay-cgroup
//!   set are in all three BPF maps and their one shared classifier gate is
//!   enabled. It names that generation and nothing else. Map keys are inert
//!   while the gate is disabled.
//!
//! A generation is `(owner, sequence, active)`. The owner is a per-process
//! random token (16 lowercase hex digits,
//! [`RegistryDirReplySourcePublisher::new`]) and the sequence is monotonic
//! within that owner, bumped whenever the desired set OR serving bit changes.
//! `active` is part of the identity so an active-empty ↔ inactive-empty
//! transition is always a new generation and a stale acknowledgement of one
//! can never satisfy the other. It is not a secret and is never treated as
//! one: it exists so that an acknowledgement written for a predecessor
//! process, for an earlier set, for a differently ordered rendering of a set,
//! or for the opposite serving state can never be read as proof about the
//! generation a live proxy is asking for. The manifest's claim lines are
//! strictly ascending in the destination order, so one set has exactly one
//! rendering and a reordered file is refused rather than normalized.
//!
//! # Lifecycle and ordering
//!
//! Publication is bound to the SERVING lifecycle, not to configuration.
//! [`NodeWaypointUdpSteering`](super::node_waypoint_udp_steering) owns the call
//! and distinguishes a bound, started, non-finished UDP/DTLS listener
//! (ACTIVE, sender proof live) from ClusterIP steering destinations (the
//! source tuples). A candidate config authorizes nothing by being parsed, and
//! a configured-but-unbound listener activates nothing. Within one reconcile:
//!
//! * steering rules for the outgoing generation are removed first,
//! * the new generation is published, and then the reconcile waits for the
//!   node-agent to acknowledge THAT EXACT generation before any steering rule is
//!   installed — publishing a claim is not evidence that a map holds it, and the
//!   window between the two is exactly the steered-but-unanswerable black hole
//!   this channel exists to close,
//! * on teardown the order reverses — rules first, then the INACTIVE
//!   generation — and the withdrawal is not proven until the node-agent
//!   acknowledges that inactive generation too. Removing ClusterIP
//!   destinations while a listener stays bound publishes ACTIVE with an empty
//!   source set rather than withdrawing the sender proof.
//!
//! Every failure is fail-closed: a publication that cannot be written refuses
//! the whole generation and tears the datapath down, a pending or stale
//! acknowledgement keeps the rules absent and retries on the next reconcile
//! (there is no wait, no sleep, and no blocked worker), and a withdrawal that
//! cannot be proven is never recorded as done. A crashed predecessor's rules are
//! reaped by the successor's mandatory first-pass teardown; its `applied` file
//! carries a different owner and therefore satisfies nothing.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::capture::{MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS, NodeWaypointUdpSteerDestination};
use crate::sync_compat::AtomicUpdate;

/// Directory under the pod registry root carrying the reply-source channel. A
/// dot-prefixed sibling of the pod files, like the readiness markers, so a
/// channel file can never be mistaken for a pod UID entry.
pub const NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR: &str = ".udp-reply-src";

/// The proxy-written desired generation. Proxy writes, node-agent reads.
pub const NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE: &str = "desired";

/// The node-agent-written acknowledgement. Node-agent writes, proxy reads.
pub const NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE: &str = "applied";

/// Manifest and acknowledgement leaders. Distinct so an acknowledgement can
/// never be parsed as a desired generation, or the reverse.
const MANIFEST_MAGIC: &str = "ferrum-udp-reply-src";
const ACK_MAGIC: &str = "ferrum-udp-reply-src-ack";
/// `v3` adds an explicit `active`/`inactive` serving token so a bound
/// headless/VIP-less listener can keep the relay-cgroup sender proof live with
/// an empty source set. `v1` named no relay identity; `v2` still equated an
/// empty source set with withdrawal. Both are unparseable: honouring either
/// would authorize the wrong half of the classifier's conjunction.
const PROTOCOL_VERSION: &str = "v3";
/// Canonical serving-state tokens. Anything else, including empty, mixed case,
/// or a synonym, refuses the whole generation.
const STATE_ACTIVE: &str = "active";
const STATE_INACTIVE: &str = "inactive";

/// Owner tokens are exactly this many lowercase hex digits. Fixed width so the
/// parse is total and a padded or truncated spelling is not a second name for
/// one owner.
const OWNER_TOKEN_CHARS: usize = 16;

/// Header field spelling for "this generation names no relay identity". A
/// single `-` cannot collide with a real pod UID because [`parse_relay_pod_uid`]
/// refuses a leading dash.
const NO_RELAY_POD_UID: &str = "-";

/// Upper bound on the relay pod UID token. A Kubernetes pod UID is a 36-byte
/// RFC 4122 UUID; the slack absorbs non-standard control planes without letting
/// the field grow into an unbounded path component.
const MAX_RELAY_POD_UID_CHARS: usize = 64;

/// `6-` + 32 hex digits + `-` + 5 port digits + `\n`.
const MAX_CLAIM_LINE_BYTES: usize = 41;

/// Magic (20) + space + version (2) + space + owner (16) + space + a 20-digit
/// `u64` + space + state (`inactive` is 8) + space + a 3-digit count + space +
/// the relay pod UID ([`MAX_RELAY_POD_UID_CHARS`]) + `\n`, with slack.
const MAX_HEADER_BYTES: usize = 192;

/// Hard read bound for the desired generation. Anything larger is refused
/// outright rather than parsed: the writer is Ferrum, so an oversized file is a
/// fault or a plant, never a bigger legitimate set.
const MAX_MANIFEST_BYTES: usize =
    MAX_HEADER_BYTES + MAX_CLAIM_LINE_BYTES * MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS;

/// Hard read bound for the acknowledgement, which is exactly one header line.
const MAX_ACK_BYTES: usize = MAX_HEADER_BYTES;

/// One coherent publication of the authorized reply-source set AND the
/// serving/active bit that decides whether the relay-cgroup sender proof is
/// live.
///
/// `owner` is process-unique, `sequence` is monotonic within it, and `active`
/// is part of the identity, so equality answers exactly one question: "is the
/// set AND serving state the node-agent proved applied the set this process is
/// asking for right now?" An active-empty generation and an inactive-empty
/// generation are therefore distinct even when both have zero sources — a
/// stale acknowledgement of one can never satisfy the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplySourceGeneration {
    owner: String,
    sequence: u64,
    active: bool,
}

impl ReplySourceGeneration {
    /// The publishing process's token. Diagnostics only; never a credential.
    #[allow(dead_code)] // Diagnostic/test accessor; the token is compared as a whole.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Monotonic position within [`Self::owner`].
    #[allow(dead_code)] // Diagnostic/test accessor.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Whether this generation keeps the relay-cgroup sender proof live.
    ///
    /// Active-empty (a bound headless/VIP-less listener) is true; a true
    /// withdrawal is false. Part of canonical identity: an active-empty ↔
    /// inactive-empty transition is a new generation.
    #[allow(dead_code)] // Diagnostic/test accessor.
    pub fn active(&self) -> bool {
        self.active
    }

    /// Sentinel generation for a publisher-less steering instance (non-Linux,
    /// or no registry directory). Nothing is authorized and nothing is
    /// materialized there, so the pair is trivially coherent. It can never be
    /// confused with a real generation: the parser requires 16 lowercase hex
    /// digits for an owner and a nonzero sequence, so this value cannot come off
    /// disk and cannot be written to it.
    ///
    /// Publisher-less steering still distinguishes active-empty from
    /// inactive-empty so quiet-poll `generation_proven` cannot treat a bound
    /// headless listener as a proven withdrawal.
    pub(crate) fn inert_with_active(active: bool) -> Self {
        Self {
            owner: "inert".to_string(),
            sequence: 0,
            active,
        }
    }
}

/// The desired generation as the node-agent reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredReplySources {
    /// The generation to acknowledge once — and only once — the whole set below
    /// is live in EVERY BPF map family.
    pub generation: ReplySourceGeneration,
    /// The complete authorized set, ascending and deduplicated by construction:
    /// the parser refuses any other rendering.
    pub sources: Vec<NodeWaypointUdpSteerDestination>,
    /// The Kubernetes pod UID of the publishing NodeWaypoint proxy, from which
    /// the node-agent resolves the relay's cgroup-v2 subtree host-side (issues
    /// #3956, #3957).
    ///
    /// This is a NAME, never an authorization: the node-agent resolves it
    /// against the real cgroup hierarchy and refuses it outright when it names
    /// an ENROLLED workload, so the channel can never authorize one of the pods
    /// this guard protects to answer as the relay.
    ///
    /// `None` only for an INACTIVE generation — a withdrawal authorizes
    /// nothing and therefore needs no identity, which is what keeps teardown
    /// reliable on a proxy that cannot learn its own pod UID. An ACTIVE
    /// generation, including one with zero ClusterIP sources (a bound
    /// headless/VIP-less or direct-node listener), MUST name a usable relay
    /// identity so the node-agent can keep `FERRUM_UDP_RELAY_CGROUPS` live.
    /// [`parse_manifest`] refuses every other combination: active without
    /// identity, inactive with sources, inactive with identity, a non-empty
    /// source set that is not active, malformed state tokens, and inconsistent
    /// counts.
    pub relay_pod_uid: Option<String>,
}

/// Encode one authorized reply source as a manifest claim line.
///
/// Hex rather than the textual address form on purpose: an IPv6 address has
/// many textual spellings (`::1` / `0:0:0:0:0:0:0:1`) but exactly one byte
/// sequence, so a fixed-width hex rendering makes the claim set a true set —
/// two spellings of one address cannot become two lines, and the node-agent's
/// parse is a total function on a closed charset with no separator ambiguity.
pub fn encode_claim(source: &NodeWaypointUdpSteerDestination) -> String {
    use std::fmt::Write as _;

    let mut name = String::with_capacity(MAX_CLAIM_LINE_BYTES);
    // Writing into a `String` is infallible, and the rendering is fixed-width,
    // which is what makes the parse below a total inverse.
    match source.ip {
        IpAddr::V4(addr) => {
            name.push_str("4-");
            for octet in addr.octets() {
                let _ = write!(name, "{octet:02x}");
            }
        }
        IpAddr::V6(addr) => {
            name.push_str("6-");
            for octet in addr.octets() {
                let _ = write!(name, "{octet:02x}");
            }
        }
    }
    let _ = write!(name, "-{}", source.port);
    name
}

/// Strictly parse a claim line back into an authorized reply source.
///
/// `None` for anything that is not exactly the shape [`encode_claim`] produces:
/// wrong family tag, wrong address width, non-lowercase-hex digits, a missing or
/// extra separator, a non-numeric or out-of-range port, or port `0` (no listener
/// binds it, so it can only be junk). An unrecognized line authorizes nothing,
/// which is the fail-closed answer — and because it appears inside a counted
/// manifest, it refuses the WHOLE generation rather than narrowing it.
pub fn decode_claim(name: &str) -> Option<NodeWaypointUdpSteerDestination> {
    let mut parts = name.split('-');
    let family = parts.next()?;
    let addr = parts.next()?;
    let port_text = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    // Lowercase hex only. Accepting uppercase would make two names describe one
    // address, and the claim set would stop being a set.
    if !addr
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let ip = match family {
        "4" if addr.len() == 8 => {
            let mut octets = [0u8; 4];
            decode_hex_octets(addr, &mut octets)?;
            IpAddr::from(octets)
        }
        "6" if addr.len() == 32 => {
            let mut octets = [0u8; 16];
            decode_hex_octets(addr, &mut octets)?;
            IpAddr::from(octets)
        }
        _ => return None,
    };
    // Round-trip the port for the same canonicality reason: `+80`, ` 80`, and
    // `080` all parse to 80, and three names for one source would defeat the
    // set semantics the whole-set replacement depends on. Port 0 is never bound
    // by a listener, so it can only be junk.
    let port = parse_canonical_u64(port_text)?;
    if port == 0 || port > u16::MAX as u64 {
        return None;
    }
    Some(NodeWaypointUdpSteerDestination {
        ip,
        port: port as u16,
    })
}

fn decode_hex_octets(hex: &str, out: &mut [u8]) -> Option<()> {
    let bytes = hex.as_bytes();
    if bytes.len() != out.len() * 2 {
        return None;
    }
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        *slot = ((high << 4) | low) as u8;
    }
    Some(())
}

/// Decimal with exactly one spelling. `+7`, ` 7`, and `007` all parse to 7, and
/// three spellings of one number would make the manifest non-canonical.
fn parse_canonical_u64(token: &str) -> Option<u64> {
    let value: u64 = token.parse().ok()?;
    if value.to_string() != token {
        return None;
    }
    Some(value)
}

/// Strictly parse the relay-identity header field.
///
/// `Some(None)` is the `-` sentinel (no relay identity, valid only for an empty
/// generation); `Some(Some(uid))` is a pod UID; `None` refuses the manifest.
///
/// The charset is deliberately narrower than "any pod UID a control plane might
/// mint": lowercase alphanumerics and interior dashes only, bounded length, no
/// leading or trailing dash. The node-agent turns this token into a filesystem
/// path under the cgroup root, so `/`, `\\`, `.`, and `..` must be
/// unrepresentable HERE, at the trust boundary, rather than sanitized later by
/// whichever consumer happens to remember to.
fn parse_relay_pod_uid(token: &str) -> Option<Option<String>> {
    if token == NO_RELAY_POD_UID {
        return Some(None);
    }
    if token.is_empty() || token.len() > MAX_RELAY_POD_UID_CHARS {
        return None;
    }
    if token.starts_with('-') || token.ends_with('-') {
        return None;
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return None;
    }
    Some(Some(token.to_string()))
}

fn parse_owner(token: &str) -> Option<String> {
    if token.len() != OWNER_TOKEN_CHARS {
        return None;
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(token.to_string())
}

/// Render the whole desired generation. `sources` must already be ascending and
/// deduplicated — [`RegistryDirReplySourcePublisher::publish`] guarantees it,
/// and [`parse_manifest`] refuses anything else. `active` is the serving bit:
/// true keeps the relay-cgroup sender proof live even when `sources` is empty.
fn render_manifest(
    generation: &ReplySourceGeneration,
    sources: &[NodeWaypointUdpSteerDestination],
    relay_pod_uid: Option<&str>,
) -> String {
    use std::fmt::Write as _;

    let mut body = String::with_capacity(MAX_HEADER_BYTES + sources.len() * MAX_CLAIM_LINE_BYTES);
    let state = if generation.active {
        STATE_ACTIVE
    } else {
        STATE_INACTIVE
    };
    let _ = writeln!(
        body,
        "{MANIFEST_MAGIC} {PROTOCOL_VERSION} {} {} {state} {} {}",
        generation.owner,
        generation.sequence,
        sources.len(),
        relay_pod_uid.unwrap_or(NO_RELAY_POD_UID)
    );
    for source in sources {
        let _ = writeln!(body, "{}", encode_claim(source));
    }
    body
}

/// Strictly parse the desired generation.
///
/// Total and closed: a wrong magic or version, a non-canonical owner or
/// sequence, a count that disagrees with the body, an over-bound count, a claim
/// line that is not exactly a claim, a duplicate or out-of-order claim, trailing
/// bytes, a missing final newline, or non-UTF-8 all yield `None` — which the
/// caller turns into a refusal of the WHOLE generation. There is deliberately no
/// arm that salvages a prefix: a narrowed set acknowledged as complete is the
/// exact failure this channel exists to prevent.
fn parse_manifest(bytes: &[u8]) -> Option<DesiredReplySources> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    let mut lines = text.split('\n');

    let mut header = lines.next()?.split(' ');
    if header.next()? != MANIFEST_MAGIC || header.next()? != PROTOCOL_VERSION {
        return None;
    }
    let owner = parse_owner(header.next()?)?;
    let sequence = parse_canonical_u64(header.next()?)?;
    let active = match header.next()? {
        STATE_ACTIVE => true,
        STATE_INACTIVE => false,
        _ => return None,
    };
    let count = parse_canonical_u64(header.next()?)?;
    let relay_pod_uid = parse_relay_pod_uid(header.next()?)?;
    if header.next().is_some() {
        return None;
    }
    // Sequence 0 is never published, so it can only be junk or a sentinel.
    if sequence == 0 || count > MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS as u64 {
        return None;
    }
    // Serving state, source count, and relay identity are one statement:
    //
    // * ACTIVE requires a usable relay identity even at count 0, so a bound
    //   headless/VIP-less listener can keep the sender proof live without
    //   authorizing any ClusterIP tuple.
    // * INACTIVE is the only true withdrawal: zero sources and no identity.
    // * A non-empty source set implies active; the inverse combinations
    //   (active without identity, inactive with sources, inactive with
    //   identity) are the shapes that would open the wrong half of the
    //   classifier's conjunction and are refused whole.
    if active {
        relay_pod_uid.as_ref()?;
    } else if count > 0 || relay_pod_uid.is_some() {
        return None;
    }

    let count = count as usize;
    let mut sources: Vec<NodeWaypointUdpSteerDestination> = Vec::with_capacity(count);
    let mut previous: Option<NodeWaypointUdpSteerDestination> = None;
    for _ in 0..count {
        let claim = decode_claim(lines.next()?)?;
        // Strictly ascending: one set has exactly one rendering, so a duplicate
        // or a reordered file cannot become a second name for a generation.
        if let Some(previous) = previous
            && claim <= previous
        {
            return None;
        }
        previous = Some(claim);
        sources.push(claim);
    }
    // Exactly the empty tail the final newline produces, and nothing after it.
    if !lines.next()?.is_empty() || lines.next().is_some() {
        return None;
    }

    Some(DesiredReplySources {
        generation: ReplySourceGeneration {
            owner,
            sequence,
            active,
        },
        sources,
        relay_pod_uid,
    })
}

fn parse_ack(bytes: &[u8]) -> Option<ReplySourceGeneration> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    let mut lines = text.split('\n');
    let mut header = lines.next()?.split(' ');
    if !lines.next()?.is_empty() || lines.next().is_some() {
        return None;
    }
    if header.next()? != ACK_MAGIC || header.next()? != PROTOCOL_VERSION {
        return None;
    }
    let owner = parse_owner(header.next()?)?;
    let sequence = parse_canonical_u64(header.next()?)?;
    let active = match header.next()? {
        STATE_ACTIVE => true,
        STATE_INACTIVE => false,
        _ => return None,
    };
    if sequence == 0 || header.next().is_some() {
        return None;
    }
    Some(ReplySourceGeneration {
        owner,
        sequence,
        active,
    })
}

/// Publishes the authorized reply-source set for the serving generation and
/// reports what the node-agent has acknowledged.
///
/// Behind a trait so the steering reconcile's ordering, acknowledgement gating,
/// and fail-closed behaviour are testable without a registry directory, a
/// node-agent, or root.
pub trait NodeWaypointUdpReplySourcePublisher: Send + Sync + 'static {
    /// Publish exactly `sources` as the desired generation with serving state
    /// `active`, replacing whatever was published before, and return the
    /// generation that names it.
    ///
    /// `active == true` keeps the relay-cgroup sender proof live, including
    /// when `sources` is empty (a bound headless/VIP-less or direct-node
    /// listener). `active == false` is the only true withdrawal: `sources`
    /// must be empty and the generation names no relay identity. A non-empty
    /// source set with `active == false`, or an active generation this proxy
    /// cannot name a relay identity for, is refused rather than published.
    ///
    /// Republishing an unchanged `(active, sources)` pair returns the SAME
    /// generation, so a reconcile that is merely waiting for the node-agent
    /// cannot walk the sequence forward faster than the acknowledgement can
    /// chase it. An active-empty ↔ inactive-empty transition is a changed
    /// identity and always advances the sequence.
    fn publish(
        &self,
        sources: &[NodeWaypointUdpSteerDestination],
        active: bool,
    ) -> Result<ReplySourceGeneration, String>;

    /// The generation the node-agent has proven live in BOTH BPF map families,
    /// or `None` when it has proven nothing. Never blocks.
    fn acknowledged(&self) -> Result<Option<ReplySourceGeneration>, String>;
}

/// Production publisher: one atomically replaced manifest under the pod registry
/// directory the node-agent already polls.
pub struct RegistryDirReplySourcePublisher {
    dir: PathBuf,
    /// This proxy's own Kubernetes pod UID, from which the node-agent resolves
    /// the relay cgroup subtree that makes a UDP relay datagram provable.
    /// `None` when the deployment supplies no downward-API identity: every
    /// ACTIVE publication then fails closed (nothing is steered and the sender
    /// proof is not opened), while an INACTIVE withdrawal generation still
    /// publishes so teardown stays reliable.
    relay_pod_uid: Option<String>,
    /// Whether `FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID` was SET but rejected,
    /// as opposed to simply absent. Both leave `relay_pod_uid` `None` and both
    /// refuse every ACTIVE publication, but only one of them is a
    /// misconfiguration the operator can correct — and the startup diagnostic
    /// in `arm_mesh_runtime_startup` only fires for the ABSENT case.
    #[allow(dead_code)] // Diagnostic/test accessor.
    relay_pod_uid_rejected: bool,
    /// Secure-random process owner. `None` makes every publication fail closed;
    /// a predictable fallback could collide with a predecessor and let its
    /// acknowledgement satisfy this process.
    owner: Option<String>,
    /// Next sequence to hand out. Monotonic for the life of the process even
    /// across a mutex poisoning, so a sequence is never reused for a different
    /// set — which is what would let a stale acknowledgement satisfy a
    /// generation it never saw.
    next_sequence: AtomicU64,
    /// The set most recently published, with its sequence and serving bit, so
    /// an unchanged republication of the same `(active, sources)` pair keeps
    /// its generation. Active-empty and inactive-empty are distinct here.
    last: Mutex<Option<(u64, bool, Vec<NodeWaypointUdpSteerDestination>)>>,
}

impl RegistryDirReplySourcePublisher {
    /// `registry_dir` is the pod registry root
    /// (`FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR`); the channel subdirectory
    /// is appended here so no caller can pick a different one.
    ///
    /// `relay_pod_uid` is this proxy's own pod UID
    /// (`FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID`, downward API
    /// `metadata.uid`). A blank or unrepresentable value is normalized to
    /// `None` HERE rather than written to the channel, so an unusable identity
    /// becomes a refusal to authorize rather than a manifest the node-agent has
    /// to refuse later.
    pub fn new(registry_dir: impl AsRef<Path>, relay_pod_uid: Option<&str>) -> Self {
        let accepted = relay_pod_uid
            .map(str::trim)
            .filter(|uid| !uid.is_empty())
            .and_then(|uid| parse_relay_pod_uid(uid).flatten());
        // A value that was SUPPLIED and rejected is a different operator
        // problem from one that was never supplied, and the startup warning in
        // `arm_mesh_runtime_startup` only covers the latter. Without this the
        // only symptom of a mistyped UID is the steering reconcile's generic
        // "active generation could not be published", while the UDP relay stays
        // permanently dark. The rejected value is NOT logged: it is a pod
        // identity, and it is exactly the shape this parser refused to let
        // reach a filesystem path.
        let rejected = relay_pod_uid.is_some() && accepted.is_none();
        if rejected {
            tracing::warn!(
                "FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID is set but is not a usable pod \
                 identity, so it is treated as unset: the node-agent cannot resolve this \
                 relay's cgroup and NodeWaypoint UDP/DTLS admission fails closed at the \
                 pod-veth guard. It must be lowercase alphanumerics and interior dashes \
                 only, at most {MAX_RELAY_POD_UID_CHARS} characters, exactly as the \
                 downward API `metadata.uid` renders it."
            );
        }
        Self {
            dir: registry_dir
                .as_ref()
                .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR),
            owner: owner_token(),
            relay_pod_uid: accepted,
            relay_pod_uid_rejected: rejected,
            next_sequence: AtomicU64::new(1),
            last: Mutex::new(None),
        }
    }

    /// Whether construction saw a relay pod UID that was SET but unusable.
    ///
    /// `false` for both an accepted identity and an absent one; the two absent
    /// cases are what this distinguishes.
    #[allow(dead_code)] // Diagnostic/test accessor.
    pub fn relay_pod_uid_rejected(&self) -> bool {
        self.relay_pod_uid_rejected
    }
}

impl NodeWaypointUdpReplySourcePublisher for RegistryDirReplySourcePublisher {
    fn publish(
        &self,
        sources: &[NodeWaypointUdpSteerDestination],
        active: bool,
    ) -> Result<ReplySourceGeneration, String> {
        let owner = self.owner.as_deref().ok_or_else(|| {
            "secure randomness is unavailable for the NodeWaypoint UDP reply-source owner"
                .to_string()
        })?;
        if sources.len() > MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS {
            return Err(format!(
                "refusing to authorize {} NodeWaypoint UDP/DTLS reply sources; the bound is {}",
                sources.len(),
                MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS
            ));
        }
        if !active && !sources.is_empty() {
            return Err(
                "refusing to publish an inactive NodeWaypoint UDP/DTLS generation with reply \
                 sources; a withdrawal authorizes nothing"
                    .to_string(),
            );
        }
        // Fail closed rather than publishing an ACTIVE generation with no
        // sender proof behind it (issues #3956, #3957), including the
        // active-empty headless/VIP-less shape: without a relay identity the
        // node-agent cannot resolve FERRUM_UDP_RELAY_CGROUPS, and opening the
        // gate over an empty sender map is the same replay. INACTIVE is
        // exempt: it authorizes nothing, and a withdrawal that could not be
        // published is exactly the state that leaves a predecessor's
        // authorization live.
        if active && self.relay_pod_uid.is_none() {
            return Err(
                "refusing to authorize NodeWaypoint UDP/DTLS relay sender proof: this proxy has no \
                 usable relay pod identity, so the node-agent could not resolve the relay cgroup \
                 the tc UDP guard requires. Set FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID from the \
                 downward API `metadata.uid`."
                    .to_string(),
            );
        }
        // Canonicalize here rather than trusting the caller: the manifest's
        // ascending-and-unique invariant is what makes one set have one
        // rendering, and therefore what makes an acknowledgement exact.
        let mut canonical = sources.to_vec();
        canonical.sort_unstable();
        canonical.dedup();

        std::fs::create_dir_all(&self.dir).map_err(|error| {
            format!(
                "failed to create the NodeWaypoint UDP reply-source channel directory: {}",
                io_detail(&error)
            )
        })?;

        let mut last = lock_recovering(&self.last);
        let sequence = match last.as_ref() {
            Some((sequence, published_active, published))
                if *published_active == active && published == &canonical =>
            {
                *sequence
            }
            _ => self
                .next_sequence
                .update_with(Ordering::SeqCst, Ordering::SeqCst, |sequence| {
                    sequence.checked_add(1)
                })
                .map_err(|_| {
                    "NodeWaypoint UDP reply-source generation sequence is exhausted".to_string()
                })?,
        };
        let generation = ReplySourceGeneration {
            owner: owner.to_string(),
            sequence,
            active,
        };
        // INACTIVE always renders the no-identity sentinel, whether or not
        // this proxy has an identity: a withdrawal authorizes nothing, so
        // naming a relay in it would be a claim the generation does not make.
        // ACTIVE always names this proxy's identity, including at source count
        // zero. `acknowledged` reconstructs the expected manifest by this same
        // rule, so the two renderings must agree exactly.
        let relay_pod_uid = if active {
            self.relay_pod_uid.as_deref()
        } else {
            None
        };
        let body = render_manifest(&generation, &canonical, relay_pod_uid);

        // Forget the recorded set BEFORE the write: if the rename fails, what
        // the node-agent can read is unknown, and reusing this sequence for a
        // later set would let an acknowledgement of the old one satisfy it.
        *last = None;
        atomic_write(
            &self.dir,
            NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE,
            owner,
            body.as_bytes(),
        )?;
        *last = Some((sequence, active, canonical));
        Ok(generation)
    }

    fn acknowledged(&self) -> Result<Option<ReplySourceGeneration>, String> {
        let last = lock_recovering(&self.last);
        let Some((sequence, active, sources)) = last.as_ref() else {
            return Ok(None);
        };
        let Some(owner) = self.owner.as_ref() else {
            return Ok(None);
        };
        let expected = DesiredReplySources {
            generation: ReplySourceGeneration {
                owner: owner.clone(),
                sequence: *sequence,
                active: *active,
            },
            sources: sources.clone(),
            // Mirror `publish`'s own rendering rather than the field: inactive
            // carries no identity even when this proxy has one; active always
            // names it.
            relay_pod_uid: if *active {
                self.relay_pod_uid.clone()
            } else {
                None
            },
        };

        // The acknowledgement alone is insufficient: a predecessor can write
        // a late proof after a successor has replaced `desired`, and hostile or
        // corrupt content can preserve `(owner, sequence)` while changing the
        // set or serving bit. Bind the proof to this publisher's exact
        // manifest, checking on both sides of the acknowledgement read so an
        // already-superseded publication never satisfies the serving reconcile.
        if read_desired_generation_in(&self.dir)?.as_ref() != Some(&expected) {
            return Ok(None);
        }
        let acknowledged = read_acknowledgement_in(&self.dir)?;
        if acknowledged.as_ref() != Some(&expected.generation) {
            return Ok(None);
        }
        if read_desired_generation_in(&self.dir)?.as_ref() != Some(&expected) {
            return Ok(None);
        }
        Ok(acknowledged)
    }
}

/// A per-process token identifying the publishing proxy on the channel.
///
/// NOT a secret and never treated as one: it is written in clear to a file both
/// halves read, and it authorizes nothing by itself. Its only job is to make an
/// acknowledgement left by a crashed predecessor — or by a differently ordered
/// history — unable to satisfy this process's generation. If the selected
/// cryptographic provider cannot supply randomness, publication fails closed;
/// a PID/time fallback is not process-unique across every restart environment.
fn owner_token() -> Option<String> {
    use crate::fips::backend::rand::SecureRandom as _;
    use std::fmt::Write as _;

    let mut bytes = [0u8; OWNER_TOKEN_CHARS / 2];
    let rng = crate::fips::backend::rand::SystemRandom::new();
    if rng.fill(&mut bytes).is_err() {
        return None;
    }
    let mut token = String::with_capacity(OWNER_TOKEN_CHARS);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    Some(token)
}

/// Temporary-file tag for the node-agent's acknowledgement writes, so the two
/// halves of the channel can never stage into the same temporary name.
fn acknowledger_tag() -> Result<String, String> {
    owner_token()
        .map(|token| format!("agent{token}"))
        .ok_or_else(|| {
            "secure randomness is unavailable for a NodeWaypoint UDP acknowledgement write"
                .to_string()
        })
}

fn lock_recovering<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned lock carries a plain value here, and the sequence source is an
    // atomic, so recovering is sound: the worst case is that the next
    // publication bumps the sequence when it did not have to.
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Stage into a temporary sibling and `rename` into place.
///
/// `rename` within one directory is atomic, which is the entire reason the
/// channel is a manifest: a reader on a 250 ms poll observes the whole previous
/// generation or the whole new one, never a partially rewritten set.
fn atomic_write(dir: &Path, name: &str, tag: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    let temp = dir.join(format!(".tmp.{name}.{tag}"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&temp).map_err(|error| {
        format!(
            "failed to create a NodeWaypoint UDP reply-source staging file: {}",
            io_detail(&error)
        )
    })?;
    let staged = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = staged {
        let _ = std::fs::remove_file(&temp);
        return Err(format!(
            "failed to stage a NodeWaypoint UDP reply-source channel write: {}",
            io_detail(&error)
        ));
    }
    std::fs::rename(&temp, dir.join(name)).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        format!(
            "failed to publish a NodeWaypoint UDP reply-source channel write: {}",
            io_detail(&error)
        )
    })
}

/// Read at most `max` bytes of a channel file. `Ok(None)` means absent.
///
/// Over-bound content is an ERROR, not a truncation: the writer is Ferrum, so an
/// oversized file is a fault or a plant and the fail-closed answer is to refuse
/// the generation. A non-regular entry is refused before any read, so a FIFO
/// planted in this directory cannot park the reader.
fn read_bounded(path: &Path, max: usize) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to open a NodeWaypoint UDP reply-source channel file: {}",
                io_detail(&error)
            ));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        format!(
            "failed to stat a NodeWaypoint UDP reply-source channel file: {}",
            io_detail(&error)
        )
    })?;
    if !metadata.is_file() {
        return Err(
            "a NodeWaypoint UDP reply-source channel entry is not a regular file".to_string(),
        );
    }
    let mut buffer = Vec::with_capacity(max.min(4096) + 1);
    (&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|error| {
            format!(
                "failed to read a NodeWaypoint UDP reply-source channel file: {}",
                io_detail(&error)
            )
        })?;
    if buffer.len() > max {
        return Err("a NodeWaypoint UDP reply-source channel file exceeds its bound".to_string());
    }
    Ok(Some(buffer))
}

/// Read the proxy's desired generation.
///
/// The node-agent's side of the contract. `Ok(None)` is "nothing published",
/// which is the correct fail-closed reading and not an error: the proxy creates
/// the channel on its first publication. An unreadable, over-bound, or malformed
/// manifest is an ERROR, so the caller revokes rather than retaining.
pub fn read_desired_generation(registry_dir: &Path) -> Result<Option<DesiredReplySources>, String> {
    let dir = registry_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    read_desired_generation_in(&dir)
}

fn read_desired_generation_in(dir: &Path) -> Result<Option<DesiredReplySources>, String> {
    let path = dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE);
    let Some(bytes) = read_bounded(&path, MAX_MANIFEST_BYTES)? else {
        return Ok(None);
    };
    parse_manifest(&bytes).map(Some).ok_or_else(|| {
        "the published NodeWaypoint UDP reply-source generation is malformed".to_string()
    })
}

/// Read the node-agent's acknowledgement, if any.
pub fn read_acknowledgement(registry_dir: &Path) -> Result<Option<ReplySourceGeneration>, String> {
    read_acknowledgement_in(&registry_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR))
}

fn read_acknowledgement_in(dir: &Path) -> Result<Option<ReplySourceGeneration>, String> {
    let path = dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);
    let Some(bytes) = read_bounded(&path, MAX_ACK_BYTES)? else {
        return Ok(None);
    };
    // A malformed acknowledgement acknowledges NOTHING. That is the pending
    // answer rather than an error: the datapath simply stays unsteered until the
    // node-agent writes a well-formed one.
    Ok(parse_ack(&bytes))
}

/// Record that `generation`'s COMPLETE IPv4 + IPv6 set is live in both maps.
///
/// The node-agent's only write on this channel, and the only statement the proxy
/// accepts as proof. Callers must have retracted any earlier acknowledgement and
/// applied the whole set before calling it.
pub fn write_acknowledgement(
    registry_dir: &Path,
    generation: &ReplySourceGeneration,
) -> Result<(), String> {
    let dir = registry_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    let body = format!(
        "{ACK_MAGIC} {PROTOCOL_VERSION} {} {} {}\n",
        generation.owner,
        generation.sequence,
        if generation.active {
            STATE_ACTIVE
        } else {
            STATE_INACTIVE
        }
    );
    atomic_write(
        &dir,
        NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE,
        &acknowledger_tag()?,
        body.as_bytes(),
    )
}

/// Remove any acknowledgement.
///
/// Called before the node-agent touches a map for a new generation and on every
/// refusal, so an acknowledgement never outlives the state it described. An
/// absent file is success — "nothing is acknowledged" is exactly the intent.
pub fn clear_acknowledgement(registry_dir: &Path) -> Result<(), String> {
    let path = registry_dir
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to retract the NodeWaypoint UDP reply-source acknowledgement: {}",
            io_detail(&error)
        )),
    }
}

/// Diagnostics carry the failure CLASS, never the path: the registry root is
/// operator-configured and a claim embeds a Service address, and neither belongs
/// in a log line an operator reads for a filesystem fault.
fn io_detail(error: &std::io::Error) -> String {
    error.kind().to_string()
}

// Contract coverage lives in
// `tests/unit/gateway_core/node_waypoint_udp_reply_source_tests.rs` (claim
// round-trip incl. IPv4/IPv6 parity, strict decode refusals, atomic whole-set
// publication, generation identity/monotonicity, stale and foreign
// acknowledgement refusal, and the bound) and in
// `tests/integration/mesh_node_waypoint_udp_scope_tests.rs` (the node-agent's
// apply-then-acknowledge half).
