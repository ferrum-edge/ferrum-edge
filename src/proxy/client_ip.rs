//! Client IP extraction with trusted proxy support.
//!
//! When the gateway sits behind load balancers, CDNs, or reverse proxies, the
//! TCP socket address (`remote_addr`) is the proxy's IP — not the real client's.
//! This module resolves the true originating client IP from `X-Forwarded-For`
//! (XFF) and recognizes the original HTTP or HTTPS scheme from
//! `X-Forwarded-Proto`, but only when the direct peer belongs to the
//! trusted-proxy set.
//!
//! # Security model
//!
//! A malicious client can prepend arbitrary IPs to `X-Forwarded-For`. Only the
//! **rightmost** entries — those appended by infrastructure you control — are
//! trustworthy. The algorithm:
//!
//! 1. Parse the XFF header into a list of IPs (left-to-right order).
//! 2. Walk from right to left. While the entry matches a trusted proxy CIDR,
//!    skip it and continue.
//! 3. The first non-trusted, valid entry is the real client IP.
//! 4. If a malformed (unparseable) entry is encountered after the trusted
//!    suffix, **stop the walk** and fall back to the socket address. Continuing
//!    leftward would reach more attacker-controlled entries — fail closed.
//! 5. If all entries are trusted (or XFF is absent/empty), fall back to the
//!    TCP socket address.
//!
//! # Configured single-hop real-IP header
//!
//! When `FERRUM_REAL_IP_HEADER` names an authoritative header (`X-Real-IP`,
//! `CF-Connecting-IP`, …), that header is the trusted proxy's **overwrite-only**
//! assertion of one client address. It is therefore accepted only when the
//! request carries **exactly one** field-line holding **exactly one** valid IP
//! (or `ip:port`) value. Zero, duplicate (identical or differing), non-UTF-8,
//! comma-list, or otherwise malformed field-lines are rejected and the direct
//! socket identity is kept — without then falling through to `X-Forwarded-For`,
//! whose contents are less authoritative than the header the operator named.
//!
//! This multiplicity check exists because a trusted proxy that *preserves* a
//! client-supplied copy of the header and *appends* its own would otherwise
//! leave the selected value dependent on field order.
//!
//! # Configuration
//!
//! Set `FERRUM_TRUSTED_PROXIES` to a comma-separated list of CIDRs and/or IPs:
//!
//! ```text
//! FERRUM_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1
//! ```
//!
//! The list is parsed **strictly**: every entry must be a valid IP or CIDR and
//! empty comma segments are rejected. A typo must not silently shrink the trust
//! boundary — that would collapse every downstream client onto the proxy's own
//! socket address for IP policy, geo/bot attribution, and per-IP limits. Invalid
//! configuration fails `ferrum-edge validate` and fails startup before any
//! listener binds; nothing installs a partially parsed trust set.
//!
//! When unset (empty), XFF headers are **ignored** and the socket IP is always
//! used — which is the secure default for edge deployments.

use crate::util::cidr::CidrSet;
use std::net::IpAddr;
use tracing::debug;

/// A parsed set of trusted proxy CIDRs for efficient IP matching.
///
/// A thin wrapper over the shared [`CidrSet`](crate::util::cidr::CidrSet)
/// primitive, so trusted-proxy matching and the backend egress allow/deny
/// lists share one implementation and cannot drift.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    cidrs: CidrSet,
}

impl TrustedProxies {
    /// Parse a comma-separated list of CIDRs/IPs, failing if **any** entry is
    /// invalid or empty.
    ///
    /// Accepts formats like `10.0.0.0/8`, `192.168.1.1`, `::1`, `fd00::/8`, and
    /// `::ffff:10.0.0.0/104`; whitespace around entries is trimmed. A wholly
    /// empty (or whitespace-only) input is the valid "no entries" configuration.
    /// Malformed prefixes, junk entries, and empty/trailing/doubled comma
    /// segments are errors — a partially parsed set is never returned, because
    /// silently dropping one entry moves a security boundary.
    ///
    /// This is the only parser for **every** IP trust boundary in the gateway
    /// (forwarding trust, admin allowlist, metrics allowlist), so `boundary`
    /// names the configuration variable in the startup log line instead of the
    /// wording being specific to any one caller.
    pub fn parse_strict(raw: &str, boundary: &str) -> Result<Self, String> {
        let cidrs = CidrSet::parse_strict(raw)?;
        if !cidrs.is_empty() {
            tracing::info!("Configured {} CIDR/IP entries for {boundary}", cidrs.len());
        }
        Ok(Self { cidrs })
    }

    /// Returns an empty set (forwarded client metadata will be ignored).
    #[allow(dead_code)] // Used by tests
    pub fn none() -> Self {
        Self {
            cidrs: CidrSet::default(),
        }
    }

    /// Returns the number of configured CIDR entries.
    #[allow(dead_code)] // Used by tests
    pub fn len(&self) -> usize {
        self.cidrs.len()
    }

    /// Returns true if no trusted proxies are configured.
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// Check whether the given IP belongs to any trusted proxy CIDR.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.cidrs.contains(ip)
    }

    /// Whether a comma-separated CIDR/IP list permits **every** source address
    /// of some family — a literal `/0` or a union spanning the whole family
    /// (e.g. `0.0.0.0/1,128.0.0.0/1`). Such an allowlist makes the XFF
    /// trusted-proxy filter match every source, so it provides no real
    /// restriction. Delegates to the shared `CidrSet` so the canonicalization
    /// matches the runtime filter; side-effect free, safe for config
    /// classification at startup.
    pub fn cidr_list_permits_all(raw: &str) -> bool {
        crate::util::cidr::CidrSet::parse_lenient(raw)
            .0
            .permits_all_family()
    }
}

/// Return the original HTTP-family client-facing scheme reported through a
/// trusted proxy chain.
///
/// A singleton `X-Forwarded-Proto` value is the overwrite-only contract: the
/// directly connected trusted proxy vouches for that original scheme. A
/// multi-value list is accepted only when it has the same cardinality as the
/// `X-Forwarded-For` list. Its scheme is selected at the first untrusted XFF
/// entry found after walking the validated trusted suffix from right to left,
/// so safely appended chains preserve the browser-facing value instead of the
/// nearest hop's value. Malformed or misaligned trusted suffixes return `None`.
/// Callers must never use this result for an untrusted socket peer because the
/// headers may then be client-controlled.
pub fn trusted_forwarded_request_scheme<'a, 'b>(
    socket_addr: &IpAddr,
    forwarded_for_values: impl IntoIterator<Item = &'a [u8]>,
    forwarded_proto_values: impl IntoIterator<Item = &'b [u8]>,
    trusted_proxies: &TrustedProxies,
) -> Option<&'static str> {
    if !trusted_proxies.contains(socket_addr) {
        return None;
    }

    // Track the rightmost non-trusted XFF entry without allocating a temporary
    // vector. Any malformed entry clears the candidate; a later untrusted
    // entry restores it because that later entry is the boundary reached first
    // by the canonical right-to-left trust walk.
    let mut forwarded_for_count = 0usize;
    let mut client_boundary = None;
    for value in forwarded_for_values {
        for entry in value.split(|byte| *byte == b',') {
            let index = forwarded_for_count;
            forwarded_for_count += 1;
            let entry = trim_header_ows(entry);
            client_boundary = match std::str::from_utf8(entry)
                .ok()
                .and_then(|entry| entry.parse::<IpAddr>().ok())
            {
                Some(ip) if trusted_proxies.contains(&ip) => client_boundary,
                Some(_) => Some(index),
                None => None,
            };
        }
    }

    let mut forwarded_proto_count = 0usize;
    let mut singleton_proto = None;
    let mut boundary_proto = None;
    let mut trusted_proto_suffix_valid = true;
    for value in forwarded_proto_values {
        for proto in value.split(|byte| *byte == b',') {
            let index = forwarded_proto_count;
            forwarded_proto_count += 1;
            let proto = recognized_forwarded_proto(trim_header_ows(proto));
            if index == 0 {
                singleton_proto = proto;
            }
            if client_boundary.is_some_and(|boundary| index >= boundary) && proto.is_none() {
                trusted_proto_suffix_valid = false;
            }
            if client_boundary == Some(index) {
                boundary_proto = proto;
            }
        }
    }

    if forwarded_proto_count == 1 {
        return singleton_proto;
    }
    if forwarded_proto_count == forwarded_for_count && trusted_proto_suffix_valid {
        boundary_proto
    } else {
        None
    }
}

fn recognized_forwarded_proto(value: &[u8]) -> Option<&'static str> {
    match value {
        proto if proto.eq_ignore_ascii_case(b"http") => Some("http"),
        proto if proto.eq_ignore_ascii_case(b"https") => Some("https"),
        _ => None,
    }
}

fn trim_header_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

/// Resolve the real client IP from the request context.
///
/// When trusted proxies are configured and the request contains an
/// `X-Forwarded-For` header, walks the XFF chain right-to-left, skipping
/// trusted proxy IPs, and returns the first untrusted IP.
/// IPv4-mapped IPv6 results are canonicalized to native IPv4 before the value
/// enters request accounting or plugin execution.
///
/// When no trusted proxies are configured, returns the canonical socket IP.
///
/// The `socket_addr` variant accepts a pre-parsed `IpAddr` to avoid redundant
/// parsing on the hot path when the caller already has a parsed IP.
#[allow(dead_code)] // Used by external test crates via public API
pub fn resolve_client_ip(
    socket_ip: &str,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> String {
    // Parse the socket IP once; if unparseable, return it as-is
    let socket_addr: IpAddr = match socket_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return socket_ip.to_string(),
    };

    // Fast path: no trusted proxies configured — always use socket IP.
    if trusted_proxies.is_empty() {
        return socket_addr.to_canonical().to_string();
    }

    resolve_client_ip_parsed(socket_ip, &socket_addr, xff_header, trusted_proxies)
}

/// Like `resolve_client_ip` but accepts a pre-parsed `IpAddr` so callers on
/// the hot path avoid parsing the socket IP string twice. The returned text is
/// canonicalized before it becomes the request client identity.
pub fn resolve_client_ip_parsed(
    socket_ip: &str,
    socket_addr: &IpAddr,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> String {
    // No XFF header — use socket IP
    let xff = match xff_header {
        Some(h) if !h.trim().is_empty() => h,
        _ => return socket_addr.to_canonical().to_string(),
    };

    // If the direct connection is NOT from a trusted proxy, the XFF header
    // could be entirely attacker-controlled — ignore it.
    if !trusted_proxies.contains(socket_addr) {
        debug!(
            socket_ip = socket_ip,
            "Direct connection not from trusted proxy; ignoring X-Forwarded-For"
        );
        return socket_addr.to_canonical().to_string();
    }

    // Walk XFF entries right-to-left without collecting into a Vec.
    // rsplit(',') yields entries from right to left directly.
    for entry in xff.rsplit(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.parse::<IpAddr>() {
            Ok(ip) => {
                if !trusted_proxies.contains(&ip) {
                    // First untrusted IP = real client
                    return ip.to_canonical().to_string();
                }
                // This is a trusted proxy, keep walking left
            }
            Err(_) => {
                // Unparseable entry after the trusted suffix — stop the walk.
                // Entries to the left are MORE attacker-controlled; continuing
                // would let a spoofed IP feed ACLs, rate limits, and logs.
                // Fail closed: fall through to the socket address below.
                debug!(
                    entry = entry,
                    "Malformed X-Forwarded-For entry after trusted suffix; \
                     falling back to socket address"
                );
                break;
            }
        }
    }

    // All XFF entries were trusted proxies — fall back to socket IP
    socket_addr.to_canonical().to_string()
}

/// Outcome of evaluating every field-line of the configured real-IP header.
///
/// The three states are deliberately distinct: only [`Self::Absent`] may fall
/// through to the `X-Forwarded-For` walk. [`Self::Rejected`] means the operator
/// named an authoritative header and the request's copy of it could not be
/// trusted, so the direct socket identity stands and no weaker forwarded source
/// is consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealIpHeaderOutcome {
    /// The header carried no field-line at all (or no header is configured).
    Absent,
    /// Exactly one field-line held exactly one valid, canonicalized address.
    Accepted(String),
    /// Field-lines were present but not a single unambiguous trusted value.
    Rejected,
}

/// Resolve a configured single-hop real-IP header from a trusted direct proxy.
///
/// Unlike `X-Forwarded-For`, configured headers such as `CF-Connecting-IP` or
/// `X-Real-IP` are the direct proxy's overwrite-only assertion of exactly one
/// client address, so `field_lines` must yield exactly one value holding
/// exactly one IP. The AWS `CloudFront-Viewer-Address` form (`ip:source-port`)
/// is also accepted, with the source port discarded.
///
/// Every other shape is [`RealIpHeaderOutcome::Rejected`]:
///
/// * **Duplicate field-lines**, identical or differing, in either order — a
///   proxy that preserves a client-supplied copy and appends its own leaves the
///   authoritative value ambiguous, so neither line is used.
/// * **Non-UTF-8 bytes**, which must be counted rather than silently skipped.
/// * **Comma-separated chains**, empty values, and unparseable text.
/// * **Any value at all from an untrusted direct peer**, where the header is
///   entirely client-controlled.
///
/// Rejection is logged at `debug` (not `warn`) because a remote client can
/// trigger it on every request through a preserve-and-append proxy; an
/// unconditional per-request warning would be a log-flood surface.
pub fn resolve_real_ip_header_field_lines<'a>(
    socket_ip: &str,
    socket_addr: &IpAddr,
    field_lines: impl IntoIterator<Item = &'a [u8]>,
    trusted_proxies: &TrustedProxies,
) -> RealIpHeaderOutcome {
    let mut field_lines = field_lines.into_iter();
    let Some(first) = field_lines.next() else {
        return RealIpHeaderOutcome::Absent;
    };

    // Trust is checked before the value is parsed or logged: from an untrusted
    // peer the bytes are attacker text, not a proxy assertion.
    if !trusted_proxies.contains(socket_addr) {
        debug!(
            socket_ip = socket_ip,
            "Direct connection not from trusted proxy; ignoring configured real-IP header"
        );
        return RealIpHeaderOutcome::Rejected;
    }

    if field_lines.next().is_some() {
        debug!(
            socket_ip = socket_ip,
            "Configured real-IP header arrived as multiple field-lines; \
             the authoritative client address is ambiguous, keeping the socket address"
        );
        return RealIpHeaderOutcome::Rejected;
    }

    match parse_single_real_ip_field_line(first) {
        Some(ip) => RealIpHeaderOutcome::Accepted(ip.to_canonical().to_string()),
        None => {
            debug!(
                socket_ip = socket_ip,
                "Configured real-IP header was not a single parseable IP address or IP:port value"
            );
            RealIpHeaderOutcome::Rejected
        }
    }
}

/// Parse one real-IP field-line. `None` for non-UTF-8 bytes, an empty value, a
/// comma-separated chain, or text that is neither an IP nor an `ip:port`.
fn parse_single_real_ip_field_line(field_line: &[u8]) -> Option<IpAddr> {
    let value = std::str::from_utf8(field_line).ok()?.trim();
    if value.is_empty() || value.contains(',') {
        return None;
    }
    parse_single_real_ip_value(value)
}

fn parse_single_real_ip_value(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))
}

/// Resolve client IP from the request's forwarded metadata.
///
/// `real_ip_field_lines` yields every field-line of the configured real-IP
/// header (an empty iterator when no header is configured). When it yields at
/// least one line, that single-hop header is the only forwarded source
/// considered: an accepted value wins, and a rejected one returns `None` so
/// callers keep the socket IP rather than falling through to XFF. Only a wholly
/// absent header falls back to the XFF walk.
pub fn resolve_forwarded_client_ip<'a>(
    socket_ip: &str,
    socket_addr: &IpAddr,
    real_ip_field_lines: impl IntoIterator<Item = &'a [u8]>,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    if trusted_proxies.is_empty() {
        return None;
    }

    match resolve_real_ip_header_field_lines(
        socket_ip,
        socket_addr,
        real_ip_field_lines,
        trusted_proxies,
    ) {
        RealIpHeaderOutcome::Accepted(ip) => return Some(ip),
        RealIpHeaderOutcome::Rejected => return None,
        RealIpHeaderOutcome::Absent => {}
    }

    let resolved = resolve_client_ip_parsed(socket_ip, socket_addr, xff_header, trusted_proxies);
    if resolved == socket_ip {
        None
    } else {
        Some(resolved)
    }
}
