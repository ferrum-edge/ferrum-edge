//! Canonical client-identity helpers (advisory GHSA-vjwj-657f-5w9g).
//!
//! Ferrum treats a client's network address as **one** security principal
//! regardless of how the accepting socket happened to represent it. A
//! dual-stack (`[::]`) listener reports an IPv4 peer as the IPv4-mapped IPv6
//! form `::ffff:a.b.c.d`, and trusted forwarding metadata — `X-Forwarded-For`,
//! a configured real-IP header, a PROXY v2 `AF_INET6` address block, mesh
//! capture metadata — can carry the same shape for a host that also connects
//! natively over IPv4.
//!
//! Left unfolded, `192.0.2.10` and `::ffff:192.0.2.10` become two principals:
//! two per-IP connection/datagram/byte budgets, two log and metric label
//! values, two IP-restriction evaluations, and a GeoIP query that searches the
//! MaxMind IPv6 tree (or is rejected outright by an IPv4-only database)
//! instead of reaching the IPv4 country record. With the default
//! `on_lookup_failure: allow`, that last case silently admits traffic a
//! country deny policy would otherwise reject.
//!
//! Every ingress and metadata-restoration boundary therefore folds the address
//! through [`canonical_ip`] exactly once, *before* the value reaches a plugin,
//! rate-limit key, log line, metric label, or GeoIP lookup. Downstream
//! consumers receive an already-canonical value and must not re-derive one.
//!
//! # What is *not* folded
//!
//! * **True IPv6 semantics are preserved.** Only the `::ffff:0:0/96` mapped
//!   range denotes the same host as its embedded IPv4 address. Deprecated
//!   IPv4-*compatible* addresses (`::a.b.c.d`) and NAT64 translation prefixes
//!   (`64:ff9b::/96`) are distinct network identities and stay IPv6 — this is
//!   exactly `IpAddr::to_canonical`'s contract, which unmaps via
//!   `Ipv6Addr::to_ipv4_mapped` and nothing else.
//! * **Transport addresses used to send.** UDP reply destinations and DTLS
//!   demux keys must keep the address family the receiving socket produced, so
//!   a reply socket built from an `AF_INET` original destination is not handed
//!   an `AF_INET6` peer (and vice versa). Those paths canonicalize the
//!   *identity* they publish while keeping the raw `SocketAddr` they send to.
//!   [`canonical_socket_addr`] exists for the capture paths that deliberately
//!   canonicalize both together, and documents that choice at the call site.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its embedded IPv4
/// form. Native IPv4 and genuine IPv6 addresses are returned unchanged.
///
/// This is the single definition of Ferrum's client-identity equivalence; every
/// other helper in this module is expressed in terms of it.
#[inline]
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// [`canonical_ip`] applied to a socket address, preserving the port.
///
/// Use this only where the *transport* address is intentionally canonicalized
/// as well as the identity — notably the mesh UDP capture path, where the
/// per-datagram original destination recovered from `cmsg` is `AF_INET` and the
/// reply socket must agree with the client's family.
#[inline]
pub fn canonical_socket_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

/// Render a canonical client identity. One allocation, no intermediate parse.
///
/// IPv4 is rendered by hand: it runs once per request, and `core::fmt`'s
/// `Ipv4Addr` path cost about 0.5% of gateway CPU on the gRPC benchmark (issue
/// #5588). The output is byte-identical to `Ipv4Addr`'s `Display`.
#[inline]
pub fn canonical_ip_string(ip: IpAddr) -> String {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => ipv4_string(v4),
        v6 => v6.to_string(),
    }
}

/// Render an IP address for a per-client quota key, folding IPv6 addresses to
/// the configured network prefix while keeping IPv4 host keys unchanged.
pub fn rate_limit_ip_string(ip: IpAddr, ipv6_prefix: u8) -> String {
    match canonical_ip(ip) {
        IpAddr::V4(ip) => ipv4_string(ip),
        IpAddr::V6(ip) => {
            let prefix = ipv6_prefix.min(128);
            let mut octets = ip.octets();
            let whole_bytes = usize::from(prefix / 8);
            let remaining_bits = prefix % 8;
            if remaining_bits != 0 {
                octets[whole_bytes] &= u8::MAX << (8 - remaining_bits);
            }
            let zero_from = if remaining_bits == 0 {
                whole_bytes
            } else {
                whole_bytes + 1
            };
            octets[zero_from..].fill(0);
            Ipv6Addr::from(octets).to_string()
        }
    }
}

/// Parse and render a source address for a per-client quota key.
pub fn rate_limit_client_ip_string(client_ip: &str, ipv6_prefix: u8) -> Option<String> {
    parse_canonical_client_ip(client_ip).map(|ip| rate_limit_ip_string(ip, ipv6_prefix))
}

fn ipv4_string(ip: Ipv4Addr) -> String {
    let mut out = String::with_capacity(15);
    for (index, octet) in ip.octets().into_iter().enumerate() {
        if index > 0 {
            out.push('.');
        }
        if octet >= 100 {
            out.push(char::from(b'0' + octet / 100));
        }
        if octet >= 10 {
            out.push(char::from(b'0' + octet / 10 % 10));
        }
        out.push(char::from(b'0' + octet % 10));
    }
    out
}

/// Render a canonical client identity into the shared `Arc<str>` form used by
/// per-connection and per-datagram hot paths, so downstream clones are refcount
/// bumps rather than allocations.
#[inline]
pub fn canonical_ip_arc(ip: IpAddr) -> Arc<str> {
    Arc::from(canonical_ip_string(ip))
}

/// Parse the client/rule literal forms Ferrum's IP policy grammar accepts,
/// without allocating.
///
/// IPv4 uses the standard library's strict literal grammar. Brackets and zone
/// identifiers remain IPv6-only; accepting them on IPv4 would broaden the
/// established policy grammar.
pub fn parse_client_ip_literal(client_ip: &str) -> Option<IpAddr> {
    if let Ok(ipv4) = client_ip.parse() {
        return Some(IpAddr::V4(ipv4));
    }

    let unbracketed = client_ip
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(client_ip);
    let without_zone = unbracketed
        .find('%')
        .map_or(unbracketed, |index| &unbracketed[..index]);
    without_zone.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// Parse a client-identity string into its canonical typed address.
///
/// `None` for anything that is not an address literal (an authenticated
/// consumer identity, a malformed value). Callers that gate policy on this must
/// treat `None` as "no typed identity" and fail closed according to their own
/// configured policy — never as "allow".
pub fn parse_canonical_client_ip(client_ip: &str) -> Option<IpAddr> {
    parse_client_ip_literal(client_ip).map(canonical_ip)
}

/// Canonical text form of a client-identity string, borrowing when the input is
/// already canonical.
///
/// Gateway-produced identities are canonical at ingress, so the common path is
/// a single `memchr` for `':'` and a borrow — no parse and no allocation.
/// Non-address identities (consumer usernames) are returned untouched, which
/// keeps identity-keyed maps stable for authenticated principals.
pub fn canonical_client_ip_text(client_ip: &str) -> Cow<'_, str> {
    // Every IPv4-mapped form contains ':'. Native IPv4 — the overwhelmingly
    // common case on a dual-stack listener after ingress canonicalization —
    // never does, so it never reaches the parser.
    if !client_ip.contains(':') {
        return Cow::Borrowed(client_ip);
    }
    match parse_client_ip_literal(client_ip) {
        Some(IpAddr::V6(ipv6)) => match ipv6.to_ipv4_mapped() {
            Some(ipv4) => Cow::Owned(ipv4.to_string()),
            None => Cow::Borrowed(client_ip),
        },
        _ => Cow::Borrowed(client_ip),
    }
}
