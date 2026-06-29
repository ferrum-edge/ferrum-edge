//! Client IP extraction with trusted proxy support.
//!
//! When the gateway sits behind load balancers, CDNs, or reverse proxies, the
//! TCP socket address (`remote_addr`) is the proxy's IP — not the real client's.
//! This module resolves the true originating client IP by walking the
//! `X-Forwarded-For` (XFF) chain from right to left, stripping entries that
//! belong to trusted proxies.
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
//! # Configuration
//!
//! Set `FERRUM_TRUSTED_PROXIES` to a comma-separated list of CIDRs and/or IPs:
//!
//! ```text
//! FERRUM_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1
//! ```
//!
//! When unset (empty), XFF headers are **ignored** and the socket IP is always
//! used — which is the secure default for edge deployments.

use std::net::IpAddr;
use tracing::debug;

/// A parsed set of trusted proxy CIDRs for efficient IP matching.
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    cidrs: Vec<CidrEntry>,
}

#[derive(Debug, Clone)]
struct CidrEntry {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedProxies {
    /// Parse a comma-separated list of CIDRs/IPs into a `TrustedProxies` set.
    ///
    /// Accepts formats like: `10.0.0.0/8`, `192.168.1.1`, `::1`, `fd00::/8`
    /// Whitespace around entries is trimmed. Invalid entries are logged and skipped.
    pub fn parse(raw: &str) -> Self {
        let mut cidrs = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some(cidr) = Self::parse_cidr(entry) {
                cidrs.push(cidr);
            } else {
                tracing::warn!(
                    "Ignoring invalid trusted proxy entry: {:?}. Expected IP or CIDR notation.",
                    entry
                );
            }
        }
        if !cidrs.is_empty() {
            tracing::info!(
                "Configured {} trusted proxy CIDR(s) for X-Forwarded-For resolution",
                cidrs.len()
            );
        }
        Self { cidrs }
    }

    /// Parse a comma-separated list of CIDRs/IPs, failing if any entry is invalid.
    ///
    /// Unlike `parse()` which skips invalid entries, this method returns an error
    /// if the input is non-empty but produces zero valid CIDRs. Used for security-
    /// critical allowlists (e.g., admin API) where a typo must not silently fail open.
    pub fn parse_strict(raw: &str) -> Result<Self, String> {
        if raw.trim().is_empty() {
            return Ok(Self { cidrs: Vec::new() });
        }
        let mut cidrs = Vec::new();
        let mut invalid = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                invalid.push("<empty>".to_string());
                continue;
            }
            if let Some(cidr) = Self::parse_cidr(entry) {
                cidrs.push(cidr);
            } else {
                invalid.push(entry.to_string());
            }
        }
        if !invalid.is_empty() {
            return Err(format!(
                "Invalid CIDR/IP entries: {}. Expected formats: 10.0.0.0/8, 192.168.1.1, ::1",
                invalid.join(", ")
            ));
        }
        if !cidrs.is_empty() {
            tracing::info!("Configured {} admin allowed CIDR(s)", cidrs.len());
        }
        Ok(Self { cidrs })
    }

    /// Returns an empty set (no trusted proxies — XFF headers will be ignored).
    #[allow(dead_code)] // Used by tests
    pub fn none() -> Self {
        Self { cidrs: Vec::new() }
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
        self.cidrs.iter().any(|cidr| cidr.matches(ip))
    }

    /// Whether a comma-separated CIDR/IP list permits **every** source address
    /// of some family — i.e. the entries together cover all of IPv4 or all of
    /// IPv6. This catches both a literal `/0` (`0.0.0.0/0`, `::/0`, or an
    /// IPv4-mapped spelling like `::ffff:0.0.0.0/96` the parser folds to an IPv4
    /// `/0`) AND a UNION that covers the whole space with no single `/0` entry
    /// (e.g. `0.0.0.0/1,128.0.0.0/1`). Such an allowlist makes the filter match
    /// every source, so it provides no real restriction.
    ///
    /// Reuses the same `parse_cidr` canonicalization as the runtime filter (so
    /// mapped-IPv6 spellings cannot slip past) and is side-effect free (no
    /// logging) — safe to call from config classification at startup.
    pub fn cidr_list_permits_all(raw: &str) -> bool {
        let mut v4: Vec<(u128, u128)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some(cidr) = Self::parse_cidr(entry) else {
                continue;
            };
            match cidr.network {
                IpAddr::V4(net) => {
                    // prefix ∈ [0,32]; `32 - prefix` ∈ [0,32] shifts safely in u128.
                    let prefix = u32::from(cidr.prefix_len).min(32);
                    let host = (1u128 << (32 - prefix)) - 1;
                    let start = u128::from(u32::from(net)) & !host;
                    v4.push((start, start | host));
                }
                IpAddr::V6(net) => {
                    let prefix = u32::from(cidr.prefix_len).min(128);
                    let (start, end) = if prefix == 0 {
                        (0u128, u128::MAX) // avoid the UB of shifting a u128 by 128
                    } else {
                        let host = (1u128 << (128 - prefix)) - 1;
                        let start = u128::from(net) & !host;
                        (start, start | host)
                    };
                    v6.push((start, end));
                }
            }
        }
        ranges_cover_full(&mut v4, u128::from(u32::MAX)) || ranges_cover_full(&mut v6, u128::MAX)
    }

    fn parse_cidr(entry: &str) -> Option<CidrEntry> {
        if let Some((ip_str, prefix_str)) = entry.split_once('/') {
            let ip: IpAddr = ip_str.parse().ok()?;
            let prefix_len: u8 = prefix_str.parse().ok()?;
            let (ip, prefix_len) = canonicalize_cidr_network(ip, prefix_len)?;
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix_len > max_prefix {
                return None;
            }
            Some(CidrEntry {
                network: ip,
                prefix_len,
            })
        } else {
            // Bare IP — treat as /32 or /128
            let ip: IpAddr = entry.parse().ok()?;
            let ip = canonicalize_ip(ip);
            let prefix_len = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(CidrEntry {
                network: ip,
                prefix_len,
            })
        }
    }
}

/// Whether the inclusive `[start, end]` ranges cover the entire `[0, max]`
/// interval once sorted and merged. Used by `cidr_list_permits_all` to detect a
/// CIDR allowlist whose union admits every address of a family. `max` is
/// `u32::MAX` for the IPv4 set and `u128::MAX` for the IPv6 set (IPv4 ranges are
/// widened to `u128` for a single implementation).
fn ranges_cover_full(ranges: &mut [(u128, u128)], max: u128) -> bool {
    if ranges.is_empty() {
        return false;
    }
    ranges.sort_unstable();
    // Coverage must begin at 0; otherwise the low addresses are unprotected.
    if ranges[0].0 != 0 {
        return false;
    }
    let mut covered = ranges[0].1;
    for &(start, end) in ranges.iter().skip(1) {
        if covered >= max {
            return true;
        }
        // A gap exists if the next range starts beyond the next uncovered
        // address (`covered + 1`). `saturating_add` avoids overflow at u128::MAX.
        if start > covered.saturating_add(1) {
            return false;
        }
        if end > covered {
            covered = end;
        }
    }
    covered >= max
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

fn canonicalize_cidr_network(ip: IpAddr, prefix_len: u8) -> Option<(IpAddr, u8)> {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                if prefix_len < 96 {
                    return None;
                }
                Some((IpAddr::V4(v4), prefix_len - 96))
            } else {
                Some((IpAddr::V6(v6), prefix_len))
            }
        }
        other => Some((other, prefix_len)),
    }
}

impl CidrEntry {
    fn matches(&self, ip: &IpAddr) -> bool {
        match (&self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => matches_ipv4(*net, *addr, self.prefix_len),
            (IpAddr::V4(net), IpAddr::V6(addr)) => {
                if let Some(v4) = addr.to_ipv4_mapped() {
                    matches_ipv4(*net, v4, self.prefix_len)
                } else {
                    false
                }
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => matches_ipv6(*net, *addr, self.prefix_len),
            _ => false, // v4 vs v6 mismatch
        }
    }
}

fn matches_ipv4(network: std::net::Ipv4Addr, addr: std::net::Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let net_bits = u32::from(network);
    let addr_bits = u32::from(addr);
    let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
    (net_bits & mask) == (addr_bits & mask)
}

fn matches_ipv6(network: std::net::Ipv6Addr, addr: std::net::Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let net_bits = u128::from(network);
    let addr_bits = u128::from(addr);
    let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
    (net_bits & mask) == (addr_bits & mask)
}

/// Resolve the real client IP from the request context.
///
/// When trusted proxies are configured and the request contains an
/// `X-Forwarded-For` header, walks the XFF chain right-to-left, skipping
/// trusted proxy IPs, and returns the first untrusted IP.
///
/// When no trusted proxies are configured, returns the socket IP unchanged.
///
/// The `socket_addr` variant accepts a pre-parsed `IpAddr` to avoid redundant
/// parsing on the hot path when the caller already has a parsed IP.
#[allow(dead_code)] // Used by external test crates via public API
pub fn resolve_client_ip(
    socket_ip: &str,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> String {
    // Fast path: no trusted proxies configured — always use socket IP
    if trusted_proxies.is_empty() {
        return socket_ip.to_string();
    }

    // Parse the socket IP once; if unparseable, return it as-is
    let socket_addr: IpAddr = match socket_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return socket_ip.to_string(),
    };

    resolve_client_ip_parsed(socket_ip, &socket_addr, xff_header, trusted_proxies)
}

/// Like `resolve_client_ip` but accepts a pre-parsed `IpAddr` so callers on
/// the hot path avoid parsing the socket IP string twice.
pub fn resolve_client_ip_parsed(
    socket_ip: &str,
    socket_addr: &IpAddr,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> String {
    // No XFF header — use socket IP
    let xff = match xff_header {
        Some(h) if !h.trim().is_empty() => h,
        _ => return socket_ip.to_string(),
    };

    // If the direct connection is NOT from a trusted proxy, the XFF header
    // could be entirely attacker-controlled — ignore it.
    if !trusted_proxies.contains(socket_addr) {
        debug!(
            socket_ip = socket_ip,
            "Direct connection not from trusted proxy; ignoring X-Forwarded-For"
        );
        return socket_ip.to_string();
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
                    return ip.to_string();
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
    socket_ip.to_string()
}

/// Resolve a configured single-hop real-IP header from a trusted direct proxy.
///
/// Unlike `X-Forwarded-For`, configured headers such as `CF-Connecting-IP` or
/// `X-Real-IP` are expected to contain exactly one IP address. The AWS
/// `CloudFront-Viewer-Address` form (`ip:source-port`) is also accepted.
/// Comma-separated chains or malformed values are ignored so client-controlled
/// header text cannot feed ACLs, rate limits, or logs.
pub fn resolve_real_ip_header(
    socket_ip: &str,
    socket_addr: &IpAddr,
    header_value: &str,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    if !trusted_proxies.contains(socket_addr) {
        debug!(
            socket_ip = socket_ip,
            "Direct connection not from trusted proxy; ignoring configured real-IP header"
        );
        return None;
    }

    let value = header_value.trim();
    if value.is_empty() || value.contains(',') {
        debug!(
            value = value,
            "Configured real-IP header must contain a single IP address or IP:port value"
        );
        return None;
    }

    match parse_single_real_ip_value(value) {
        Ok(ip) => Some(ip.to_string()),
        Err(_) => {
            debug!(
                value = value,
                "Configured real-IP header was not a parseable IP address or IP:port value"
            );
            None
        }
    }
}

fn parse_single_real_ip_value(value: &str) -> Result<IpAddr, std::net::AddrParseError> {
    value
        .parse::<IpAddr>()
        .or_else(|_| value.parse::<std::net::SocketAddr>().map(|addr| addr.ip()))
}

/// Resolve client IP when a caller has already performed targeted header
/// lookups from the request.
///
/// If a configured real-IP header is present, that single-hop header is the
/// only forwarded source considered. Rejected real-IP values return `None` so
/// callers keep the socket IP rather than falling through to XFF. When the
/// configured real-IP header is absent, this falls back to the XFF walk.
pub fn resolve_forwarded_client_ip(
    socket_ip: &str,
    socket_addr: &IpAddr,
    real_ip_header_value: Option<&str>,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    if trusted_proxies.is_empty() {
        return None;
    }

    if let Some(value) = real_ip_header_value {
        return resolve_real_ip_header(socket_ip, socket_addr, value, trusted_proxies);
    }

    let resolved = resolve_client_ip_parsed(socket_ip, socket_addr, xff_header, trusted_proxies);
    if resolved == socket_ip {
        None
    } else {
        Some(resolved)
    }
}
