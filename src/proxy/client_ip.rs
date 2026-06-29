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
    /// Parse a comma-separated list of CIDRs/IPs into a `TrustedProxies` set.
    ///
    /// Accepts formats like: `10.0.0.0/8`, `192.168.1.1`, `::1`, `fd00::/8`
    /// Whitespace around entries is trimmed. Invalid entries are logged and skipped.
    pub fn parse(raw: &str) -> Self {
        let (cidrs, invalid) = CidrSet::parse_lenient(raw);
        for entry in &invalid {
            tracing::warn!(
                "Ignoring invalid trusted proxy entry: {:?}. Expected IP or CIDR notation.",
                entry
            );
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
        let cidrs = CidrSet::parse_strict(raw)?;
        if !cidrs.is_empty() {
            tracing::info!("Configured {} admin allowed CIDR(s)", cidrs.len());
        }
        Ok(Self { cidrs })
    }

    /// Returns an empty set (no trusted proxies — XFF headers will be ignored).
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
