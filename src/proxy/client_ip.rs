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
//! 3. The first non-trusted entry is the real client IP.
//! 4. If all entries are trusted (or XFF is absent/empty), fall back to the
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

    fn parse_cidr(entry: &str) -> Option<CidrEntry> {
        if let Some((ip_str, prefix_str)) = entry.split_once('/') {
            let ip: IpAddr = ip_str.parse().ok()?;
            let prefix_len: u8 = prefix_str.parse().ok()?;
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

impl CidrEntry {
    fn matches(&self, ip: &IpAddr) -> bool {
        match (&self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_bits = u32::from(*net);
                let addr_bits = u32::from(*addr);
                let mask = u32::MAX
                    .checked_shl(32 - self.prefix_len as u32)
                    .unwrap_or(0);
                (net_bits & mask) == (addr_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_bits = u128::from(*net);
                let addr_bits = u128::from(*addr);
                let mask = u128::MAX
                    .checked_shl(128 - self.prefix_len as u32)
                    .unwrap_or(0);
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false, // v4 vs v6 mismatch
        }
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
                // Unparseable entry — treat as the client IP (conservative).
                // An attacker could have inserted garbage, but stopping here
                // is safer than skipping to an earlier (more attacker-controlled)
                // entry.
                debug!(
                    entry = entry,
                    "Unparseable X-Forwarded-For entry; treating as client IP"
                );
                return entry.to_string();
            }
        }
    }

    // All XFF entries were trusted proxies — fall back to socket IP
    socket_ip.to_string()
}
