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
    #[cfg(test)]
    pub fn none() -> Self {
        Self { cidrs: Vec::new() }
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
pub fn resolve_client_ip(
    socket_ip: &str,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> String {
    // Fast path: no trusted proxies configured — always use socket IP
    if trusted_proxies.is_empty() {
        return socket_ip.to_string();
    }

    // No XFF header — use socket IP
    let xff = match xff_header {
        Some(h) if !h.trim().is_empty() => h,
        _ => return socket_ip.to_string(),
    };

    // Parse the socket IP; if unparseable, return it as-is
    let socket_addr: IpAddr = match socket_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return socket_ip.to_string(),
    };

    // If the direct connection is NOT from a trusted proxy, the XFF header
    // could be entirely attacker-controlled — ignore it.
    if !trusted_proxies.contains(&socket_addr) {
        debug!(
            socket_ip = socket_ip,
            "Direct connection not from trusted proxy; ignoring X-Forwarded-For"
        );
        return socket_ip.to_string();
    }

    // Parse XFF entries (comma-separated, left-to-right order)
    let entries: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();

    // Walk right-to-left, skip trusted proxies
    for entry in entries.iter().rev() {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── TrustedProxies parsing ───────────────────────────────────────────

    #[test]
    fn parse_empty_string_yields_no_proxies() {
        let tp = TrustedProxies::parse("");
        assert!(tp.is_empty());
    }

    #[test]
    fn parse_single_ipv4() {
        let tp = TrustedProxies::parse("10.0.0.1");
        assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!tp.contains(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn parse_ipv4_cidr() {
        let tp = TrustedProxies::parse("10.0.0.0/8");
        assert!(tp.contains(&"10.255.255.255".parse().unwrap()));
        assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!tp.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_multiple_cidrs_with_whitespace() {
        let tp = TrustedProxies::parse(" 10.0.0.0/8 , 172.16.0.0/12 , ::1 ");
        assert!(tp.contains(&"10.1.2.3".parse().unwrap()));
        assert!(tp.contains(&"172.16.5.1".parse().unwrap()));
        assert!(tp.contains(&"::1".parse().unwrap()));
        assert!(!tp.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let tp = TrustedProxies::parse("fd00::/8");
        assert!(tp.contains(&"fd12::1".parse().unwrap()));
        assert!(!tp.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn invalid_entries_are_skipped() {
        let tp = TrustedProxies::parse("10.0.0.1, not-an-ip, 192.168.1.0/24");
        assert_eq!(tp.cidrs.len(), 2);
        assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
        assert!(tp.contains(&"192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn invalid_prefix_length_is_skipped() {
        let tp = TrustedProxies::parse("10.0.0.0/33");
        assert!(tp.is_empty());
    }

    // ── resolve_client_ip ────────────────────────────────────────────────

    #[test]
    fn no_trusted_proxies_returns_socket_ip() {
        let tp = TrustedProxies::none();
        assert_eq!(
            resolve_client_ip("1.2.3.4", Some("5.6.7.8, 9.10.11.12"), &tp),
            "1.2.3.4"
        );
    }

    #[test]
    fn no_xff_header_returns_socket_ip() {
        let tp = TrustedProxies::parse("10.0.0.0/8");
        assert_eq!(resolve_client_ip("10.0.0.1", None, &tp), "10.0.0.1");
    }

    #[test]
    fn empty_xff_header_returns_socket_ip() {
        let tp = TrustedProxies::parse("10.0.0.0/8");
        assert_eq!(resolve_client_ip("10.0.0.1", Some(""), &tp), "10.0.0.1");
        assert_eq!(resolve_client_ip("10.0.0.1", Some("  "), &tp), "10.0.0.1");
    }

    #[test]
    fn socket_not_trusted_ignores_xff() {
        let tp = TrustedProxies::parse("10.0.0.0/8");
        // Socket IP 1.2.3.4 is NOT trusted, so XFF is ignored
        assert_eq!(
            resolve_client_ip("1.2.3.4", Some("5.6.7.8"), &tp),
            "1.2.3.4"
        );
    }

    #[test]
    fn single_xff_entry_behind_trusted_proxy() {
        let tp = TrustedProxies::parse("10.0.0.0/8");
        // Connection from 10.0.0.1 (trusted), XFF says real client is 203.0.113.50
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("203.0.113.50"), &tp),
            "203.0.113.50"
        );
    }

    #[test]
    fn multi_hop_xff_skips_trusted_proxies() {
        // Two trusted proxy hops: CDN (172.16.1.1) → LB (10.0.0.1)
        let tp = TrustedProxies::parse("10.0.0.0/8, 172.16.0.0/12");
        // XFF: "client, cdn_ingress" — socket is the LB
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("203.0.113.50, 172.16.1.1"), &tp),
            "203.0.113.50"
        );
    }

    #[test]
    fn attacker_prepended_ip_is_ignored() {
        let tp = TrustedProxies::parse("10.0.0.0/8");
        // Attacker sent X-Forwarded-For: 1.1.1.1 to make it look like Cloudflare
        // Real chain: "1.1.1.1, 203.0.113.50" — socket is 10.0.0.1
        // Walking right-to-left: 203.0.113.50 is NOT trusted → that's the client
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("1.1.1.1, 203.0.113.50"), &tp),
            "203.0.113.50"
        );
    }

    #[test]
    fn all_xff_entries_trusted_falls_back_to_socket() {
        let tp = TrustedProxies::parse("10.0.0.0/8, 172.16.0.0/12");
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("10.0.0.2, 172.16.0.1"), &tp),
            "10.0.0.1"
        );
    }

    #[test]
    fn unparseable_xff_entry_treated_as_client() {
        let tp = TrustedProxies::parse("10.0.0.0/8");
        // Garbage in XFF — stop at the unparseable entry
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("unknown, 203.0.113.50"), &tp),
            "203.0.113.50"
        );
    }

    #[test]
    fn ipv6_trusted_proxy_with_xff() {
        let tp = TrustedProxies::parse("::1, fd00::/8");
        assert_eq!(
            resolve_client_ip("::1", Some("2001:db8::1"), &tp),
            "2001:db8::1"
        );
    }

    #[test]
    fn real_world_cloudflare_pattern() {
        // Cloudflare IPs (subset) as trusted proxies
        let tp = TrustedProxies::parse("173.245.48.0/20, 103.21.244.0/22, 10.0.0.0/8");
        // Client → Cloudflare (173.245.49.1) → Internal LB (10.0.0.1) → Gateway
        // XFF: "198.51.100.23, 173.245.49.1"
        // Socket: 10.0.0.1
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("198.51.100.23, 173.245.49.1"), &tp),
            "198.51.100.23"
        );
    }
}
