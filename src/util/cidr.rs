//! A small, allocation-free CIDR set for operator-supplied IP allow/deny lists.
//!
//! Parses a comma-separated list of CIDRs and bare IPs (`10.0.0.0/8`,
//! `169.254.169.254/32`, `fc00::/7`, `::1`) once at config-load time into
//! pre-computed `(network, prefix)` entries, then answers `contains()` with
//! integer bit-masking — no per-call allocation or string work.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) match the equivalent IPv4
//! rule: rule networks are canonicalised to their embedded v4 form at parse
//! time, and a mapped *query* is compared against a v4 rule as its embedded v4
//! address. So a dual-stack socket that surfaces a mapped address cannot slip
//! past a v4 allow/deny rule. A mapped query is NOT folded into v6 rules — a
//! `::/0` rule still matches it (it is textually IPv6), but a v4 rule matches
//! it by its embedded address. This preserves the long-standing
//! `client_ip::TrustedProxies` matching behaviour.
//!
//! This is the single CIDR-matching primitive in the gateway:
//! `proxy::client_ip::TrustedProxies` (X-Forwarded-For trusted-proxy matching)
//! is a thin wrapper over [`CidrSet`], and the backend egress policy
//! (`BackendEgressPolicy`) uses it for its allow/deny lists — so allow/deny
//! and trusted-proxy matching cannot drift.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A parsed set of CIDRs / bare IPs for efficient membership testing.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    entries: Vec<CidrEntry>,
}

#[derive(Debug, Clone)]
struct CidrEntry {
    network: IpAddr,
    prefix_len: u8,
}

impl CidrSet {
    /// Parse a comma-separated list of CIDRs / bare IPs, failing if any
    /// non-empty entry is invalid.
    ///
    /// An empty or whitespace-only input yields an empty set (no entries).
    /// Used for security-critical allow/deny lists where a typo must surface
    /// loudly at startup rather than silently failing open (or closed).
    ///
    /// Accepted forms: `10.0.0.0/8`, `192.168.1.1` (bare IP → `/32`),
    /// `::1` (bare IP → `/128`), `fc00::/7`, `::ffff:10.0.0.0/104`.
    pub fn parse_strict(raw: &str) -> Result<Self, String> {
        // A wholly empty / whitespace-only list is a valid "no entries"
        // configuration. A list that contains a comma but an empty segment
        // (e.g. a trailing or doubled comma) is a typo and is rejected below.
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        let (entries, invalid) = Self::parse_entries(raw, true);
        if !invalid.is_empty() {
            return Err(format!(
                "Invalid CIDR/IP entries: {}. Expected formats: 10.0.0.0/8, 192.168.1.1, ::1, fc00::/7",
                invalid.join(", ")
            ));
        }
        Ok(Self { entries })
    }

    /// Parse like [`Self::parse_strict`] but skip invalid entries (including
    /// empty comma segments) instead of failing, returning the parsed set plus
    /// the list of rejected non-empty entry strings so the caller can decide
    /// how to surface them (e.g. log a warning per entry).
    ///
    /// **No IP trust boundary may be built from this.** Every enforcing
    /// allow/deny/trust list — forwarding trust, admin, metrics, backend egress
    /// — uses [`Self::parse_strict`], because retaining a partially parsed set
    /// silently moves the boundary a typo was meant to describe. This variant
    /// exists only for side-effect-free *classification* of a raw list (see
    /// `client_ip::TrustedProxies::cidr_list_permits_all`, which answers "would
    /// this list restrict anything?" for a startup exposure warning).
    pub fn parse_lenient(raw: &str) -> (Self, Vec<String>) {
        let (entries, invalid) = Self::parse_entries(raw, false);
        (Self { entries }, invalid)
    }

    /// Shared entry parser: returns `(valid entries, invalid entry strings)`.
    /// When `reject_empty` is set, an empty comma segment is reported as the
    /// `<empty>` marker (strict mode); otherwise it is silently skipped.
    fn parse_entries(raw: &str, reject_empty: bool) -> (Vec<CidrEntry>, Vec<String>) {
        let mut entries = Vec::new();
        let mut invalid = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                if reject_empty {
                    invalid.push("<empty>".to_string());
                }
                continue;
            }
            match Self::parse_entry(entry) {
                Some(cidr) => entries.push(cidr),
                None => invalid.push(entry.to_string()),
            }
        }
        (entries, invalid)
    }

    /// Returns true if no entries are configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of configured entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether `ip` falls within any configured CIDR.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.entries.iter().any(|entry| entry.matches(ip))
    }

    /// Whether these entries together cover **every** address of IPv4 or IPv6 —
    /// a literal `/0` (`0.0.0.0/0`, `::/0`, or an IPv4-mapped spelling like
    /// `::ffff:0.0.0.0/96` the parser folds to an IPv4 `/0`) OR a UNION that
    /// spans the whole family with no single `/0` entry (e.g.
    /// `0.0.0.0/1,128.0.0.0/1`). Such an allowlist imposes no real restriction.
    /// Entries are already canonicalized + masked at parse time, so the runtime
    /// filter and this check agree on mapped-IPv6 spellings.
    pub fn permits_all_family(&self) -> bool {
        let mut v4: Vec<(u128, u128)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        for entry in &self.entries {
            match entry.network {
                IpAddr::V4(net) => {
                    // prefix ∈ [0,32]; `32 - prefix` ∈ [0,32] shifts safely in u128.
                    let prefix = u32::from(entry.prefix_len).min(32);
                    let host = (1u128 << (32 - prefix)) - 1;
                    let start = u128::from(u32::from(net)) & !host;
                    v4.push((start, start | host));
                }
                IpAddr::V6(net) => {
                    let prefix = u32::from(entry.prefix_len).min(128);
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

    fn parse_entry(entry: &str) -> Option<CidrEntry> {
        if let Some((network_str, prefix_str)) = entry.split_once('/') {
            let ip: IpAddr = network_str.trim().parse().ok()?;
            let prefix_len: u8 = prefix_str.trim().parse().ok()?;
            let (network, prefix_len) = canonicalize_cidr_network(ip, prefix_len)?;
            let max_prefix = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix_len > max_prefix {
                return None;
            }
            Some(CidrEntry {
                network: mask_network(network, prefix_len),
                prefix_len,
            })
        } else {
            // Bare IP — treat as /32 (v4) or /128 (v6).
            let ip = canonicalize_ip(entry.trim().parse().ok()?);
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
/// interval once sorted and merged. Used by [`CidrSet::permits_all_family`] to
/// detect a CIDR allowlist whose union admits every address of a family. `max`
/// is `u32::MAX` for the IPv4 set and `u128::MAX` for the IPv6 set (IPv4 ranges
/// are widened to `u128` for a single implementation).
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

/// Collapse an IPv4-mapped IPv6 address to its embedded IPv4 form so that v4
/// rules and v4 queries compare apples-to-apples regardless of representation.
fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// Canonicalise a CIDR network: an IPv4-mapped IPv6 network with a `>= /96`
/// prefix becomes the equivalent IPv4 network so it matches mapped queries.
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

/// Zero the host bits of `network` so a non-canonical rule like `10.1.2.3/8`
/// is stored (and compared) as `10.0.0.0/8`.
fn mask_network(network: IpAddr, prefix_len: u8) -> IpAddr {
    match network {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0)
            };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0)
            };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

impl CidrEntry {
    fn matches(&self, ip: &IpAddr) -> bool {
        match (&self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => matches_ipv4(*net, *addr, self.prefix_len),
            // An IPv4-mapped IPv6 query (`::ffff:a.b.c.d`) is compared against a
            // v4 rule as its embedded v4 address — a dual-stack socket that
            // surfaces a mapped address still matches the v4 rule.
            (IpAddr::V4(net), IpAddr::V6(addr)) => match addr.to_ipv4_mapped() {
                Some(v4) => matches_ipv4(*net, v4, self.prefix_len),
                None => false,
            },
            (IpAddr::V6(net), IpAddr::V6(addr)) => matches_ipv6(*net, *addr, self.prefix_len),
            // A real v4 query never matches a v6 rule.
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

fn matches_ipv4(network: Ipv4Addr, addr: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
    (u32::from(network) & mask) == (u32::from(addr) & mask)
}

fn matches_ipv6(network: Ipv6Addr, addr: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
    (u128::from(network) & mask) == (u128::from(addr) & mask)
}
