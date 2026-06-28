//! Tests for the shared CIDR-matching primitive `util::cidr::CidrSet` (used by
//! the backend egress policy and `client_ip::TrustedProxies`).

use ferrum_edge::util::cidr::CidrSet;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test IP literal")
}

#[test]
fn empty_or_whitespace_input_is_empty_set() {
    assert!(CidrSet::parse_strict("").expect("empty ok").is_empty());
    assert!(CidrSet::parse_strict("   ").expect("ws ok").is_empty());
}

#[test]
fn parse_strict_rejects_empty_comma_segments() {
    // A stray/trailing comma is a typo in a security list — fail loud rather
    // than silently parse a partial list (matches the admin trusted-proxy
    // allowlist semantics).
    let err = CidrSet::parse_strict("10.0.0.0/8,").unwrap_err();
    assert!(err.contains("<empty>"), "got: {err}");
    assert!(CidrSet::parse_strict(",").is_err());
    assert!(CidrSet::parse_strict("10.0.0.0/8, ,192.168.0.0/24").is_err());
}

#[test]
fn parse_lenient_skips_empty_and_reports_only_bad_entries() {
    let (set, invalid) = CidrSet::parse_lenient("10.0.0.0/8, , bogus, 192.168.0.0/24");
    assert_eq!(set.len(), 2);
    assert!(set.contains(&ip("10.1.2.3")));
    assert!(set.contains(&ip("192.168.0.9")));
    assert_eq!(invalid, vec!["bogus".to_string()]);
}

#[test]
fn invalid_entry_is_rejected() {
    assert!(CidrSet::parse_strict("not-an-ip").is_err());
    assert!(CidrSet::parse_strict("10.0.0.0/33").is_err());
    assert!(CidrSet::parse_strict("::1/129").is_err());
    assert!(CidrSet::parse_strict("10.0.0.0/8,garbage").is_err());
}

#[test]
fn ipv4_cidr_membership() {
    let set = CidrSet::parse_strict("10.0.0.0/8, 192.168.1.0/24").expect("parse");
    assert_eq!(set.len(), 2);
    assert!(set.contains(&ip("10.255.0.1")));
    assert!(set.contains(&ip("192.168.1.42")));
    assert!(!set.contains(&ip("192.168.2.1")));
    assert!(!set.contains(&ip("11.0.0.1")));
}

#[test]
fn bare_ipv4_is_slash_32() {
    let set = CidrSet::parse_strict("169.254.169.254").expect("parse");
    assert!(set.contains(&ip("169.254.169.254")));
    assert!(!set.contains(&ip("169.254.169.253")));
}

#[test]
fn host_bits_are_masked() {
    // A non-canonical network must still match the whole block.
    let set = CidrSet::parse_strict("10.1.2.3/8").expect("parse");
    assert!(set.contains(&ip("10.9.9.9")));
}

#[test]
fn ipv6_cidr_membership() {
    let set = CidrSet::parse_strict("fc00::/7, 2001:db8::/32").expect("parse");
    assert!(set.contains(&ip("fc00::1")));
    assert!(set.contains(&ip("fd00::abcd")));
    assert!(set.contains(&ip("2001:db8::1")));
    assert!(!set.contains(&ip("2001:dead::1")));
}

#[test]
fn ipv4_mapped_query_matches_v4_rule() {
    let set = CidrSet::parse_strict("10.0.0.0/8").expect("parse");
    // A dual-stack socket may surface 10.0.0.5 as ::ffff:10.0.0.5.
    assert!(set.contains(&ip("::ffff:10.0.0.5")));
}

#[test]
fn ipv4_mapped_rule_matches_v4_query() {
    let set = CidrSet::parse_strict("::ffff:10.0.0.0/104").expect("parse");
    assert!(set.contains(&ip("10.0.0.5")));
}

#[test]
fn zero_prefix_matches_all_v4() {
    let set = CidrSet::parse_strict("0.0.0.0/0").expect("parse");
    assert!(set.contains(&ip("8.8.8.8")));
    assert!(set.contains(&ip("127.0.0.1")));
}
