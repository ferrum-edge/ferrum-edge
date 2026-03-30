//! Tests for client IP resolution module

use ferrum_edge::proxy::client_ip::{TrustedProxies, resolve_client_ip};

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
    assert_eq!(tp.len(), 2);
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
