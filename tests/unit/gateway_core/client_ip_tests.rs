//! Tests for client IP resolution module

use ferrum_edge::proxy::client_ip::{
    TrustedProxies, resolve_client_ip, resolve_forwarded_client_ip, resolve_real_ip_header,
};

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
fn parse_ipv4_mapped_ipv6_cidr_matches_ipv4_socket() {
    let tp = TrustedProxies::parse("::ffff:10.0.0.0/120");
    assert!(tp.contains(&"10.0.0.42".parse().unwrap()));
    assert!(tp.contains(&"::ffff:10.0.0.42".parse().unwrap()));
    assert!(!tp.contains(&"10.0.1.1".parse().unwrap()));
}

#[test]
fn ipv4_mapped_ipv6_socket_can_match_ipv6_cidr() {
    let tp = TrustedProxies::parse("::/0");
    assert!(tp.contains(&"::ffff:10.0.0.42".parse().unwrap()));
    assert!(!tp.contains(&"10.0.0.42".parse().unwrap()));
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

#[test]
fn parse_strict_empty_string_yields_no_proxies() {
    let tp = TrustedProxies::parse_strict("  ").unwrap();

    assert!(tp.is_empty());
}

#[test]
fn parse_strict_accepts_empty_configuration() {
    let tp = TrustedProxies::parse_strict(" \t ").unwrap();
    assert!(tp.is_empty());
}

#[test]
fn parse_strict_accepts_mixed_ip_and_cidr_entries() {
    let tp = TrustedProxies::parse_strict(" 10.0.0.1 , 192.168.0.0/24 , fd00::/8 ").unwrap();

    assert_eq!(tp.len(), 3);
    assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
    assert!(tp.contains(&"192.168.0.42".parse().unwrap()));
    assert!(tp.contains(&"fd12::1".parse().unwrap()));
    assert!(!tp.contains(&"203.0.113.9".parse().unwrap()));
}

#[test]
fn parse_strict_rejects_any_invalid_entry() {
    let err = TrustedProxies::parse_strict("10.0.0.1, not-an-ip, 192.168.0.0/24").unwrap_err();

    assert!(err.contains("Invalid CIDR/IP entries: not-an-ip"));
    assert!(err.contains("Expected formats"));
}

#[test]
fn parse_strict_rejects_invalid_entries() {
    let err = TrustedProxies::parse_strict("10.0.0.1, not-an-ip, 192.168.1.0/24")
        .expect_err("strict parsing must reject malformed entries");
    assert!(err.contains("not-an-ip"));
}

#[test]
fn parse_strict_rejects_invalid_ipv4_mapped_ipv6_prefix() {
    let err = TrustedProxies::parse_strict("::ffff:10.0.0.0/95").unwrap_err();

    assert!(err.contains("Invalid CIDR/IP entries: ::ffff:10.0.0.0/95"));
}

#[test]
fn parse_strict_rejects_empty_comma_segments() {
    let err = TrustedProxies::parse_strict("10.0.0.1,")
        .expect_err("strict parsing must reject trailing separators");
    assert!(err.contains("<empty>"));

    let err = TrustedProxies::parse_strict(",")
        .expect_err("strict parsing must reject comma-only configuration");
    assert!(err.contains("<empty>"));
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
fn unparseable_xff_entry_is_skipped() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    // Garbage in left side of XFF — skipped, valid IP returned
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("unknown, 203.0.113.50"), &tp),
        "203.0.113.50"
    );
}

#[test]
fn unparseable_rightmost_xff_entry_stops_walk_falls_back_to_socket() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    // Rightmost entry is garbage — stop the walk, fall back to socket.
    // Continuing leftward into 203.0.113.50 is unsafe because that value
    // is attacker-controlled (prepended before the trusted suffix).
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("203.0.113.50, not-an-ip"), &tp),
        "10.0.0.1"
    );
}

#[test]
fn all_unparseable_xff_entries_fall_back_to_socket() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    // All XFF entries are garbage — fall back to socket IP
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("garbage, not-an-ip, !!!"), &tp),
        "10.0.0.1"
    );
}

#[test]
fn mixed_garbage_trusted_and_valid_xff_stops_at_garbage() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    // XFF: "203.0.113.50, <script>alert(1)</script>, 10.0.0.2"
    // Walk right-to-left: 10.0.0.2 is trusted (skip), script tag is
    // unparseable — STOP. Fall back to socket address. 203.0.113.50
    // is to the left of the garbage and therefore attacker-controlled.
    assert_eq!(
        resolve_client_ip(
            "10.0.0.1",
            Some("203.0.113.50, <script>alert(1)</script>, 10.0.0.2"),
            &tp
        ),
        "10.0.0.1"
    );
}

#[test]
fn garbage_between_trusted_entries_stops_walk() {
    let tp = TrustedProxies::parse("10.0.0.0/8, 172.16.0.0/12");
    // XFF: "198.51.100.1, malicious\ninjection, 172.16.0.1, 10.0.0.2"
    // Walk right-to-left: 10.0.0.2 trusted, 172.16.0.1 trusted,
    // malicious\ninjection is malformed — STOP. Fall back to socket.
    // 198.51.100.1 is to the left and attacker-controlled.
    assert_eq!(
        resolve_client_ip(
            "10.0.0.1",
            Some("198.51.100.1, malicious\ninjection, 172.16.0.1, 10.0.0.2"),
            &tp
        ),
        "10.0.0.1"
    );
}

#[test]
fn only_garbage_and_trusted_entries_fall_back_to_socket() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    // XFF: "not-an-ip, also-garbage, 10.0.0.2"
    // Walk right-to-left: 10.0.0.2 trusted, rest unparseable — socket fallback
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("not-an-ip, also-garbage, 10.0.0.2"), &tp),
        "10.0.0.1"
    );
}

#[test]
fn malformed_entry_between_valid_entries_stops_walk() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    // XFF: "198.51.100.23, not-an-ip, 203.0.113.50"
    // Walk right-to-left: 203.0.113.50 is NOT trusted → return it as
    // the real client IP. The malformed entry is never reached because
    // the walk already found a valid untrusted IP.
    assert_eq!(
        resolve_client_ip(
            "10.0.0.1",
            Some("198.51.100.23, not-an-ip, 203.0.113.50"),
            &tp
        ),
        "203.0.113.50"
    );
}

#[test]
fn malformed_entry_after_trusted_suffix_stops_walk() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    // XFF: "198.51.100.23, not-an-ip, 10.0.0.2"
    // Walk right-to-left: 10.0.0.2 is trusted (skip), not-an-ip is
    // malformed — STOP. 198.51.100.23 is to the left and therefore
    // attacker-controlled. Fall back to socket address.
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("198.51.100.23, not-an-ip, 10.0.0.2"), &tp),
        "10.0.0.1"
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

// ── resolve_real_ip_header ──────────────────────────────────────────────

#[test]
fn real_ip_header_accepts_single_ip_from_trusted_proxy() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header("10.0.0.1", &socket_addr, " 203.0.113.50 ", &tp).as_deref(),
        Some("203.0.113.50")
    );
}

#[test]
fn real_ip_header_normalizes_single_ip_value() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header(
            "10.0.0.1",
            &socket_addr,
            " 2001:0db8:0000:0000:0000:0000:0000:0001 ",
            &tp
        )
        .as_deref(),
        Some("2001:db8::1")
    );
}

#[test]
fn real_ip_header_accepts_cloudfront_viewer_address_with_port() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header("10.0.0.1", &socket_addr, "198.51.100.10:46532", &tp).as_deref(),
        Some("198.51.100.10")
    );
}

#[test]
fn real_ip_header_accepts_bracketed_ipv6_with_port() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header(
            "10.0.0.1",
            &socket_addr,
            "[2001:0db8:0000:0000:0000:0000:0000:0001]:46532",
            &tp
        )
        .as_deref(),
        Some("2001:db8::1")
    );
}

#[test]
fn real_ip_header_rejects_empty_value() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header("10.0.0.1", &socket_addr, "  ", &tp),
        None
    );
}

#[test]
fn real_ip_header_rejects_comma_separated_chain() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header("10.0.0.1", &socket_addr, "198.51.100.23, 203.0.113.50", &tp,),
        None
    );
}

// ── resolve_forwarded_client_ip ─────────────────────────────────────────────

#[test]
fn absent_real_ip_header_falls_back_to_xff_resolution() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_forwarded_client_ip("10.0.0.1", &socket_addr, None, Some("203.0.113.50"), &tp)
            .as_deref(),
        Some("203.0.113.50")
    );
}

#[test]
fn present_empty_real_ip_header_keeps_socket_ip_instead_of_xff() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_forwarded_client_ip(
            "10.0.0.1",
            &socket_addr,
            Some("  "),
            Some("203.0.113.50"),
            &tp
        ),
        None
    );
}

#[test]
fn present_real_ip_header_from_untrusted_peer_keeps_socket_ip_instead_of_xff() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "198.51.100.2".parse().unwrap();

    assert_eq!(
        resolve_forwarded_client_ip(
            "198.51.100.2",
            &socket_addr,
            Some("203.0.113.50"),
            Some("192.0.2.9"),
            &tp
        ),
        None
    );
}

#[test]
fn real_ip_header_rejects_malformed_value() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header("10.0.0.1", &socket_addr, "not-an-ip", &tp),
        None
    );
}

#[test]
fn real_ip_header_rejects_malformed_source_port() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "10.0.0.1".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header("10.0.0.1", &socket_addr, "198.51.100.10:not-a-port", &tp),
        None
    );
}

#[test]
fn real_ip_header_rejects_untrusted_direct_peer() {
    let tp = TrustedProxies::parse("10.0.0.0/8");
    let socket_addr = "198.51.100.2".parse().unwrap();

    assert_eq!(
        resolve_real_ip_header("198.51.100.2", &socket_addr, "203.0.113.50", &tp),
        None
    );
}
