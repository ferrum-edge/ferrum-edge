//! Tests for client IP resolution module

use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::client_ip::{
    RealIpHeaderOutcome, TrustedProxies, resolve_client_ip, resolve_forwarded_client_ip,
    resolve_real_ip_header_field_lines, trusted_forwarded_request_scheme,
};

/// Build a trust set from a list the test asserts is valid. Production parsing
/// is strict everywhere (advisory GHSA-pvj7-hhqj-rpv5), so there is no
/// infallible constructor to reach for; rejection cases assert on the `Err`.
fn trusted(raw: &str) -> TrustedProxies {
    TrustedProxies::parse_strict(raw, "FERRUM_TRUSTED_PROXIES")
        .expect("test trusted-proxy list must be valid")
}

/// Evaluate the configured real-IP header from its raw field lines, the way the
/// H1/H2/H3 request paths do.
fn real_ip_outcome_bytes(
    socket_ip: &str,
    field_lines: &[&[u8]],
    trusted_proxies: &TrustedProxies,
) -> RealIpHeaderOutcome {
    let socket_addr = socket_ip.parse().expect("valid socket IP");
    resolve_real_ip_header_field_lines(
        socket_ip,
        &socket_addr,
        field_lines.iter().copied(),
        trusted_proxies,
    )
}

/// UTF-8 convenience wrapper over [`real_ip_outcome_bytes`].
fn real_ip_outcome(
    socket_ip: &str,
    field_lines: &[&str],
    trusted_proxies: &TrustedProxies,
) -> RealIpHeaderOutcome {
    let bytes: Vec<&[u8]> = field_lines.iter().map(|line| line.as_bytes()).collect();
    real_ip_outcome_bytes(socket_ip, &bytes, trusted_proxies)
}

/// Resolve through the same entry point the H1/H2/H3 request paths use.
fn forwarded_client_ip(
    socket_ip: &str,
    real_ip_lines: &[&str],
    xff: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    let socket_addr = socket_ip.parse().expect("valid socket IP");
    let bytes: Vec<&[u8]> = real_ip_lines.iter().map(|line| line.as_bytes()).collect();
    resolve_forwarded_client_ip(
        socket_ip,
        &socket_addr,
        bytes.iter().copied(),
        xff,
        trusted_proxies,
    )
}

// ── TrustedProxies parsing ───────────────────────────────────────────

#[test]
fn parse_empty_string_yields_no_proxies() {
    let tp = trusted("");
    assert!(tp.is_empty());
}

#[test]
fn parse_single_ipv4() {
    let tp = trusted("10.0.0.1");
    assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
    assert!(!tp.contains(&"10.0.0.2".parse().unwrap()));
}

#[test]
fn parse_ipv4_cidr() {
    let tp = trusted("10.0.0.0/8");
    assert!(tp.contains(&"10.255.255.255".parse().unwrap()));
    assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
    assert!(!tp.contains(&"11.0.0.1".parse().unwrap()));
}

#[test]
fn parse_ipv4_mapped_ipv6_cidr_matches_ipv4_socket() {
    let tp = trusted("::ffff:10.0.0.0/120");
    assert!(tp.contains(&"10.0.0.42".parse().unwrap()));
    assert!(tp.contains(&"::ffff:10.0.0.42".parse().unwrap()));
    assert!(!tp.contains(&"10.0.1.1".parse().unwrap()));
}

#[test]
fn ipv4_mapped_ipv6_socket_can_match_ipv6_cidr() {
    let tp = trusted("::/0");
    assert!(tp.contains(&"::ffff:10.0.0.42".parse().unwrap()));
    assert!(!tp.contains(&"10.0.0.42".parse().unwrap()));
}

#[test]
fn parse_multiple_cidrs_with_whitespace() {
    let tp = trusted(" 10.0.0.0/8 , 172.16.0.0/12 , ::1 ");
    assert!(tp.contains(&"10.1.2.3".parse().unwrap()));
    assert!(tp.contains(&"172.16.5.1".parse().unwrap()));
    assert!(tp.contains(&"::1".parse().unwrap()));
    assert!(!tp.contains(&"8.8.8.8".parse().unwrap()));
}

#[test]
fn parse_ipv6_cidr() {
    let tp = trusted("fd00::/8");
    assert!(tp.contains(&"fd12::1".parse().unwrap()));
    assert!(!tp.contains(&"2001:db8::1".parse().unwrap()));
}

/// A mixed valid/invalid list must not silently retain the valid part: the
/// dropped entry is exactly the hop whose forwarded identity would stop being
/// believed (advisory GHSA-pvj7-hhqj-rpv5).
#[test]
fn mixed_valid_and_invalid_entries_are_rejected_not_partially_retained() {
    let err = TrustedProxies::parse_strict(
        "10.0.0.1, not-an-ip, 192.168.1.0/24",
        "FERRUM_TRUSTED_PROXIES",
    )
    .expect_err("a partial trust set must never be installed");
    assert!(err.contains("not-an-ip"), "got: {err}");
}

#[test]
fn invalid_prefix_length_is_rejected() {
    let err = TrustedProxies::parse_strict("10.0.0.0/33", "FERRUM_TRUSTED_PROXIES")
        .expect_err("an out-of-range prefix must be rejected");
    assert!(err.contains("10.0.0.0/33"), "got: {err}");
}

#[test]
fn junk_and_doubled_comma_segments_are_rejected() {
    for raw in [
        "junk",
        "10.0.0.0/8,,192.168.0.0/16",
        ",10.0.0.0/8",
        "10.0.0.0/8, ",
        "10.0.0.0/8, 192.168.0.0/16/24",
    ] {
        assert!(
            TrustedProxies::parse_strict(raw, "FERRUM_TRUSTED_PROXIES").is_err(),
            "{raw:?} must be rejected"
        );
    }
}

/// Canonical IPv4 / IPv6 / IPv4-mapped forms all survive strict parsing and
/// keep matching the same addresses the runtime filter sees.
#[test]
fn strict_parsing_preserves_canonical_address_forms() {
    let tp = trusted("10.0.0.0/8,fd00::/8,::ffff:192.0.2.0/120,::1,203.0.113.7");
    assert!(tp.contains(&"10.1.2.3".parse().unwrap()));
    assert!(tp.contains(&"fd12::1".parse().unwrap()));
    assert!(tp.contains(&"192.0.2.9".parse().unwrap()));
    assert!(tp.contains(&"::ffff:192.0.2.9".parse().unwrap()));
    assert!(tp.contains(&"::1".parse().unwrap()));
    assert!(tp.contains(&"203.0.113.7".parse().unwrap()));
    assert!(!tp.contains(&"203.0.113.8".parse().unwrap()));
}

#[test]
fn parse_strict_empty_string_yields_no_proxies() {
    let tp = TrustedProxies::parse_strict("  ", "FERRUM_TRUSTED_PROXIES").unwrap();

    assert!(tp.is_empty());
}

#[test]
fn parse_strict_accepts_empty_configuration() {
    let tp = TrustedProxies::parse_strict(" \t ", "FERRUM_TRUSTED_PROXIES").unwrap();
    assert!(tp.is_empty());
}

#[test]
fn parse_strict_accepts_mixed_ip_and_cidr_entries() {
    let tp = TrustedProxies::parse_strict(
        " 10.0.0.1 , 192.168.0.0/24 , fd00::/8 ",
        "FERRUM_TRUSTED_PROXIES",
    )
    .unwrap();

    assert_eq!(tp.len(), 3);
    assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
    assert!(tp.contains(&"192.168.0.42".parse().unwrap()));
    assert!(tp.contains(&"fd12::1".parse().unwrap()));
    assert!(!tp.contains(&"203.0.113.9".parse().unwrap()));
}

#[test]
fn parse_strict_rejects_any_invalid_entry() {
    let err = TrustedProxies::parse_strict(
        "10.0.0.1, not-an-ip, 192.168.0.0/24",
        "FERRUM_TRUSTED_PROXIES",
    )
    .unwrap_err();

    assert!(err.contains("Invalid CIDR/IP entries: not-an-ip"));
    assert!(err.contains("Expected formats"));
}

#[test]
fn parse_strict_rejects_invalid_ipv4_mapped_ipv6_prefix() {
    let err =
        TrustedProxies::parse_strict("::ffff:10.0.0.0/95", "FERRUM_TRUSTED_PROXIES").unwrap_err();

    assert!(err.contains("Invalid CIDR/IP entries: ::ffff:10.0.0.0/95"));
}

#[test]
fn parse_strict_rejects_empty_comma_segments() {
    let err = TrustedProxies::parse_strict("10.0.0.1,", "FERRUM_TRUSTED_PROXIES")
        .expect_err("strict parsing must reject trailing separators");
    assert!(err.contains("<empty>"));

    let err = TrustedProxies::parse_strict(",", "FERRUM_TRUSTED_PROXIES")
        .expect_err("strict parsing must reject comma-only configuration");
    assert!(err.contains("<empty>"));
}

#[test]
fn forwarded_scheme_accepts_overwrite_or_correlated_append_from_a_trusted_peer() {
    let trusted_set = trusted("10.0.0.0/8");
    let trusted_peer = "10.0.0.8".parse().expect("valid trusted peer IP");
    let untrusted_peer = "203.0.113.8".parse().expect("valid untrusted peer IP");

    assert_eq!(
        trusted_forwarded_request_scheme(
            &trusted_peer,
            std::iter::empty(),
            [b" HTTPS\t".as_slice()],
            &trusted_set,
        ),
        Some("https")
    );
    assert_eq!(
        trusted_forwarded_request_scheme(
            &trusted_peer,
            [b"203.0.113.8, 10.0.0.7".as_slice()],
            [b"http, https".as_slice()],
            &trusted_set,
        ),
        Some("http")
    );
    assert_eq!(
        trusted_forwarded_request_scheme(
            &trusted_peer,
            [
                b"198.51.100.1, 203.0.113.8".as_slice(),
                b"10.0.0.7".as_slice(),
            ],
            [b"attacker, http".as_slice(), b"https".as_slice()],
            &trusted_set,
        ),
        Some("http")
    );
    assert_eq!(
        trusted_forwarded_request_scheme(
            &trusted_peer,
            [b"203.0.113.8, 10.0.0.7".as_slice()],
            [b"https".as_slice()],
            &trusted_set,
        ),
        Some("https"),
        "a singleton value is the trusted proxy's overwrite-only contract"
    );
    assert_eq!(
        trusted_forwarded_request_scheme(
            &trusted_peer,
            [b"203.0.113.8, 10.0.0.7".as_slice()],
            [b"http, https, https".as_slice()],
            &trusted_set,
        ),
        None
    );
    assert_eq!(
        trusted_forwarded_request_scheme(
            &trusted_peer,
            [b"203.0.113.8, not-an-ip, 10.0.0.7".as_slice()],
            [b"http, https, https".as_slice()],
            &trusted_set,
        ),
        None
    );
    assert_eq!(
        trusted_forwarded_request_scheme(
            &trusted_peer,
            [b"203.0.113.8, 10.0.0.7".as_slice()],
            [b"http".as_slice(), &[0x80]],
            &trusted_set,
        ),
        None
    );
    assert_eq!(
        trusted_forwarded_request_scheme(
            &untrusted_peer,
            [b"203.0.113.8".as_slice()],
            [b"https".as_slice()],
            &trusted_set,
        ),
        None
    );
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
    let tp = trusted("10.0.0.0/8");
    assert_eq!(resolve_client_ip("10.0.0.1", None, &tp), "10.0.0.1");
}

#[test]
fn empty_xff_header_returns_socket_ip() {
    let tp = trusted("10.0.0.0/8");
    assert_eq!(resolve_client_ip("10.0.0.1", Some(""), &tp), "10.0.0.1");
    assert_eq!(resolve_client_ip("10.0.0.1", Some("  "), &tp), "10.0.0.1");
}

#[test]
fn socket_not_trusted_ignores_xff() {
    let tp = trusted("10.0.0.0/8");
    // Socket IP 1.2.3.4 is NOT trusted, so XFF is ignored
    assert_eq!(
        resolve_client_ip("1.2.3.4", Some("5.6.7.8"), &tp),
        "1.2.3.4"
    );
}

#[test]
fn single_xff_entry_behind_trusted_proxy() {
    let tp = trusted("10.0.0.0/8");
    // Connection from 10.0.0.1 (trusted), XFF says real client is 203.0.113.50
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("203.0.113.50"), &tp),
        "203.0.113.50"
    );
}

#[test]
fn multi_hop_xff_skips_trusted_proxies() {
    // Two trusted proxy hops: CDN (172.16.1.1) → LB (10.0.0.1)
    let tp = trusted("10.0.0.0/8, 172.16.0.0/12");
    // XFF: "client, cdn_ingress" — socket is the LB
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("203.0.113.50, 172.16.1.1"), &tp),
        "203.0.113.50"
    );
}

#[test]
fn attacker_prepended_ip_is_ignored() {
    let tp = trusted("10.0.0.0/8");
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
    let tp = trusted("10.0.0.0/8, 172.16.0.0/12");
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("10.0.0.2, 172.16.0.1"), &tp),
        "10.0.0.1"
    );
}

#[test]
fn unparseable_xff_entry_is_skipped() {
    let tp = trusted("10.0.0.0/8");
    // Garbage in left side of XFF — skipped, valid IP returned
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("unknown, 203.0.113.50"), &tp),
        "203.0.113.50"
    );
}

#[test]
fn unparseable_rightmost_xff_entry_stops_walk_falls_back_to_socket() {
    let tp = trusted("10.0.0.0/8");
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
    let tp = trusted("10.0.0.0/8");
    // All XFF entries are garbage — fall back to socket IP
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("garbage, not-an-ip, !!!"), &tp),
        "10.0.0.1"
    );
}

#[test]
fn mixed_garbage_trusted_and_valid_xff_stops_at_garbage() {
    let tp = trusted("10.0.0.0/8");
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
    let tp = trusted("10.0.0.0/8, 172.16.0.0/12");
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
    let tp = trusted("10.0.0.0/8");
    // XFF: "not-an-ip, also-garbage, 10.0.0.2"
    // Walk right-to-left: 10.0.0.2 trusted, rest unparseable — socket fallback
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("not-an-ip, also-garbage, 10.0.0.2"), &tp),
        "10.0.0.1"
    );
}

#[test]
fn malformed_entry_between_valid_entries_stops_walk() {
    let tp = trusted("10.0.0.0/8");
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
    let tp = trusted("10.0.0.0/8");
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
    let tp = trusted("::1, fd00::/8");
    assert_eq!(
        resolve_client_ip("::1", Some("2001:db8::1"), &tp),
        "2001:db8::1"
    );
}

#[test]
fn real_world_cloudflare_pattern() {
    // Cloudflare IPs (subset) as trusted proxies
    let tp = trusted("173.245.48.0/20, 103.21.244.0/22, 10.0.0.0/8");
    // Client → Cloudflare (173.245.49.1) → Internal LB (10.0.0.1) → Gateway
    // XFF: "198.51.100.23, 173.245.49.1"
    // Socket: 10.0.0.1
    assert_eq!(
        resolve_client_ip("10.0.0.1", Some("198.51.100.23, 173.245.49.1"), &tp),
        "198.51.100.23"
    );
}

// ── resolve_real_ip_header_field_lines ──────────────────────────────────────

#[test]
fn real_ip_header_accepts_single_ip_from_trusted_proxy() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &[" 203.0.113.50 "], &tp),
        RealIpHeaderOutcome::Accepted("203.0.113.50".to_string())
    );
}

#[test]
fn real_ip_header_normalizes_single_ip_value() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome(
            "10.0.0.1",
            &[" 2001:0db8:0000:0000:0000:0000:0000:0001 "],
            &tp
        ),
        RealIpHeaderOutcome::Accepted("2001:db8::1".to_string())
    );
}

#[test]
fn real_ip_header_canonicalizes_ipv4_mapped_value() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &["::ffff:192.0.2.10"], &tp),
        RealIpHeaderOutcome::Accepted("192.0.2.10".to_string())
    );
}

#[test]
fn real_ip_header_accepts_cloudfront_viewer_address_with_port() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &["198.51.100.10:46532"], &tp),
        RealIpHeaderOutcome::Accepted("198.51.100.10".to_string())
    );
}

#[test]
fn real_ip_header_accepts_bracketed_ipv6_with_port() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome(
            "10.0.0.1",
            &["[2001:0db8:0000:0000:0000:0000:0000:0001]:46532"],
            &tp
        ),
        RealIpHeaderOutcome::Accepted("2001:db8::1".to_string())
    );
}

#[test]
fn absent_real_ip_header_field_lines_are_absent_not_rejected() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &[], &tp),
        RealIpHeaderOutcome::Absent
    );
}

#[test]
fn real_ip_header_rejects_empty_value() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &["  "], &tp),
        RealIpHeaderOutcome::Rejected
    );
}

#[test]
fn real_ip_header_rejects_comma_separated_chain() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &["198.51.100.23, 203.0.113.50"], &tp),
        RealIpHeaderOutcome::Rejected
    );
}

#[test]
fn real_ip_header_rejects_malformed_value() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &["not-an-ip"], &tp),
        RealIpHeaderOutcome::Rejected
    );
}

#[test]
fn real_ip_header_rejects_malformed_source_port() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("10.0.0.1", &["198.51.100.10:not-a-port"], &tp),
        RealIpHeaderOutcome::Rejected
    );
}

/// A non-UTF-8 field-line must be counted and rejected, never silently skipped
/// so that some other line becomes "the" value.
#[test]
fn real_ip_header_rejects_non_utf8_field_line() {
    let tp = trusted("10.0.0.0/8");
    let invalid: &[u8] = &[0x80, 0xfe];

    assert_eq!(
        real_ip_outcome_bytes("10.0.0.1", &[invalid], &tp),
        RealIpHeaderOutcome::Rejected
    );
    // Paired with a valid line, the valid one must not win.
    assert_eq!(
        real_ip_outcome_bytes("10.0.0.1", &[invalid, b"198.51.100.23"], &tp),
        RealIpHeaderOutcome::Rejected
    );
    assert_eq!(
        real_ip_outcome_bytes("10.0.0.1", &[b"198.51.100.23", invalid], &tp),
        RealIpHeaderOutcome::Rejected
    );
}

#[test]
fn real_ip_header_rejects_untrusted_direct_peer() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        real_ip_outcome("198.51.100.2", &["203.0.113.50"], &tp),
        RealIpHeaderOutcome::Rejected
    );
}

/// Core of advisory GHSA-fx4w-68hx-mj7r: a trusted proxy that preserves the
/// client's copy of the authoritative header and appends its own leaves two
/// field-lines. Neither may be selected, in EITHER order, and identical
/// duplicates are no better — the operator's contract is one overwritten value.
#[test]
fn duplicate_real_ip_field_lines_are_rejected_in_either_order() {
    let tp = trusted("10.0.0.0/8");

    // Attacker line first, proxy's authoritative line appended.
    assert_eq!(
        real_ip_outcome("10.0.0.1", &["203.0.113.50", "198.51.100.23"], &tp),
        RealIpHeaderOutcome::Rejected
    );
    // Reversed field order — the selection must not depend on it.
    assert_eq!(
        real_ip_outcome("10.0.0.1", &["198.51.100.23", "203.0.113.50"], &tp),
        RealIpHeaderOutcome::Rejected
    );
    // Identical duplicates are still ambiguous field-lines.
    assert_eq!(
        real_ip_outcome("10.0.0.1", &["198.51.100.23", "198.51.100.23"], &tp),
        RealIpHeaderOutcome::Rejected
    );
    // A valid line paired with junk must not fall back to the valid one.
    assert_eq!(
        real_ip_outcome("10.0.0.1", &["not-an-ip", "198.51.100.23"], &tp),
        RealIpHeaderOutcome::Rejected
    );
    // Three lines are rejected too.
    assert_eq!(
        real_ip_outcome(
            "10.0.0.1",
            &["203.0.113.50", "203.0.113.51", "198.51.100.23"],
            &tp
        ),
        RealIpHeaderOutcome::Rejected
    );
}

// ── resolve_forwarded_client_ip ─────────────────────────────────────────────

#[test]
fn absent_real_ip_header_falls_back_to_xff_resolution() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        forwarded_client_ip("10.0.0.1", &[], Some("203.0.113.50"), &tp).as_deref(),
        Some("203.0.113.50")
    );
}

#[test]
fn forwarded_ipv4_mapped_address_is_canonicalized_before_plugins() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        forwarded_client_ip("10.0.0.1", &[], Some("::ffff:192.0.2.10"), &tp).as_deref(),
        Some("192.0.2.10")
    );
    assert_eq!(
        forwarded_client_ip("10.0.0.1", &["::ffff:192.0.2.10"], None, &tp).as_deref(),
        Some("192.0.2.10")
    );
}

#[test]
fn present_empty_real_ip_header_keeps_socket_ip_instead_of_xff() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        forwarded_client_ip("10.0.0.1", &["  "], Some("203.0.113.50"), &tp),
        None
    );
}

#[test]
fn present_real_ip_header_from_untrusted_peer_keeps_socket_ip_instead_of_xff() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        forwarded_client_ip("198.51.100.2", &["203.0.113.50"], Some("192.0.2.9"), &tp),
        None
    );
}

/// Duplicate authoritative headers fall back to the direct socket identity and
/// must NOT then consider `X-Forwarded-For` — XFF is the weaker source the
/// operator chose to override.
#[test]
fn duplicate_real_ip_field_lines_keep_socket_ip_and_never_consult_xff() {
    let tp = trusted("10.0.0.0/8");

    assert_eq!(
        forwarded_client_ip(
            "10.0.0.1",
            &["203.0.113.50", "198.51.100.23"],
            Some("192.0.2.9"),
            &tp
        ),
        None
    );
}

#[test]
fn untrusted_peer_boundary_ignores_every_forwarded_source() {
    let tp = trusted("10.0.0.0/8");

    // Real-IP header, duplicated real-IP header, and XFF alike.
    assert_eq!(
        forwarded_client_ip("198.51.100.2", &[], Some("203.0.113.50"), &tp),
        None
    );
    assert_eq!(
        forwarded_client_ip(
            "198.51.100.2",
            &["203.0.113.50", "203.0.113.51"],
            Some("203.0.113.52"),
            &tp
        ),
        None
    );
}

// ── RequestContext field-line parity (raw vs materialized) ──────────────────

fn context_with_real_ip_lines(values: &[&str]) -> RequestContext {
    let mut headers = hyper::HeaderMap::new();
    for value in values {
        headers.append(
            hyper::header::HeaderName::from_static("x-real-ip"),
            hyper::header::HeaderValue::from_str(value).expect("valid header value"),
        );
    }
    let mut ctx = RequestContext::new("10.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.set_raw_headers(headers);
    ctx
}

fn resolve_via_context(ctx: &RequestContext, tp: &TrustedProxies) -> Option<String> {
    let socket_addr = "10.0.0.1".parse().expect("valid socket IP");
    resolve_forwarded_client_ip(
        "10.0.0.1",
        &socket_addr,
        ctx.header_field_lines("x-real-ip"),
        Some("192.0.2.9"),
        tp,
    )
}

/// The same duplicate-line verdict must hold whether or not headers have been
/// materialized — materialization retains the raw wire map, and the folded map
/// would join duplicates with `, ` which the single-value contract rejects.
#[test]
fn context_field_lines_reject_duplicates_raw_and_materialized() {
    let tp = trusted("10.0.0.0/8");

    for order in [
        ["203.0.113.50", "198.51.100.23"],
        ["198.51.100.23", "203.0.113.50"],
        ["198.51.100.23", "198.51.100.23"],
    ] {
        let raw_ctx = context_with_real_ip_lines(&order);
        assert_eq!(resolve_via_context(&raw_ctx, &tp), None, "raw: {order:?}");

        let mut materialized_ctx = context_with_real_ip_lines(&order);
        materialized_ctx.materialize_headers();
        assert_eq!(
            resolve_via_context(&materialized_ctx, &tp),
            None,
            "materialized: {order:?}"
        );
    }
}

#[test]
fn context_field_lines_accept_a_single_line_raw_and_materialized() {
    let tp = trusted("10.0.0.0/8");

    let raw_ctx = context_with_real_ip_lines(&["198.51.100.23"]);
    assert_eq!(
        resolve_via_context(&raw_ctx, &tp).as_deref(),
        Some("198.51.100.23")
    );

    let mut materialized_ctx = context_with_real_ip_lines(&["198.51.100.23"]);
    materialized_ctx.materialize_headers();
    assert_eq!(
        resolve_via_context(&materialized_ctx, &tp).as_deref(),
        Some("198.51.100.23")
    );
}

/// With the header absent in both states, resolution falls back to the XFF walk.
#[test]
fn context_without_the_configured_header_falls_back_to_xff() {
    let tp = trusted("10.0.0.0/8");

    let raw_ctx = context_with_real_ip_lines(&[]);
    assert_eq!(
        resolve_via_context(&raw_ctx, &tp).as_deref(),
        Some("192.0.2.9")
    );

    let mut materialized_ctx = context_with_real_ip_lines(&[]);
    materialized_ctx.materialize_headers();
    assert_eq!(
        resolve_via_context(&materialized_ctx, &tp).as_deref(),
        Some("192.0.2.9")
    );
}

/// A context that never held the raw wire map at all: `headers` carries only the
/// folded value materialization would have produced. The contexts above retain
/// their raw map even after `materialize_headers()`, so they never reach this
/// branch of `RequestContext::header_field_lines`.
fn context_with_folded_real_ip(value: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new("10.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    if let Some(value) = value {
        let folded = value.to_string();
        ctx.headers.insert("x-real-ip".to_string(), folded);
    }
    ctx
}

/// The documented degraded state must still fail closed: without raw headers the
/// accessor can only see one folded value, and folding joins repeated field-lines
/// with `, `, which the single-value contract rejects as a comma list.
#[test]
fn context_without_raw_headers_falls_back_to_the_folded_value_and_fails_closed() {
    let tp = trusted("10.0.0.0/8");

    let duplicates = context_with_folded_real_ip(Some("203.0.113.50, 198.51.100.23"));
    assert!(!duplicates.has_raw_headers());
    assert_eq!(resolve_via_context(&duplicates, &tp), None);

    // Non-vacuity: a lone folded value still resolves, so the rejection above is
    // not this branch simply refusing everything it sees.
    let single = context_with_folded_real_ip(Some("198.51.100.23"));
    assert_eq!(
        resolve_via_context(&single, &tp).as_deref(),
        Some("198.51.100.23")
    );

    // Absent here is Absent, not Rejected: the XFF walk still runs.
    let absent = context_with_folded_real_ip(None);
    assert_eq!(
        resolve_via_context(&absent, &tp).as_deref(),
        Some("192.0.2.9")
    );
}
