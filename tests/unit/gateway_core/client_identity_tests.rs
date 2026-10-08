//! Coverage for the shared canonical client-identity boundary
//! (advisory GHSA-vjwj-657f-5w9g).
//!
//! Ferrum folds IPv4-mapped IPv6 client addresses to native IPv4 exactly once,
//! at every ingress and metadata-restoration boundary, so `192.0.2.10` and
//! `::ffff:192.0.2.10` are one security principal for per-IP budgets, IP/GeoIP
//! policy, logs, and metric labels. These tests pin that contract on the shared
//! helper plus the two production entry points that are otherwise only
//! reachable behind a live socket: the HTTP-family accept loop (including
//! node-agent source-IP restoration) and the HTTP/3 connection identity pair
//! that connection migration refreshes.

use ferrum_edge::util::client_identity::{
    canonical_client_ip_text, canonical_ip, canonical_ip_arc, canonical_ip_string,
    canonical_socket_addr, parse_canonical_client_ip, parse_client_ip_literal,
    rate_limit_ip_string,
};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn ip(value: &str) -> IpAddr {
    value.parse().expect("test IP literal")
}

fn socket(value: &str) -> SocketAddr {
    value.parse().expect("test socket literal")
}

// ── The fold itself ──────────────────────────────────────────────────

#[test]
fn mapped_and_native_ipv4_are_one_principal() {
    assert_eq!(canonical_ip(ip("::ffff:192.0.2.10")), ip("192.0.2.10"));
    assert_eq!(canonical_ip(ip("192.0.2.10")), ip("192.0.2.10"));
    assert_eq!(
        canonical_ip_string(ip("::ffff:192.0.2.10")),
        canonical_ip_string(ip("192.0.2.10"))
    );
    assert_eq!(
        canonical_ip_arc(ip("::ffff:192.0.2.10")).as_ref(),
        "192.0.2.10"
    );
}

#[test]
fn canonical_ipv4_rendering_matches_display_for_every_octet_width() {
    // The hand-rolled IPv4 renderer must stay byte-identical to `Display`.
    for octet in 0..=u8::MAX {
        for addr in [
            Ipv4Addr::new(octet, 0, 9, 10),
            Ipv4Addr::new(99, octet, 100, 255),
            Ipv4Addr::new(1, 10, octet, 100),
            Ipv4Addr::new(255, 254, 0, octet),
        ] {
            assert_eq!(canonical_ip_string(IpAddr::V4(addr)), addr.to_string());
            let mapped = IpAddr::V6(addr.to_ipv6_mapped());
            assert_eq!(canonical_ip_string(mapped), addr.to_string());
        }
    }
}

#[test]
fn true_ipv6_semantics_are_preserved() {
    // A genuine IPv6 host is its own principal and must never collapse onto an
    // IPv4 address.
    for literal in [
        "2001:db8::10",
        "::1",
        // Deprecated IPv4-*compatible* form: a distinct network identity from
        // the IPv4 address it embeds, and NOT what `to_ipv4_mapped` unmaps.
        "::192.0.2.10",
        // NAT64 translation prefix: also a distinct identity.
        "64:ff9b::c000:20a",
    ] {
        assert_eq!(
            canonical_ip(ip(literal)),
            ip(literal),
            "true IPv6 address must be preserved: {literal}"
        );
    }
    assert_ne!(canonical_ip(ip("::192.0.2.10")), ip("192.0.2.10"));
    assert_ne!(canonical_ip(ip("64:ff9b::c000:20a")), ip("192.0.2.10"));
}

#[test]
fn rate_limit_ipv6_prefix_groups_network_hosts_and_keeps_ipv4_exact() {
    assert_eq!(
        rate_limit_ip_string(ip("2001:db8:abcd:12::1"), 64),
        rate_limit_ip_string(ip("2001:db8:abcd:12::ffff"), 64)
    );
    assert_ne!(
        rate_limit_ip_string(ip("2001:db8:abcd:12::1"), 64),
        rate_limit_ip_string(ip("2001:db8:abcd:13::1"), 64)
    );
    assert_ne!(
        rate_limit_ip_string(ip("2001:db8:abcd:12::1"), 128),
        rate_limit_ip_string(ip("2001:db8:abcd:12::2"), 128)
    );
    assert_eq!(rate_limit_ip_string(ip("192.0.2.1"), 64), "192.0.2.1");
}

#[test]
fn canonical_socket_addr_folds_the_address_and_keeps_the_port() {
    assert_eq!(
        canonical_socket_addr(socket("[::ffff:192.0.2.10]:44321")),
        socket("192.0.2.10:44321")
    );
    assert_eq!(
        canonical_socket_addr(socket("[2001:db8::10]:44321")),
        socket("[2001:db8::10]:44321")
    );
    assert_eq!(
        canonical_socket_addr(socket("192.0.2.10:44321")),
        socket("192.0.2.10:44321")
    );
}

// ── Text identities ──────────────────────────────────────────────────

#[test]
fn canonical_text_folds_mapped_and_borrows_everything_else() {
    assert_eq!(canonical_client_ip_text("::ffff:192.0.2.10"), "192.0.2.10");
    assert_eq!(canonical_client_ip_text("::FFFF:192.0.2.10"), "192.0.2.10");
    // Already-canonical gateway identities are returned untouched, without an
    // allocation — the hot-path contract for per-connection key building.
    for value in ["192.0.2.10", "2001:db8::10", "consumer:alice"] {
        assert!(
            matches!(canonical_client_ip_text(value), Cow::Borrowed(_)),
            "already-canonical identity must be borrowed: {value}"
        );
        assert_eq!(canonical_client_ip_text(value), value);
    }
}

#[test]
fn parse_canonical_client_ip_folds_bracketed_and_zoned_literals() {
    assert_eq!(
        parse_canonical_client_ip("[::ffff:192.0.2.10]"),
        Some(ip("192.0.2.10"))
    );
    assert_eq!(
        parse_canonical_client_ip("::ffff:192.0.2.10%eth0"),
        Some(ip("192.0.2.10"))
    );
    assert_eq!(
        parse_canonical_client_ip("[2001:db8::10]"),
        Some(ip("2001:db8::10"))
    );
    // A non-address identity has no typed form; callers must fail closed on it
    // rather than treat it as an allowed address.
    assert_eq!(parse_canonical_client_ip("not-an-ip"), None);
    assert_eq!(parse_canonical_client_ip(""), None);
    // Brackets and zones stay IPv6-only, matching the established policy grammar.
    assert_eq!(parse_client_ip_literal("[192.0.2.10]"), None);
}

// ── Ingress boundary: HTTP-family accept + restored source IP ─────────

/// The identity the HTTP-family accept loop installs for one connection,
/// optionally with a node-agent-restored source IP replacing the loopback peer.
fn accept_identity(accepted: &str, restored: Option<&str>) -> SocketAddr {
    ferrum_edge::_test_support::accept_peer_identity_for_test(socket(accepted), restored.map(ip))
}

#[test]
fn accepted_dual_stack_peer_is_canonical_before_any_request_context() {
    let identity = accept_identity("[::ffff:192.0.2.10]:44321", None);
    assert_eq!(identity, socket("192.0.2.10:44321"));
    assert_eq!(
        identity,
        accept_identity("192.0.2.10:44321", None),
        "a mapped accept and a native accept must yield one principal"
    );
}

#[test]
fn restored_source_ip_metadata_is_canonicalized_too() {
    // Node-waypoint in-netns capture rewrites the pod's egress to loopback and
    // restores the real source IP from node-agent metadata. That restored value
    // is attacker-independent but still representation-dependent, so it is
    // folded on exactly the same terms as a directly accepted peer.
    let restored = accept_identity("[::1]:44321", Some("::ffff:10.1.2.3"));
    assert_eq!(restored, socket("10.1.2.3:44321"));
    assert_eq!(
        restored,
        accept_identity("127.0.0.1:44321", Some("10.1.2.3"))
    );

    // A restored true-IPv6 pod address keeps its own identity.
    assert_eq!(
        accept_identity("[::1]:44321", Some("fd00::5")),
        socket("[fd00::5]:44321")
    );
}

// ── Ingress boundary: HTTP/3 connection start and migration ───────────

/// The identity pair the H3 connection loop installs for a QUIC peer.
fn h3_identity(peer: &str) -> (SocketAddr, std::sync::Arc<str>) {
    ferrum_edge::_test_support::h3_client_identity_for_test(socket(peer))
}

#[test]
fn h3_connection_identity_pair_is_canonical_and_self_consistent() {
    let (peer, socket_ip) = h3_identity("[::ffff:198.51.100.7]:443");
    assert_eq!(peer, socket("198.51.100.7:443"));
    assert_eq!(socket_ip.as_ref(), "198.51.100.7");
    assert_eq!(
        peer.ip().to_string(),
        socket_ip.as_ref(),
        "the typed peer and the pre-formatted string must describe one address"
    );
}

#[test]
fn h3_migration_onto_a_mapped_path_keeps_one_principal() {
    // The connection starts natively over IPv4 and migrates to a dual-stack
    // path that reports the same host as `::ffff:…`. The refreshed identity
    // must be the same principal, or the migrated client would silently get a
    // second per-IP budget and a second GeoIP decision mid-connection.
    let (_, before) = h3_identity("198.51.100.7:443");
    let (after_peer, after) = h3_identity("[::ffff:198.51.100.7]:998");
    assert_eq!(before, after);
    assert_eq!(after_peer.port(), 998, "the migrated port is preserved");

    // Migrating to a genuinely different IPv6 address is a real identity change.
    let (_, elsewhere) = h3_identity("[2001:db8::7]:998");
    assert_ne!(before, elsewhere);
}
