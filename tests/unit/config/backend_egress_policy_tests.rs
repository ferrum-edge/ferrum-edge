//! Tests for the resolved backend egress policy (`BackendEgressPolicy`):
//! the SSRF posture that composes the `FERRUM_BACKEND_ALLOW_IPS` mode with
//! `FERRUM_BACKEND_ALLOW_CIDRS` / `FERRUM_BACKEND_DENY_CIDRS` and the
//! dangerous-range baseline.

use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, is_always_blocked_range};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid test IP literal")
}

/// The production default: mode `both` + dangerous-range baseline on, no CIDR
/// overlays. This is what a gateway gets with no `FERRUM_BACKEND_*` env vars.
fn default_policy() -> BackendEgressPolicy {
    BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid default")
}

// ── Default posture: dangerous ranges blocked, real backends allowed ────────

#[test]
fn default_blocks_cloud_metadata_and_link_local() {
    let p = default_policy();
    // The canonical SSRF pivot and the whole link-local /16.
    assert!(!p.is_allowed(&ip("169.254.169.254")));
    assert!(!p.is_allowed(&ip("169.254.42.42")));
    // IPv6 link-local.
    assert!(!p.is_allowed(&ip("fe80::1")));
    // IPv4-mapped metadata must be caught too.
    assert!(!p.is_allowed(&ip("::ffff:169.254.169.254")));
    // AWS EC2 IPv6 instance metadata (IMDSv6), inside ULA — blocked, but
    // ordinary ULA backends stay allowed.
    assert!(!p.is_allowed(&ip("fd00:ec2::254")));
    assert!(p.is_allowed(&ip("fd00:ec2::1")));
    assert!(p.is_allowed(&ip("fd12:3456::1")));
    // NAT64 well-known prefix (64:ff9b::/96) encoding the IPv4 metadata address
    // must be blocked too (IPv6-only / NAT64 rebinding), while NAT64 of a public
    // address stays allowed.
    assert!(!p.is_allowed(&ip("64:ff9b::a9fe:a9fe"))); // 169.254.169.254
    assert!(!p.is_allowed(&ip("64:ff9b::e000:1"))); // 224.0.0.1 (multicast)
    assert!(p.is_allowed(&ip("64:ff9b::808:808"))); // 8.8.8.8
    // Alibaba Cloud / ENS IMDS host (100.100.100.200) sits in CGNAT, not
    // link-local — block the EXACT host while leaving the rest of CGNAT allowed,
    // including the IPv4-mapped and NAT64 encodings (IPv6-only / rebinding).
    assert!(!p.is_allowed(&ip("100.100.100.200")));
    assert!(!p.is_allowed(&ip("::ffff:100.100.100.200")));
    assert!(!p.is_allowed(&ip("64:ff9b::6464:64c8"))); // 100.100.100.200
    assert!(p.is_allowed(&ip("100.100.100.201"))); // adjacent CGNAT host stays allowed
    assert!(p.is_allowed(&ip("100.64.0.1"))); // ordinary CGNAT backend stays allowed
    // NAT64 local-use prefix (RFC 8215, 64:ff9b:1::/48) encoding the IPv4 IMDS
    // must be blocked too — both the contiguous embedding and a NAT64 of a
    // public address (which stays allowed).
    assert!(!p.is_allowed(&ip("64:ff9b:1:a9fe:a9fe::"))); // 169.254.169.254
    assert!(!p.is_allowed(&ip("64:ff9b:1:6464:64c8::"))); // 100.100.100.200 (Alibaba)
    assert!(p.is_allowed(&ip("64:ff9b:1:808:808::"))); // 8.8.8.8 (public) stays allowed
}

#[test]
fn default_blocks_multicast_unspecified_broadcast() {
    let p = default_policy();
    assert!(!p.is_allowed(&ip("224.0.0.1"))); // v4 multicast
    assert!(!p.is_allowed(&ip("239.255.255.250")));
    assert!(!p.is_allowed(&ip("ff02::1"))); // v6 multicast
    assert!(!p.is_allowed(&ip("0.0.0.0"))); // unspecified / this-host
    assert!(!p.is_allowed(&ip("0.1.2.3"))); // 0.0.0.0/8
    assert!(!p.is_allowed(&ip("::"))); // v6 unspecified
    assert!(!p.is_allowed(&ip("255.255.255.255"))); // limited broadcast
}

#[test]
fn default_allows_loopback_rfc1918_and_public() {
    let p = default_policy();
    // Loopback: mesh inbound dials 127.0.0.1, sidecars use it — must work.
    assert!(p.is_allowed(&ip("127.0.0.1")));
    assert!(p.is_allowed(&ip("::1")));
    // RFC1918: the primary backend case.
    assert!(p.is_allowed(&ip("10.0.0.1")));
    assert!(p.is_allowed(&ip("172.16.4.4")));
    assert!(p.is_allowed(&ip("192.168.1.10")));
    // IPv6 ULA (the RFC1918 equivalent) and CGNAT stay allowed.
    assert!(p.is_allowed(&ip("fc00::1")));
    assert!(p.is_allowed(&ip("100.64.0.1")));
    // Ordinary public addresses.
    assert!(p.is_allowed(&ip("8.8.8.8")));
    assert!(p.is_allowed(&ip("2606:4700:4700::1111")));
}

// ── is_always_blocked_range is a strict subset of is_private_ip ─────────────

#[test]
fn baseline_handles_ipv4_mapped_and_compat_forms() {
    // Loopback in every form stays allowed.
    assert!(!is_always_blocked_range(&ip("::1")));
    // IPv4-mapped (`::ffff:a.b.c.d`) and deprecated IPv4-compatible (`::a.b.c.d`)
    // dangerous addresses are both caught.
    assert!(is_always_blocked_range(&ip("::ffff:169.254.169.254")));
    assert!(is_always_blocked_range(&ip("::169.254.169.254")));
    assert!(is_always_blocked_range(&ip("::ffff:0.0.0.0")));
    // ...but a mapped public / RFC1918 address is treated as its v4 form.
    assert!(!is_always_blocked_range(&ip("::ffff:8.8.8.8")));
    assert!(!is_always_blocked_range(&ip("::ffff:10.0.0.1")));
}

#[test]
fn baseline_predicate_excludes_loopback_and_rfc1918() {
    // The baseline must NOT include loopback / RFC1918 / ULA.
    assert!(!is_always_blocked_range(&ip("127.0.0.1")));
    assert!(!is_always_blocked_range(&ip("::1")));
    assert!(!is_always_blocked_range(&ip("10.0.0.1")));
    assert!(!is_always_blocked_range(&ip("192.168.1.1")));
    assert!(!is_always_blocked_range(&ip("fc00::1")));
    // But it DOES include the never-legit pivots.
    assert!(is_always_blocked_range(&ip("169.254.169.254")));
    assert!(is_always_blocked_range(&ip("224.0.0.1")));
    assert!(is_always_blocked_range(&ip("0.0.0.0")));
    assert!(is_always_blocked_range(&ip("::")));
    assert!(is_always_blocked_range(&ip("fe80::1")));
}

// ── Allow-CIDR escape hatch ─────────────────────────────────────────────────

#[test]
fn allow_cidr_reenables_a_blocked_metadata_address() {
    // Operator who genuinely runs an IMDS proxy re-allows the exact address.
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Both, "169.254.169.254/32", "", true)
        .expect("valid");
    assert!(p.is_allowed(&ip("169.254.169.254")));
    // ...but the rest of the link-local range stays blocked.
    assert!(!p.is_allowed(&ip("169.254.1.1")));
}

#[test]
fn allow_cidr_overrides_public_mode_for_private_backend() {
    // Public-only egress, but carve out one internal /24.
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Public, "10.1.2.0/24", "", true)
        .expect("valid");
    assert!(p.is_allowed(&ip("10.1.2.5"))); // carved out
    assert!(!p.is_allowed(&ip("10.9.9.9"))); // still denied (private under public)
    assert!(p.is_allowed(&ip("8.8.8.8"))); // public still fine
}

// ── Deny-CIDR ───────────────────────────────────────────────────────────────

#[test]
fn deny_cidr_blocks_within_an_otherwise_allowed_mode() {
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.0.0.0/8", true)
        .expect("valid");
    assert!(!p.is_allowed(&ip("10.5.5.5")));
    assert!(p.is_allowed(&ip("11.0.0.1")));
    assert!(p.is_allowed(&ip("192.168.1.1"))); // other RFC1918 unaffected
}

#[test]
fn deny_cidr_matches_ipv6_embedded_forms() {
    // A v4 deny rule must also catch a backend that resolves to the IPv6
    // encoding of that v4 range (rebinding), and the allow-CIDR escape hatch
    // works on the embedded form too.
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.0.0.0/8", true)
        .expect("valid");
    assert!(!p.is_allowed(&ip("10.0.0.1"))); // raw v4
    assert!(!p.is_allowed(&ip("::ffff:10.0.0.1"))); // IPv4-mapped
    assert!(!p.is_allowed(&ip("64:ff9b::a00:1"))); // well-known NAT64 of 10.0.0.1
    assert!(!p.is_allowed(&ip("64:ff9b:1:a00:1::"))); // local-use NAT64 of 10.0.0.1
    // No false embedded match: a different range and loopback stay allowed.
    assert!(p.is_allowed(&ip("11.0.0.1")));
    assert!(p.is_allowed(&ip("64:ff9b:1:b00:1::"))); // local-use NAT64 of 11.0.0.1
    assert!(p.is_allowed(&ip("::1")));

    // Allow-CIDR escape hatch also matches the embedded form.
    let carved = BackendEgressPolicy::from_env(BackendAllowIps::Public, "10.1.2.0/24", "", true)
        .expect("valid");
    assert!(carved.is_allowed(&ip("64:ff9b::a01:205"))); // NAT64 of 10.1.2.5
}

#[test]
fn deny_cidr_matches_both_local_use_nat64_layouts() {
    // A NAT64 local-use prefix (64:ff9b:1::/48) can embed the IPv4 contiguously
    // OR in the RFC 6052 /48 u-byte-split layout. With a /24 deny the two
    // decodings of the same address diverge, so both must be checked:
    //   64:ff9b:1:a01:205::    = 10.1.2.5 contiguous
    //   64:ff9b:1:a01:2:500::  = 10.1.2.5 under RFC 6052 (10.1.0.2 contiguous)
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.1.2.0/24", true)
        .expect("valid");
    assert!(!p.is_allowed(&ip("10.1.2.5"))); // raw v4
    assert!(!p.is_allowed(&ip("64:ff9b:1:a01:205::"))); // contiguous layout
    assert!(!p.is_allowed(&ip("64:ff9b:1:a01:2:500::"))); // RFC 6052 /48 layout
    // Neither layout of this address lands in 10.1.2.0/24 → stays allowed.
    assert!(p.is_allowed(&ip("64:ff9b:1:a02:2:500::")));
}

#[test]
fn ambiguous_local_use_nat64_deny_wins_over_cross_decode_allow() {
    // A NAT64 local-use address decodes to TWO IPv4s; an allow match on one decode
    // must NOT override a deny match on the other (the backend could resolve to
    // either layout). `64:ff9b:1:a01:2:500::` is 10.1.0.2 contiguously (allow-listed)
    // but 10.1.2.5 under RFC 6052 (deny-listed) — so it must be DENIED.
    let p = BackendEgressPolicy::from_env(
        BackendAllowIps::Both,
        "10.1.0.2/32", // allow the contiguous decode
        "10.1.2.0/24", // deny the RFC 6052 decode's range
        true,
    )
    .expect("valid");
    assert!(p.is_allowed(&ip("10.1.0.2"))); // the allow-listed decode on its own
    assert!(!p.is_allowed(&ip("10.1.2.5"))); // the denied decode on its own
    assert!(!p.is_allowed(&ip("64:ff9b:1:a01:2:500::"))); // ambiguous: deny wins

    // Escape hatch still works when BOTH decodes are explicitly allow-listed.
    let both = BackendEgressPolicy::from_env(
        BackendAllowIps::Both,
        "10.1.0.2/32,10.1.2.5/32",
        "10.1.2.0/24",
        true,
    )
    .expect("valid");
    assert!(both.is_allowed(&ip("64:ff9b:1:a01:2:500::")));

    // The same protection covers the dangerous-range baseline: allow-listing only
    // one decode of a NAT64-encoded IMDS address must not let it through, because
    // the other decode is still link-local.
    let imds = BackendEgressPolicy::from_env(BackendAllowIps::Both, "169.254.169.254/32", "", true)
        .expect("valid");
    assert!(!imds.is_allowed(&ip("64:ff9b:1:a9fe:a9fe::")));
}

#[test]
fn public_mode_blocks_local_use_nat64_with_public_decodes() {
    // Under `public` mode all private/reserved backends are blocked. A local-use
    // NAT64 literal (64:ff9b:1::/48) is ITSELF private/reserved (`is_private_ip`
    // classifies the whole RFC 8215 prefix as private), so it must be blocked even
    // when both decoded IPv4s are public (8.8.8.8) — the decode checks alone don't
    // catch it, the original IPv6's mode check does.
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Public, "", "", true).expect("valid");
    assert!(p.is_allowed(&ip("8.8.8.8"))); // the public decode on its own
    assert!(!p.is_allowed(&ip("64:ff9b:1:808:808::"))); // private NAT64 prefix blocked
    // The allow-CIDR escape hatch still re-permits it (allow > mode).
    let carved = BackendEgressPolicy::from_env(BackendAllowIps::Public, "8.8.8.8/32", "", true)
        .expect("valid");
    assert!(carved.is_allowed(&ip("64:ff9b:1:808:808::")));
}

#[test]
fn deny_ipv6_cidr_blocks_local_use_nat64_literal() {
    // An IPv6-form deny CIDR on the local-use NAT64 prefix must block the literal
    // even when both decoded IPv4s would otherwise pass under `both` mode — the
    // shared precedence applies deny_cidrs to the original IPv6 address, not just
    // the decodes.
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "64:ff9b:1::/48", true)
        .expect("valid");
    assert!(!p.is_allowed(&ip("64:ff9b:1:808:808::"))); // public decodes, IPv6 prefix denied
    assert!(p.is_allowed(&ip("8.8.8.8"))); // bare decode unaffected by the IPv6 deny
    // An explicit allow CIDR still overrides the IPv6 deny (allow > deny).
    let carved = BackendEgressPolicy::from_env(
        BackendAllowIps::Both,
        "64:ff9b:1::/48",
        "64:ff9b:1::/48",
        true,
    )
    .expect("valid");
    assert!(carved.is_allowed(&ip("64:ff9b:1:808:808::")));
}

#[test]
fn allow_cidr_takes_precedence_over_deny_cidr() {
    // Overlapping allow + deny: allow wins (checked first).
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Both, "10.0.0.5/32", "10.0.0.0/8", true)
        .expect("valid");
    assert!(p.is_allowed(&ip("10.0.0.5"))); // allow-listed host
    assert!(!p.is_allowed(&ip("10.0.0.6"))); // still denied by the /8
}

// ── Mode behaviour (public/private) is preserved ────────────────────────────

#[test]
fn public_mode_rejects_private_allows_public() {
    let p = BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public);
    assert!(!p.is_allowed(&ip("10.0.0.1")));
    assert!(!p.is_allowed(&ip("127.0.0.1")));
    assert!(p.is_allowed(&ip("8.8.8.8")));
}

#[test]
fn private_mode_rejects_public_allows_private() {
    let p = BackendEgressPolicy::from_allow_ips(BackendAllowIps::Private);
    assert!(p.is_allowed(&ip("10.0.0.1")));
    assert!(!p.is_allowed(&ip("8.8.8.8")));
}

// ── Opt-out of the baseline ─────────────────────────────────────────────────

#[test]
fn baseline_disabled_allows_metadata_again() {
    // FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false restores the old open posture.
    let p = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", false).expect("valid");
    assert!(p.is_allowed(&ip("169.254.169.254")));
    assert!(p.is_allowed(&ip("0.0.0.0")));
}

#[test]
fn unrestricted_allows_everything() {
    let p = BackendEgressPolicy::unrestricted();
    assert!(p.is_allowed(&ip("169.254.169.254")));
    assert!(p.is_allowed(&ip("127.0.0.1")));
    assert!(p.is_allowed(&ip("10.0.0.1")));
    assert!(p.is_allowed(&ip("8.8.8.8")));
}

// ── is_fully_open ───────────────────────────────────────────────────────────

#[test]
fn is_fully_open_only_when_nothing_can_deny() {
    assert!(BackendEgressPolicy::unrestricted().is_fully_open());
    // baseline on => not fully open (this is the production default)
    assert!(!default_policy().is_fully_open());
    // baseline off + both + no deny => fully open
    assert!(
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", false)
            .unwrap()
            .is_fully_open()
    );
    // a deny CIDR makes it not-fully-open even with baseline off
    assert!(
        !BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.0.0.0/8", false)
            .unwrap()
            .is_fully_open()
    );
    // public mode is never fully open
    assert!(!BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public).is_fully_open());
    // allow-CIDRs alone (which only ever permit) do not stop it being fully open
    assert!(
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "10.0.0.0/8", "", false)
            .unwrap()
            .is_fully_open()
    );
}

// ── Parsing / error handling ────────────────────────────────────────────────

#[test]
fn invalid_cidr_is_rejected_at_construction() {
    assert!(BackendEgressPolicy::from_env(BackendAllowIps::Both, "not-a-cidr", "", true).is_err());
    assert!(BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.0.0.0/99", true).is_err());
    // The error names which env var was bad.
    let err = BackendEgressPolicy::from_env(BackendAllowIps::Both, "10.0.0.0/8,bogus", "", true)
        .unwrap_err();
    assert!(err.contains("FERRUM_BACKEND_ALLOW_CIDRS"), "got: {err}");
}

#[test]
fn deny_reason_is_actionable() {
    let p = default_policy();
    let reason = p.deny_reason(&ip("169.254.169.254")).expect("denied");
    assert!(
        reason.contains("cloud-metadata") || reason.contains("baseline"),
        "got: {reason}"
    );
    // An allowed address yields no reason.
    assert!(p.deny_reason(&ip("10.0.0.1")).is_none());

    let denied =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "10.0.0.0/8", true).unwrap();
    assert!(
        denied
            .deny_reason(&ip("10.0.0.1"))
            .expect("denied")
            .contains("FERRUM_BACKEND_DENY_CIDRS")
    );
}

#[test]
fn proxy_admission_screens_url_style_ipv4_literals() {
    let p = default_policy();
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "noncanonical-imds",
        "hosts": ["example.com"],
        "backend_host": "2852039166",
        "backend_port": 80
    }))
    .expect("valid proxy shape");

    let errors = proxy
        .validate_backend_egress_ips(&p)
        .expect_err("decimal IPv4 form should be canonicalized and denied");
    assert!(
        errors.iter().any(|err| err.contains("169.254.169.254")),
        "expected canonical metadata IP in error, got {errors:?}"
    );
}

#[test]
fn upstream_admission_screens_url_style_ipv4_literals() {
    let p = default_policy();
    let upstream: ferrum_edge::config::types::Upstream =
        serde_json::from_value(serde_json::json!({
            "id": "noncanonical-imds-upstream",
            "targets": [{ "host": "0xa9fea9fe", "port": 80 }]
        }))
        .expect("valid upstream shape");

    let errors = upstream
        .validate_backend_egress_ips(&p)
        .expect_err("hex IPv4 form should be canonicalized and denied");
    assert!(
        errors.iter().any(|err| err.contains("169.254.169.254")),
        "expected canonical metadata IP in error, got {errors:?}"
    );
}
