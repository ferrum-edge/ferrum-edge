use ferrum_edge::plugins::ip_restriction::IpRestriction;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, RequestContext, StreamConnectionContext, priority,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use super::plugin_utils;

fn create_context_with_ip(ip: &str) -> RequestContext {
    RequestContext::new(ip.to_string(), "GET".to_string(), "/test".to_string())
}

fn create_stream_context_with_ip(ip: &str) -> StreamConnectionContext {
    StreamConnectionContext {
        client_ip: ip.to_string(),
        direct_client_ip: ip.to_string(),
        canonical_client_ip: Default::default(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 8080,
        backend_scheme: ferrum_edge::config::types::BackendScheme::Tcp,
        consumer_index: Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
        identified_consumer: None,
        authenticated_identity: None,
        auth_method: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
        mesh_direction: None,
        node_waypoint_policy_scope: None,
        first_bytes: None,
        first_bytes_kind: None,
    }
}

// ── Allow mode tests ────────────────────────────────────────────────

#[tokio::test]
async fn allow_mode_ip_in_allow_list_passes() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.100", "10.0.0.1"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.100");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn allow_mode_ip_not_in_allow_list_is_rejected() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.100", "10.0.0.1"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("172.16.0.5");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Deny mode tests ─────────────────────────────────────────────────

#[tokio::test]
async fn deny_mode_ip_in_deny_list_is_rejected() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["192.168.1.100"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.100");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_mode_ip_not_in_deny_list_passes() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["192.168.1.100"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("10.0.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

// ── CIDR matching ───────────────────────────────────────────────────

#[tokio::test]
async fn allow_mode_cidr_match_passes() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.0/24"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.42");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn allow_mode_cidr_no_match_rejects() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.0/24"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.2.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_mode_cidr_match_rejects() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/8"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("10.255.255.255");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_mode_cidr_no_match_passes() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/8"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("172.16.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

// ── IPv6 exact match ────────────────────────────────────────────────

#[tokio::test]
async fn ipv6_exact_match_passes() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn ipv6_exact_match_different_ip_rejects() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("2001:0db8:85a3:0000:0000:8a2e:0370:9999");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── IPv6 CIDR matching ──────────────────────────────────────────────

#[tokio::test]
async fn ipv6_cidr_match_passes() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["2001:db8::/32"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("2001:0db8:aaaa:bbbb:cccc:dddd:eeee:ffff");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn ipv6_cidr_no_match_rejects() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["2001:db8::/32"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("2001:0db9:0000:0000:0000:0000:0000:0001");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn ipv6_cidr_deny_match_rejects() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["fe80::/10"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("fe80:0000:0000:0000:0000:0000:0000:0001");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Empty lists ─────────────────────────────────────────────────────

#[tokio::test]
async fn empty_allow_list_rejects_creation() {
    // Empty allow list (and no deny list) means no rules at all — should fail.
    let result = IpRestriction::new(&json!({
        "allow": []
    }));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("at least one"));
}

#[tokio::test]
async fn empty_deny_list_rejects_creation() {
    // Empty deny list (and no allow list) means no rules at all — should fail.
    let result = IpRestriction::new(&json!({
        "deny": []
    }));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("at least one"));
}

#[tokio::test]
async fn empty_deny_list_deny_first_mode_rejects_creation() {
    // Empty deny list with deny_first mode but no allow list — no rules, should fail.
    let result = IpRestriction::new(&json!({
        "deny": [],
        "mode": "deny_first"
    }));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("at least one"));
}

// ── Default config (no lists) ───────────────────────────────────────

#[tokio::test]
async fn default_config_rejects_creation() {
    // Empty config has no allow or deny rules — should return Err.
    let result = IpRestriction::new(&json!({}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("at least one"));
}

#[tokio::test]
async fn default_config_rejects_creation_for_any_ip() {
    // Empty config should fail creation, not allow any IP through.
    let result = IpRestriction::new(&json!({}));
    assert!(result.is_err());
}

// ── Both allow and deny lists (deny takes precedence in allow_first) ──

#[tokio::test]
async fn allow_first_deny_takes_precedence_when_ip_in_both_lists() {
    // Deny rules override allow rules even in allow_first mode, matching the
    // stream path and avoiding protocol-specific bypasses.
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.100"],
        "deny": ["192.168.1.100"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.100");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_first_deny_takes_precedence_when_ip_in_both_lists() {
    // In deny_first mode: deny is checked first. If IP is in deny list, reject.
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.100"],
        "deny": ["192.168.1.100"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.100");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn allow_first_with_both_lists_ip_only_in_allow() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["10.0.0.1"],
        "deny": ["192.168.1.100"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("10.0.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn allow_first_with_both_lists_ip_in_neither() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["10.0.0.1"],
        "deny": ["192.168.1.100"]
    }))
    .unwrap();

    // IP not in allow list -> rejected (allow list is non-empty, so IP must be in it)
    let mut ctx = create_context_with_ip("172.16.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_first_with_both_lists_ip_only_in_allow() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["10.0.0.1"],
        "deny": ["192.168.1.100"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("10.0.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn deny_first_with_both_lists_ip_in_neither() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["10.0.0.1"],
        "deny": ["192.168.1.100"],
        "mode": "deny_first"
    }))
    .unwrap();

    // Not denied, but not in allow list -> rejected
    let mut ctx = create_context_with_ip("172.16.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

// ── Custom status code ──────────────────────────────────────────────
// The current plugin implementation always uses 403. These tests verify
// that rejection status is consistently 403 for both error messages.

#[tokio::test]
async fn rejected_ip_returns_403_with_not_allowed_message() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["10.0.0.1"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("not allowed"));
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

#[tokio::test]
async fn denied_ip_returns_403_with_denied_message() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["192.168.1.1"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("denied"));
        }
        other => panic!("Expected Reject, got {:?}", other),
    }
}

// ── Plugin metadata ─────────────────────────────────────────────────

#[tokio::test]
async fn plugin_name_is_ip_restriction() {
    let plugin = IpRestriction::new(&json!({"allow": ["0.0.0.0/0"]})).unwrap();
    assert_eq!(plugin.name(), "ip_restriction");
}

#[tokio::test]
async fn plugin_priority_is_150() {
    let plugin = IpRestriction::new(&json!({"allow": ["0.0.0.0/0"]})).unwrap();
    assert_eq!(plugin.priority(), priority::IP_RESTRICTION);
    assert_eq!(plugin.priority(), 150);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
}

// ── IPv6 with :: shorthand ──────────────────────────────────────────

#[tokio::test]
async fn ipv6_loopback_exact_match() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["::1"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("::1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn ipv6_shorthand_cidr_match() {
    // Spec change (commit e7377d94): IPv4-mapped IPv6 addresses
    // (`::ffff:a.b.c.d`) are now normalised to their plain IPv4 form
    // before policy matching, so they MUST match against IPv4 rules rather
    // than the IPv6 mapped-prefix family. This test now uses a true IPv6
    // address that is NOT a mapped IPv4 form so the IPv6 CIDR parser path
    // remains exercised.
    let plugin = IpRestriction::new(&json!({
        "allow": ["2001:db8::/32"]
    }))
    .unwrap();

    // Fully-expanded form of 2001:db8::1 — shorthand parser must still
    // accept the equivalent dot-decomposed form.
    let mut ctx = create_context_with_ip("2001:0db8:0000:0000:0000:0000:0000:0001");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

// ── Multiple IPs in lists ───────────────────────────────────────────

#[tokio::test]
async fn allow_list_with_multiple_entries() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["10.0.0.1", "10.0.0.2", "192.168.1.0/24"]
    }))
    .unwrap();

    // Exact match on second entry
    let mut ctx = create_context_with_ip("10.0.0.2");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // CIDR match
    let mut ctx = create_context_with_ip("192.168.1.50");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);

    // No match
    let mut ctx = create_context_with_ip("172.16.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_list_with_multiple_entries() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.1", "172.16.0.0/12"],
        "mode": "deny_first"
    }))
    .unwrap();

    // Exact match
    let mut ctx = create_context_with_ip("10.0.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));

    // CIDR match
    let mut ctx = create_context_with_ip("172.20.0.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));

    // Not denied
    let mut ctx = create_context_with_ip("192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn allow_first_stream_connect_matches_http_when_ip_in_both_lists() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.100"],
        "deny": ["192.168.1.100"]
    }))
    .unwrap();

    let mut ctx = create_stream_context_with_ip("192.168.1.100");
    let result = plugin.on_stream_connect(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[test]
fn invalid_allow_rule_rejects_creation() {
    let result = IpRestriction::new(&json!({
        "allow": ["not-an-ip"]
    }));

    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("invalid allow rule 'not-an-ip'"),
    );
}

#[test]
fn invalid_deny_cidr_rule_rejects_creation() {
    let result = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/99"],
        "mode": "deny_first"
    }));

    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("invalid deny rule '10.0.0.0/99'"),
    );
}

#[test]
fn invalid_mode_rejects_creation() {
    let result = IpRestriction::new(&json!({
        "allow": ["10.0.0.0/8"],
        "mode": "permit_first"
    }));

    assert!(result.is_err());
    assert!(result.err().unwrap().contains("mode"));
}

#[test]
fn non_array_allow_rejects_creation() {
    let result = IpRestriction::new(&json!({
        "allow": "10.0.0.0/8"
    }));

    assert!(result.is_err());
    assert!(result.err().unwrap().contains("allow"));
}

#[test]
fn empty_rule_string_rejects_creation() {
    let result = IpRestriction::new(&json!({
        "deny": [""]
    }));

    assert!(result.is_err());
    assert!(result.err().unwrap().contains("non-empty"));
}

// ── IPv6 zone identifier handling ───────────────────────────────────
// A malformed X-Forwarded-For from an upstream proxy could surface a
// client IP with a zone suffix (e.g. "fe80::1%eth0"). Stripping the zone
// before matching prevents these IPs from being treated as `Unknown` and
// silently bypassing deny rules.

#[tokio::test]
async fn ipv6_client_ip_with_zone_suffix_matches_deny_rule() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["fe80::/10"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("fe80::1%eth0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn ipv6_client_ip_with_zone_suffix_matches_exact_allow_rule() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["fe80::1"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("fe80::1%wlan0");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn ipv6_rule_with_zone_suffix_is_normalized_to_address() {
    // Operators should not put zones in rules, but if they do, the suffix is
    // stripped at parse time so the rule still matches the bare IPv6 address.
    let plugin = IpRestriction::new(&json!({
        "allow": ["fe80::1%eth0"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("fe80::1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn ipv6_mapped_ipv4_form_matches_cidr_without_heap_parser() {
    // Spec change (commit e7377d94): client IPs supplied in IPv4-mapped
    // IPv6 form are normalised to plain IPv4 before policy matching, so
    // they MUST be allowed via IPv4 rules. The companion test
    // `ipv4_rule_matches_ipv4_mapped_ipv6_client` covers the deny side of
    // the same contract.
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.0.0/16"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("::ffff:192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[test]
fn ipv4_too_many_octets_is_rejected() {
    // Defensive — make sure the optimized parser still catches over-long IPv4.
    let result = IpRestriction::new(&json!({
        "allow": ["1.2.3.4.5"]
    }));
    assert!(result.is_err());
}

#[test]
fn ipv6_only_literal_decorations_do_not_broaden_ipv4_rules() {
    use ferrum_edge::plugins::ip_restriction::ip_matches;

    assert!(!ip_matches("[192.0.2.1]", "192.0.2.1"));
    assert!(!ip_matches("192.0.2.1%eth0", "192.0.2.1"));
    assert!(!ip_matches("192.0.2.1", "[192.0.2.1]"));
    assert!(!ip_matches("192.0.2.1", "192.0.2.1%eth0"));
}

#[tokio::test]
async fn ipv4_rule_matches_ipv4_mapped_ipv6_client() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["192.168.1.0/24"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("::ffff:192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_mode_ipv4_mapped_ipv6_exact_rule_rejects_ipv4_mapped_client() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["::ffff:192.168.1.100"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("::ffff:192.168.1.100");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_mode_ipv4_mapped_ipv6_cidr_rule_rejects_ipv4_mapped_client() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["::ffff:192.168.1.0/120"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("::ffff:192.168.1.42");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_mode_ipv4_mapped_ipv6_exact_rule_rejects_canonicalized_ipv4_client() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["::ffff:192.168.1.100"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.100");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn deny_mode_ipv4_mapped_ipv6_cidr_rule_rejects_canonicalized_ipv4_client() {
    let plugin = IpRestriction::new(&json!({
        "deny": ["::ffff:192.168.1.0/120"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.42");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[test]
fn mapped_ipv6_cidr_prefixes_below_96_reject_construction() {
    for prefix in [0, 64, 95] {
        let config = json!({"allow": [format!("::ffff:192.0.2.44/{prefix}")]});
        let error = IpRestriction::new(&config)
            .err()
            .expect("mapped IPv6 CIDRs below /96 must be rejected");
        assert!(error.contains("invalid allow rule"), "{error}");
    }
}

#[tokio::test]
async fn mapped_ipv6_cidr_prefix_boundaries_map_to_ipv4() {
    let all_ipv4 = IpRestriction::new(&json!({
        "allow": ["::ffff:192.0.2.44/96"]
    }))
    .unwrap();
    let mut ipv4 = create_context_with_ip("203.0.113.9");
    plugin_utils::assert_continue(all_ipv4.on_request_received(&mut ipv4).await);
    let mut ipv6 = create_context_with_ip("2001:db8::1");
    plugin_utils::assert_reject(all_ipv4.on_request_received(&mut ipv6).await, Some(403));

    let exact_ipv4 = IpRestriction::new(&json!({
        "allow": ["::ffff:192.0.2.44/128"]
    }))
    .unwrap();
    let mut exact = create_context_with_ip("192.0.2.44");
    plugin_utils::assert_continue(exact_ipv4.on_request_received(&mut exact).await);
    let mut adjacent = create_context_with_ip("192.0.2.45");
    plugin_utils::assert_reject(
        exact_ipv4.on_request_received(&mut adjacent).await,
        Some(403),
    );
}

#[test]
fn noncanonical_ipv4_rule_literals_reject_construction() {
    for rule in [
        "010.1.2.3",
        "+10.1.2.3",
        "10.01.2.3",
        "10.1.2.03",
        "010.1.2.3/24",
        "+10.1.2.3/24",
    ] {
        let config = json!({"deny": [rule]});
        assert!(
            IpRestriction::new(&config).is_err(),
            "non-canonical IPv4 rule must be rejected: {rule}"
        );
    }
}

#[test]
fn canonical_ipv4_rule_literals_remain_valid() {
    for rule in ["0.0.0.0", "10.1.2.3", "255.255.255.255/32"] {
        let config = json!({"deny": [rule]});
        assert!(
            IpRestriction::new(&config).is_ok(),
            "canonical IPv4 rule must remain valid: {rule}"
        );
    }
}

// ── Fail closed on unparseable client IP (finding #10) ──────────────
// An unparseable client IP (e.g. a malformed X-Forwarded-For token that
// survives upstream sourcing) must NOT bypass a deny rule. Before the fix,
// a deny-only config fell through to Continue because Unknown matched no
// rule and the allow-enforcement branch was skipped for an empty allow list.

#[tokio::test]
async fn deny_first_deny_only_rejects_unparseable_client_ip() {
    // Classic "block these bad IPs" config: deny list, no allow list,
    // deny_first mode. An unparseable IP previously fell through to Continue.
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/8"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("not-an-ip");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn allow_first_deny_only_rejects_unparseable_client_ip() {
    // Deny-only config in the default allow_first mode also failed open for
    // Unknown because the allow-enforcement branch was guarded by a non-empty
    // allow list.
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/8"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("garbage value");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn empty_string_client_ip_is_rejected() {
    // An empty client IP is unparseable and must fail closed under a
    // deny-only config rather than silently pass.
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/8"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn unparseable_client_ip_rejected_on_stream_path() {
    // The stream (TCP/UDP) path goes through the same check_ip, so it must
    // also fail closed on an unparseable client IP under a deny-only config.
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/8"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_stream_context_with_ip("not-an-ip");
    let result = plugin.on_stream_connect(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn allow_list_still_rejects_unparseable_client_ip() {
    // Allow-list configs already failed closed for Unknown; confirm the fix
    // does not regress that behavior (still rejected, now via the up-front
    // unparseable-IP guard).
    let plugin = IpRestriction::new(&json!({
        "allow": ["10.0.0.0/8"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("not-an-ip");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn parseable_client_ip_not_affected_by_fail_closed_guard() {
    // Regression guard: a normal parseable IP that is not denied must still
    // pass under a deny-only config — the fail-closed branch must only trigger
    // for genuinely unparseable input.
    let plugin = IpRestriction::new(&json!({
        "deny": ["10.0.0.0/8"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

// ── Family-scoped zero-length CIDR prefixes ────────────────────────
// Standard CIDR rules are address-family scoped: `0.0.0.0/0` matches all
// IPv4 addresses, and `::/0` matches all IPv6 addresses. They must not satisfy
// an allow-list check for the opposite address family on a dual-stack listener.

#[tokio::test]
async fn ipv4_zero_cidr_allow_rejects_ipv6_client() {
    // `0.0.0.0/0` as an allow rule must not permit an IPv6 client.
    let plugin = IpRestriction::new(&json!({
        "allow": ["0.0.0.0/0"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("2001:db8::1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn ipv6_zero_cidr_allow_rejects_ipv4_client() {
    // `::/0` as an allow rule must not permit an IPv4 client.
    let plugin = IpRestriction::new(&json!({
        "allow": ["::/0"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[tokio::test]
async fn ipv6_zero_cidr_deny_does_not_block_ipv4_client() {
    // `::/0` is IPv6-only, so it must not deny an IPv4 client.
    let plugin = IpRestriction::new(&json!({
        "deny": ["::/0"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn ipv4_zero_cidr_deny_does_not_block_ipv6_client() {
    // The mirror case: `0.0.0.0/0` is IPv4-only, so it must not deny IPv6.
    let plugin = IpRestriction::new(&json!({
        "deny": ["0.0.0.0/0"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("2001:db8::1");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_continue(result);
}

#[tokio::test]
async fn zero_cidr_matches_same_family_client() {
    // Sanity: zero-length CIDR prefixes still match their own family.
    let plugin = IpRestriction::new(&json!({
        "deny": ["0.0.0.0/0"],
        "mode": "deny_first"
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("203.0.113.5");
    let result = plugin.on_request_received(&mut ctx).await;
    plugin_utils::assert_reject(result, Some(403));
}

#[test]
fn ip_matches_zero_cidr_is_family_scoped() {
    use ferrum_edge::plugins::ip_restriction::ip_matches;

    assert!(!ip_matches("2001:db8::1", "0.0.0.0/0"));
    assert!(!ip_matches("192.168.1.1", "::/0"));
    assert!(ip_matches("10.0.0.1", "0.0.0.0/0"));
    assert!(ip_matches("fe80::1", "::/0"));
    assert!(!ip_matches("not-an-ip", "0.0.0.0/0"));
    assert!(!ip_matches("not-an-ip", "::/0"));
}

// ── Strict configuration contract ──────────────────────────────────

#[test]
fn config_must_be_an_object() {
    for config in [json!(null), json!([]), json!(true), json!("allow all")] {
        let error = IpRestriction::new(&config)
            .err()
            .expect("non-object config must be rejected");
        assert!(error.contains("config must be an object"), "{error}");
    }
}

#[test]
fn unknown_keys_are_rejected_even_when_another_policy_list_is_valid() {
    for config in [
        json!({"alow": ["10.0.0.0/8"], "deny": ["192.0.2.0/24"]}),
        json!({"allow": ["10.0.0.0/8"], "denny": ["192.0.2.0/24"]}),
        json!({"allow": ["10.0.0.0/8"], "mod": "deny_first"}),
    ] {
        let error = IpRestriction::new(&config)
            .err()
            .expect("unknown key must be rejected");
        assert!(error.contains("unknown configuration field"), "{error}");
        assert!(error.contains("allow, deny, mode"), "{error}");
    }
}

#[test]
fn shared_admin_and_config_admission_rejects_broadened_policy_shape() {
    let config = json!({
        "alow": ["10.0.0.0/8"],
        "deny": ["192.0.2.0/24"]
    });
    let error = ferrum_edge::plugins::validate_plugin_config("ip_restriction", &config)
        .expect_err("shared plugin admission must reject the typo");
    assert!(
        error.contains("unknown configuration field 'alow'"),
        "{error}"
    );
}

#[test]
fn null_and_malformed_rule_arrays_are_rejected() {
    for config in [
        json!({"allow": null, "deny": ["192.0.2.0/24"]}),
        json!({"allow": ["10.0.0.0/8"], "deny": null}),
        json!({"allow": {"cidr": "10.0.0.0/8"}}),
        json!({"deny": ["192.0.2.1", null]}),
        json!({"allow": ["10.0.0.1", 7]}),
    ] {
        assert!(
            IpRestriction::new(&config).is_err(),
            "malformed rule array must be rejected: {config}"
        );
    }
}

#[test]
fn explicit_null_mode_is_rejected() {
    let error = IpRestriction::new(&json!({
        "allow": ["10.0.0.0/8"],
        "mode": null
    }))
    .err()
    .expect("null mode must not silently select allow_first");
    assert!(error.contains("mode"));
}

#[test]
fn one_empty_list_is_allowed_only_when_the_other_list_enforces_policy() {
    assert!(IpRestriction::new(&json!({"allow": [], "deny": ["192.0.2.0/24"]})).is_ok());
    assert!(IpRestriction::new(&json!({"allow": ["10.0.0.0/8"], "deny": []})).is_ok());
    assert!(IpRestriction::new(&json!({"allow": [], "deny": []})).is_err());
}

// ── Compiled range-index regressions ───────────────────────────────

fn sparse_ipv4_rules(count: u32) -> Vec<String> {
    (0..count)
        .map(|index| Ipv4Addr::from(0x0a00_0001_u32 + index * 2).to_string())
        .collect()
}

#[tokio::test]
async fn ten_thousand_rule_miss_and_high_address_match_preserve_decisions() {
    let rules = sparse_ipv4_rules(10_000);
    let high_match = rules
        .last()
        .expect("large fixture has a final rule")
        .clone();
    let plugin = IpRestriction::new(&json!({"allow": rules})).unwrap();

    let mut miss = create_context_with_ip("203.0.113.250");
    plugin_utils::assert_reject(plugin.on_request_received(&mut miss).await, Some(403));

    let mut high = create_context_with_ip(&high_match);
    plugin_utils::assert_continue(plugin.on_request_received(&mut high).await);
}

#[tokio::test]
async fn ten_thousand_rule_deny_miss_continues() {
    let plugin = IpRestriction::new(&json!({
        "deny": sparse_ipv4_rules(10_000),
        "mode": "deny_first"
    }))
    .unwrap();
    let mut miss = create_context_with_ip("203.0.113.250");
    plugin_utils::assert_continue(plugin.on_request_received(&mut miss).await);
}

#[tokio::test]
async fn duplicate_and_overlapping_ranges_keep_deny_precedence() {
    let plugin = IpRestriction::new(&json!({
        "allow": [
            "10.0.0.0/8",
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.1.2.3",
            "10.1.2.3"
        ],
        "deny": ["10.1.2.128/25", "10.1.2.192/26", "10.1.2.200"]
    }))
    .unwrap();

    let mut allowed_overlap = create_context_with_ip("10.1.2.127");
    plugin_utils::assert_continue(plugin.on_request_received(&mut allowed_overlap).await);

    for denied in ["10.1.2.128", "10.1.2.200", "10.1.2.255"] {
        let mut ctx = create_context_with_ip(denied);
        plugin_utils::assert_reject(plugin.on_request_received(&mut ctx).await, Some(403));
    }
}

#[tokio::test]
async fn merged_prefix_boundaries_remain_inclusive_and_family_scoped() {
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.0.2.0/31", "2001:db8::/127"]
    }))
    .unwrap();

    for allowed in ["192.0.2.0", "192.0.2.1", "2001:db8::", "2001:db8::1"] {
        let mut ctx = create_context_with_ip(allowed);
        plugin_utils::assert_continue(plugin.on_request_received(&mut ctx).await);
    }
    for outside in ["192.0.2.2", "2001:db8::2"] {
        let mut ctx = create_context_with_ip(outside);
        plugin_utils::assert_reject(plugin.on_request_received(&mut ctx).await, Some(403));
    }
}

// ── Typed client-IP reuse across instances ─────────────────────────

#[tokio::test]
async fn multiple_http_instances_share_one_canonical_client_ip() {
    let deny_other = IpRestriction::new(&json!({"deny": ["198.51.100.0/24"]})).unwrap();
    let allow_client = IpRestriction::new(&json!({"allow": ["192.0.2.0/24"]})).unwrap();
    let mut ctx = create_context_with_ip("::ffff:192.0.2.44");

    assert!(!ctx.canonical_client_ip_is_initialized());
    plugin_utils::assert_continue(deny_other.on_request_received(&mut ctx).await);
    assert!(ctx.canonical_client_ip_is_initialized());
    assert!(matches!(ctx.canonical_client_ip(), Some(IpAddr::V4(_))));
    plugin_utils::assert_continue(allow_client.on_request_received(&mut ctx).await);
}

#[tokio::test]
async fn multiple_stream_instances_share_one_canonical_client_ip() {
    let deny_other = IpRestriction::new(&json!({"deny": ["2001:db8:ffff::/48"]})).unwrap();
    let allow_client = IpRestriction::new(&json!({"allow": ["2001:db8::/32"]})).unwrap();
    let mut ctx = create_stream_context_with_ip("2001:db8::44");

    assert!(!ctx.canonical_client_ip_is_initialized());
    plugin_utils::assert_continue(deny_other.on_stream_connect(&mut ctx).await);
    assert!(ctx.canonical_client_ip_is_initialized());
    plugin_utils::assert_continue(allow_client.on_stream_connect(&mut ctx).await);
}

#[tokio::test]
async fn malformed_client_ip_is_cached_and_fails_closed_for_every_instance() {
    let first = IpRestriction::new(&json!({"deny": ["10.0.0.0/8"]})).unwrap();
    let second = IpRestriction::new(&json!({"deny": ["192.168.0.0/16"]})).unwrap();
    let mut ctx = create_context_with_ip("not-an-ip");

    plugin_utils::assert_reject(first.on_request_received(&mut ctx).await, Some(403));
    assert!(ctx.canonical_client_ip_is_initialized());
    assert_eq!(ctx.canonical_client_ip(), None);
    plugin_utils::assert_reject(second.on_request_received(&mut ctx).await, Some(403));
}
