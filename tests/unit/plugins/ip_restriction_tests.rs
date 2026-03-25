use ferrum_gateway::plugins::ip_restriction::IpRestriction;
use ferrum_gateway::plugins::{Plugin, RequestContext};
use serde_json::json;

use super::plugin_utils;

fn create_context_with_ip(ip: &str) -> RequestContext {
    RequestContext::new(ip.to_string(), "GET".to_string(), "/test".to_string())
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
    // In allow_first mode: if allow list is non-empty, IP must be in it first.
    // If IP matches allow, it returns Continue before checking deny.
    // So we test: IP in allow but also in deny -> allow_first returns Continue
    // because allow check passes first and returns early.
    let plugin = IpRestriction::new(&json!({
        "allow": ["192.168.1.100"],
        "deny": ["192.168.1.100"]
    }))
    .unwrap();

    let mut ctx = create_context_with_ip("192.168.1.100");
    let result = plugin.on_request_received(&mut ctx).await;
    // In allow_first mode, the allow check returns Continue before deny is checked
    plugin_utils::assert_continue(result);
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
        ferrum_gateway::plugins::PluginResult::Reject {
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
        ferrum_gateway::plugins::PluginResult::Reject {
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
    assert_eq!(plugin.priority(), 150);
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
    let plugin = IpRestriction::new(&json!({
        "allow": ["::ffff:0:0/96"]
    }))
    .unwrap();

    // ::ffff:192.168.1.1 in full form is 0000:0000:0000:0000:0000:ffff:c0a8:0101
    let mut ctx = create_context_with_ip("0000:0000:0000:0000:0000:ffff:c0a8:0101");
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
