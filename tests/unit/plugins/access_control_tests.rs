//! Tests for access_control plugin

use ferrum_gateway::plugins::{Plugin, access_control::AccessControl};
use serde_json::json;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

#[tokio::test]
async fn test_access_control_plugin_creation() {
    let config = json!({
        "allowed_ips": ["127.0.0.1", "10.0.0.0/8"],
        "blocked_ips": ["192.168.1.100"]
    });
    let plugin = AccessControl::new(&config);
    assert_eq!(plugin.name(), "access_control");
}

#[tokio::test]
async fn test_access_control_plugin_allowed_ip() {
    let config = json!({
        "allowed_ips": ["127.0.0.1", "10.0.0.0/8"],
        "blocked_ips": ["192.168.1.100"]
    });
    let plugin = AccessControl::new(&config);

    // Test allowed IP
    let mut allowed_ctx = create_test_context();
    allowed_ctx.client_ip = "127.0.0.1".to_string();

    let result = plugin.authorize(&mut allowed_ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_plugin_blocked_ip() {
    let config = json!({
        "allowed_ips": ["127.0.0.1", "10.0.0.0/8"],
        "blocked_ips": ["192.168.1.100"]
    });
    let plugin = AccessControl::new(&config);

    // Test blocked IP
    let mut blocked_ctx = create_test_context();
    blocked_ctx.client_ip = "192.168.1.100".to_string();

    let result = plugin.authorize(&mut blocked_ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_plugin_cidr_allowed() {
    let config = json!({
        "allowed_ips": ["10.0.0.0/8"],
        "blocked_ips": []
    });
    let plugin = AccessControl::new(&config);

    // Test IP within allowed CIDR range
    let mut allowed_ctx = create_test_context();
    allowed_ctx.client_ip = "10.0.0.50".to_string();

    let result = plugin.authorize(&mut allowed_ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_plugin_cidr_blocked() {
    let config = json!({
        "allowed_ips": [],
        "blocked_ips": ["192.168.0.0/16"]
    });
    let plugin = AccessControl::new(&config);

    // Test IP within blocked CIDR range
    let mut blocked_ctx = create_test_context();
    blocked_ctx.client_ip = "192.168.0.50".to_string();

    let result = plugin.authorize(&mut blocked_ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_plugin_no_rules() {
    let config = json!({});
    let plugin = AccessControl::new(&config);

    // With no rules, should allow all
    let mut ctx = create_test_context();
    ctx.client_ip = "any.ip.address".to_string();

    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_plugin_not_in_allowed() {
    let config = json!({
        "allowed_ips": ["127.0.0.1"],
        "blocked_ips": []
    });
    let plugin = AccessControl::new(&config);

    // Test IP not in allowed list
    let mut blocked_ctx = create_test_context();
    blocked_ctx.client_ip = "192.168.1.100".to_string();

    let result = plugin.authorize(&mut blocked_ctx).await;
    assert_reject(result, Some(403));
}

// ---- CIDR tests for the fixed implementation ----

#[tokio::test]
async fn test_access_control_cidr_24_allowed() {
    let config = json!({
        "allowed_ips": ["172.16.0.0/24"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    ctx.client_ip = "172.16.0.123".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_cidr_24_outside_range() {
    let config = json!({
        "allowed_ips": ["172.16.0.0/24"]
    });
    let plugin = AccessControl::new(&config);

    // 172.16.1.1 should NOT match 172.16.0.0/24
    let mut ctx = create_test_context();
    ctx.client_ip = "172.16.1.1".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_cidr_16_range() {
    let config = json!({
        "allowed_ips": ["192.168.0.0/16"]
    });
    let plugin = AccessControl::new(&config);

    // Both should match /16
    let mut ctx = create_test_context();
    ctx.client_ip = "192.168.0.1".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    let mut ctx2 = create_test_context();
    ctx2.client_ip = "192.168.255.254".to_string();
    let result2 = plugin.authorize(&mut ctx2).await;
    assert_continue(result2);
}

#[tokio::test]
async fn test_access_control_cidr_8_range() {
    let config = json!({
        "allowed_ips": ["10.0.0.0/8"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    ctx.client_ip = "10.255.255.255".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    let mut ctx2 = create_test_context();
    ctx2.client_ip = "11.0.0.1".to_string();
    let result2 = plugin.authorize(&mut ctx2).await;
    assert_reject(result2, Some(403));
}

#[tokio::test]
async fn test_access_control_cidr_32_exact() {
    let config = json!({
        "allowed_ips": ["10.0.0.1/32"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    ctx.client_ip = "10.0.0.1".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);

    let mut ctx2 = create_test_context();
    ctx2.client_ip = "10.0.0.2".to_string();
    let result2 = plugin.authorize(&mut ctx2).await;
    assert_reject(result2, Some(403));
}

#[tokio::test]
async fn test_access_control_blocked_cidr_range() {
    let config = json!({
        "blocked_ips": ["172.16.0.0/12"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    ctx.client_ip = "172.20.5.10".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

// ---- Consumer-based tests ----

#[tokio::test]
async fn test_access_control_allowed_consumer() {
    let config = json!({
        "allowed_consumers": ["testuser"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_disallowed_consumer() {
    let config = json!({
        "disallowed_consumers": ["testuser"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_consumer_not_in_allowed_list() {
    let config = json!({
        "allowed_consumers": ["admin", "superuser"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    // ctx has consumer "testuser" which is NOT in allowed list
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_no_consumer_identified() {
    let config = json!({
        "allowed_consumers": ["admin"]
    });
    let plugin = AccessControl::new(&config);

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_access_control_blocked_ip_takes_precedence_over_allowed() {
    let config = json!({
        "allowed_ips": ["10.0.0.0/8"],
        "blocked_ips": ["10.0.0.5"]
    });
    let plugin = AccessControl::new(&config);

    // IP is in allowed range but explicitly blocked
    let mut ctx = create_test_context();
    ctx.client_ip = "10.0.0.5".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}
