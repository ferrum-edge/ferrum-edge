//! Tests for access_control plugin

use ferrum_gateway::plugins::{access_control::AccessControl, Plugin, PluginResult};
use serde_json::json;

mod plugin_utils;
use plugin_utils::{create_test_context, assert_continue, assert_reject};

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
    allowed_ctx.client_ip = "10.0.1.100".to_string();
    
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
    blocked_ctx.client_ip = "192.168.1.50".to_string();
    
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
