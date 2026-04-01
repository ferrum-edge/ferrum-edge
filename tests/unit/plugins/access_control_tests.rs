//! Tests for access_control plugin

use ferrum_edge::plugins::{Plugin, access_control::AccessControl};
use serde_json::json;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

#[tokio::test]
async fn test_access_control_plugin_creation() {
    let config = json!({
        "allowed_consumers": ["testuser"],
        "disallowed_consumers": ["blocked-user"]
    });
    let plugin = AccessControl::new(&config).unwrap();
    assert_eq!(plugin.name(), "access_control");
}

#[tokio::test]
async fn test_access_control_ignores_legacy_ip_keys_when_consumer_rules_exist() {
    let config = json!({
        "allowed_ips": ["10.0.0.0/8"],
        "blocked_ips": ["192.168.1.100"],
        "allowed_consumers": ["testuser"]
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.client_ip = "203.0.113.50".to_string();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_rejects_when_only_legacy_ip_keys_are_present() {
    let config = json!({
        "blocked_ips": ["192.168.1.100"]
    });
    let result = AccessControl::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("allowed_consumers"));
}

#[tokio::test]
async fn test_access_control_plugin_no_rules() {
    // Empty config has no rules at all — should return Err.
    let config = json!({});
    let result = AccessControl::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("at least one"));
}

#[tokio::test]
async fn test_access_control_empty_consumer_lists_reject_creation() {
    let config = json!({
        "allowed_consumers": [],
        "disallowed_consumers": []
    });
    let result = AccessControl::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("at least one"));
}

#[tokio::test]
async fn test_access_control_allowed_consumer() {
    let config = json!({
        "allowed_consumers": ["testuser"]
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_disallowed_consumer() {
    let config = json!({
        "disallowed_consumers": ["testuser"]
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_consumer_not_in_allowed_list() {
    let config = json!({
        "allowed_consumers": ["admin", "superuser"]
    });
    let plugin = AccessControl::new(&config).unwrap();

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
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_access_control_disallowed_consumer_takes_precedence() {
    let config = json!({
        "allowed_consumers": ["testuser"],
        "disallowed_consumers": ["testuser"]
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}
