//! Tests for access_control plugin

use ferrum_edge::config::types::{BackendProtocol, Consumer};
use ferrum_edge::plugins::{Plugin, access_control::AccessControl};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn create_stream_context(
    consumer: Option<Arc<Consumer>>,
) -> ferrum_edge::plugins::StreamConnectionContext {
    ferrum_edge::plugins::StreamConnectionContext {
        client_ip: "127.0.0.1".to_string(),
        proxy_id: "tcp-proxy".to_string(),
        proxy_name: Some("TCP Proxy".to_string()),
        listen_port: 5432,
        backend_protocol: BackendProtocol::Tcp,
        consumer_index: Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
        identified_consumer: consumer,
        authenticated_identity: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
    }
}

fn make_consumer_with_groups(username: &str, groups: Vec<&str>) -> Consumer {
    Consumer {
        id: format!("consumer-{}", username),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: groups.into_iter().map(String::from).collect(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// ---- Plugin creation tests ----

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
async fn test_access_control_creation_with_allow_authenticated_identity_only() {
    let config = json!({
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();
    assert_eq!(plugin.name(), "access_control");
}

// ---- Consumer username tests ----

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

// ---- External identity tests ----

#[tokio::test]
async fn test_access_control_allows_authenticated_identity_when_enabled() {
    let config = json!({
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("oidc-user-123".to_string());
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_authenticated_identity_still_rejected_when_disabled() {
    let config = json!({
        "allowed_consumers": ["admin"]
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("oidc-user-123".to_string());
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_access_control_enabled_but_no_authenticated_identity_still_rejects() {
    let config = json!({
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = None;
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_access_control_consumer_rules_still_apply_when_authenticated_identity_also_present() {
    let config = json!({
        "disallowed_consumers": ["testuser"],
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.authenticated_identity = Some("external-user".to_string());
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
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

// ---- Stream proxy tests ----

#[tokio::test]
async fn test_access_control_stream_connect_allowed_consumer() {
    let plugin = AccessControl::new(&json!({
        "allowed_consumers": ["stream-user"]
    }))
    .unwrap();

    let mut ctx = create_stream_context(Some(Arc::new(Consumer {
        id: "consumer-1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "stream-user".to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })));

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_stream_connect_rejects_without_consumer() {
    let plugin = AccessControl::new(&json!({
        "allowed_consumers": ["stream-user"]
    }))
    .unwrap();

    let mut ctx = create_stream_context(None);
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_reject(result, Some(401));
}

// ---- Group-based access control tests ----

#[tokio::test]
async fn test_access_control_creation_with_allowed_groups_only() {
    let config = json!({
        "allowed_groups": ["engineering", "platform"]
    });
    let plugin = AccessControl::new(&config).unwrap();
    assert_eq!(plugin.name(), "access_control");
}

#[tokio::test]
async fn test_access_control_creation_with_disallowed_groups_only() {
    let config = json!({
        "disallowed_groups": ["banned"]
    });
    let plugin = AccessControl::new(&config).unwrap();
    assert_eq!(plugin.name(), "access_control");
}

#[tokio::test]
async fn test_access_control_empty_groups_reject_creation() {
    let config = json!({
        "allowed_groups": [],
        "disallowed_groups": []
    });
    let result = AccessControl::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("at least one"));
}

#[tokio::test]
async fn test_access_control_allowed_group_allows_consumer() {
    let plugin = AccessControl::new(&json!({
        "allowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "alice",
        vec!["engineering", "backend"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_allowed_group_rejects_consumer_not_in_group() {
    let plugin = AccessControl::new(&json!({
        "allowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "bob",
        vec!["marketing"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_allowed_group_rejects_consumer_with_no_groups() {
    let plugin = AccessControl::new(&json!({
        "allowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups("bob", vec![])));
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_disallowed_group_rejects_consumer() {
    let plugin = AccessControl::new(&json!({
        "disallowed_groups": ["banned"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "alice",
        vec!["engineering", "banned"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_disallowed_group_allows_consumer_not_in_group() {
    let plugin = AccessControl::new(&json!({
        "disallowed_groups": ["banned"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "alice",
        vec!["engineering"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_group_deny_takes_precedence_over_group_allow() {
    let plugin = AccessControl::new(&json!({
        "allowed_groups": ["engineering"],
        "disallowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "alice",
        vec!["engineering"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_consumer_username_allow_with_group_deny() {
    // Consumer username is in allowed_consumers, but consumer's group is in disallowed_groups.
    // Deny should take precedence.
    let plugin = AccessControl::new(&json!({
        "allowed_consumers": ["alice"],
        "disallowed_groups": ["banned"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups("alice", vec!["banned"])));
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_group_allow_bypasses_consumer_allow_list() {
    // Consumer username "alice" is NOT in allowed_consumers, but her group is in allowed_groups.
    // Should be allowed.
    let plugin = AccessControl::new(&json!({
        "allowed_consumers": ["admin"],
        "allowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "alice",
        vec!["engineering"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_consumer_allow_bypasses_group_allow_list() {
    // Consumer username "admin" IS in allowed_consumers, even though they have no matching groups.
    let plugin = AccessControl::new(&json!({
        "allowed_consumers": ["admin"],
        "allowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "admin",
        vec!["marketing"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_neither_consumer_nor_group_in_allow_lists() {
    let plugin = AccessControl::new(&json!({
        "allowed_consumers": ["admin"],
        "allowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "bob",
        vec!["marketing"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_consumer_username_deny_with_group_allow() {
    // Consumer username is disallowed, even though group is allowed. Deny wins.
    let plugin = AccessControl::new(&json!({
        "disallowed_consumers": ["alice"],
        "allowed_groups": ["engineering"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "alice",
        vec!["engineering"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_multiple_groups_any_match_allows() {
    let plugin = AccessControl::new(&json!({
        "allowed_groups": ["platform", "sre"]
    }))
    .unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "alice",
        vec!["engineering", "sre"],
    )));
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_stream_connect_allowed_group() {
    let plugin = AccessControl::new(&json!({
        "allowed_groups": ["db-access"]
    }))
    .unwrap();

    let mut ctx = create_stream_context(Some(Arc::new(make_consumer_with_groups(
        "stream-user",
        vec!["db-access"],
    ))));
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_stream_connect_disallowed_group() {
    let plugin = AccessControl::new(&json!({
        "disallowed_groups": ["restricted"]
    }))
    .unwrap();

    let mut ctx = create_stream_context(Some(Arc::new(make_consumer_with_groups(
        "stream-user",
        vec!["restricted"],
    ))));
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert_reject(result, Some(403));
}
