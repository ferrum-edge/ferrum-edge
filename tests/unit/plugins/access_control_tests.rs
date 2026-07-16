//! Tests for access_control plugin

use ferrum_edge::_test_support::normalize_reject_response;
use ferrum_edge::config::types::{BackendScheme, Consumer};
use ferrum_edge::plugins::{
    HTTP_FAMILY_AND_STREAM_PROTOCOLS, Plugin, PluginResult, access_control::AccessControl, priority,
};
use ferrum_edge::proxy::grpc_proxy::grpc_status;
use hyper::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn create_stream_context(
    consumer: Option<Arc<Consumer>>,
) -> ferrum_edge::plugins::StreamConnectionContext {
    ferrum_edge::plugins::StreamConnectionContext {
        client_ip: "127.0.0.1".to_string(),
        direct_client_ip: "127.0.0.1".to_string(),
        canonical_client_ip: Default::default(),
        proxy_id: "tcp-proxy".to_string(),
        proxy_name: Some("TCP Proxy".to_string()),
        listen_port: 5432,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
        identified_consumer: consumer,
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
    assert_eq!(plugin.priority(), priority::ACCESS_CONTROL);
    assert_eq!(
        plugin.supported_protocols(),
        HTTP_FAMILY_AND_STREAM_PROTOCOLS
    );
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[tokio::test]
async fn test_access_control_rejects_removed_ip_keys() {
    let config = json!({
        "allowed_ips": ["10.0.0.0/8"],
        "blocked_ips": ["192.168.1.100"],
        "allowed_consumers": ["testuser"]
    });
    let err = match AccessControl::new(&config) {
        Ok(_) => panic!("removed IP keys should be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("ip_restriction"), "got: {err}");
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
async fn test_access_control_rejects_invalid_config_types() {
    let cases = [
        json!(null),
        json!([]),
        json!({"allowed_consumers": "testuser"}),
        json!({"allowed_consumers": [42]}),
        json!({"allowed_consumers": [""]}),
        json!({"disallowed_consumers": "testuser"}),
        json!({"allowed_groups": "engineering"}),
        json!({"disallowed_groups": ["banned", false]}),
        json!({"allow_authenticated_identity": "true"}),
    ];

    for config in cases {
        assert!(
            AccessControl::new(&config).is_err(),
            "config should fail validation: {config}"
        );
    }
}

#[tokio::test]
async fn test_access_control_rejects_blank_rules() {
    for field in [
        "allowed_consumers",
        "disallowed_consumers",
        "allowed_groups",
        "disallowed_groups",
    ] {
        for value in ["   ", "\t", "\n", "\r\n"] {
            let mut object = serde_json::Map::new();
            object.insert(field.to_string(), json!([value]));
            let config = serde_json::Value::Object(object);
            assert!(
                AccessControl::new(&config).is_err(),
                "{field} must reject {value:?}"
            );
        }
    }

    assert!(
        AccessControl::new(&json!({
            "allowed_consumers": ["a".repeat(256)]
        }))
        .is_err()
    );
    assert!(
        AccessControl::new(&json!({
            "allowed_groups": ["a".repeat(256)]
        }))
        .is_err()
    );
    assert!(
        AccessControl::new(&json!({
            "disallowed_consumers": ["a".repeat(4097)],
            "allow_authenticated_identity": true
        }))
        .is_err()
    );
}

#[tokio::test]
async fn test_access_control_rules_match_padded_principals_byte_for_byte() {
    // Principals are never canonicalized: Consumer usernames may legally carry
    // whitespace padding and external identity claims are preserved
    // byte-for-byte. Rules must therefore be stored byte-for-byte too — a
    // trimmed rule could never match the padded principal it targets, turning
    // the deny-list fail-open.

    // Padded deny rule revokes a padded signed external identity.
    let deny_external = AccessControl::new(&json!({
        "allow_authenticated_identity": true,
        "disallowed_consumers": [" alice "]
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some(" alice ".to_string());
    assert_reject(deny_external.authorize(&mut ctx).await, Some(403));

    // The padded rule targets exactly " alice "; the distinct principal
    // "alice" is not covered by it.
    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("alice".to_string());
    assert_continue(deny_external.authorize(&mut ctx).await);

    // Padded deny rule matches a padded Consumer username.
    let deny_consumer = AccessControl::new(&json!({
        "disallowed_consumers": [" alice "]
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(" alice ", vec![])));
    assert_reject(deny_consumer.authorize(&mut ctx).await, Some(403));

    // Padded group deny rule matches the identical padded acl_group only.
    let deny_group = AccessControl::new(&json!({
        "disallowed_groups": ["  contractors  "]
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "testuser",
        vec!["  contractors  "],
    )));
    assert_reject(deny_group.authorize(&mut ctx).await, Some(403));
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "testuser",
        vec!["contractors"],
    )));
    assert_continue(deny_group.authorize(&mut ctx).await);

    // Padded allow rule admits exactly the padded username, nothing else.
    let allow_padded = AccessControl::new(&json!({
        "allowed_consumers": [" alice "]
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups(" alice ", vec![])));
    assert_continue(allow_padded.authorize(&mut ctx).await);
    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups("alice", vec![])));
    assert_reject(allow_padded.authorize(&mut ctx).await, Some(403));
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

// ---- Finding #3: allow-list + allow_authenticated_identity must be rejected ----

#[tokio::test]
async fn test_access_control_rejects_allow_list_with_authenticated_identity() {
    // Security regression (finding #3): a consumer allow-list combined with
    // `allow_authenticated_identity=true` is a fail-open footgun — the allow-list
    // keys off mapped Consumers and is never applied to an unmapped external
    // identity, so the combination would silently bypass the allow-list. It must
    // be rejected at construction (admin API 400 / file-mode startup failure).
    let config = json!({
        "allowed_consumers": ["alice"],
        "allow_authenticated_identity": true
    });
    let err = match AccessControl::new(&config) {
        Ok(_) => panic!("allow_consumers + allow_authenticated_identity must be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("allow_authenticated_identity"), "got: {err}");
    assert!(err.contains("allow-list"), "got: {err}");
}

#[tokio::test]
async fn test_access_control_rejects_allowed_groups_with_authenticated_identity() {
    // Same fail-open footgun via the group allow-list (finding #3).
    let config = json!({
        "allowed_groups": ["engineering"],
        "allow_authenticated_identity": true
    });
    let err = match AccessControl::new(&config) {
        Ok(_) => panic!("allowed_groups + allow_authenticated_identity must be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("allow_authenticated_identity"), "got: {err}");
}

#[tokio::test]
async fn test_access_control_deny_list_with_authenticated_identity_is_allowed() {
    // A deny-list combined with `allow_authenticated_identity` remains valid:
    // `disallowed_consumers` IS applied to the external identity string, so the
    // combination is meaningful (revoke a compromised external principal).
    let config = json!({
        "disallowed_consumers": ["compromised"],
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();
    assert_eq!(plugin.name(), "access_control");
}

// ---- Finding #4: unknown/misspelled config keys must be rejected ----

#[tokio::test]
async fn test_access_control_rejects_unknown_key_alone() {
    // A misspelled allow key on its own must fail config validation rather than
    // be silently dropped (finding #4).
    let config = json!({
        "allowed_consumer": ["alice"]
    });
    let err = match AccessControl::new(&config) {
        Ok(_) => panic!("unknown config key must be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("allowed_consumer"), "got: {err}");
}

#[tokio::test]
async fn test_access_control_rejects_unknown_key_alongside_valid_key() {
    // The concrete defect from finding #4: a valid deny-list key masks a typo'd
    // allow-list key. Without rejection this silently degrades an intended
    // allow-list ("deny all except alice") into a deny-list-only policy
    // ("allow all except bad"). Must be rejected at construction.
    let config = json!({
        "disallowed_consumers": ["bad"],
        "allowed_consumer": ["alice"]
    });
    let err = match AccessControl::new(&config) {
        Ok(_) => panic!("unknown config key alongside a valid key must be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("unknown config key"), "got: {err}");
    assert!(err.contains("allowed_consumer"), "got: {err}");
}

#[tokio::test]
async fn test_access_control_rejects_misspelled_keys() {
    // The specific typos called out in finding #4.
    for typo in [
        json!({"disallow_consumers": ["bad"], "allowed_consumers": ["alice"]}),
        json!({"allow_authenticated_identitiy": true, "disallowed_consumers": ["bad"]}),
    ] {
        let err = match AccessControl::new(&typo) {
            Ok(_) => panic!("misspelled key must be rejected: {typo}"),
            Err(err) => err,
        };
        assert!(err.contains("unknown config key"), "got: {err} for {typo}");
    }
}

#[tokio::test]
async fn test_access_control_accepts_all_known_keys() {
    // The full set of known keys (without the rejected allow-list + bypass combo)
    // must still construct, so the unknown-key guard has no false positives.
    let config = json!({
        "allowed_consumers": ["alice"],
        "disallowed_consumers": ["bad"],
        "allowed_groups": ["engineering"],
        "disallowed_groups": ["banned"]
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
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_grpc_distinguishes_authorization_from_authentication() {
    let plugin = AccessControl::new(&json!({
        "allowed_consumers": ["admin"]
    }))
    .unwrap();

    for (identity, http_status, expected_grpc_status) in [
        (Some("external-user"), 403, grpc_status::PERMISSION_DENIED),
        (None, 401, grpc_status::UNAUTHENTICATED),
    ] {
        let mut ctx = create_test_context();
        ctx.identified_consumer = None;
        ctx.authenticated_identity = identity.map(str::to_string);
        let PluginResult::Reject {
            status_code,
            body,
            headers,
        } = plugin.authorize(&mut ctx).await
        else {
            panic!("ACL must reject this identity state");
        };
        assert_eq!(status_code, http_status);

        let normalized = normalize_reject_response(
            StatusCode::from_u16(status_code).unwrap(),
            body.as_bytes(),
            &headers,
            true,
        );
        assert_eq!(normalized.http_status, StatusCode::OK);
        assert!(normalized.body.is_empty());
        assert_eq!(normalized.grpc_status, Some(expected_grpc_status));
        let expected_grpc_status = expected_grpc_status.to_string();
        assert_eq!(
            normalized.headers.get("grpc-status").map(String::as_str),
            Some(expected_grpc_status.as_str())
        );
    }
}

#[tokio::test]
async fn test_access_control_blank_external_identity_is_unauthenticated() {
    let plugin = AccessControl::new(&json!({
        "allow_authenticated_identity": true
    }))
    .unwrap();

    for identity in ["", "   ", "\t\n"] {
        let mut ctx = create_test_context();
        ctx.identified_consumer = None;
        ctx.authenticated_identity = Some(identity.to_string());
        let result = plugin.authorize(&mut ctx).await;
        assert_reject(result, Some(401));
    }
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
async fn test_access_control_disallowed_external_identity_is_rejected() {
    // External identity in disallowed_consumers must be rejected, even when
    // `allow_authenticated_identity = true` and no Consumer is mapped.
    let config = json!({
        "disallowed_consumers": ["alice"],
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("alice".to_string());
    let result = plugin.authorize(&mut ctx).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_access_control_can_revoke_long_external_identity_exactly() {
    let long_identity = format!("spiffe://example.test/workload/{}", "a".repeat(300));
    let plugin = AccessControl::new(&json!({
        "disallowed_consumers": [long_identity],
        "allow_authenticated_identity": true
    }))
    .unwrap();

    let mut denied = create_test_context();
    denied.identified_consumer = None;
    denied.authenticated_identity = Some(long_identity.clone());
    assert_reject(plugin.authorize(&mut denied).await, Some(403));

    let mut distinct = create_test_context();
    distinct.identified_consumer = None;
    distinct.authenticated_identity = Some(format!("{long_identity}-other"));
    assert_continue(plugin.authorize(&mut distinct).await);
}

#[tokio::test]
async fn test_access_control_fails_closed_for_external_identity_beyond_rule_bound() {
    let plugin = AccessControl::new(&json!({
        "allow_authenticated_identity": true
    }))
    .unwrap();
    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("a".repeat(4097));

    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
}

#[tokio::test]
async fn test_access_control_allowed_external_identity_continues() {
    // External identity NOT in disallowed_consumers must pass when
    // `allow_authenticated_identity = true` and no Consumer is mapped.
    let config = json!({
        "disallowed_consumers": ["alice"],
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("bob".to_string());
    let result = plugin.authorize(&mut ctx).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_access_control_no_authenticated_identity_still_rejects_with_deny_list() {
    // Regression: with `allow_authenticated_identity = true` and a deny list,
    // a request with no Consumer AND no external identity must still be rejected
    // with 401 (no identity at all to gate on).
    let config = json!({
        "disallowed_consumers": ["alice"],
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
async fn test_access_control_consumer_path_unchanged_when_disallowed_with_external_auth_enabled() {
    // Regression: an identified Consumer named "alice" with the deny list applied
    // must still be rejected via the existing Consumer path (independent of
    // `allow_authenticated_identity`).
    let config = json!({
        "disallowed_consumers": ["alice"],
        "allow_authenticated_identity": true
    });
    let plugin = AccessControl::new(&config).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups("alice", vec![])));
    ctx.authenticated_identity = None;
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
