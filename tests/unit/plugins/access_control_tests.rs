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
    let mut ctx = ferrum_edge::plugins::StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        Some("TCP Proxy".to_string()),
        5432,
        BackendScheme::Tcp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    );
    ctx.identified_consumer = consumer;
    ctx
}

fn make_consumer_with_groups(username: &str, groups: Vec<&str>) -> Consumer {
    Consumer {
        labels: Default::default(),
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
    assert!(
        result
            .err()
            .unwrap()
            .contains("`allowed_consumers` must not be an empty array")
    );

    let result = AccessControl::new(&json!({"disallowed_consumers": []}));
    assert!(result.err().unwrap().contains("at least one"));
}

// ---- Issue #6607: an explicitly empty allow-list is refused, not allow-all ----

#[tokio::test]
async fn test_access_control_explicitly_empty_allow_list_is_refused() {
    // Each of these used to construct with the empty allow-list treated as "no
    // allow restriction", silently admitting every consumer the deny side did
    // not name.
    for config in [
        json!({"allowed_consumers": [], "disallowed_consumers": ["mallory"]}),
        json!({"allowed_groups": [], "disallowed_groups": ["banned"]}),
        json!({"allowed_consumers": [], "allow_authenticated_identity": true}),
        json!({"allowed_groups": [], "allow_authenticated_identity": true}),
        json!({"allowed_consumers": [], "allowed_groups": ["engineering"]}),
        json!({"allowed_consumers": ["alice"], "allowed_groups": []}),
    ] {
        let error = AccessControl::new(&config)
            .err()
            .unwrap_or_else(|| panic!("explicitly empty allow-list must be refused: {config}"));
        assert!(
            error.contains("must not be an empty array"),
            "{config}: {error}"
        );
    }
}

#[tokio::test]
async fn test_access_control_omitted_allow_list_means_no_allow_restriction() {
    // Omitted allow-lists keep their meaning: only the deny side applies.
    let plugin = AccessControl::new(&json!({"disallowed_consumers": ["mallory"]})).unwrap();

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups("alice", vec![])));
    assert_continue(plugin.authorize(&mut ctx).await);

    let mut ctx = create_test_context();
    ctx.identified_consumer = Some(Arc::new(make_consumer_with_groups("mallory", vec![])));
    assert_reject(plugin.authorize(&mut ctx).await, Some(403));
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
        labels: Default::default(),
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
    assert!(
        result
            .err()
            .unwrap()
            .contains("`allowed_groups` must not be an empty array")
    );

    let result = AccessControl::new(&json!({"disallowed_groups": []}));
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

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let canary = "'SECURITY_DIAGNOSTIC_CANARY\"`\n\\payload";
    let cases: &[(serde_json::Value, &[&str])] = &[
        (json!({(canary): true}), &["unknown config key"]),
        (
            json!({"allowed_consumers": [8675309]}),
            &["`allowed_consumers`", "must be strings"],
        ),
    ];

    for (config, expected) in cases {
        let error = ferrum_edge::plugins::validate_plugin_config("access_control", config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for &fragment in *expected {
            assert!(
                rendered.contains(fragment),
                "missing {fragment:?}: {rendered}"
            );
        }
        for supplied in [
            "SECURITY_DIAGNOSTIC_CANARY",
            "security-diagnostic-canary",
            "8675309",
            "54321",
            "16384",
            "true",
        ] {
            assert!(
                !rendered.contains(supplied),
                "leaked {supplied:?}: {rendered}"
            );
        }
    }
}

// ---- External-identity rules (realm-aware allow / deny) ----

/// A request whose external identity was committed through the shared
/// authentication boundary, so it carries `mechanism` as its verified realm.
fn external_identity_context(
    identity: &str,
    mechanism: &'static str,
) -> ferrum_edge::plugins::RequestContext {
    use ferrum_edge::plugins::utils::auth_attempt::AuthenticationAttempt;
    use ferrum_edge::plugins::utils::auth_flow::{VerifyOutcome, commit_authentication_attempt};

    let mut ctx = create_test_context();
    ctx.identified_consumer = None;
    let committed = commit_authentication_attempt(
        &mut ctx,
        AuthenticationAttempt::new(),
        VerifyOutcome::success(None, Some(identity.to_string()), None),
        mechanism,
        true,
    )
    .expect("external identity commits");
    assert!(committed, "the external identity must be committed");
    assert_eq!(
        ctx.authenticated_identity_realm()
            .map(|realm| realm.mechanism()),
        Some(mechanism)
    );
    ctx
}

#[tokio::test]
async fn test_access_control_external_allow_list_admits_only_listed_identities() {
    let plugin = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "alice"}]
    }))
    .unwrap();

    let mut listed = external_identity_context("alice", "jwks_auth");
    assert_continue(plugin.authorize(&mut listed).await);

    let mut unlisted = external_identity_context("bob", "jwks_auth");
    assert_reject(plugin.authorize(&mut unlisted).await, Some(403));

    // An identity set without the commit boundary has no realm; an unscoped
    // entry still matches it.
    let mut unscoped = create_test_context();
    unscoped.identified_consumer = None;
    unscoped.authenticated_identity = Some("alice".to_string());
    assert_continue(plugin.authorize(&mut unscoped).await);

    let mut nobody = create_test_context();
    nobody.identified_consumer = None;
    assert_reject(plugin.authorize(&mut nobody).await, Some(401));
}

#[tokio::test]
async fn test_access_control_external_allow_entry_is_scoped_to_its_mechanism() {
    let plugin = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "alice", "mechanism": "jwks_auth"}]
    }))
    .unwrap();

    let mut jwks = external_identity_context("alice", "jwks_auth");
    assert_continue(plugin.authorize(&mut jwks).await);

    // The same subject string asserted by a different authority is a different
    // principal.
    let mut ldap = external_identity_context("alice", "ldap_auth");
    assert_reject(plugin.authorize(&mut ldap).await, Some(403));

    // No verified realm: a scoped allow entry cannot establish admission.
    let mut unknown_realm = create_test_context();
    unknown_realm.identified_consumer = None;
    unknown_realm.authenticated_identity = Some("alice".to_string());
    assert_reject(plugin.authorize(&mut unknown_realm).await, Some(403));
}

#[tokio::test]
async fn test_access_control_external_deny_entry_is_scoped_to_its_mechanism() {
    let plugin = AccessControl::new(&json!({
        "allow_authenticated_identity": true,
        "disallowed_external_identities": [{"identity": "alice", "mechanism": "ldap_auth"}]
    }))
    .unwrap();

    let mut ldap = external_identity_context("alice", "ldap_auth");
    assert_reject(plugin.authorize(&mut ldap).await, Some(403));

    let mut jwks = external_identity_context("alice", "jwks_auth");
    assert_continue(plugin.authorize(&mut jwks).await);

    // No verified realm: a scoped deny entry fails closed.
    let mut unknown_realm = create_test_context();
    unknown_realm.identified_consumer = None;
    unknown_realm.authenticated_identity = Some("alice".to_string());
    assert_reject(plugin.authorize(&mut unknown_realm).await, Some(403));

    let mut other = external_identity_context("bob", "ldap_auth");
    assert_continue(plugin.authorize(&mut other).await);
}

#[tokio::test]
async fn test_access_control_external_deny_overrides_external_allow() {
    let plugin = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "alice"}],
        "disallowed_external_identities": [{"identity": "alice", "mechanism": "ldap_auth"}],
        "disallowed_consumers": ["mallory"]
    }))
    .unwrap();

    let mut ldap = external_identity_context("alice", "ldap_auth");
    assert_reject(plugin.authorize(&mut ldap).await, Some(403));

    let mut jwks = external_identity_context("alice", "jwks_auth");
    assert_continue(plugin.authorize(&mut jwks).await);

    // `disallowed_consumers` stays a realm-blind external deny.
    let plugin = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "mallory"}],
        "disallowed_consumers": ["mallory"]
    }))
    .unwrap();
    let mut mallory = external_identity_context("mallory", "jwks_auth");
    assert_reject(plugin.authorize(&mut mallory).await, Some(403));
}

#[tokio::test]
async fn test_access_control_external_only_allow_list_denies_mapped_consumers() {
    let plugin = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "alice"}]
    }))
    .unwrap();

    // An allow-list means "only these principals": a mapped Consumer matches
    // none of the (empty) consumer allow-lists.
    let mut consumer = create_test_context();
    consumer.identified_consumer = Some(Arc::new(make_consumer_with_groups("alice", vec![])));
    assert_reject(plugin.authorize(&mut consumer).await, Some(403));

    // Combined with a group allow-list, the matching Consumer passes.
    let plugin = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "alice"}],
        "allowed_groups": ["engineering"]
    }))
    .unwrap();
    let mut engineer = create_test_context();
    engineer.identified_consumer = Some(Arc::new(make_consumer_with_groups(
        "carol",
        vec!["engineering"],
    )));
    assert_continue(plugin.authorize(&mut engineer).await);
    let mut external = external_identity_context("alice", "oidc_relying_party");
    assert_continue(plugin.authorize(&mut external).await);
}

#[tokio::test]
async fn test_access_control_stream_identity_never_matches_a_scoped_allow_entry() {
    let scoped = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "svc", "mechanism": "jwks_auth"}]
    }))
    .unwrap();
    let mut ctx = create_stream_context(None);
    ctx.authenticated_identity = Some("svc".to_string());
    assert_reject(scoped.on_stream_connect(&mut ctx).await, Some(403));

    let unscoped = AccessControl::new(&json!({
        "allowed_external_identities": [{"identity": "svc"}]
    }))
    .unwrap();
    let mut ctx = create_stream_context(None);
    ctx.authenticated_identity = Some("svc".to_string());
    assert_continue(unscoped.on_stream_connect(&mut ctx).await);
}

#[test]
fn test_access_control_external_identity_rule_validation() {
    for config in [
        json!({"allowed_external_identities": [{"identity": "alice"}]}),
        json!({"disallowed_external_identities": [{"identity": "alice", "mechanism": "jwks_auth"}]}),
        json!({"disallowed_external_identities": [], "allow_authenticated_identity": true}),
        json!({
            "allowed_external_identities": [
                {"identity": "alice", "mechanism": "jwks_auth"},
                {"identity": "alice", "mechanism": "ldap_auth"}
            ],
            "allowed_consumers": ["bob"]
        }),
    ] {
        assert!(
            AccessControl::new(&config).is_ok(),
            "config should be accepted: {config}"
        );
    }

    for (config, fragment) in [
        (
            json!({"allowed_external_identities": []}),
            "must not be an empty array",
        ),
        (
            json!({
                "allowed_external_identities": [{"identity": "alice"}],
                "allow_authenticated_identity": true
            }),
            "allow_authenticated_identity",
        ),
        (
            json!({"allowed_external_identities": ["alice"]}),
            "must be objects",
        ),
        (
            json!({"allowed_external_identities": {"identity": "alice"}}),
            "must be an array of objects",
        ),
        (
            json!({"allowed_external_identities": [{"mechanism": "jwks_auth"}]}),
            "`identity` string",
        ),
        (
            json!({"allowed_external_identities": [{"identity": "   "}]}),
            "non-whitespace",
        ),
        (
            json!({"allowed_external_identities": [{"identity": "a".repeat(4097)}]}),
            "must not exceed 4096",
        ),
        (
            json!({"disallowed_external_identities": [{"identity": "alice", "mechanism": "jwks"}]}),
            "`mechanism` must be one of",
        ),
        (
            json!({"disallowed_external_identities": [{"identity": "alice", "mechanism": 7}]}),
            "`mechanism` must be one of",
        ),
        (
            json!({"disallowed_external_identities": [{"identity": "alice", "realm": "x"}]}),
            "accept only `identity` and `mechanism`",
        ),
    ] {
        let err = match AccessControl::new(&config) {
            Ok(_) => panic!("config should be rejected: {config}"),
            Err(err) => err,
        };
        assert!(err.contains(fragment), "got: {err} for {config}");
    }
}

// ---- Consumer rename referential integrity ----

fn access_control_plugin_config(
    id: &str,
    namespace: &str,
    config: serde_json::Value,
) -> ferrum_edge::config::types::PluginConfig {
    ferrum_edge::config::types::PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        plugin_name: "access_control".to_string(),
        namespace: namespace.to_string(),
        config,
        scope: ferrum_edge::config::types::PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn gateway_config_with(
    consumers: Vec<Consumer>,
    plugin_configs: Vec<ferrum_edge::config::types::PluginConfig>,
) -> ferrum_edge::config::types::GatewayConfig {
    ferrum_edge::config::types::GatewayConfig {
        consumers,
        plugin_configs,
        ..Default::default()
    }
}

#[test]
fn test_access_control_config_names_consumer_username_checks_both_lists() {
    use ferrum_edge::plugins::access_control::config_names_consumer_username;

    let config = json!({
        "allowed_consumers": ["alice"],
        "disallowed_consumers": ["mallory"],
        "allowed_groups": ["bob"]
    });
    assert!(config_names_consumer_username(&config, "alice"));
    assert!(config_names_consumer_username(&config, "mallory"));
    assert!(
        !config_names_consumer_username(&config, "bob"),
        "group names are not usernames"
    );
    assert!(
        !config_names_consumer_username(&config, " alice"),
        "matching is byte-for-byte"
    );
}

#[test]
fn test_access_control_file_reload_refuses_rename_of_referenced_consumer() {
    use ferrum_edge::plugins::access_control::consumer_rename_conflicts;

    let namespace = ferrum_edge::config::types::default_namespace();
    let mallory = make_consumer_with_groups("mallory", vec![]);
    let mut renamed = mallory.clone();
    renamed.username = "m.reyes".to_string();
    let deny = access_control_plugin_config(
        "acl-deny",
        &namespace,
        json!({"disallowed_consumers": ["mallory"]}),
    );
    let previous = gateway_config_with(vec![mallory.clone()], vec![deny.clone()]);

    // Deny side: the rename would un-revoke the principal.
    let conflicts = consumer_rename_conflicts(
        &previous,
        &gateway_config_with(vec![renamed.clone()], vec![deny.clone()]),
    );
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    assert!(conflicts[0].contains("acl-deny"), "{conflicts:?}");
    assert!(
        !conflicts[0].contains("mallory") && !conflicts[0].contains("m.reyes"),
        "diagnostics name resource ids, not usernames: {conflicts:?}"
    );

    // Allow side: the rename would orphan the allow entry.
    let allow = access_control_plugin_config(
        "acl-allow",
        &namespace,
        json!({"allowed_consumers": ["mallory"]}),
    );
    let conflicts = consumer_rename_conflicts(
        &gateway_config_with(vec![mallory.clone()], vec![allow.clone()]),
        &gateway_config_with(vec![renamed.clone()], vec![allow]),
    );
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");

    // Renaming the rule in the same reload is accepted.
    let updated_deny = access_control_plugin_config(
        "acl-deny",
        &namespace,
        json!({"disallowed_consumers": ["m.reyes"]}),
    );
    assert!(
        consumer_rename_conflicts(
            &previous,
            &gateway_config_with(vec![renamed.clone()], vec![updated_deny])
        )
        .is_empty()
    );

    // An update that keeps the username, and a rename of an unreferenced
    // consumer, are unaffected.
    let mut regrouped = mallory.clone();
    regrouped.acl_groups = vec!["engineering".to_string()];
    assert!(
        consumer_rename_conflicts(
            &previous,
            &gateway_config_with(vec![regrouped], vec![deny.clone()])
        )
        .is_empty()
    );
    let other = make_consumer_with_groups("carol", vec![]);
    let mut other_renamed = other.clone();
    other_renamed.username = "carol2".to_string();
    assert!(
        consumer_rename_conflicts(
            &gateway_config_with(vec![mallory.clone(), other], vec![deny.clone()]),
            &gateway_config_with(vec![mallory.clone(), other_renamed], vec![deny.clone()])
        )
        .is_empty()
    );

    // A rule in another namespace does not pin this namespace's consumer.
    let foreign = access_control_plugin_config(
        "acl-foreign",
        "other-namespace",
        json!({"disallowed_consumers": ["mallory"]}),
    );
    assert!(
        consumer_rename_conflicts(
            &gateway_config_with(vec![mallory], vec![foreign.clone()]),
            &gateway_config_with(vec![renamed], vec![foreign])
        )
        .is_empty()
    );
}
