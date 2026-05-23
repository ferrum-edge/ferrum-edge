//! Tests for admin audit primitives.

use chrono::{Duration, Utc};
use ferrum_edge::admin::audit::{
    AuditActor, AuditEvent, AuditListFilter, create_diff, delete_diff, update_diff,
};
use ferrum_edge::admin::jwt_auth::{AdminClaims, AdminRole};
use serde_json::json;
use uuid::Uuid;

fn claims_with_role(role: serde_json::Value) -> AdminClaims {
    let now = Utc::now();
    AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "audit-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::minutes(5)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        additional: json!({ "role": role }),
    }
}

#[test]
fn test_audit_actor_from_claims_copies_subject_and_role() {
    let claims = claims_with_role(json!("operator"));

    let actor = AuditActor::from_claims(&claims).unwrap();

    assert_eq!(actor.sub, "audit-user");
    assert_eq!(actor.role, AdminRole::Operator);
}

#[test]
fn test_audit_actor_from_claims_rejects_missing_role() {
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "audit-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::minutes(5)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let err = AuditActor::from_claims(&claims).unwrap_err();

    assert!(err.contains("Missing admin role claim"));
}

#[test]
fn test_audit_actor_from_claims_rejects_non_string_role() {
    let claims = claims_with_role(json!(["admin"]));

    let err = AuditActor::from_claims(&claims).unwrap_err();

    assert!(err.contains("Invalid admin role claim type"));
}

#[test]
fn test_audit_event_new_populates_metadata_and_preserves_diff() {
    let actor = AuditActor {
        sub: "admin-user".to_string(),
        role: AdminRole::Admin,
    };
    let diff = update_diff(json!({ "enabled": false }), json!({ "enabled": true }));
    let before = Utc::now();

    let event = AuditEvent::new(
        &actor,
        "update",
        "plugin_config",
        "auth-plugin",
        "tenant-a",
        diff.clone(),
    );
    let after = Utc::now();

    assert!(Uuid::parse_str(&event.id).is_ok());
    assert!(event.ts >= before);
    assert!(event.ts <= after);
    assert_eq!(event.actor, "admin-user");
    assert_eq!(event.action, "update");
    assert_eq!(event.resource_type, "plugin_config");
    assert_eq!(event.resource_id, "auth-plugin");
    assert_eq!(event.namespace, "tenant-a");
    assert_eq!(event.diff, diff);
}

#[test]
fn test_audit_diff_helpers_preserve_operation_shape() {
    let before = json!({ "name": "before", "nested": { "count": 1 } });
    let after = json!({ "name": "after", "nested": { "count": 2 } });

    assert_eq!(
        create_diff(after.clone()),
        json!({ "after": after.clone() })
    );
    assert_eq!(
        update_diff(before.clone(), after.clone()),
        json!({ "before": before.clone(), "after": after })
    );
    assert_eq!(delete_diff(before.clone()), json!({ "before": before }));
}

#[test]
fn test_audit_list_filter_default_is_empty_with_zero_pagination() {
    let filter = AuditListFilter::default();

    assert!(filter.actor.is_none());
    assert!(filter.action.is_none());
    assert!(filter.resource_type.is_none());
    assert!(filter.resource_id.is_none());
    assert!(filter.start.is_none());
    assert!(filter.end.is_none());
    assert_eq!(filter.limit, 0);
    assert_eq!(filter.offset, 0);
}
