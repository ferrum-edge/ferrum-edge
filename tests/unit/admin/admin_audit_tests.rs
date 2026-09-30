//! Tests for admin audit primitives.

use chrono::{Duration, Utc};
use ferrum_edge::admin::advancing_u32_offset;
use ferrum_edge::admin::audit::{
    AuditActor, AuditEvent, AuditListFilter, create_diff, credential_update_diff, delete_diff,
    update_diff,
};
use ferrum_edge::admin::jwt_auth::{AdminClaims, AdminKeyTier, AdminRole, VerifiedAdminToken};
use serde_json::json;
use uuid::Uuid;

fn verified(claims: AdminClaims, key_tier: AdminKeyTier) -> VerifiedAdminToken {
    VerifiedAdminToken {
        header: jsonwebtoken::Header::default(),
        claims,
        key_tier,
        namespace_ceiling: None,
    }
}

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

    let actor = AuditActor::from_verified(&verified(claims, AdminKeyTier::Primary)).unwrap();

    assert_eq!(actor.sub, "audit-user");
    assert_eq!(actor.role, AdminRole::Operator);
    assert_eq!(actor.key_tier, AdminKeyTier::Primary);
    assert_eq!(actor.audit_subject(), "audit-user");
}

#[test]
fn test_audit_actor_from_viewer_key_is_capped_and_labelled() {
    let mut claims = claims_with_role(json!("admin"));
    claims.additional["scope"] = json!("diagnostics:read");
    let token = verified(claims, AdminKeyTier::Viewer);
    assert!(!token.grants_scope("diagnostics:read"));

    let actor = AuditActor::from_verified(&token).unwrap();

    assert_eq!(actor.role, AdminRole::Viewer);
    assert_eq!(actor.key_tier, AdminKeyTier::Viewer);
    assert_eq!(actor.audit_subject(), "viewer-key:audit-user");
    let event = AuditEvent::new(&actor, "read", "config", "c1", "ferrum", json!({}));
    assert_eq!(event.actor, "viewer-key:audit-user");
}

#[test]
fn test_primary_subjects_cannot_impersonate_a_viewer_key_actor() {
    let actor_for = |sub: &str, key_tier: AdminKeyTier| {
        let mut claims = claims_with_role(json!("viewer"));
        claims.sub = sub.to_string();
        AuditActor::from_verified(&verified(claims, key_tier)).unwrap()
    };

    let viewer = actor_for("alice", AdminKeyTier::Viewer).audit_subject();
    assert_eq!(viewer, "viewer-key:alice");
    let lookalike = actor_for("viewer-key:alice", AdminKeyTier::Primary).audit_subject();
    assert_eq!(lookalike, "primary-key:viewer-key:alice");
    assert_ne!(lookalike, viewer);

    // The escape is itself escaped, so the mapping stays injective.
    let escaped = actor_for("primary-key:viewer-key:alice", AdminKeyTier::Primary);
    assert_eq!(
        escaped.audit_subject(),
        "primary-key:primary-key:viewer-key:alice"
    );
    let plain = actor_for("alice", AdminKeyTier::Primary).audit_subject();
    assert_eq!(plain, "alice");
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

    let err = AuditActor::from_verified(&verified(claims, AdminKeyTier::Primary)).unwrap_err();

    assert!(err.contains("Missing admin role claim"));
}

#[test]
fn test_audit_actor_from_claims_rejects_non_string_role() {
    let claims = claims_with_role(json!(["admin"]));

    let err = AuditActor::from_verified(&verified(claims, AdminKeyTier::Primary)).unwrap_err();

    assert!(err.contains("Invalid admin role claim type"));
}

#[test]
fn test_audit_event_new_populates_metadata_and_preserves_diff() {
    let actor = AuditActor {
        sub: "admin-user".to_string(),
        role: AdminRole::Admin,
        allowed_namespaces: ferrum_edge::grpc::auth::AllowedNamespaces::empty(),
        key_tier: AdminKeyTier::Primary,
        namespace_ceiling: None,
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
    assert!(event.source_address.is_empty());
    assert!(event.request_id.is_empty());
    assert!(event.outcome.is_empty());
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
    assert_eq!(
        credential_update_diff("basicauth", before.clone(), json!({"updated": true})),
        json!({
            "credential_type": "basicauth",
            "credential_change": "[REDACTED]",
            "before": before.clone(),
            "after": {"updated": true},
        })
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

#[test]
fn audit_next_offset_is_strictly_advancing_and_representable() {
    assert_eq!(advancing_u32_offset(10, 25, 100), Some(35));
    assert_eq!(advancing_u32_offset(75, 25, 100), None);
    assert_eq!(advancing_u32_offset(10, 0, 100), None);
    assert_eq!(advancing_u32_offset(u32::MAX - 1, 2, i64::MAX), None);
    assert_eq!(advancing_u32_offset(u32::MAX, 1, i64::MAX), None);
}

// ---------------------------------------------------------------------------
// Mesh config-revision reset audit (issue #4177)
// ---------------------------------------------------------------------------

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Once;

use ferrum_edge::admin::audit::{AuditPipelineConfig, AuditUnavailablePolicy, initialize};
use ferrum_edge::admin::audit_spool::SpooledAuditRecord;
use ferrum_edge::admin::{
    AdminConnLimiter, AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::modes::mesh::revision::MeshConfigRevision;
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use jsonwebtoken::{EncodingKey, Header, encode};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct MeshResetTestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for MeshResetTestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "mesh-config-revision-reset-audit-secret".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn mesh_reset_jwt_manager(config: &MeshResetTestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn mesh_reset_operator_token(config: &MeshResetTestConfig) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "mesh-reset-operator",
        "role": "operator",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::minutes(5)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

fn init_mesh_reset_audit_pipeline_once(dir: &TempDir) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let cfg = AuditPipelineConfig {
            enabled: true,
            spool_dir: Some(dir.path().to_path_buf()),
            policy: AuditUnavailablePolicy::FailClosed,
            destination: "sqlite:ferrum:0123456789abcdef0123456789abcdef".to_string(),
            queue_capacity: 8,
            spool_max_records: 1,
            retained_max_records: 8,
            max_delivery_attempts: 3,
        };
        initialize(cfg).expect("audit pipeline initializes for mesh reset tests");
    });
}

fn mesh_reset_admin_state(
    jwt: JwtManager,
    mesh_runtime: MeshRuntimeState,
    read_only: bool,
    audit_enabled: bool,
) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt,
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "mesh".to_string(),
        read_only,
        admin_audit_enabled: audit_enabled,
        admin_audit_fallback_dir: Some(crate::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: Some(mesh_runtime),
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: None,
    }
}

async fn start_mesh_reset_admin(state: AdminState) -> SocketAddr {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Hold the sender for the server's lifetime: this helper returns only the
        // address, so dropping it here would close the watch channel and the
        // listener would stop before the test issued its first request.
        let _shutdown_tx = shutdown_tx;
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual_addr).await.is_ok() {
            return actual_addr;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener never became ready");
}

async fn post_mesh_reset(addr: SocketAddr, path: &str, token: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to admin listener");
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         X-Request-Id: mesh-reset-audit-test\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write admin request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read admin response");
    let raw = String::from_utf8(response).expect("utf-8 response");
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, raw)
}

fn install_mesh_revision(runtime: &MeshRuntimeState, authority: &str, sequence: u64) {
    let slice = MeshSlice {
        revision: Some(MeshConfigRevision::new(authority, sequence)),
        ..MeshSlice::default()
    };
    let _guard = ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock();
    runtime.install_slice(slice);
}

fn spool_instance_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<_> = std::fs::read_dir(root.join("instances"))
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn read_pending_spool_records(spool_root: &Path) -> Vec<SpooledAuditRecord> {
    let mut records = Vec::new();
    for instance in spool_instance_dirs(spool_root) {
        let pending = instance.join("pending");
        if !pending.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&pending).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let bytes = std::fs::read(&path).expect("read spool record");
                let record: SpooledAuditRecord =
                    serde_json::from_slice(&bytes).expect("parse spool record");
                records.push(record);
            }
        }
    }
    records
}

#[tokio::test]
#[serial_test::serial(mesh_config_revision_reset_audit)]
async fn mesh_config_revision_reset_requires_confirm_and_records_audit_on_success() {
    let audit_dir = TempDir::new().expect("audit spool tempdir");
    init_mesh_reset_audit_pipeline_once(&audit_dir);

    let tc = MeshResetTestConfig::default();
    let token = mesh_reset_operator_token(&tc);
    let runtime = MeshRuntimeState::new();
    install_mesh_revision(&runtime, "db", 4821);

    let state = mesh_reset_admin_state(mesh_reset_jwt_manager(&tc), runtime, true, true);
    let addr = start_mesh_reset_admin(state).await;

    let (status, body) = post_mesh_reset(addr, "/mesh/config-revision/reset", &token).await;
    assert_eq!(status, 400, "unconfirmed reset must be rejected: {body}");
    assert!(
        body.contains("confirm=true"),
        "rejection must name the confirmation knob: {body}"
    );

    let (status, body) =
        post_mesh_reset(addr, "/mesh/config-revision/reset?confirm=true", &token).await;
    assert_eq!(status, 200, "confirmed reset must succeed: {body}");
    assert!(body.contains("\"status\":\"reset\""), "body: {body}");

    let records = read_pending_spool_records(audit_dir.path());
    let reset_events: Vec<_> = records
        .iter()
        .filter(|record| record.event.action == "reset")
        .collect();
    assert_eq!(reset_events.len(), 1, "one reset audit record: {records:?}");
    let event = &reset_events[0].event;
    assert_eq!(event.resource_type, "mesh_config_revision");
    assert_eq!(event.resource_id, "db");
    assert_eq!(event.outcome, "success");
    assert_eq!(event.source_address, "127.0.0.1");
    assert_eq!(event.request_id, "mesh-reset-audit-test");
    assert_eq!(event.diff["cleared_authority"], "db");
    assert_eq!(event.diff["cleared_sequence"], 4821);

    let (status, body) =
        post_mesh_reset(addr, "/mesh/config-revision/reset?confirm=true", &token).await;
    assert_eq!(
        status, 503,
        "fail-closed audit saturation must refuse a second reset: {body}"
    );
    assert!(
        body.contains("audit_unavailable_reason"),
        "503 must carry the closed-set audit reason: {body}"
    );
}
