//! Admin API Tests
//!
//! Tests for the Ferrum Edge Admin API including JWT authentication

use chrono::Utc;
use ferrum_edge::_test_support::{
    AdminMtlsDnsAdmissionHoldProbe, admin_batch_persistence_message_for_test,
    admin_consumer_persistence_response_for_test, admin_database_error_body_for_test,
    admin_mtls_dns_admission_contention_response, admin_mtls_dns_admission_drop_should_release,
    admin_proxy_route_conflict_message_for_test, admin_recovery_persistence_message_for_test,
    admin_throttle_conflict_message_for_test, admin_wrapped_mtls_conflict_message_for_test,
    admin_wrapped_mtls_conflict_response_for_test,
};
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{AdminClaims, AdminRole, JwtConfig, JwtManager},
};
use http_body_util::BodyExt;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

#[derive(Clone, Default)]
struct SharedAdminLogWriter(Arc<Mutex<Vec<u8>>>);

impl SharedAdminLogWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for SharedAdminLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedAdminLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn mtls_dns_admission_lifecycle_only_retains_uncertain_mutations() {
    assert!(admin_mtls_dns_admission_drop_should_release(false, false));
    assert!(admin_mtls_dns_admission_drop_should_release(true, true));
    assert!(!admin_mtls_dns_admission_drop_should_release(true, false));
}

type RestoreImportResult = (usize, Vec<String>);

fn restore_import_succeeded(result: &RestoreImportResult) -> bool {
    result.1.is_empty()
}

#[tokio::test]
async fn mtls_dns_admission_single_mutation_drop_behaviour_is_unchanged() {
    let probe = AdminMtlsDnsAdmissionHoldProbe::new();
    assert!(probe.drop_releases(), "not-started mutation releases");

    // A cancelled in-flight mutation retains the fence.
    tokio::select! {
        biased;
        _ = probe.run_mutation(std::future::pending::<()>()) => unreachable!(),
        _ = std::future::ready(()) => {}
    }
    assert!(
        !probe.drop_releases(),
        "cancelled in-flight mutation retains"
    );

    let fresh = AdminMtlsDnsAdmissionHoldProbe::new();
    fresh.run_mutation(async { 1_u8 }).await;
    assert!(fresh.drop_releases(), "settled mutation releases");
    fresh.run_mutation(async { 2_u8 }).await;
    assert!(
        fresh.drop_releases(),
        "sequential settled mutations release"
    );
}

#[tokio::test]
async fn mtls_dns_admission_nested_mutation_does_not_settle_outer_uncertain_mutation() {
    let probe = AdminMtlsDnsAdmissionHoldProbe::new();
    let (inner_done_tx, inner_done_rx) = tokio::sync::oneshot::channel::<()>();
    let outer = probe.run_mutation(async {
        probe.run_mutation(async {}).await;
        let _ = inner_done_tx.send(());
        std::future::pending::<()>().await
    });
    tokio::select! {
        biased;
        _ = outer => unreachable!(),
        _ = inner_done_rx => {}
    }
    assert!(
        !probe.drop_releases(),
        "a nested mutation's exit must restore the outer in-flight state"
    );
}

#[tokio::test]
async fn mtls_dns_restore_import_errors_then_unpolled_rollback_retains_fence() {
    let probe = AdminMtlsDnsAdmissionHoldProbe::new();
    probe
        .run_restore_clear(async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    assert!(!probe.drop_releases(), "cleared namespace retains");

    let result: RestoreImportResult = probe
        .run_restore_import(
            async { (3, vec!["chunk failed".to_string()]) },
            restore_import_succeeded,
        )
        .await;
    assert_eq!(result.1.len(), 1);
    assert!(
        !probe.drop_releases(),
        "import with errors must not settle the incomplete restore"
    );

    // The compensating rollback is dispatched through an admission wrapper
    // that can fail (for example `ensure_held()`) without polling it.
    let rollback = probe.run_restore_rollback(async { Ok::<(), Vec<String>>(()) });
    drop(rollback);
    assert!(
        !probe.drop_releases(),
        "an unpolled rollback leaves a half-restored namespace fenced"
    );
}

#[tokio::test]
async fn mtls_dns_restore_cancellation_after_clear_retains_fence() {
    // Cancelled between the clear and the import dispatch.
    let probe = AdminMtlsDnsAdmissionHoldProbe::new();
    probe
        .run_restore_clear(async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    assert!(!probe.drop_releases());

    // Cancelled while the import is in flight.
    let in_flight = AdminMtlsDnsAdmissionHoldProbe::new();
    in_flight
        .run_restore_clear(async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    tokio::select! {
        biased;
        _ = in_flight.run_restore_import(
            std::future::pending::<RestoreImportResult>(),
            restore_import_succeeded,
        ) => unreachable!(),
        _ = std::future::ready(()) => {}
    }
    assert!(!in_flight.drop_releases());

    // Cancelled while the compensating rollback is in flight.
    let rolling_back = AdminMtlsDnsAdmissionHoldProbe::new();
    rolling_back
        .run_restore_clear(async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    rolling_back
        .run_restore_import(
            async { (0, vec!["chunk failed".to_string()]) },
            restore_import_succeeded,
        )
        .await;
    tokio::select! {
        biased;
        _ = rolling_back.run_restore_rollback(
            std::future::pending::<Result<(), Vec<String>>>(),
        ) => unreachable!(),
        _ = std::future::ready(()) => {}
    }
    assert!(!rolling_back.drop_releases());
}

// The production finalizer path (`finish_failed_restore` through
// `/restore`) is covered by
// `tests/integration/admin_cached_config_tests.rs::mtls_dns_restore_failed_rollback_retains_fence`.
#[tokio::test]
async fn mtls_dns_restore_failed_rollback_phase_retains_from_any_prior_phase() {
    let after_import = AdminMtlsDnsAdmissionHoldProbe::new();
    after_import
        .run_restore_clear(async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    after_import
        .run_restore_import(
            async { (0, vec!["chunk failed".to_string()]) },
            restore_import_succeeded,
        )
        .await;
    let rollback = after_import
        .run_restore_rollback(async { Err::<(), _>(vec!["replay failed".to_string()]) })
        .await;
    assert!(rollback.is_err());
    assert!(!after_import.drop_releases());

    // A non-atomic clear failure reaches the rollback without a recorded
    // clear; a failed replay must still retain the fence.
    let after_partial_clear = AdminMtlsDnsAdmissionHoldProbe::new();
    assert!(
        after_partial_clear
            .run_restore_clear(async { Err::<(), _>("partial clear") })
            .await
            .is_err()
    );
    assert!(after_partial_clear.drop_releases());
    let rollback = after_partial_clear
        .run_restore_rollback(async { Err::<(), _>(vec!["replay failed".to_string()]) })
        .await;
    assert!(rollback.is_err());
    assert!(!after_partial_clear.drop_releases());
}

#[tokio::test]
async fn mtls_dns_restore_success_and_completed_rollback_release_fence() {
    let restored = AdminMtlsDnsAdmissionHoldProbe::new();
    restored
        .run_restore_clear(async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    restored
        .run_restore_import(async { (5, Vec::new()) }, restore_import_succeeded)
        .await;
    assert!(restored.drop_releases(), "successful restore releases");

    let rolled_back = AdminMtlsDnsAdmissionHoldProbe::new();
    rolled_back
        .run_restore_clear(async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    rolled_back
        .run_restore_import(
            async { (1, vec!["chunk failed".to_string()]) },
            restore_import_succeeded,
        )
        .await;
    rolled_back
        .run_restore_rollback(async { Ok::<(), Vec<String>>(()) })
        .await
        .unwrap();
    assert!(rolled_back.drop_releases(), "completed rollback releases");

    // A definitively failed clear never enters the incomplete-restore phase.
    let clear_aborted = AdminMtlsDnsAdmissionHoldProbe::new();
    assert!(
        clear_aborted
            .run_restore_clear(async { Err::<(), _>("atomic abort") })
            .await
            .is_err()
    );
    assert!(clear_aborted.drop_releases());
}

/// Source slice from `start` up to the next `end` marker.
fn admin_source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing {start}"));
    let to = source[from..]
        .find(end)
        .map(|offset| from + offset)
        .unwrap_or_else(|| panic!("missing {end} after {start}"));
    &source[from..to]
}

/// Issue #7062 (following #7032): the lost-lease recovery sites cannot be
/// driven through the SQLite `/restore` harness, so pin their wiring
/// structurally. Recovery keeps the restore's original guard (the durable
/// fence) across the namespace lease reacquisition: neither recovery section
/// may release it or replace it with a reacquired owner, which would leave a
/// window with no fence over a cleared or partially imported namespace. Both
/// rollback finalizers must gate their explicit release on the restore phase.
#[test]
fn mtls_dns_restore_recovery_paths_keep_phase_gated_fence() {
    let source = include_str!("../../../src/admin/mod.rs");
    let handler = admin_source_section(source, "async fn handle_restore(", "\nasync fn ");

    let lost_clear = admin_source_section(
        handler,
        "if let Some(_error) = delete_admission_error {",
        "if let Err(e) = delete_result {",
    );
    let lost_import = admin_source_section(
        handler,
        "error_persistence_failure_redacted(\"restore_namespace_admission_lost_during_import\");",
        "let rollback = finish_failed_restore(",
    );
    for (site, section) in [("lost clear", lost_clear), ("lost import", lost_import)] {
        assert!(
            !section.contains("restore_guard.release()"),
            "{site} recovery must not release the restore guard before recovery"
        );
        assert!(
            !section.contains("restore_guard = "),
            "{site} recovery must keep the original restore guard, not reacquire one"
        );
        let reacquire = section
            .find("crud::lock_namespace_config_admission(")
            .unwrap_or_else(|| panic!("{site} recovery must reacquire namespace admission"));
        assert!(
            section[..reacquire].contains("drop(namespace_config_admission_guard);"),
            "{site} recovery drops only the lost namespace lease before reacquiring it"
        );
    }
    let failed_import_phase = lost_import
        .find("restore_guard.retain_restore_import_failed();")
        .expect("the lost import must record the failed-import phase");
    assert!(
        failed_import_phase
            < lost_import
                .find("crud::lock_namespace_config_admission(")
                .expect("lost import reacquisition"),
        "the lost import must record the failed-import phase before any await"
    );
    assert!(
        lost_clear.contains("restore_guard.retain_restore_cleared();"),
        "a lost clear that may have removed rows must enter the cleared phase"
    );

    assert!(
        handler.contains("if !restore_guard.restore_phase_allows_release() {"),
        "the successful-import release must be phase gated"
    );

    for (start, end) in [
        (
            "async fn finish_failed_restore(",
            "async fn finish_failed_restore_after_intervening_clear(",
        ),
        (
            "async fn finish_failed_restore_after_intervening_clear(",
            "async fn finish_atomic_delete_failure(",
        ),
    ] {
        let finalizer = admin_source_section(source, start, end);
        let gate = finalizer
            .find("let fence_retained = !guard.restore_phase_allows_release();")
            .unwrap_or_else(|| panic!("{start} must gate its release on the restore phase"));
        let retained = finalizer.find("if fence_retained {").unwrap_or_else(|| {
            panic!("{start} must retain the fence when the phase forbids release")
        });
        let release = finalizer
            .find("} else if let Err(_error) = guard.release().await {")
            .unwrap_or_else(|| panic!("{start} must release only in the gated else branch"));
        assert!(gate < retained && retained < release, "{start} gate order");
        assert_eq!(
            finalizer.matches("guard.release().await").count(),
            1,
            "{start} must have no ungated release"
        );
    }
}

#[tokio::test]
async fn mtls_dns_restore_lost_lease_phase_retains_until_rollback_completes() {
    // Lease lost during clear or import: the original owner stays in the
    // incomplete phase until its rollback completes.
    let after_clear = AdminMtlsDnsAdmissionHoldProbe::new();
    after_clear.mark_restore_cleared();
    assert!(!after_clear.drop_releases());
    after_clear
        .run_restore_rollback(async { Ok::<(), Vec<String>>(()) })
        .await
        .unwrap();
    assert!(after_clear.drop_releases());

    let after_import = AdminMtlsDnsAdmissionHoldProbe::new();
    after_import.mark_restore_import_failed();
    assert!(!after_import.drop_releases());
    drop(after_import.run_restore_rollback(async { Ok::<(), Vec<String>>(()) }));
    assert!(!after_import.drop_releases());
}

#[tokio::test]
async fn mtls_dns_admission_contention_is_retryable_and_redacted() {
    let raw_detail = "mysql topology secret-admission-owner";
    let response = admin_mtls_dns_admission_contention_response(raw_detail);
    assert_eq!(response.status(), hyper::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers()[hyper::header::RETRY_AFTER]
            .to_str()
            .unwrap(),
        "1"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(
        body,
        r#"{"error":"Namespace mutation is temporarily unavailable; retry later"}"#
    );
    assert!(!body.contains(raw_detail));
}

#[tokio::test]
async fn persistence_failures_are_redacted_from_admin_responses_and_logs() {
    let raw_backend_detail = "postgres://ferrum:s3cr3t-dsn-password@db.internal:5432/ferrum_prod: relation secret_schema.consumers violates constraint secret_constraint using index secret_index";
    let raw_unique_detail = "E11000 duplicate key error collection: ferrum.consumers index: secret_index dup key: { credentials.keyauth.key: must-not-escape }";
    let writer = SharedAdminLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(writer.clone())
        .finish();

    crate::diagnostic_test_interest::ensure_interest_floor();
    let (
        batch_message,
        recovery_message,
        database_body,
        generic_consumer_response,
        unique_batch_message,
        unique_consumer_response,
    ) = tracing::subscriber::with_default(subscriber, || {
        (
            admin_batch_persistence_message_for_test(raw_backend_detail),
            admin_recovery_persistence_message_for_test(raw_backend_detail),
            admin_database_error_body_for_test(raw_backend_detail),
            admin_consumer_persistence_response_for_test(raw_backend_detail),
            admin_batch_persistence_message_for_test(raw_unique_detail),
            admin_consumer_persistence_response_for_test(raw_unique_detail),
        )
    });

    assert_eq!(batch_message, "Database unavailable — operation failed");
    assert_eq!(
        recovery_message,
        "failed to clear existing config: Database unavailable — operation failed"
    );
    assert_eq!(
        database_body,
        json!({"error": "Database unavailable — operation failed"})
    );
    assert_eq!(
        generic_consumer_response.status(),
        hyper::StatusCode::INTERNAL_SERVER_ERROR
    );
    let generic_consumer_body = generic_consumer_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        String::from_utf8(generic_consumer_body.to_vec()).unwrap(),
        r#"{"error":"Database unavailable — operation failed"}"#
    );

    assert_eq!(
        unique_batch_message,
        "Resource identity conflicts with an existing resource in the namespace"
    );
    assert_eq!(
        unique_consumer_response.status(),
        hyper::StatusCode::CONFLICT
    );
    let unique_consumer_body = unique_consumer_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        String::from_utf8(unique_consumer_body.to_vec()).unwrap(),
        r#"{"error":"Consumer identity or credential conflicts with another Consumer in the namespace"}"#
    );

    let logs = writer.contents();
    assert!(logs.contains("external_recovery_regression"));
    assert!(logs.contains("database_response"));
    assert!(logs.contains("consumer_persist"));
    assert!(logs.contains("detail_withheld=true"));
    let visible = format!(
        "{batch_message}\n{recovery_message}\n{database_body}\n{unique_batch_message}\n{logs}"
    );
    for sentinel in [
        "s3cr3t-dsn-password",
        "db.internal:5432",
        "ferrum_prod",
        "secret_schema",
        "secret_constraint",
        "secret_index",
        "credentials.keyauth.key",
        "must-not-escape",
    ] {
        assert!(
            !visible.contains(sentinel),
            "admin response or log leaked persistence sentinel {sentinel:?}: {visible}"
        );
    }
}

#[tokio::test]
async fn typed_and_static_persistence_conflicts_survive_wrapping_without_context_leaks() {
    let raw_backend_detail = "insert into secret_schema.consumers on postgres://ferrum:s3cr3t-dsn-password@db.internal:5432/ferrum_prod using secret_constraint";
    let mtls_message = admin_wrapped_mtls_conflict_message_for_test(raw_backend_detail);
    let mtls_response = admin_wrapped_mtls_conflict_response_for_test(raw_backend_detail);
    let throttle_message = admin_throttle_conflict_message_for_test(raw_backend_detail);
    let route_message = admin_proxy_route_conflict_message_for_test(raw_backend_detail);

    assert_eq!(
        mtls_message,
        "mTLS DNS identity conflict: consumers edge-a and edge-b share mTLS DNS identity svc.internal"
    );
    assert_eq!(mtls_response.status(), hyper::StatusCode::CONFLICT);
    let mtls_body = mtls_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        String::from_utf8(mtls_body.to_vec()).unwrap(),
        r#"{"error":"mTLS DNS identity conflict: consumers edge-a and edge-b share mTLS DNS identity svc.internal"}"#
    );
    assert_eq!(
        throttle_message,
        "PluginConfig 'throttle-a' cannot attach to UDP proxy 'edge-a'"
    );
    assert_eq!(
        route_message,
        ferrum_edge::config::db_backend::PROXY_ROUTE_CONFLICT_ERROR
    );
    for message in [mtls_message, throttle_message, route_message] {
        for sentinel in [
            "secret_schema",
            "s3cr3t-dsn-password",
            "db.internal:5432",
            "ferrum_prod",
            "secret_constraint",
        ] {
            assert!(
                !message.contains(sentinel),
                "typed/static conflict leaked wrapping context {sentinel:?}: {message}"
            );
        }
    }
}

/// Test configuration for admin API
#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
    admin_addr: SocketAddr,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-admin-api".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
            admin_addr: "127.0.0.1:0".parse().unwrap(),
        }
    }
}

/// Create a test JWT manager
fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    let jwt_config = JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    JwtManager::new(jwt_config)
}

/// Create a test admin state
fn create_test_admin_state(config: &TestConfig) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: false, // Default to read-write for existing tests
        admin_audit_enabled: false,
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
        mesh_runtime_state: None,
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

/// Generate a valid JWT token for testing
fn generate_test_token(config: &TestConfig, subject: &str) -> String {
    generate_test_token_with_role(config, subject, "admin")
}

/// Generate a valid JWT token for testing with a specific role.
fn generate_test_token_with_role(config: &TestConfig, subject: &str, role: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": subject,
        "role": role,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": Uuid::new_v4().to_string()
    });

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes()).unwrap();

    encode(&header, &claims, &key).unwrap()
}

async fn send_raw_admin_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: &str,
) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to admin listener");
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
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
    String::from_utf8(response).expect("admin response should be utf-8")
}

fn raw_http_status(response: &str) -> u16 {
    response
        .lines()
        .next()
        .expect("response status line")
        .split_whitespace()
        .nth(1)
        .expect("response status code")
        .parse()
        .expect("numeric response status")
}

/// Generate an invalid JWT token (wrong secret)
fn generate_invalid_token(config: &TestConfig, subject: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": subject,
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": Uuid::new_v4().to_string()
    });

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret("wrong-secret".as_bytes()).unwrap();

    encode(&header, &claims, &key).unwrap()
}

fn admin_claims_with_role(role: serde_json::Value) -> AdminClaims {
    let now = Utc::now();
    AdminClaims {
        iss: "test-ferrum-edge".to_string(),
        sub: "test-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + chrono::Duration::seconds(3600)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        additional: role,
    }
}

#[tokio::test]
async fn test_jwt_token_validation() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test valid token
    let valid_token = generate_test_token(&config, "test-user");
    let result = jwt_manager.verify_token(&valid_token);
    assert!(result.is_ok(), "Valid token should pass verification");

    // Test invalid token (wrong secret)
    let invalid_token = generate_invalid_token(&config, "test-user");
    let result = jwt_manager.verify_token(&invalid_token);
    assert!(result.is_err(), "Invalid token should fail verification");

    // Test malformed token
    let result = jwt_manager.verify_token("malformed-token");
    assert!(result.is_err(), "Malformed token should fail verification");
}

#[test]
fn test_admin_jwt_role_claim_parsing() {
    assert!(
        admin_claims_with_role(json!({})).admin_role().is_err(),
        "missing role must fail closed"
    );
    assert_eq!(
        admin_claims_with_role(json!({"role": "viewer"}))
            .admin_role()
            .unwrap(),
        AdminRole::Viewer
    );
    assert_eq!(
        admin_claims_with_role(json!({"role": "operator"}))
            .admin_role()
            .unwrap(),
        AdminRole::Operator
    );
    assert_eq!(
        admin_claims_with_role(json!({"role": "admin"}))
            .admin_role()
            .unwrap(),
        AdminRole::Admin
    );
    assert!(
        admin_claims_with_role(json!({"role": 1}))
            .admin_role()
            .is_err()
    );
    assert!(
        admin_claims_with_role(json!({"role": "root"}))
            .admin_role()
            .is_err()
    );
}

#[tokio::test]
async fn test_admin_api_integration() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config);

    // Test that the admin API is properly initialized
    assert_eq!(admin_state.mode, "test");

    // Test basic functionality
    let token = generate_test_token(&config, "test-user");
    let result = admin_state.jwt_manager.verify_token(&token);
    assert!(result.is_ok(), "Generated token should be valid");
}

#[tokio::test]
async fn test_tls_mutation_routes_require_admin_jwt_role() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config);

    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            admin_state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
    });

    let operator_token = generate_test_token_with_role(&config, "operator-user", "operator");
    let admin_token = generate_test_token_with_role(&config, "admin-user", "admin");

    let operator_response = send_raw_admin_request(
        addr,
        "POST",
        "/admin/tls/certificates",
        &operator_token,
        "{}",
    )
    .await;
    assert_eq!(
        raw_http_status(&operator_response),
        403,
        "operator token must not reach persisted TLS mutation handler: {operator_response}"
    );

    let admin_response =
        send_raw_admin_request(addr, "POST", "/admin/tls/certificates", &admin_token, "{}").await;
    assert_eq!(
        raw_http_status(&admin_response),
        400,
        "admin token should pass role gate and fail only request validation: {admin_response}"
    );

    let validate_response =
        send_raw_admin_request(addr, "POST", "/admin/tls/validate", &operator_token, "{}").await;
    assert_ne!(
        raw_http_status(&validate_response),
        403,
        "operator token should remain allowed on TLS validation route: {validate_response}"
    );

    shutdown_tx.send(true).expect("signal admin shutdown");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("admin listener task should stop")
        .expect("admin listener task join")
        .expect("admin listener should exit cleanly");
}

#[tokio::test]
async fn test_admin_http1_slow_header_timeout_closes_connection() {
    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.admin_http_header_read_timeout_seconds = 1;

    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            admin_state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
    });

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to admin listener");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write partial headers");

    let mut buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("admin listener should close slow header connection");

    match read_result {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) => {}
        other => panic!("expected EOF or reset after header timeout, got {other:?}"),
    }

    shutdown_tx.send(true).expect("signal admin shutdown");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("admin listener task should stop")
        .expect("admin listener task join")
        .expect("admin listener should exit cleanly");
}

#[tokio::test]
async fn test_jwt_configuration_validation() {
    // Test various configuration scenarios
    let configs = vec![
        (TestConfig::default(), "Default configuration"),
        (
            TestConfig {
                jwt_secret: "different-secret".to_string(),
                jwt_issuer: "different-issuer".to_string(),
                max_ttl: 7200,
                admin_addr: "127.0.0.1:0".parse().unwrap(),
            },
            "Custom configuration",
        ),
        (
            TestConfig {
                jwt_secret: "short".to_string(),
                jwt_issuer: "test".to_string(),
                max_ttl: 60,
                admin_addr: "127.0.0.1:0".parse().unwrap(),
            },
            "Minimal configuration",
        ),
    ];

    for (config, description) in configs {
        let admin_state = create_test_admin_state(&config);
        let token = generate_test_token(&config, "test-user");
        let result = admin_state.jwt_manager.verify_token(&token);

        assert!(
            result.is_ok(),
            "Configuration '{}' should work: {:?}",
            description,
            result
        );
        println!("Configuration test passed: {}", description);
    }
}

#[tokio::test]
async fn test_jwt_security_scenarios() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test 1: Token reuse
    let token = generate_test_token(&config, "test-user");
    for _ in 0..5 {
        let result = jwt_manager.verify_token(&token);
        assert!(result.is_ok());
    }

    // Test 2: Token tampering
    let token = generate_test_token(&config, "test-user");
    let tampered_token = format!("{}tampered", token);
    let result = jwt_manager.verify_token(&tampered_token);
    assert!(result.is_err());

    // Test 3: Cross-issuer attack
    let wrong_config = TestConfig {
        jwt_secret: config.jwt_secret.clone(),
        jwt_issuer: "attacker".to_string(),
        max_ttl: config.max_ttl,
        admin_addr: config.admin_addr,
    };
    let wrong_token = generate_test_token(&wrong_config, "test-user");
    let result = jwt_manager.verify_token(&wrong_token);
    assert!(result.is_err());

    println!("All security tests passed");
}

#[tokio::test]
async fn test_jwt_performance() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test performance characteristics
    let start = std::time::Instant::now();

    // Generate and verify multiple tokens
    for i in 0..100 {
        let token = generate_test_token(&config, &format!("user-{}", i));
        let result = jwt_manager.verify_token(&token);
        assert!(result.is_ok());
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 1000,
        "100 token verifications should complete within 1 second"
    );

    println!(
        "Performance test completed in {}ms for 100 tokens",
        duration.as_millis()
    );
}

#[tokio::test]
async fn test_jwt_concurrent_access() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);

    // Test concurrent token generation and verification
    let mut handles = Vec::new();

    for i in 0..50 {
        let config_clone = config.clone();
        let jwt_manager_clone = jwt_manager.clone();

        let handle = tokio::spawn(async move {
            let token = generate_test_token(&config_clone, &format!("user-{}", i));
            jwt_manager_clone.verify_token(&token).is_ok()
        });

        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 50,
        "All concurrent token verifications should succeed"
    );
}

/// Issue #4529: the admin plane must engage `ns`-claim enforcement on exactly
/// the scopes the CP↔DP gRPC plane already does. `cp` mode derives
/// `AdminState.admin_require_namespace_claim` from
/// `CpScope::namespace_claim_required(FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM)`,
/// so a multi-namespace CP cannot authorize a staging-scoped token against
/// `prod` on `/backup` or `/restore` while the gRPC plane refuses it.
#[test]
fn admin_namespace_claim_derivation_matches_cp_scope() {
    use ferrum_edge::grpc::cp_server::CpScope;

    let single = CpScope::Single("ferrum".to_string());
    assert!(
        !single.namespace_claim_required(false),
        "single-namespace CP with the flag off keeps the header a routing selector"
    );
    assert!(
        single.namespace_claim_required(true),
        "the explicit env flag still engages enforcement on a single-namespace CP"
    );

    let set = CpScope::Set(
        ["prod", "staging"]
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::HashSet<String>>(),
    );
    assert!(
        set.namespace_claim_required(false),
        "an explicit multi-namespace scope engages enforcement without the env flag"
    );

    assert!(
        CpScope::All.namespace_claim_required(false),
        "a cluster-wide CP engages enforcement without the env flag"
    );
}

/// Headers of every block enclosing byte offset `at` in `source`, innermost
/// first. A header is the text between the previous statement boundary
/// (`;`, `{` or `}`) and the block's opening brace.
fn enclosing_block_headers(source: &str, at: usize) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut headers = Vec::new();
    let mut depth = 0usize;
    let mut index = at;
    while index > 0 {
        index -= 1;
        match bytes[index] {
            b'}' => depth += 1,
            b'{' if depth > 0 => depth -= 1,
            b'{' => {
                let header_start = source[..index]
                    .rfind([';', '{', '}'])
                    .map_or(0, |boundary| boundary + 1);
                headers.push(&source[header_start..index]);
            }
            _ => {}
        }
    }
    headers
}

/// Issue #7216: `/health` builds its detail-only blocks (pool stats, failover
/// topology, admission fences, cached config, polling detail, mesh state) only
/// for the authenticated detailed tier. Unauthenticated probes receive just
/// `status` + `ready`, so they must not pay for work whose result is
/// discarded. These blocks have no observable effect on the minimal body, so
/// the gate is pinned structurally: each call sits inside a block whose header
/// tests `detailed`.
#[test]
fn health_detail_blocks_are_built_only_for_the_detailed_tier() {
    let source = include_str!("../../../src/admin/mod.rs");
    let health = admin_source_section(
        source,
        "if (path == \"/health\" || path == \"/status\") && matches!(method, Method::GET | Method::HEAD) {",
        "// Overload status.",
    );
    for call in [
        "db.pool_stats()",
        "db.failover_topology_status()",
        "db.mtls_dns_admission_fence_status()",
        "state.cached_gateway_config()",
        "\"database_polling\"",
        "egress_scope_state()",
        "crate::fips::status_metadata()",
        "failures.snapshot()",
    ] {
        let at = health
            .find(call)
            .unwrap_or_else(|| panic!("/health no longer calls {call}"));
        // The call may sit in its own block's condition
        // (`if detailed && let Some(..) = call {`) or inside a gated block.
        let statement_start = health[..at]
            .rfind([';', '{', '}'])
            .map_or(0, |boundary| boundary + 1);
        let statement = &health[statement_start..at];
        let headers = enclosing_block_headers(health, at);
        assert!(
            statement.contains("detailed")
                || headers.iter().any(|header| header.contains("detailed")),
            "{call} must be built only inside a `detailed` gate; enclosing headers: {headers:?}"
        );
    }
}

async fn send_raw_admin_request_with_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to admin listener");
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(tok) = token {
        request.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    for (k, v) in extra_headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write admin request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read admin response");
    String::from_utf8(response).expect("admin response should be utf-8")
}

fn raw_http_json_body(response: &str) -> serde_json::Value {
    let (_, body) = response
        .split_once("\r\n\r\n")
        .expect("HTTP response header/body separator");
    serde_json::from_str(body).unwrap_or_else(|e| panic!("invalid JSON body ({e}): {body}"))
}

#[tokio::test]
async fn health_live_and_status_reject_non_get_methods() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config);
    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            admin_state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
    });

    for path in ["/live", "/health", "/status"] {
        let get_resp = send_raw_admin_request_with_headers(addr, "GET", path, None, &[], "").await;
        assert_eq!(
            raw_http_status(&get_resp),
            200,
            "GET {path} should succeed anonymously"
        );

        let head_resp =
            send_raw_admin_request_with_headers(addr, "HEAD", path, None, &[], "").await;
        assert_eq!(
            raw_http_status(&head_resp),
            200,
            "HEAD {path} should succeed anonymously"
        );
        let (head_headers, head_body) = head_resp
            .split_once("\r\n\r\n")
            .expect("HTTP response header/body separator");
        assert!(
            head_body.is_empty(),
            "HEAD {path} must return an empty HTTP/1.1 body, got: {head_body:?}"
        );
        assert!(
            head_headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("content-length:")),
            "HEAD {path} must preserve Content-Length header: {head_headers}"
        );

        let post_resp =
            send_raw_admin_request_with_headers(addr, "POST", path, None, &[], "").await;
        assert_eq!(
            raw_http_status(&post_resp),
            401,
            "unauthenticated POST {path} must not bypass auth via GET/HEAD probe routes: {post_resp}"
        );
    }

    let admin_token = generate_test_token_with_role(&config, "admin-user", "admin");
    for path in ["/live", "/health", "/status"] {
        let post_resp =
            send_raw_admin_request_with_headers(addr, "POST", path, Some(&admin_token), &[], "")
                .await;
        assert_ne!(
            raw_http_status(&post_resp),
            200,
            "authenticated POST {path} must not be treated as a GET probe: {post_resp}"
        );
    }

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = server.await;
}

#[tokio::test]
async fn head_probes_return_empty_body_and_end_stream_over_http2() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config);
    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            admin_state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
    });

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to admin listener over HTTP/2");
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("HTTP/2 h2c handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    for path in ["/live", "/health", "/status"] {
        let req = hyper::Request::builder()
            .method(hyper::Method::HEAD)
            .uri(format!("http://localhost{path}"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("build HEAD request");
        let resp = sender
            .send_request(req)
            .await
            .unwrap_or_else(|e| panic!("HTTP/2 HEAD {path} failed: {e}"));
        assert_eq!(
            resp.status(),
            hyper::StatusCode::OK,
            "HTTP/2 HEAD {path} should return 200"
        );
        assert_eq!(
            resp.headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "HTTP/2 HEAD {path} must preserve Content-Type"
        );
        let content_length: usize = resp
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("HTTP/2 HEAD {path} must preserve numeric Content-Length"));
        assert!(
            content_length > 0,
            "HTTP/2 HEAD {path} Content-Length should reflect GET payload size"
        );
        assert!(
            hyper::body::Body::is_end_stream(resp.body()),
            "HTTP/2 HEAD {path} must signal END_STREAM on HEADERS frame without DATA frames"
        );
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| panic!("HTTP/2 HEAD {path} body collection failed: {e}"))
            .to_bytes();
        assert!(
            body.is_empty(),
            "HTTP/2 HEAD {path} must terminate with END_STREAM and zero body bytes, got {} bytes",
            body.len()
        );
    }

    // Unauthenticated HEAD on a protected route returns 401 with END_STREAM on
    // the HEADERS frame and zero body bytes.
    let unauth_req = hyper::Request::builder()
        .method(hyper::Method::HEAD)
        .uri("http://localhost/proxies")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("build HEAD /proxies request");
    let unauth_resp = sender
        .send_request(unauth_req)
        .await
        .expect("HTTP/2 HEAD /proxies failed");
    assert_eq!(unauth_resp.status(), hyper::StatusCode::UNAUTHORIZED);
    assert!(
        hyper::body::Body::is_end_stream(unauth_resp.body()),
        "HTTP/2 HEAD 401 must signal END_STREAM on HEADERS frame"
    );
    let unauth_body = unauth_resp
        .into_body()
        .collect()
        .await
        .expect("HTTP/2 HEAD /proxies body collection failed")
        .to_bytes();
    assert!(
        unauth_body.is_empty(),
        "HTTP/2 HEAD 401 must carry zero body bytes"
    );

    drop(sender);
    let _ = conn_task.await;
    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = server.await;
}

#[tokio::test]
async fn head_withdrawn_client_trust_returns_401_end_stream_over_http2() {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};

    struct PausedReadIo {
        inner: tokio::io::DuplexStream,
        paused: Arc<AtomicBool>,
        read_waker: Arc<std::sync::Mutex<Option<Waker>>>,
        wrote_while_paused: Arc<tokio::sync::Notify>,
    }

    impl tokio::io::AsyncRead for PausedReadIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.paused.load(Ordering::Acquire) {
                *self.read_waker.lock().expect("read waker lock") = Some(cx.waker().clone());
                if self.paused.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for PausedReadIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
            if matches!(poll, Poll::Ready(Ok(n)) if n > 0) && self.paused.load(Ordering::Acquire) {
                self.wrote_while_paused.notify_waiters();
            }
            poll
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config);
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let paused = Arc::new(AtomicBool::new(false));
    let read_waker = Arc::new(std::sync::Mutex::new(None));
    let wrote_while_paused = Arc::new(tokio::sync::Notify::new());
    let gated_client_io = PausedReadIo {
        inner: client_io,
        paused: Arc::clone(&paused),
        read_waker: Arc::clone(&read_waker),
        wrote_while_paused: Arc::clone(&wrote_while_paused),
    };

    let trust_session = ferrum_edge::_test_support::new_admin_client_trust_session_for_test();
    let server_session = trust_session.clone();
    let server = tokio::spawn(async move {
        ferrum_edge::_test_support::serve_admin_io_with_client_trust_for_test(
            server_io,
            admin_state,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            server_session,
        )
        .await;
    });

    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(gated_client_io),
    )
    .await
    .expect("HTTP/2 h2c handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    // Confirm the connection is established while client trust is live.
    let get_req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("http://localhost/live")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("build GET /live request");
    let get_resp = sender
        .send_request(get_req)
        .await
        .expect("HTTP/2 GET /live while live");
    assert_eq!(get_resp.status(), hyper::StatusCode::OK);
    let _ = get_resp
        .into_body()
        .collect()
        .await
        .expect("collect GET body");

    // Pause client reads so the client flushes stream 3's HEADERS frame before
    // it can read and ACK the server's graceful-shutdown GOAWAY+PING; retire
    // trust synchronously before yielding so `session.is_retired()` is
    // guaranteed true when `serve_admin_io` dispatches the HEAD stream.
    let write_seen = wrote_while_paused.notified();
    tokio::pin!(write_seen);
    write_seen.as_mut().enable();
    paused.store(true, Ordering::Release);

    let head_req = hyper::Request::builder()
        .method(hyper::Method::HEAD)
        .uri("http://localhost/live")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("build HEAD /live request");
    let head_fut = sender.send_request(head_req);
    trust_session.cancellation_token().cancel();

    write_seen.await;
    paused.store(false, Ordering::Release);
    if let Some(waker) = read_waker.lock().expect("read waker lock").take() {
        waker.wake();
    }

    let head_resp = head_fut
        .await
        .expect("HTTP/2 HEAD /live after trust withdrawal");
    assert_eq!(
        head_resp.status(),
        hyper::StatusCode::UNAUTHORIZED,
        "retired client-trust HEAD must return 401"
    );
    assert!(
        head_resp
            .headers()
            .get(hyper::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("ClientCertificate")),
        "retired client-trust 401 must carry client-certificate challenge"
    );
    assert!(
        hyper::body::Body::is_end_stream(head_resp.body()),
        "retired client-trust HTTP/2 HEAD 401 must signal END_STREAM on HEADERS frame"
    );
    let head_body = head_resp
        .into_body()
        .collect()
        .await
        .expect("collect retired HEAD body")
        .to_bytes();
    assert!(
        head_body.is_empty(),
        "retired client-trust HTTP/2 HEAD 401 must carry zero body bytes"
    );

    drop(sender);
    let _ = conn_task.await;
    let _ = server.await;
}

#[test]
fn content_type_allowed_enforces_concrete_rfc9110_media_types() {
    use ferrum_edge::_test_support::api_spec_external_ref_content_type_allowed_for_test as content_type_allowed;

    for allowed in [
        "application/json",
        "application/json; charset=utf-8",
        "application/yaml",
        "application/vnd.oai.openapi+json",
        "application/vnd.oai.openapi+yaml; charset=\"utf-8\"",
        "text/plain",
    ] {
        assert!(
            content_type_allowed(allowed),
            "expected allowed media type: {allowed:?}"
        );
    }

    for rejected in [
        "application/json; charset=",
        "application/json;",
        "*/vendor+json",
        "*/*",
        "application/*",
        "application/foo/bar+json",
        "application/+json",
        "text/html",
    ] {
        assert!(
            !content_type_allowed(rejected),
            "expected rejected media type: {rejected:?}"
        );
    }
}

#[test]
fn head_withdrawn_trust_401_restore_partial_clear_and_tls_settlement_invariants() {
    let admin_source = include_str!("../../../src/admin/mod.rs");
    let retired_at = admin_source
        .find("session.is_retired()")
        .expect("withdrawn client trust guard");
    let wrap_at = retired_at
        + admin_source[retired_at..]
            .find("GuardedAdminBody::wrap_response(response, guard)")
            .expect("GuardedAdminBody convergence point");
    let transport_tail = &admin_source[retired_at..wrap_at];
    assert!(
        transport_tail.contains("strip_head_response_body(&mut response)"),
        "withdrawn-trust 401 and dispatched responses must converge before HEAD body stripping"
    );

    let restore_at = admin_source
        .find("if clear_may_be_partial")
        .expect("non-atomic potentially partial clear branch");
    let restore_end = restore_at
        + admin_source[restore_at..]
            .find("};")
            .expect("end of rollback status selection");
    let restore_slice = &admin_source[restore_at..restore_end];
    assert!(
        restore_slice.contains("\"skipped_after_intervening_write\""),
        "potentially partial non-atomic restore clear with intervening write must report skipped_after_intervening_write"
    );

    let tls_source = include_str!("../../../src/admin/tls_management.rs");
    for helper in [
        "async fn respond_managed_upsert(",
        "async fn respond_managed_update(",
        "async fn respond_acme_certificate_upsert(",
        "async fn respond_acme_certificate_update(",
        "pub(super) async fn handle_delete_managed(",
        "pub(super) async fn handle_delete_acme_certificate(",
    ] {
        let start = tls_source
            .find(helper)
            .unwrap_or_else(|| panic!("missing {helper}"));
        let end = start
            + tls_source[start..]
                .find("\n}\n")
                .unwrap_or_else(|| panic!("end of {helper}"));
        let body = &tls_source[start..end];
        assert!(
            body.contains("spawn_with_request_slot("),
            "{helper} must transfer settlement and audit to spawn_with_request_slot"
        );
        assert!(
            body.contains("request_managed_source_reloads()"),
            "{helper} must trigger watcher reloads inside detached settlement"
        );
        assert!(
            body.contains("super::record_operation_audit("),
            "{helper} must record its success audit inside detached settlement"
        );
    }
    for helper in [
        "pub(super) async fn handle_create_acme_order(",
        "pub(super) async fn handle_delete_acme_order(",
        "pub(super) async fn handle_renew_acme_certificate(",
    ] {
        let start = tls_source
            .find(helper)
            .unwrap_or_else(|| panic!("missing {helper}"));
        let end = start
            + tls_source[start..]
                .find("\n}\n")
                .unwrap_or_else(|| panic!("end of {helper}"));
        let body = &tls_source[start..end];
        assert!(
            body.contains("spawn_with_request_slot("),
            "{helper} must transfer settlement and audit to spawn_with_request_slot"
        );
        assert!(
            body.contains("super::record_operation_audit("),
            "{helper} must record its success audit inside detached settlement"
        );
    }
    let inv_start = tls_source
        .find("pub(super) async fn handle_inventory(")
        .expect("handle_inventory");
    let inv_end = inv_start
        + tls_source[inv_start..]
            .find("\n}\n")
            .expect("end of handle_inventory");
    let inv_body = &tls_source[inv_start..inv_end];
    assert!(
        inv_body.contains("TLS_INVENTORY_SLOTS"),
        "handle_inventory must bound blocking concurrency with TLS_INVENTORY_SLOTS"
    );
}

#[tokio::test]
async fn admin_response_budget_chunks_holds_permit_and_rejects_oversized_payloads() {
    // Oversized payloads (> budget capacity) must be refused rather than clamped
    // down to fit, and concurrent bodies exceeding remaining budget must fail fast.
    let (oversized_refused, first_admitted, second_refused) =
        ferrum_edge::_test_support::check_admin_response_budget_limits_for_test(
            256,
            300 * 1024,
            180 * 1024,
        );
    assert!(
        oversized_refused,
        "payload exceeding per-connection budget must be rejected without clamping"
    );
    assert!(
        first_admitted,
        "first fitting payload must be admitted by pre-check"
    );
    assert!(
        second_refused,
        "second payload exceeding remaining budget must be rejected"
    );

    // A 200 KiB budgeted body must yield multiple <= 64 KiB frames, keep the
    // permit reserved across intermediate frames, release on drop, and drop
    // immediately when stripped for HEAD.
    let (
        frame_count,
        available_after_acquire,
        available_mid_stream,
        available_after_drop,
        head_released,
    ) = ferrum_edge::_test_support::exercise_admin_response_budget_wrapper_for_test(
        256,
        200 * 1024,
    )
    .await
    .expect("budgeted response wrapper test helper");
    assert_eq!(
        frame_count, 4,
        "200 KiB body must stream as four <=64 KiB chunks"
    );
    assert_eq!(available_after_acquire, 56);
    assert_eq!(
        available_mid_stream, 56,
        "budget permit must remain held while subsequent chunks are still pending"
    );
    assert_eq!(
        available_after_drop, 256,
        "budget permit must release completely once GuardedAdminBody drops"
    );
    assert!(
        head_released,
        "strip_head_response_body must release response budget immediately"
    );

    // Bounded format conversion must abort before materializing oversized output.
    let json_payload =
        br#"{"openapi":"3.1.0","info":{"title":"Example","version":"1.0.0"},"paths":{}}"#;
    assert!(
        ferrum_edge::_test_support::api_spec_convert_format_capped_for_test(
            json_payload,
            ferrum_edge::config::types::SpecFormat::Json,
            ferrum_edge::config::types::SpecFormat::Yaml,
            16,
        )
        .is_err(),
        "capped JSON->YAML conversion must fail closed when output exceeds max_bytes"
    );
}

#[test]
fn stored_spec_assoc_decompress_cap_honors_conf_file_and_rejects_invalid_values() {
    use ferrum_edge::admin::api_specs::stored_spec_assoc_decompress_cap_from_resolved;
    use ferrum_edge::config::conf_file::{ConfFile, resolve_ferrum_var_checked_from};

    let conf = ConfFile::parse("FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB = 100\n")
        .expect("conf file with raised spec body limit parses");
    let resolved =
        resolve_ferrum_var_checked_from(None, &Ok(conf), "FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB")
            .expect("conf lookup succeeds");
    assert_eq!(
        stored_spec_assoc_decompress_cap_from_resolved(resolved.as_deref())
            .expect("100 MiB conf value parses"),
        200 * 1024 * 1024,
        "conf-file 100 MiB limit must yield a 200 MiB stored-spec association recovery cap"
    );

    // Default (unset) stays at the 64 MiB floor.
    assert_eq!(
        stored_spec_assoc_decompress_cap_from_resolved(None).expect("default cap"),
        64 * 1024 * 1024
    );

    // Invalid or zero values fail closed instead of silently falling back to 25 MiB.
    assert!(stored_spec_assoc_decompress_cap_from_resolved(Some("0")).is_err());
    assert!(stored_spec_assoc_decompress_cap_from_resolved(Some("not-a-number")).is_err());
}

#[tokio::test]
async fn if_match_and_conditional_do_not_preempt_forbidden_on_delete_and_bodyless_post() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config);
    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            admin_state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
    });

    let viewer_token = generate_test_token_with_role(&config, "viewer-user", "viewer");
    let operator_token = generate_test_token_with_role(&config, "operator-user", "operator");

    for (token, method, path, headers, body) in [
        (
            &viewer_token,
            "DELETE",
            "/proxies/p1",
            vec![("If-Match", "malformed")],
            "{}",
        ),
        (
            &viewer_token,
            "DELETE",
            "/proxies/p1?conditional=true",
            vec![("If-Match", "malformed")],
            "{}",
        ),
        (
            &viewer_token,
            "POST",
            "/backend-capabilities/refresh",
            vec![("If-Match", "\"etag\"")],
            "",
        ),
        (
            &viewer_token,
            "POST",
            "/backend-capabilities/refresh?conditional=true",
            vec![],
            "",
        ),
        (
            &operator_token,
            "DELETE",
            "/api-specs/s1",
            vec![("If-Match", "\"etag\"")],
            "{}",
        ),
        (
            &operator_token,
            "DELETE",
            "/gateway-trust-bundles/b1",
            vec![("If-Match", "\"etag\"")],
            "{}",
        ),
        (
            &operator_token,
            "POST",
            "/namespaces",
            vec![("If-Match", "\"etag\"")],
            "{}",
        ),
        (
            &operator_token,
            "POST",
            "/restore?confirm=true",
            vec![("If-Match", "malformed")],
            "{}",
        ),
    ] {
        let resp =
            send_raw_admin_request_with_headers(addr, method, path, Some(token), &headers, body)
                .await;
        assert_eq!(
            raw_http_status(&resp),
            403,
            "{method} {path} with {:?} must return 403 Forbidden before precondition 400: {resp}",
            headers
        );
    }

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = server.await;
}

#[test]
fn failed_restore_and_atomic_delete_helpers_record_failure_or_unknown_outcome() {
    let source = include_str!("../../../src/admin/mod.rs");
    for (fn_sig, expected_outcome) in [
        ("async fn finish_failed_restore(", "AuditOutcome::Failure"),
        (
            "async fn finish_failed_restore_after_intervening_clear(",
            "AuditOutcome::Failure",
        ),
        (
            "async fn finish_atomic_delete_failure(",
            "AuditOutcome::Failure",
        ),
        (
            "async fn finish_unknown_atomic_delete_failure(",
            "AuditOutcome::UnknownOutcome",
        ),
    ] {
        let body = admin_source_section(source, fn_sig, "\nasync fn ");
        assert!(
            body.contains(expected_outcome),
            "{fn_sig} must set {expected_outcome} on its audit event"
        );
    }
}

#[test]
fn gateway_trust_bundle_record_validate_fields_enforces_resource_id_and_254_byte_cap() {
    use ferrum_edge::config::gateway_trust::{GatewayTrustBundleRecord, MAX_TRUST_BUNDLE_ID_BYTES};
    assert_eq!(MAX_TRUST_BUNDLE_ID_BYTES, 254);

    let make_record = |id: &str| -> GatewayTrustBundleRecord {
        serde_json::from_value(json!({
            "id": id,
            "namespace": "ferrum",
            "trust_domain": "cluster.local",
            "bundle": {
                "local": {
                    "trust_domain": "cluster.local",
                    "x509_authorities": []
                }
            }
        }))
        .expect("deserialize GatewayTrustBundleRecord")
    };

    for invalid_id in [
        "../escape",
        "has space",
        "slash/id",
        &"a".repeat(MAX_TRUST_BUNDLE_ID_BYTES + 1),
    ] {
        let errs = make_record(invalid_id)
            .validate_fields()
            .expect_err("invalid trust bundle id must be rejected");
        assert!(
            errs.iter().any(|e| e.contains("id")),
            "expected id error for {invalid_id:?}, got {errs:?}"
        );
    }

    let valid_254 = "a".repeat(MAX_TRUST_BUNDLE_ID_BYTES);
    let errs = make_record(&valid_254)
        .validate_fields()
        .expect_err("empty x509_authorities still fails material validation");
    assert!(
        !errs
            .iter()
            .any(|e| e.starts_with("id ") || e.contains("trust bundle id")),
        "254-byte valid resource id must pass id validation: {errs:?}"
    );
}

#[tokio::test]
async fn restore_confirm_query_flag_fails_closed_on_repeated_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("restore_confirm.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = ferrum_edge::config::db_loader::DatabaseStore::connect_with_pool_config(
        "sqlite",
        &db_url,
        ferrum_edge::config::db_loader::DbPoolConfig::default(),
    )
    .await
    .expect("connect sqlite store");

    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.db = Some(Arc::new(store));
    admin_state.mode = "database".to_string();

    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            admin_state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
    });

    let admin_token = generate_test_token_with_role(&config, "admin-user", "admin");
    let resp = send_raw_admin_request_with_headers(
        addr,
        "POST",
        "/restore?confirm=true&confirm=false",
        Some(&admin_token),
        &[],
        "{}",
    )
    .await;
    assert_eq!(
        raw_http_status(&resp),
        400,
        "repeated confirm=true&confirm=false must fail closed with 400: {resp}"
    );

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = server.await;
}

#[test]
fn decompress_gzip_capped_handles_usize_max_without_overflow() {
    use flate2::{Compression, write::GzEncoder};
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(b"hello ferrum").expect("write gzip payload");
    let compressed = enc.finish().expect("finish gzip");

    let out = ferrum_edge::admin::spec_codec::decompress_gzip_capped(&compressed, usize::MAX)
        .expect("usize::MAX cap must not overflow");
    assert_eq!(out, b"hello ferrum");
}

#[tokio::test]
async fn crud_put_preserves_created_at_across_updates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("crud_created_at.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = ferrum_edge::config::db_loader::DatabaseStore::connect_with_pool_config(
        "sqlite",
        &db_url,
        ferrum_edge::config::db_loader::DbPoolConfig::default(),
    )
    .await
    .expect("connect sqlite store");

    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.db = Some(Arc::new(store));
    admin_state.mode = "database".to_string();

    let listener = tokio::net::TcpListener::bind(config.admin_addr)
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin listener addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            admin_state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
    });

    let admin_token = generate_test_token_with_role(&config, "admin-user", "admin");

    // 1. Proxy create + update
    let create_proxy = send_raw_admin_request(
        addr,
        "POST",
        "/proxies",
        &admin_token,
        &json!({
            "id": "p-preserve",
            "name": "initial",
            "listen_path": "/preserve",
            "backend_host": "example.com",
            "backend_port": 443
        })
        .to_string(),
    )
    .await;
    assert_eq!(raw_http_status(&create_proxy), 201, "{create_proxy}");
    let created_proxy = raw_http_json_body(&create_proxy);

    tokio::time::sleep(Duration::from_millis(20)).await;

    let update_proxy = send_raw_admin_request(
        addr,
        "PUT",
        "/proxies/p-preserve",
        &admin_token,
        &json!({
            "name": "updated",
            "listen_path": "/preserve",
            "backend_host": "example.com",
            "backend_port": 443
        })
        .to_string(),
    )
    .await;
    assert_eq!(raw_http_status(&update_proxy), 200, "{update_proxy}");
    let updated_proxy = raw_http_json_body(&update_proxy);
    assert_eq!(
        updated_proxy["created_at"], created_proxy["created_at"],
        "PUT /proxies/{{id}} must preserve created_at"
    );

    // 2. Upstream create + update
    let create_upstream = send_raw_admin_request(
        addr,
        "POST",
        "/upstreams",
        &admin_token,
        &json!({
            "id": "u-preserve",
            "name": "initial-u",
            "targets": [{"host": "example.com", "port": 443, "weight": 100}]
        })
        .to_string(),
    )
    .await;
    assert_eq!(raw_http_status(&create_upstream), 201, "{create_upstream}");
    let created_upstream = raw_http_json_body(&create_upstream);

    tokio::time::sleep(Duration::from_millis(20)).await;

    let update_upstream = send_raw_admin_request(
        addr,
        "PUT",
        "/upstreams/u-preserve",
        &admin_token,
        &json!({
            "name": "updated-u",
            "targets": [{"host": "example.com", "port": 8443, "weight": 100}]
        })
        .to_string(),
    )
    .await;
    assert_eq!(raw_http_status(&update_upstream), 200, "{update_upstream}");
    let updated_upstream = raw_http_json_body(&update_upstream);
    assert_eq!(
        updated_upstream["created_at"], created_upstream["created_at"],
        "PUT /upstreams/{{id}} must preserve created_at"
    );

    // 3. Consumer create + update
    let create_consumer = send_raw_admin_request(
        addr,
        "POST",
        "/consumers",
        &admin_token,
        &json!({
            "id": "c-preserve",
            "username": "alice-preserve"
        })
        .to_string(),
    )
    .await;
    assert_eq!(raw_http_status(&create_consumer), 201, "{create_consumer}");
    let created_consumer = raw_http_json_body(&create_consumer);

    tokio::time::sleep(Duration::from_millis(20)).await;

    let update_consumer = send_raw_admin_request(
        addr,
        "PUT",
        "/consumers/c-preserve",
        &admin_token,
        &json!({
            "username": "alice-preserve-updated"
        })
        .to_string(),
    )
    .await;
    assert_eq!(raw_http_status(&update_consumer), 200, "{update_consumer}");
    let updated_consumer = raw_http_json_body(&update_consumer);
    assert_eq!(
        updated_consumer["created_at"], created_consumer["created_at"],
        "PUT /consumers/{{id}} must preserve created_at"
    );

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = server.await;
}

#[test]
fn managed_tls_store_atomic_update_existing_and_delete_kind() {
    use ferrum_edge::tls::managed::{
        ManagedTlsError, ManagedTlsMaterialKind, ManagedTlsRecord, ManagedTlsStore,
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open(dir.path()).expect("open managed tls store");

    let jwks_v1 = ManagedTlsRecord::new_jwks(
        "rec-1".to_string(),
        "jwks-v1".to_string(),
        None,
        r#"{"keys":[]}"#.to_string(),
    );

    // update_existing fails with NotFound when absent (never silently creates)
    assert!(matches!(
        store.update_existing(jwks_v1.clone()),
        Err(ManagedTlsError::NotFound(_))
    ));

    // Create initial JWKS record
    let created = store.upsert(jwks_v1, false).expect("create jwks");

    // Cross-kind update_existing fails with KindConflict
    let ca_wrong_kind = ManagedTlsRecord::new_ca_bundle(
        "rec-1".to_string(),
        "ca-clash".to_string(),
        None,
        "dummy-ca".to_string(),
    );
    assert!(matches!(
        store.update_existing(ca_wrong_kind),
        Err(ManagedTlsError::KindConflict {
            existing_kind: "jwks",
            requested_kind: "ca_bundle",
            ..
        })
    ));

    // Same-kind update_existing succeeds and preserves created_at
    let jwks_v2 = ManagedTlsRecord::new_jwks(
        "rec-1".to_string(),
        "jwks-v2".to_string(),
        None,
        r#"{"keys":[]}"#.to_string(),
    );
    let updated = store.update_existing(jwks_v2).expect("update jwks");
    assert_eq!(updated.created_at, created.created_at);
    assert_eq!(updated.name, "jwks-v2");

    // delete_kind_if_authorized rejects wrong kind atomically without deleting
    assert!(matches!(
        store.delete_kind_if_authorized("rec-1", ManagedTlsMaterialKind::CaBundle, || true),
        Err(ManagedTlsError::WrongKind { .. })
    ));
    assert!(
        store.get("rec-1").is_ok(),
        "wrong-kind delete must not remove record"
    );

    // delete_kind_if_authorized deletes matching kind when authorized
    let deleted = store
        .delete_kind_if_authorized("rec-1", ManagedTlsMaterialKind::Jwks, || true)
        .expect("delete matching kind");
    assert!(deleted.is_some());
    assert!(matches!(
        store.get("rec-1"),
        Err(ManagedTlsError::NotFound(_))
    ));
}

#[test]
fn acme_certificate_store_update_existing_rejects_missing() {
    use ferrum_edge::tls::acme::{
        AcmeCertificateRecord, AcmeCertificateStore, AcmeError, AcmeIssuedCertificateInput,
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let store = AcmeCertificateStore::open(dir.path()).expect("open acme cert store");

    let cert = rcgen::generate_simple_self_signed(vec!["example.com".to_string()])
        .expect("generate self-signed cert");
    let record = AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: "acme-missing".to_string(),
        domains: vec!["example.com".to_string()],
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
        account_id: None,
        order_url: None,
        cert_pem: cert.cert.pem(),
        key_pem: cert.signing_key.serialize_pem(),
        chain_pem: None,
    })
    .expect("build acme cert record");

    assert!(matches!(
        store.update_existing_certificate(record.clone()),
        Err(AcmeError::NotFound(_))
    ));
    store
        .upsert_certificate(record.clone(), false)
        .expect("insert acme cert");
    let updated = store
        .update_existing_certificate(record)
        .expect("update existing acme cert");
    assert_eq!(updated.id, "acme-missing");
}
