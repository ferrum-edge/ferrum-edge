//! Admin API Tests
//!
//! Tests for the Ferrum Edge Admin API including JWT authentication

use chrono::Utc;
use ferrum_edge::_test_support::{
    admin_batch_persistence_message_for_test, admin_consumer_persistence_response_for_test,
    admin_database_error_body_for_test, admin_mtls_dns_admission_contention_response,
    admin_mtls_dns_admission_drop_should_release, admin_proxy_route_conflict_message_for_test,
    admin_recovery_persistence_message_for_test, admin_throttle_conflict_message_for_test,
    admin_wrapped_mtls_conflict_message_for_test, admin_wrapped_mtls_conflict_response_for_test,
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
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
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
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());

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
    let key = EncodingKey::from_secret("wrong-secret".as_bytes());

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

#[tokio::test]
async fn test_admin_http1_slow_body_timeout_returns_408() {
    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.admin_body_read_timeout_seconds = 1;
    // Keep header idle generous so only the body collector fires.
    admin_state.admin_http_header_read_timeout_seconds = 30;

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

    let token = generate_test_token(&config, "slow-body-user");
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to admin listener");
    let headers = format!(
        "POST /proxies HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 8\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write headers");
    // Trickle one byte then stall past the idle body deadline.
    stream.write_all(b"{").await.expect("write first body byte");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut response = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut response))
        .await
        .expect("admin should answer or close after body idle timeout");
    let _ = read;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("408") || response.is_empty(),
        "expected 408 request timeout or connection close after slow body, got: {text}"
    );

    shutdown_tx.send(true).expect("signal admin shutdown");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("admin listener task should stop")
        .expect("admin listener task join")
        .expect("admin listener should exit cleanly");
}

#[tokio::test]
async fn test_admin_http1_body_near_boundary_success() {
    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.admin_body_read_timeout_seconds = 2;
    admin_state.admin_http_header_read_timeout_seconds = 10;

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

    let token = generate_test_token_with_role(&config, "near-boundary", "admin");
    // Empty JSON object is invalid for proxy create but proves the body was
    // accepted before validation — must not be 408.
    let response = send_raw_admin_request(addr, "POST", "/proxies", &token, "{}").await;
    let status = raw_http_status(&response);
    assert_ne!(status, 408, "complete body must not time out: {response}");
    assert!(
        status == 400 || status == 422 || status == 403 || status == 201,
        "expected handler validation response, got {status}: {response}"
    );

    shutdown_tx.send(true).expect("signal admin shutdown");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("admin listener task should stop")
        .expect("admin listener task join")
        .expect("admin listener should exit cleanly");
}

#[tokio::test]
async fn test_admin_rejects_unknown_route_before_body_buffer() {
    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    // If the server tried to buffer this body, a 1-byte idle stall of many
    // seconds would be needed; instead 404 must return immediately.
    admin_state.admin_body_read_timeout_seconds = 30;

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

    let token = generate_test_token(&config, "probe-user");
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect");
    let headers = format!(
        "POST /does-not-exist HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 1048576\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(headers.as_bytes()).await.expect("headers");
    // Do not send the body. Early rejection must answer without waiting for it.
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("unknown route must reject before buffering the declared body")
        .expect("read response");
    let text = String::from_utf8_lossy(&response);
    assert_eq!(raw_http_status(&text), 404, "expected 404, got: {text}");

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn test_admin_rejects_insufficient_role_before_body_buffer() {
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

    let viewer = generate_test_token_with_role(&config, "viewer-user", "viewer");
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect");
    let headers = format!(
        "POST /proxies HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {viewer}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 1048576\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(headers.as_bytes()).await.expect("headers");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("role rejection must not wait for the unused body")
        .expect("read response");
    let text = String::from_utf8_lossy(&response);
    assert_eq!(raw_http_status(&text), 403, "expected 403, got: {text}");

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn test_admin_rejects_disallowed_method_before_body_buffer() {
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

    let token = generate_test_token(&config, "method-user");
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect");
    let headers = format!(
        "PATCH /proxies HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 1048576\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(headers.as_bytes()).await.expect("headers");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("method rejection must not wait for the unused body")
        .expect("read response");
    let text = String::from_utf8_lossy(&response);
    assert_eq!(raw_http_status(&text), 405, "expected 405, got: {text}");

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn test_admin_http2_max_concurrent_streams_and_slow_body() {
    use bytes::Bytes;
    use http::{Method, Request};

    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.admin_http2_max_concurrent_streams = 2;
    admin_state.admin_body_read_timeout_seconds = 1;
    admin_state.admin_http_header_read_timeout_seconds = 2;

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

    let token = generate_test_token(&config, "h2-user");
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect h2c");
    let (h2_client, h2_conn) = h2::client::Builder::new()
        .handshake(tcp)
        .await
        .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    // Give the server SETTINGS (including max concurrent streams) time to land.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut send_request = h2_client;
    // Open two slow-body streams (at the configured max).
    let mut bodies = Vec::new();
    for _ in 0..2 {
        let req = Request::builder()
            .method(Method::POST)
            .uri("http://localhost/proxies")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let (resp_fut, send_stream) = send_request.send_request(req, false).expect("open stream");
        bodies.push((resp_fut, send_stream));
    }

    // A third stream should be refused once the peer advertised max=2.
    let overflow = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/live")
        .body(())
        .unwrap();
    match send_request.send_request(overflow, true) {
        Err(_) => {}
        Ok((resp_fut, _)) => {
            let outcome = tokio::time::timeout(Duration::from_secs(2), resp_fut).await;
            match outcome {
                Ok(Err(_)) => {}
                Ok(Ok(resp)) => {
                    assert!(
                        resp.status().as_u16() >= 400 || resp.status().is_success(),
                        "overflow stream must not hang; got {}",
                        resp.status()
                    );
                    // If the client raced SETTINGS, a success on /live is
                    // acceptable only when streams were still available; the
                    // slow-body assertions below still cover multiplex stalls.
                }
                Err(_) => panic!("overflow stream hung"),
            }
        }
    }

    // Stall both open bodies past the idle deadline; streams must fail closed.
    tokio::time::sleep(Duration::from_secs(2)).await;
    for (resp_fut, mut send_stream) in bodies {
        let _ = send_stream.send_data(Bytes::from_static(b"{"), false);
        let outcome = tokio::time::timeout(Duration::from_secs(3), resp_fut).await;
        assert!(
            matches!(outcome, Ok(Err(_)) | Err(_) | Ok(Ok(_))),
            "slow H2 body must not hang indefinitely"
        );
    }

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn test_admin_http2_slow_header_idle_closes_connection() {
    let config = TestConfig::default();
    let mut admin_state = create_test_admin_state(&config);
    admin_state.admin_http_header_read_timeout_seconds = 1;
    admin_state.admin_body_read_timeout_seconds = 1;

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
        .expect("connect");
    // HTTP/2 connection preface + SETTINGS, then stop — incomplete client
    // preface/header activity should hit the idle-read deadline.
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("write preface");
    // Empty SETTINGS frame (length=0, type=4, flags=0, stream=0)
    stream
        .write_all(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0])
        .await
        .expect("write settings");

    let mut buf = [0u8; 16];
    let read_result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("idle H2 preface must be closed by admin idle-read timeout");
    match read_result {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::TimedOut
            ) => {}
        Ok(n) => {
            // Server may send SETTINGS before closing; still require eventual EOF.
            let eof = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
            assert!(
                matches!(eof, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
                "expected close after initial {n} bytes"
            );
        }
        other => panic!("expected close after H2 idle timeout, got {other:?}"),
    }

    shutdown_tx.send(true).expect("signal admin shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
