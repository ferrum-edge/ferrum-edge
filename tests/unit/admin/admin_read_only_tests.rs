//! Admin Read-Only Mode Tests
//!
//! Tests for the Admin API read-only mode functionality

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;

/// Test configuration for admin API
#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-admin-api".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
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

/// Create a test admin state with specified read-only mode
fn create_test_admin_state(config: &TestConfig, read_only: bool) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only,
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
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

/// Generate a valid JWT token for testing
fn generate_test_token(config: &TestConfig, subject: &str) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": subject,
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string()
    });

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());

    encode(&header, &claims, &key).unwrap()
}

#[tokio::test]
async fn test_admin_state_read_only_field() {
    let config = TestConfig::default();

    // Test read-only state
    let admin_state_read_only = create_test_admin_state(&config, true);
    assert!(
        admin_state_read_only.read_only,
        "Admin state should be read-only"
    );

    // Test read-write state
    let admin_state_read_write = create_test_admin_state(&config, false);
    assert!(
        !admin_state_read_write.read_only,
        "Admin state should not be read-only"
    );
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
    let wrong_config = TestConfig {
        jwt_secret: "wrong-secret".to_string(),
        jwt_issuer: config.jwt_issuer.clone(),
        max_ttl: config.max_ttl,
    };
    let invalid_token = generate_test_token(&wrong_config, "test-user");
    let result = jwt_manager.verify_token(&invalid_token);
    assert!(result.is_err(), "Invalid token should fail verification");
}

#[tokio::test]
async fn test_admin_api_integration() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config, false);

    // Test that admin API is properly initialized
    assert_eq!(admin_state.mode, "test");
    assert!(
        !admin_state.read_only,
        "Default admin state should not be read-only"
    );

    // Test basic functionality
    let token = generate_test_token(&config, "test-user");
    let result = admin_state.jwt_manager.verify_token(&token);
    assert!(result.is_ok(), "Generated token should be valid");
}

#[tokio::test]
async fn test_admin_read_only_mode_configuration() {
    let config = TestConfig::default();

    // Test read-only mode configuration
    let admin_state_read_only = create_test_admin_state(&config, true);
    assert!(
        admin_state_read_only.read_only,
        "Read-only mode should be enabled"
    );

    // Test read-write mode configuration
    let admin_state_read_write = create_test_admin_state(&config, false);
    assert!(
        !admin_state_read_write.read_only,
        "Read-write mode should not be read-only"
    );
}

#[tokio::test]
async fn test_admin_state_mode_field() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config, false);

    // Test mode field is set correctly
    assert_eq!(admin_state.mode, "test");

    // Test mode field can be different
    let admin_state_prod = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "production".to_string(),
        read_only: false,
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
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    assert_eq!(admin_state_prod.mode, "production");
}

#[tokio::test]
async fn test_admin_state_jwt_manager() {
    let config = TestConfig::default();
    let admin_state = create_test_admin_state(&config, false);

    // Test JWT manager is properly initialized
    let token = generate_test_token(&config, "test-user");
    let result = admin_state.jwt_manager.verify_token(&token);
    assert!(result.is_ok(), "JWT manager should work correctly");
}

#[tokio::test]
async fn test_check_write_allowed_permits_when_db_available() {
    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag),
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
    };
    assert!(
        state.check_write_allowed().is_none(),
        "Writes should be allowed when db_available=true and read_only=false"
    );
}

#[tokio::test]
async fn test_check_write_allowed_blocks_when_db_unavailable() {
    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag),
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
    };
    let resp = state.check_write_allowed();
    assert!(
        resp.is_some(),
        "Writes should be blocked when db_available=false"
    );
    assert_eq!(
        resp.unwrap().status(),
        hyper::StatusCode::SERVICE_UNAVAILABLE,
        "Should return 503 when DB is unavailable"
    );
}

#[tokio::test]
async fn test_check_write_allowed_blocks_when_read_only() {
    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag),
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
    };
    let resp = state.check_write_allowed();
    assert!(
        resp.is_some(),
        "Writes should be blocked when read_only=true"
    );
    assert_eq!(
        resp.unwrap().status(),
        hyper::StatusCode::FORBIDDEN,
        "Should return 403 when read_only"
    );
}

#[tokio::test]
async fn test_check_write_allowed_permits_when_no_db_flag() {
    let config = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "file".to_string(),
        read_only: false,
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
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    assert!(
        state.check_write_allowed().is_none(),
        "Writes should be allowed when db_available is None and read_only=false"
    );
}

#[tokio::test]
async fn test_db_available_flag_transitions() {
    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag.clone()),
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
    };

    // Initially available
    assert!(state.check_write_allowed().is_none());

    // Simulate DB going down
    db_flag.store(false, Ordering::Relaxed);
    assert!(state.check_write_allowed().is_some());

    // Simulate DB recovery
    db_flag.store(true, Ordering::Relaxed);
    assert!(state.check_write_allowed().is_none());
}

#[tokio::test]
async fn test_check_write_allowed_blocks_on_failover_without_opt_in() {
    use ferrum_edge::_test_support::DbPoolConfig;
    use ferrum_edge::config::db_backend::DatabaseBackend;
    use ferrum_edge::config::db_loader::DatabaseStore;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    assert!(!store.failover_topology_status().primary_active);

    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let db: Arc<dyn ferrum_edge::config::db_backend::DatabaseBackend> = Arc::new(store);
    let state = AdminState {
        db: Some(db),
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag),
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
    };

    assert!(
        state.admin_writes_currently_blocked(),
        "observe-only gate must report writes blocked on failover"
    );
    let resp = state.check_write_allowed();
    assert!(resp.is_some(), "mutations must fail closed on failover");
    assert_eq!(
        resp.unwrap().status(),
        hyper::StatusCode::SERVICE_UNAVAILABLE
    );
    // Observe-only and mutation gates must not diverge on the default fail-closed path.
    assert!(state.admin_writes_currently_blocked());
}

#[tokio::test]
async fn test_check_write_allowed_opt_in_is_policy_pure() {
    use ferrum_edge::_test_support::DbPoolConfig;
    use ferrum_edge::config::db_backend::DatabaseBackend;
    use ferrum_edge::config::db_loader::DatabaseStore;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let mut store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    store.set_failover_allow_writes(true);

    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let db: Arc<dyn ferrum_edge::config::db_backend::DatabaseBackend> = Arc::new(store);
    let state = AdminState {
        db: Some(db.clone()),
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag),
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
    };

    assert!(
        !state.admin_writes_currently_blocked(),
        "opt-in must leave observe-only gate open"
    );
    let before = db.failover_topology_status();
    assert!(before.allow_writes);
    assert!(
        before.opt_in_writes_enabled_during_window,
        "store opt-in enablement records the window risk marker"
    );
    assert!(
        state.check_write_allowed().is_none(),
        "opt-in must admit mutations on failover"
    );
    let after = db.failover_topology_status();
    assert_eq!(
        before, after,
        "check_write_allowed must be observationally pure (no mutation counters)"
    );
    // Rejected/invalid requests never reach persistence; the public health
    // surface must not claim "accepted" writes from gate admission alone.
    assert!(
        state.check_write_allowed().is_none() && state.check_write_allowed().is_none(),
        "repeated gate checks must stay pure"
    );
    assert_eq!(db.failover_topology_status(), after);
}

#[tokio::test]
async fn test_admit_write_pins_and_blocks_on_failover_without_opt_in() {
    use ferrum_edge::_test_support::DbPoolConfig;
    use ferrum_edge::config::db_backend::DatabaseBackend;
    use ferrum_edge::config::db_loader::DatabaseStore;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_rw_url = format!("sqlite:{}?mode=rw", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let store = DatabaseStore::connect_with_failover(
        "sqlite",
        &primary_rw_url,
        std::slice::from_ref(&failover_url),
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    assert!(!store.failover_topology_status().primary_active);

    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let db: Arc<dyn ferrum_edge::config::db_backend::DatabaseBackend> = Arc::new(store);
    let state = AdminState {
        db: Some(db),
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag),
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
    };

    let Err(err) = state.admit_write().await else {
        panic!("admit_write must fail closed on failover without opt-in");
    };
    assert_eq!(err.status(), hyper::StatusCode::SERVICE_UNAVAILABLE);

    // Independent TLS/ACME stores must not inherit sticky DB failover policy.
    state
        .admit_non_config_db_write()
        .expect("admit_non_config_db_write must ignore failover topology");
}

#[tokio::test]
async fn test_admit_non_config_db_write_keeps_read_only_and_db_unavailable_gates() {
    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let read_only_state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(Arc::new(AtomicBool::new(true))),
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
    };
    let Err(read_only_err) = read_only_state.admit_non_config_db_write() else {
        panic!("admit_non_config_db_write must honor read-only mode");
    };
    assert_eq!(read_only_err.status(), hyper::StatusCode::FORBIDDEN);

    let unavailable_state = AdminState {
        read_only: false,
        db_available: Some(db_flag),
        ..read_only_state
    };
    let Err(unavailable_err) = unavailable_state.admit_non_config_db_write() else {
        panic!("admit_non_config_db_write must honor database-unavailable");
    };
    assert_eq!(
        unavailable_err.status(),
        hyper::StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn test_admit_write_retains_pin_for_mutation_lifetime_on_primary() {
    use ferrum_edge::_test_support::{
        DbPoolConfig, SqlReconnectTopology, SqlReconnectTransitionTestHooks,
        database_store_reconnect_as_failover_for_test,
        database_store_set_reconnect_transition_hooks_for_test,
    };
    use ferrum_edge::config::db_backend::DatabaseBackend;
    use ferrum_edge::config::db_loader::DatabaseStore;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::oneshot;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let primary_path = temp_dir.path().join("primary.db");
    let failover_path = temp_dir.path().join("failover.db");
    let primary_url = format!("sqlite:{}?mode=rwc", primary_path.to_string_lossy());
    let failover_url = format!("sqlite:{}?mode=rwc", failover_path.to_string_lossy());

    let store =
        DatabaseStore::connect_with_pool_config("sqlite", &primary_url, DbPoolConfig::default())
            .await
            .unwrap();
    assert!(store.failover_topology_status().primary_active);

    let config = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let db: Arc<dyn ferrum_edge::config::db_backend::DatabaseBackend> = Arc::new(store.clone());
    let state = AdminState {
        db: Some(db),
        jwt_manager: create_test_jwt_manager(&config),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag),
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
    };

    let permit = state
        .admit_write()
        .await
        .expect("primary admit_write must succeed");
    assert!(
        permit.is_pinned(),
        "admit_write must return a live topology pin for SQL backends"
    );

    let (before_lock_tx, before_lock_rx) = oneshot::channel::<()>();
    let holding = Arc::new(AtomicBool::new(false));
    let before_lock_tx = Arc::new(StdMutex::new(Some(before_lock_tx)));
    database_store_set_reconnect_transition_hooks_for_test(
        &store,
        Some(SqlReconnectTransitionTestHooks {
            before_lock: Some(Arc::new({
                let before_lock_tx = Arc::clone(&before_lock_tx);
                move |topology| {
                    let before_lock_tx = Arc::clone(&before_lock_tx);
                    Box::pin(async move {
                        if topology != SqlReconnectTopology::Failover {
                            return;
                        }
                        if let Some(tx) = before_lock_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                    })
                }
            })),
            while_holding: Some(Arc::new({
                let holding = Arc::clone(&holding);
                move |topology| {
                    let holding = Arc::clone(&holding);
                    Box::pin(async move {
                        if topology == SqlReconnectTopology::Failover {
                            holding.store(true, Ordering::SeqCst);
                        }
                    })
                }
            })),
        }),
    );

    let failover_store = store.clone();
    let failover_url_task = failover_url.clone();
    let failover_task = tokio::spawn(async move {
        database_store_reconnect_as_failover_for_test(&failover_store, &failover_url_task).await
    });
    before_lock_rx
        .await
        .expect("failover must reach write lock while admit pin is held");
    assert!(
        !holding.load(Ordering::SeqCst),
        "reconnect must wait for the full mutation permit lifetime"
    );
    assert!(store.failover_topology_status().primary_active);

    drop(permit);
    failover_task
        .await
        .expect("join failover")
        .expect("failover reconnect");
    database_store_set_reconnect_transition_hooks_for_test(&store, None);
    assert!(!store.failover_topology_status().primary_active);
}

/// Config-database Admin mutation paths must call `admit_write()` (topology
/// pin). Managed TLS/ACME handlers mutate independent stores and must call
/// `admit_non_config_db_write()` instead. The sync `check_write_allowed()`
/// remains observe-only for `/health` and policy tests.
#[test]
fn admin_mutation_handlers_use_admit_write_not_sync_gate_alone() {
    let config_db_sources = [
        ("mod.rs", include_str!("../../../src/admin/mod.rs")),
        ("crud.rs", include_str!("../../../src/admin/crud.rs")),
        (
            "api_specs/handlers.rs",
            include_str!("../../../src/admin/api_specs/handlers.rs"),
        ),
    ];
    let tls_source = include_str!("../../../src/admin/tls_management.rs");

    let joined = config_db_sources
        .iter()
        .map(|(_, src)| *src)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("admit_write().await"),
        "config-database mutation handlers must call admit_write"
    );
    assert!(
        tls_source.contains("admit_non_config_db_write()"),
        "managed TLS/ACME handlers must call admit_non_config_db_write"
    );
    assert!(
        !tls_source.contains("admit_write().await"),
        "managed TLS/ACME handlers must not pin sticky config-DB failover topology"
    );

    // Config-DB handler call sites must not use the sync gate alone.
    for (name, src) in config_db_sources {
        for (idx, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("check_write_allowed()")
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("*")
                && !trimmed.contains("fn check_write_allowed")
                && !trimmed.contains("[`Self::check_write_allowed`]")
                && !trimmed.contains("Self::check_write_allowed")
            {
                // Allow the method definition body reference only inside
                // evaluate_write_gate / docs — any `state.check_write_allowed()`
                // call in handlers is a regression of the check-to-use race.
                assert!(
                    !trimmed.contains("state.check_write_allowed()"),
                    "{name}:{} still calls state.check_write_allowed(); mutations must use admit_write:\n{trimmed}",
                    idx + 1
                );
            }
        }
    }

    // TLS/ACME must not regress to the sync observe-only gate either.
    for (idx, line) in tls_source.lines().enumerate() {
        let trimmed = line.trim();
        assert!(
            !trimmed.contains("state.check_write_allowed()"),
            "tls_management.rs:{} must not call check_write_allowed; use admit_non_config_db_write:\n{trimmed}",
            idx + 1
        );
    }
}
