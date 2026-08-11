//! External coverage for node-agent admin HTTP/HTTPS parity (issue #3704).
//!
//! Exercises the production planner/startup seam through `_test_support` so
//! HTTP-only, HTTPS-only, dual listeners, invalid TLS, reloadable TLS, optional
//! mTLS, and partial-bind cleanup stay pinned without expanding the public API.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::start_node_agent_admin_listeners_for_test;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::modes::startup_security::{
    AdminHttpsListenerPlan, load_admin_https_tls_fail_closed, load_crls_from_env, load_tls_policy,
    node_agent_admin_https_security_applicable, node_agent_admin_surface_active,
    plan_admin_https_listener,
};
use rcgen::{CertificateParams, KeyPair};
use tempfile::TempDir;

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).unwrap();
    path.to_str().unwrap().to_string()
}

fn generate_self_signed_cert() -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn expect_https_plan_error(
    result: Result<AdminHttpsListenerPlan, anyhow::Error>,
    message: &str,
) -> anyhow::Error {
    match result {
        Err(err) => err,
        Ok(_) => panic!("{message}"),
    }
}

#[test]
fn node_agent_admin_surface_active_requires_http_or_https() {
    let disabled = EnvConfig {
        node_agent_admin_enabled: false,
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: Some("/tmp/a.crt".into()),
        admin_tls_key_path: Some("/tmp/a.key".into()),
        ..EnvConfig::default()
    };
    assert!(!node_agent_admin_surface_active(&disabled));

    let http_only = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 9000,
        admin_https_port: 0,
        ..EnvConfig::default()
    };
    assert!(node_agent_admin_surface_active(&http_only));
    assert!(!node_agent_admin_https_security_applicable(&http_only));

    let https_only = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 0,
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some("/tmp/a.crt".into()),
        admin_tls_key_path: Some("/tmp/a.key".into()),
        ..EnvConfig::default()
    };
    assert!(node_agent_admin_surface_active(&https_only));
    assert!(node_agent_admin_https_security_applicable(&https_only));

    let https_port_without_tls = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 0,
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        ..EnvConfig::default()
    };
    assert!(!node_agent_admin_surface_active(&https_port_without_tls));
    assert!(node_agent_admin_https_security_applicable(
        &https_port_without_tls
    ));

    let inherited_default = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_https_port_configured: false,
        ..EnvConfig::default()
    };
    assert!(node_agent_admin_surface_active(&inherited_default));
    assert!(!node_agent_admin_https_security_applicable(
        &inherited_default
    ));
}

#[test]
fn admin_https_intent_signals_fail_closed_without_server_material() {
    ensure_crypto_provider();
    // Inherited default port 9443 is not itself intent; each TLS-only signal
    // below must make HTTPS security applicable and fail closed when cert/key
    // are absent. Port 0 remains the unconditional disable sentinel.
    let policy = load_tls_policy(&EnvConfig::default()).unwrap();
    let crls = load_crls_from_env(&EnvConfig::default()).unwrap();
    let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();

    let cases: [(&str, EnvConfig); 3] = [
        (
            "client CA bundle",
            EnvConfig {
                node_agent_admin_enabled: true,
                admin_http_port: 9000,
                admin_https_port: 9443,
                admin_https_port_configured: false,
                admin_tls_client_ca_bundle_path: Some("/tmp/admin-client-ca.pem".into()),
                ..EnvConfig::default()
            },
        ),
        (
            "OCSP response source",
            EnvConfig {
                node_agent_admin_enabled: true,
                admin_http_port: 9000,
                admin_https_port: 9443,
                admin_https_port_configured: false,
                admin_tls_ocsp_response_source: Some("/tmp/admin-ocsp.der".into()),
                ..EnvConfig::default()
            },
        ),
        (
            "admin_tls_no_verify=true",
            EnvConfig {
                node_agent_admin_enabled: true,
                admin_http_port: 9000,
                admin_https_port: 9443,
                admin_https_port_configured: false,
                admin_tls_no_verify: true,
                ..EnvConfig::default()
            },
        ),
    ];

    for (label, env) in cases {
        assert!(
            env.admin_https_explicitly_requested(),
            "{label} must count as explicit HTTPS intent"
        );
        assert!(
            node_agent_admin_https_security_applicable(&env),
            "{label} must make node-agent HTTPS security applicable"
        );
        let err = expect_https_plan_error(
            plan_admin_https_listener(
                &env,
                &policy,
                &crls,
                "Invalid node_agent admin TLS configuration",
                addr,
                None,
            ),
            &format!("{label} without server cert/key must fail closed"),
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("FERRUM_ADMIN_TLS_CERT_PATH") && msg.contains("FERRUM_ADMIN_TLS_KEY_PATH"),
            "{label} error must name missing server material: {msg}"
        );
        assert!(
            !msg.contains("/tmp/admin-"),
            "{label} error must not echo secret/path material: {msg}"
        );

        let disabled = EnvConfig {
            admin_https_port: 0,
            ..env
        };
        assert!(
            !node_agent_admin_https_security_applicable(&disabled),
            "{label}: port 0 must remain the unconditional HTTPS disable sentinel"
        );
        let disabled_plan = plan_admin_https_listener(
            &disabled,
            &policy,
            &crls,
            "Invalid node_agent admin TLS configuration",
            "127.0.0.1:0".parse().unwrap(),
            None,
        )
        .expect("port 0 must disable HTTPS even with TLS intent fields");
        assert!(matches!(
            disabled_plan,
            AdminHttpsListenerPlan::DisabledByPort
        ));
    }

    // False no_verify is not intent on its own.
    let no_verify_false = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_https_port_configured: false,
        admin_tls_no_verify: false,
        ..EnvConfig::default()
    };
    assert!(!no_verify_false.admin_https_explicitly_requested());
    assert!(!node_agent_admin_https_security_applicable(
        &no_verify_false
    ));
}

#[test]
fn plan_admin_https_listener_disabled_by_port_zero() {
    ensure_crypto_provider();
    let env = EnvConfig {
        admin_https_port: 0,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some("/tmp/a.crt".into()),
        admin_tls_key_path: Some("/tmp/a.key".into()),
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&env).unwrap();
    let crls = load_crls_from_env(&env).unwrap();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let plan = plan_admin_https_listener(&env, &policy, &crls, "test", addr, None).unwrap();
    assert!(matches!(plan, AdminHttpsListenerPlan::DisabledByPort));
}

#[test]
fn plan_admin_https_listener_disabled_by_unrequested_inherited_default() {
    ensure_crypto_provider();
    let env = EnvConfig {
        admin_https_port: 9443,
        admin_https_port_configured: false,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&env).unwrap();
    let crls = load_crls_from_env(&env).unwrap();
    let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
    let plan = plan_admin_https_listener(&env, &policy, &crls, "test", addr, None).unwrap();
    assert!(matches!(plan, AdminHttpsListenerPlan::DisabledByMissingTls));
}

#[test]
fn plan_admin_https_listener_fails_closed_on_explicit_missing_tls() {
    ensure_crypto_provider();
    let env = EnvConfig {
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&env).unwrap();
    let crls = load_crls_from_env(&env).unwrap();
    let addr: SocketAddr = "127.0.0.1:19443".parse().unwrap();
    let err = expect_https_plan_error(
        plan_admin_https_listener(
            &env,
            &policy,
            &crls,
            "Invalid node_agent admin TLS configuration",
            addr,
            None,
        ),
        "explicit HTTPS without TLS must fail closed",
    );
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid node_agent admin TLS configuration"),
        "unexpected error: {msg}"
    );
    assert!(
        msg.contains("FERRUM_ADMIN_TLS_CERT_PATH") && msg.contains("FERRUM_ADMIN_TLS_KEY_PATH"),
        "error must name the missing TLS paths: {msg}"
    );
}

#[test]
fn plan_admin_https_listener_fails_closed_on_partial_tls() {
    ensure_crypto_provider();
    let env = EnvConfig {
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some("/tmp/a.crt".into()),
        admin_tls_key_path: None,
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&env).unwrap();
    let crls = load_crls_from_env(&env).unwrap();
    let addr: SocketAddr = "127.0.0.1:19443".parse().unwrap();
    let err = expect_https_plan_error(
        plan_admin_https_listener(
            &env,
            &policy,
            &crls,
            "Invalid node_agent admin TLS configuration",
            addr,
            None,
        ),
        "partial cert/key must fail closed",
    );
    assert!(format!("{err:#}").contains("both must be configured together"));
}

#[test]
fn plan_admin_https_listener_fails_closed_on_missing_material() {
    ensure_crypto_provider();
    let env = EnvConfig {
        admin_https_port: 9443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some("/nonexistent/admin.crt".into()),
        admin_tls_key_path: Some("/nonexistent/admin.key".into()),
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&env).unwrap();
    let crls = load_crls_from_env(&env).unwrap();
    let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
    let err = expect_https_plan_error(
        plan_admin_https_listener(&env, &policy, &crls, "Invalid test admin TLS", addr, None),
        "missing TLS material must fail closed",
    );
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid test admin TLS"),
        "error must keep label without leaking raw paths aggressively: {msg}"
    );
}

#[test]
fn plan_admin_https_listener_enables_with_valid_material() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "admin.crt", &cert_pem);
    let key_path = write_pem(&dir, "admin.key", &key_pem);
    let env = EnvConfig {
        admin_https_port: 9443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some(cert_path),
        admin_tls_key_path: Some(key_path),
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&env).unwrap();
    let crls = load_crls_from_env(&env).unwrap();
    let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
    let plan =
        plan_admin_https_listener(&env, &policy, &crls, "Invalid test admin TLS", addr, None)
            .expect("valid material must plan HTTPS");
    match plan {
        AdminHttpsListenerPlan::Enabled(planned) => {
            assert_eq!(planned.addr, addr);
            assert!(planned.reload.slot.is_none());
            assert!(planned.reload.watcher_handle.is_none());
        }
        AdminHttpsListenerPlan::DisabledByPort | AdminHttpsListenerPlan::DisabledByMissingTls => {
            panic!("expected Enabled plan")
        }
    }
}

#[tokio::test]
async fn plan_admin_https_listener_instantiates_reloadable_tls_when_configured() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "admin.crt", &cert_pem);
    let key_path = write_pem(&dir, "admin.key", &key_pem);
    let env = EnvConfig {
        admin_https_port: 9443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some(cert_path),
        admin_tls_key_path: Some(key_path),
        frontend_tls_live_reload_enabled: true,
        frontend_tls_watch_interval_seconds: 30,
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&env).unwrap();
    let crls = load_crls_from_env(&env).unwrap();
    let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let plan = plan_admin_https_listener(
        &env,
        &policy,
        &crls,
        "Invalid test admin TLS",
        addr,
        Some(shutdown_rx),
    )
    .expect("reloadable admin TLS must plan");
    match plan {
        AdminHttpsListenerPlan::Enabled(mut planned) => {
            assert!(
                planned.reload.slot.is_some(),
                "live reload must publish a SharedFrontendTls slot"
            );
            assert!(
                planned.reload.watcher_handle.is_some(),
                "live reload must spawn the shared admin/frontend watcher"
            );
            let _ = shutdown_tx.send(true);
            if let Some(handle) = planned.reload.watcher_handle.take() {
                let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
            }
        }
        AdminHttpsListenerPlan::DisabledByPort | AdminHttpsListenerPlan::DisabledByMissingTls => {
            panic!("expected Enabled plan with reload handles")
        }
    }
}

#[test]
fn optional_client_ca_mtls_loads_and_fails_closed() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "admin.crt", &cert_pem);
    let key_path = write_pem(&dir, "admin.key", &key_pem);
    let ca_path = write_pem(&dir, "client-ca.crt", &cert_pem);

    let ok_env = EnvConfig {
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some(cert_path.clone()),
        admin_tls_key_path: Some(key_path.clone()),
        admin_tls_client_ca_bundle_path: Some(ca_path),
        ..EnvConfig::default()
    };
    let policy = load_tls_policy(&ok_env).unwrap();
    let crls = load_crls_from_env(&ok_env).unwrap();
    load_admin_https_tls_fail_closed(
        &ok_env,
        &policy,
        &crls,
        "Invalid node_agent admin TLS configuration",
    )
    .expect("optional client CA must load through the shared admin TLS stack")
    .expect("HTTPS with mTLS must produce a ServerConfig");

    let bad_env = EnvConfig {
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some(cert_path),
        admin_tls_key_path: Some(key_path),
        admin_tls_client_ca_bundle_path: Some("/nonexistent/client-ca.crt".into()),
        ..EnvConfig::default()
    };
    let err = load_admin_https_tls_fail_closed(
        &bad_env,
        &policy,
        &crls,
        "Invalid node_agent admin TLS configuration",
    )
    .expect_err("missing client CA must fail closed");
    assert!(
        format!("{err:#}").contains("Invalid node_agent admin TLS configuration"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn https_only_starts_when_http_port_is_zero() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "admin.crt", &cert_pem);
    let key_path = write_pem(&dir, "admin.key", &key_pem);
    let https_port = reserve_port();

    let env_config = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: 0,
        admin_https_port: https_port,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some(cert_path),
        admin_tls_key_path: Some(key_path),
        admin_bind_address: "127.0.0.1".into(),
        ..EnvConfig::default()
    };
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let startup_ready = Arc::new(AtomicBool::new(false));

    let handles =
        start_node_agent_admin_listeners_for_test(&env_config, &shutdown_tx, startup_ready)
            .await
            .expect("HTTPS-only node-agent admin must start");
    assert!(
        !handles.is_empty(),
        "HTTPS-only must spawn at least the HTTPS listener task"
    );

    let _ = shutdown_tx.send(true);
    for handle in handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("HTTPS listener must join on shutdown");
    }
}

#[tokio::test]
async fn dual_listeners_start_http_and_https() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "admin.crt", &cert_pem);
    let key_path = write_pem(&dir, "admin.key", &key_pem);
    let http_port = reserve_port();
    let https_port = reserve_port();

    let env_config = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: http_port,
        admin_https_port: https_port,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some(cert_path),
        admin_tls_key_path: Some(key_path),
        admin_bind_address: "127.0.0.1".into(),
        ..EnvConfig::default()
    };
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let startup_ready = Arc::new(AtomicBool::new(false));

    let handles =
        start_node_agent_admin_listeners_for_test(&env_config, &shutdown_tx, startup_ready)
            .await
            .expect("dual listeners must start");
    assert!(
        handles.len() >= 2,
        "dual HTTP+HTTPS must supervise both listener tasks, got {}",
        handles.len()
    );

    let _ = shutdown_tx.send(true);
    for handle in handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("both listeners must join on shutdown");
    }
}

#[tokio::test]
async fn invalid_tls_fails_before_plaintext_fallback() {
    ensure_crypto_provider();
    let http_port = reserve_port();
    let https_port = reserve_port();
    let env_config = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: http_port,
        admin_https_port: https_port,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some("/nonexistent/admin.crt".into()),
        admin_tls_key_path: Some("/nonexistent/admin.key".into()),
        admin_bind_address: "127.0.0.1".into(),
        ..EnvConfig::default()
    };
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let startup_ready = Arc::new(AtomicBool::new(false));

    let err =
        start_node_agent_admin_listeners_for_test(&env_config, &shutdown_tx, startup_ready.clone())
            .await
            .expect_err("invalid TLS must fail node-agent admin startup");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Invalid node_agent admin TLS configuration"),
        "unexpected error: {msg}"
    );
    assert!(
        !startup_ready.load(Ordering::Acquire),
        "failed TLS startup must not report ready"
    );
}

#[tokio::test]
async fn explicit_missing_tls_fails_without_plaintext_fallback() {
    ensure_crypto_provider();
    let http_port = reserve_port();
    let env_config = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: http_port,
        admin_https_port: 19443,
        admin_https_port_configured: true,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_bind_address: "127.0.0.1".into(),
        ..EnvConfig::default()
    };
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let startup_ready = Arc::new(AtomicBool::new(false));

    let err =
        start_node_agent_admin_listeners_for_test(&env_config, &shutdown_tx, startup_ready.clone())
            .await
            .expect_err("explicit HTTPS without TLS must fail closed before HTTP bind");
    assert!(
        format!("{err:#}").contains("Invalid node_agent admin TLS configuration"),
        "unexpected error: {err:#}"
    );
    assert!(
        !startup_ready.load(Ordering::Acquire),
        "failed TLS startup must not report ready"
    );

    let reclaim = tokio::net::TcpListener::bind(("127.0.0.1", http_port))
        .await
        .expect("HTTP port must remain unbound after fail-closed HTTPS");
    drop(reclaim);
}

#[tokio::test]
async fn inherited_https_default_keeps_http_only_compatible() {
    ensure_crypto_provider();
    let http_port = reserve_port();
    let env_config = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: http_port,
        admin_https_port: 9443,
        admin_https_port_configured: false,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_bind_address: "127.0.0.1".into(),
        ..EnvConfig::default()
    };
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let startup_ready = Arc::new(AtomicBool::new(false));

    let handles =
        start_node_agent_admin_listeners_for_test(&env_config, &shutdown_tx, startup_ready)
            .await
            .expect("inherited HTTPS default without TLS must stay HTTP-only");
    assert_eq!(handles.len(), 1, "only the HTTP listener should start");

    let _ = shutdown_tx.send(true);
    for handle in handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("HTTP listener must join on shutdown");
    }
}

#[tokio::test]
async fn https_bind_failure_rolls_back_http_listener() {
    ensure_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let cert_path = write_pem(&dir, "admin.crt", &cert_pem);
    let key_path = write_pem(&dir, "admin.key", &key_pem);

    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve HTTPS port");
    let blocked_https = blocker.local_addr().expect("addr").port();
    let http_port = reserve_port();

    let env_config = EnvConfig {
        node_agent_admin_enabled: true,
        admin_http_port: http_port,
        admin_https_port: blocked_https,
        admin_https_port_configured: true,
        admin_tls_cert_path: Some(cert_path),
        admin_tls_key_path: Some(key_path),
        admin_bind_address: "127.0.0.1".into(),
        ..EnvConfig::default()
    };
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let startup_ready = Arc::new(AtomicBool::new(false));

    let err =
        start_node_agent_admin_listeners_for_test(&env_config, &shutdown_tx, startup_ready.clone())
            .await
            .expect_err("occupied HTTPS port must abort startup");
    let msg = err.to_string();
    assert!(
        msg.contains("Node agent admin HTTPS listener exited before completing startup")
            || msg.contains("Timed out waiting for Node agent admin HTTPS listener"),
        "unexpected startup error: {msg}"
    );
    assert!(
        !startup_ready.load(Ordering::Acquire),
        "partial bind failure must not report ready"
    );

    // After rollback, the HTTP port must be free again (no half-started surface).
    let reclaim = tokio::net::TcpListener::bind(("127.0.0.1", http_port))
        .await
        .expect("HTTP port must be released after partial-start rollback");
    drop(reclaim);
}
