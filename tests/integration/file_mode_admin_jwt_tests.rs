//! File-mode admin JWT admission (#2977).
//!
//! File mode may mint a random read-only admin JWT secret only when no admin
//! JWT configuration is supplied. An explicitly present but invalid setting
//! (short `FERRUM_ADMIN_JWT_SECRET`, malformed `FERRUM_ADMIN_JWT_MAX_TTL`)
//! must fail `file::serve` closed instead of silently replacing operator
//! intent.

use std::sync::Mutex;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use tokio::time::sleep;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{self, ServeOptions};

/// Serialize the few tests that mutate `FERRUM_ADMIN_JWT_*` inside this
/// integration binary. Other integration modules do not touch these keys.
static ADMIN_JWT_ENV_LOCK: Mutex<()> = Mutex::new(());

struct AdminJwtEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl AdminJwtEnvGuard {
    const KEYS: [&'static str; 4] = [
        "FERRUM_ADMIN_JWT_SECRET",
        "FERRUM_ADMIN_JWT_ISSUER",
        "FERRUM_ADMIN_JWT_AUDIENCE",
        "FERRUM_ADMIN_JWT_MAX_TTL",
    ];

    fn new() -> Self {
        let lock = ADMIN_JWT_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = Self::KEYS
            .iter()
            .map(|&key| (key, std::env::var_os(key)))
            .collect();
        // Start from a clean slate so sibling process env cannot mask unset.
        for key in Self::KEYS {
            // SAFETY: `_lock` serializes JWT env mutations in this binary.
            unsafe { std::env::remove_var(key) };
        }
        Self { _lock: lock, saved }
    }

    fn set(&self, key: &'static str, value: &str) {
        // SAFETY: guard holds ADMIN_JWT_ENV_LOCK.
        unsafe { std::env::set_var(key, value) }
    }

    fn unset(&self, key: &'static str) {
        // SAFETY: guard holds ADMIN_JWT_ENV_LOCK.
        unsafe { std::env::remove_var(key) }
    }
}

impl Drop for AdminJwtEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            // SAFETY: `_lock` remains held while Drop restores the snapshot.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

fn empty_gateway_config() -> GatewayConfig {
    serde_yaml::from_str(
        "version: '1'\nproxies: []\nconsumers: []\nupstreams: []\nplugin_configs: []\n",
    )
    .expect("parse empty gateway config")
}

fn file_env(proxy_port: u16, admin_port: u16) -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::File,
        proxy_http_port: proxy_port,
        proxy_https_port: 0,
        admin_http_port: admin_port,
        admin_https_port: 0,
        // Leave admin_jwt_secret None so serve() must consult the process env
        // via create_jwt_manager_from_env (the path under test).
        admin_jwt_secret: None,
        admin_jwt_issuer: "ferrum-edge".to_string(),
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: false,
        max_connections: 0,
        proxy_bind_address: "127.0.0.1".to_string(),
        ..EnvConfig::default()
    }
}

fn mint_external_admin_token(secret: &str, issuer: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "external-operator",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + ChronoDuration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("encode external admin JWT")
}

async fn wait_for_admin_ready(admin_port: u16) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest client");
    let url = format!("http://127.0.0.1:{admin_port}/live");
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("admin /live did not become ready on port {admin_port}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_mode_rejects_explicit_short_admin_jwt_secret() {
    let env = AdminJwtEnvGuard::new();
    // 20 characters — below the 32-char minimum.
    env.set("FERRUM_ADMIN_JWT_SECRET", "short-secret-20-chars");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let admin_port = admin_listener.local_addr().unwrap().port();

    let opts = ServeOptions {
        proxy_http: Some(proxy_listener),
        admin_http: Some(admin_listener),
        // No prebound JwtManager — force the env path under test.
        admin_jwt_manager: None,
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let err = match file::serve(
        file_env(proxy_port, admin_port),
        empty_gateway_config(),
        opts,
        shutdown_tx,
    )
    .await
    {
        Ok(_) => panic!("serve() must fail when FERRUM_ADMIN_JWT_SECRET is shorter than 32 chars"),
        Err(e) => e,
    };

    let msg = err.to_string();
    assert!(
        msg.contains("Invalid admin JWT configuration") || msg.contains("FERRUM_ADMIN_JWT_SECRET"),
        "startup error must name the JWT misconfiguration; got {msg}"
    );
    assert!(
        msg.contains("at least") || msg.contains("32"),
        "startup error must describe the length rule; got {msg}"
    );
    assert!(
        !msg.contains("short-secret-20-chars"),
        "startup diagnostic must not echo the secret value; got {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_mode_rejects_invalid_max_ttl_even_when_secret_unset() {
    let env = AdminJwtEnvGuard::new();
    env.unset("FERRUM_ADMIN_JWT_SECRET");
    env.set("FERRUM_ADMIN_JWT_MAX_TTL", "not-a-ttl");

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let admin_port = admin_listener.local_addr().unwrap().port();

    let opts = ServeOptions {
        proxy_http: Some(proxy_listener),
        admin_http: Some(admin_listener),
        admin_jwt_manager: None,
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let err = match file::serve(
        file_env(proxy_port, admin_port),
        empty_gateway_config(),
        opts,
        shutdown_tx,
    )
    .await
    {
        Ok(_) => panic!("serve() must fail when FERRUM_ADMIN_JWT_MAX_TTL is malformed"),
        Err(e) => e,
    };

    let msg = err.to_string();
    assert!(
        msg.contains("Invalid admin JWT configuration") || msg.contains("FERRUM_ADMIN_JWT_MAX_TTL"),
        "startup error must name the JWT max TTL misconfiguration; got {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_mode_unset_admin_jwt_starts_and_rejects_external_tokens() {
    let env = AdminJwtEnvGuard::new();
    env.unset("FERRUM_ADMIN_JWT_SECRET");
    env.unset("FERRUM_ADMIN_JWT_MAX_TTL");
    env.unset("FERRUM_ADMIN_JWT_ISSUER");
    env.unset("FERRUM_ADMIN_JWT_AUDIENCE");

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let admin_port = admin_listener.local_addr().unwrap().port();

    let opts = ServeOptions {
        proxy_http: Some(proxy_listener),
        admin_http: Some(admin_listener),
        admin_jwt_manager: None,
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = file::serve(
        file_env(proxy_port, admin_port),
        empty_gateway_config(),
        opts,
        shutdown_tx.clone(),
    )
    .await
    .expect("serve() must succeed when admin JWT secret is unset");

    wait_for_admin_ready(admin_port).await;

    let external_secret = "externally-minted-secret-at-least-32-chars!!";
    let token = mint_external_admin_token(external_secret, "ferrum-edge");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest client");
    let resp = client
        .get(format!("http://127.0.0.1:{admin_port}/proxies"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("admin /proxies request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "externally minted token must not validate against the random file-mode secret"
    );

    let _ = shutdown_tx.send(true);
    let _ = handles.join().await;
}
