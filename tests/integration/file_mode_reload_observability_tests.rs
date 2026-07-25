//! File-mode rejected reload → admin `/health` observability (issue #2979).
//!
//! A failed SIGHUP-equivalent reload must raise the shared `config_rejected`
//! signal, keep the last-known-good runtime config, surface authenticated
//! `/health` as `degraded` + `config_rejected: true`, redact the boolean from
//! unauthenticated probes, and clear on a later Applied or Unchanged reload.

use std::io::Write;
use std::sync::atomic::Ordering;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::time::sleep;

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::file_loader::load_config_from_file;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{BackendEgressPolicy, EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{self, ServeOptions, apply_file_config_candidate};

const ADMIN_JWT_SECRET: &str = "file-mode-reload-observability-secret-32b";
const ADMIN_JWT_ISSUER: &str = "ferrum-edge-test";

fn good_config_yaml(proxy_id: &str) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "{proxy_id}"
    listen_path: "/good"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 18080
consumers: []
upstreams: []
plugin_configs: []
"#
    )
}

fn parse_gateway_yaml(yaml: &str) -> GatewayConfig {
    serde_yaml::from_str(yaml).expect("parse gateway yaml")
}

fn write_atomic_yaml(file: &NamedTempFile, contents: &str) {
    // Rewrite via a fresh truncate so consecutive stable-read probes see the
    // same committed bytes (file-mode loader rejects torn in-place updates).
    let mut handle = file.reopen().expect("reopen config file");
    handle.set_len(0).expect("truncate config file");
    handle.write_all(contents.as_bytes()).expect("write config");
    handle.flush().expect("flush config");
}

fn file_env(proxy_port: u16, admin_port: u16) -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::File,
        proxy_http_port: proxy_port,
        proxy_https_port: 0,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some(ADMIN_JWT_SECRET.to_string()),
        admin_jwt_issuer: ADMIN_JWT_ISSUER.to_string(),
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: false,
        max_connections: 0,
        proxy_bind_address: "127.0.0.1".to_string(),
        ..EnvConfig::default()
    }
}

fn mint_admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": ADMIN_JWT_ISSUER,
        "sub": "reload-observability-operator",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + ChronoDuration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ADMIN_JWT_SECRET.as_bytes()),
    )
    .expect("encode admin JWT")
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

async fn get_health(admin_port: u16, token: Option<&str>) -> (reqwest::StatusCode, Value) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest client");
    let mut req = client.get(format!("http://127.0.0.1:{admin_port}/health"));
    if let Some(token) = token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await.expect("GET /health");
    let status = resp.status();
    let body = resp.json().await.expect("/health JSON body");
    (status, body)
}

fn live_proxy_ids(handles: &file::ServeHandles) -> Vec<String> {
    handles
        .proxy_state
        .config
        .load()
        .proxies
        .iter()
        .map(|p| p.id.clone())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_mode_rejected_reload_surfaces_authenticated_health_and_clears_on_success() {
    let initial_yaml = good_config_yaml("proxy-good");
    let mut config_file = NamedTempFile::with_suffix(".yaml").expect("temp config");
    write!(config_file, "{initial_yaml}").expect("seed config");
    let config_path = config_file.path().to_str().expect("utf8 path").to_string();

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let admin_port = admin_listener.local_addr().unwrap().port();

    let jwt_manager = JwtManager::new(JwtConfig {
        secret: ADMIN_JWT_SECRET.to_string(),
        issuer: ADMIN_JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });

    let opts = ServeOptions {
        proxy_http: Some(proxy_listener),
        admin_http: Some(admin_listener),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = file::serve(
        file_env(proxy_port, admin_port),
        parse_gateway_yaml(&initial_yaml),
        opts,
        shutdown_tx.clone(),
    )
    .await
    .expect("file::serve");

    wait_for_admin_ready(admin_port).await;
    let token = mint_admin_token();

    // Baseline: healthy, no rejection detail.
    let (status, health) = get_health(admin_port, Some(&token)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "ok");
    assert!(
        health.get("config_rejected").is_none(),
        "baseline must not report config_rejected: {health:?}"
    );
    assert_eq!(live_proxy_ids(&handles), vec!["proxy-good".to_string()]);
    assert!(
        !handles.config_rejected.load(Ordering::Relaxed),
        "config_rejected must start clear"
    );

    // Rejected reload (unparseable YAML): retain last-good, raise signal.
    write_atomic_yaml(&config_file, "version: [\nthis is not valid yaml\n");
    let rejected = load_config_from_file(
        &config_path,
        30,
        &BackendEgressPolicy::unrestricted(),
        "ferrum",
    );
    assert!(rejected.is_err(), "invalid yaml must fail file load");
    apply_file_config_candidate(&handles.proxy_state, &handles.config_rejected, rejected);

    assert!(
        handles.config_rejected.load(Ordering::Relaxed),
        "rejected reload must raise config_rejected"
    );
    assert_eq!(
        live_proxy_ids(&handles),
        vec!["proxy-good".to_string()],
        "last-known-good config must be retained after rejected reload"
    );

    let (status, health) = get_health(admin_port, Some(&token)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["config_rejected"], true);
    assert_eq!(health["mode"], "file");
    assert_eq!(health["ready"], true);

    // Unauthenticated tier: coarse degraded status only — no boolean detail.
    let (unauth_status, unauth) = get_health(admin_port, None).await;
    assert_eq!(unauth_status, reqwest::StatusCode::OK);
    assert_eq!(unauth["status"], "degraded");
    assert_eq!(unauth["ready"], true);
    assert!(
        unauth.get("config_rejected").is_none(),
        "config_rejected detail must stay authenticated-only: {unauth:?}"
    );
    assert!(
        unauth.get("mode").is_none(),
        "mode must stay authenticated-only: {unauth:?}"
    );

    // Successful Applied reload clears the sticky rejection.
    let repaired_yaml = good_config_yaml("proxy-repaired");
    write_atomic_yaml(&config_file, &repaired_yaml);
    let accepted = load_config_from_file(
        &config_path,
        30,
        &BackendEgressPolicy::unrestricted(),
        "ferrum",
    );
    apply_file_config_candidate(&handles.proxy_state, &handles.config_rejected, accepted);

    assert!(
        !handles.config_rejected.load(Ordering::Relaxed),
        "successful Applied reload must clear config_rejected"
    );
    assert_eq!(live_proxy_ids(&handles), vec!["proxy-repaired".to_string()]);

    let (status, health) = get_health(admin_port, Some(&token)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "ok");
    assert!(
        health.get("config_rejected").is_none(),
        "config_rejected must clear after Applied: {health:?}"
    );

    // Reject again, then an Unchanged reload (same bytes) must also clear.
    write_atomic_yaml(&config_file, "{ definitely: broken: yaml");
    let rejected_again = load_config_from_file(
        &config_path,
        30,
        &BackendEgressPolicy::unrestricted(),
        "ferrum",
    );
    apply_file_config_candidate(
        &handles.proxy_state,
        &handles.config_rejected,
        rejected_again,
    );
    assert!(handles.config_rejected.load(Ordering::Relaxed));

    write_atomic_yaml(&config_file, &repaired_yaml);
    let unchanged = load_config_from_file(
        &config_path,
        30,
        &BackendEgressPolicy::unrestricted(),
        "ferrum",
    );
    apply_file_config_candidate(&handles.proxy_state, &handles.config_rejected, unchanged);
    assert!(
        !handles.config_rejected.load(Ordering::Relaxed),
        "successful Unchanged reload must clear config_rejected"
    );
    assert_eq!(live_proxy_ids(&handles), vec!["proxy-repaired".to_string()]);

    let (status, health) = get_health(admin_port, Some(&token)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "ok");
    assert!(
        health.get("config_rejected").is_none(),
        "config_rejected must clear after Unchanged: {health:?}"
    );

    let _ = shutdown_tx.send(true);
    let _ = handles.join().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_mode_apply_rejection_raises_config_rejected_and_keeps_last_good() {
    // A candidate that parses/loads but is rejected by update_config must also
    // raise the observability flag (apply-rejection path of #2979).
    let initial_yaml = good_config_yaml("proxy-good");
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let admin_port = admin_listener.local_addr().unwrap().port();

    let jwt_manager = JwtManager::new(JwtConfig {
        secret: ADMIN_JWT_SECRET.to_string(),
        issuer: ADMIN_JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });

    let opts = ServeOptions {
        proxy_http: Some(proxy_listener),
        admin_http: Some(admin_listener),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = file::serve(
        file_env(proxy_port, admin_port),
        parse_gateway_yaml(&initial_yaml),
        opts,
        shutdown_tx.clone(),
    )
    .await
    .expect("file::serve");

    wait_for_admin_ready(admin_port).await;
    let token = mint_admin_token();

    // Dangling upstream_id is rejected by update_config without swapping.
    let mut bad_apply = parse_gateway_yaml(&good_config_yaml("proxy-bad"));
    bad_apply.proxies[0].upstream_id = Some("does-not-exist".to_string());
    apply_file_config_candidate(
        &handles.proxy_state,
        &handles.config_rejected,
        Ok(bad_apply),
    );

    assert!(
        handles.config_rejected.load(Ordering::Relaxed),
        "apply Rejected must raise config_rejected"
    );
    assert_eq!(
        live_proxy_ids(&handles),
        vec!["proxy-good".to_string()],
        "apply Rejected must retain last-known-good config"
    );

    let (status, health) = get_health(admin_port, Some(&token)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["config_rejected"], true);

    let _ = shutdown_tx.send(true);
    let _ = handles.join().await;
}
