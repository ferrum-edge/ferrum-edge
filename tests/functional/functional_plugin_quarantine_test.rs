//! End-to-end proof that an unconstructible fail-closed plugin row never yields
//! a serving snapshot with that plugin omitted (issue #4624).
//!
//! Database-mode serving loads quarantine only `OptionalFailOpen` plugin rows
//! (`quarantine_unconstructible_plugin_configs` in
//! `src/config/validation_pipeline.rs`). `FailClosed` / `KeepLastKnownGood` /
//! unknown rows stay inside the rejecting runtime contract
//! (`collect_rejecting_runtime_config_errors`), so the whole generation is
//! refused instead of losing a security control.
//!
//! The loader-level contract is covered by
//! `tests/integration/db_mutation_decode_fail_closed_tests.rs`. What is proven
//! here is the part that contract exists for: a real gateway process, a real
//! proxy request, and a backend that counts what actually reached it.
//!
//! Each test writes the malformed row directly into SQLite. The admin API
//! rejects that shape at write time, so a direct write is the only way to model
//! the real scenario — a row persisted by an older release whose constructor
//! was later tightened.
//!
//! Run with:
//!   cargo test --test functional_tests -- --ignored --nocapture functional_plugin_quarantine

use crate::common::{TestGateway, spawn_http_counting_mutations};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tempfile::TempDir;

/// The credential the seeded consumer presents.
const API_KEY: &str = "quarantine-fail-closed-key-0123456789";

/// Accepted by `KeyAuth::new`.
const VALID_KEY_AUTH: &str = r#"{"key_location":"header:X-API-Key"}"#;

/// Refused by `KeyAuth::new`: `key_auth` rejects unknown configuration fields
/// (`src/plugins/key_auth.rs`), so this is a stored row no serving mode can
/// construct.
const MALFORMED_KEY_AUTH: &str = r#"{"key_location":"header:X-API-Key","typo":true}"#;

/// Refused by the `stdout_logging` constructor, which is `OptionalFailOpen` —
/// the one class of row a serving load is allowed to quarantine.
const MALFORMED_STDOUT_LOGGING: &str = r#"{"filtr":{}}"#;

const PROXY_ID: &str = "quarantine-proxy";
const LISTEN_PATH: &str = "/quarantine";
const CONSUMER_ID: &str = "quarantine-consumer";
const KEY_AUTH_PLUGIN_ID: &str = "quarantine-key-auth";
const STDOUT_PLUGIN_ID: &str = "quarantine-stdout-logging";

/// Upper bound on "the poll loop has observed the stored change". The poll
/// interval is 1s; the slack covers loaded CI runners and the rejected-reload
/// backoff.
const POLL_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(45);

// ============================================================================
// SQLite helpers — model an out-of-band / pre-upgrade stored row
// ============================================================================

async fn sqlite_pool(db_url: &str) -> Pool<Sqlite> {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(db_url)
        .await
        .expect("connect to the gateway's SQLite config database")
}

/// Overwrite one plugin row's `config` column, bypassing admin validation.
async fn store_plugin_config(pool: &Pool<Sqlite>, plugin_config_id: &str, config: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let affected = sqlx::query(
        "UPDATE plugin_configs SET config = ?, updated_at = ? \
         WHERE id = ? AND namespace = 'ferrum'",
    )
    .bind(config)
    .bind(now.as_str())
    .bind(plugin_config_id)
    .execute(pool)
    .await
    .expect("plugin config update must succeed")
    .rows_affected();
    assert_eq!(
        affected, 1,
        "expected to rewrite exactly one stored plugin row for {plugin_config_id}"
    );
}

/// Seed a `consumer` change so the next poll escalates to an authoritative FULL
/// reload (`IncrementalFullReloadRequired::for_consumer_changes`) instead of a
/// point-loaded delta. A direct SQL row rewrite records no change of its own,
/// and the full-reload path is the one issue #4624 is about.
async fn seed_full_reload_change(pool: &Pool<Sqlite>) {
    sqlx::query(
        "INSERT INTO config_changes (namespace, resource_type, resource_id, operation, created_at) \
         VALUES ('ferrum', 'consumer', ?, 'upsert', ?)",
    )
    .bind(CONSUMER_ID)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .expect("config_changes seed must succeed");
}

// ============================================================================
// Admin API helpers
// ============================================================================

/// Create the proxy, consumer + key credential, the attached `key_auth` row,
/// and (optionally) a global `stdout_logging` row.
async fn provision_enforced_proxy(
    gateway: &TestGateway,
    backend_port: u16,
    with_optional_plugin: bool,
) {
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();

    let response = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&json!({
            "id": PROXY_ID,
            "listen_path": LISTEN_PATH,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        }))
        .send()
        .await
        .expect("create proxy");
    assert!(
        response.status().is_success(),
        "create proxy failed: {}",
        response.status()
    );

    let response = client
        .post(gateway.admin_url("/consumers"))
        .header("Authorization", &auth)
        .json(&json!({"id": CONSUMER_ID, "username": "quarantine-user"}))
        .send()
        .await
        .expect("create consumer");
    assert!(
        response.status().is_success(),
        "create consumer failed: {}",
        response.status()
    );

    let response = client
        .put(gateway.admin_url(&format!("/consumers/{CONSUMER_ID}/credentials/keyauth")))
        .header("Authorization", &auth)
        .json(&json!([{"key": API_KEY}]))
        .send()
        .await
        .expect("add keyauth credential");
    assert!(
        response.status().is_success(),
        "add keyauth credential failed: {}",
        response.status()
    );

    let response = client
        .post(gateway.admin_url("/plugins/config"))
        .header("Authorization", &auth)
        .json(&key_auth_plugin_body(VALID_KEY_AUTH))
        .send()
        .await
        .expect("create key_auth plugin config");
    assert!(
        response.status().is_success(),
        "create key_auth plugin config failed: {}",
        response.status()
    );

    if with_optional_plugin {
        let response = client
            .post(gateway.admin_url("/plugins/config"))
            .header("Authorization", &auth)
            .json(&json!({
                "id": STDOUT_PLUGIN_ID,
                "plugin_name": "stdout_logging",
                "scope": "global",
                "enabled": true,
                "config": {},
            }))
            .send()
            .await
            .expect("create stdout_logging plugin config");
        assert!(
            response.status().is_success(),
            "create stdout_logging plugin config failed: {}",
            response.status()
        );
    }

    let response = client
        .put(gateway.admin_url(&format!("/proxies/{PROXY_ID}")))
        .header("Authorization", &auth)
        .json(&json!({
            "id": PROXY_ID,
            "listen_path": LISTEN_PATH,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "plugins": [{"plugin_config_id": KEY_AUTH_PLUGIN_ID}],
        }))
        .send()
        .await
        .expect("attach key_auth to proxy");
    assert!(
        response.status().is_success(),
        "attach key_auth to proxy failed: {}",
        response.status()
    );
}

fn key_auth_plugin_body(config: &str) -> serde_json::Value {
    json!({
        "id": KEY_AUTH_PLUGIN_ID,
        "plugin_name": "key_auth",
        "scope": "proxy",
        "proxy_id": PROXY_ID,
        "enabled": true,
        "config": serde_json::from_str::<serde_json::Value>(config).expect("plugin config json"),
    })
}

/// Authenticated `/health` body. `config_rejected` is an authenticated-tier
/// detail (`src/admin/mod.rs`), so the JWT is required to observe it.
async fn authenticated_health(gateway: &TestGateway) -> serde_json::Value {
    let response = reqwest::Client::new()
        .get(gateway.admin_url("/health"))
        .header("Authorization", gateway.auth_header())
        .send()
        .await
        .expect("authenticated /health");
    assert_eq!(response.status(), 200, "authenticated /health must answer");
    response.json().await.expect("/health body is JSON")
}

fn config_rejected(health: &serde_json::Value) -> bool {
    health
        .get("config_rejected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

// ============================================================================
// Proxy request helpers — the backend counts what actually reached it
// ============================================================================

/// A mutating request, so `spawn_http_counting_mutations` counts it. The
/// counter is the assertion that matters: "the row was removed" and
/// "`config_rejected` was raised" are both weaker than "the backend was never
/// contacted".
async fn proxy_post(gateway: &TestGateway, api_key: Option<&str>) -> reqwest::StatusCode {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .expect("proxy client");
    let mut request = client
        .post(gateway.proxy_url(&format!("{LISTEN_PATH}/write")))
        .body("payload");
    if let Some(key) = api_key {
        request = request.header("X-API-Key", key);
    }
    request.send().await.expect("proxy request").status()
}

/// Non-counted probe. `spawn_http_counting_mutations` deliberately ignores
/// `GET`, so convergence polling cannot inflate the backend-hit assertions —
/// including in the window where a poll has applied the proxy but not yet its
/// plugin association.
async fn proxy_get(gateway: &TestGateway, api_key: Option<&str>) -> Option<u16> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .expect("proxy probe client");
    let mut request = client.get(gateway.proxy_url(&format!("{LISTEN_PATH}/read")));
    if let Some(key) = api_key {
        request = request.header("X-API-Key", key);
    }
    request
        .send()
        .await
        .ok()
        .map(|response| response.status().as_u16())
}

/// Poll (with `GET`, so nothing is counted) until the proxy answers `expected`.
async fn wait_for_proxy_status(gateway: &TestGateway, api_key: Option<&str>, expected: u16) {
    let deadline = std::time::Instant::now() + POLL_CONVERGENCE_TIMEOUT;
    let mut last = None;
    while std::time::Instant::now() < deadline {
        last = proxy_get(gateway, api_key).await;
        if last == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("proxy never answered {expected} within {POLL_CONVERGENCE_TIMEOUT:?} (last: {last:?})");
}

/// Poll the authenticated health tier until `config_rejected` settles on
/// `expected`. Bounded polling rather than a fixed sleep: a rejected snapshot
/// is retried under the poll loop's own backoff, so the convergence delay is
/// not a constant.
async fn wait_for_config_rejected(gateway: &TestGateway, expected: bool) {
    let deadline = std::time::Instant::now() + POLL_CONVERGENCE_TIMEOUT;
    let mut health = serde_json::Value::Null;
    while std::time::Instant::now() < deadline {
        health = authenticated_health(gateway).await;
        if config_rejected(&health) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("config_rejected never became {expected} within {POLL_CONVERGENCE_TIMEOUT:?}: {health}");
}

fn backend_hits(counter: &Arc<AtomicU32>) -> u32 {
    counter.load(Ordering::SeqCst)
}

// ============================================================================
// Test 1 — cold start, no backup: the data plane never binds
// ============================================================================

/// A stored `key_auth` row the constructor refuses must not produce a serving
/// snapshot without `key_auth`. With no `FERRUM_DB_CONFIG_BACKUP_PATH` the only
/// fail-closed answer is to refuse to start: the proxy listener never binds, so
/// no unauthenticated request can reach the backend.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn malformed_fail_closed_plugin_row_refuses_cold_start_without_backup() {
    let (backend, hits) = spawn_http_counting_mutations()
        .await
        .expect("counting backend");
    let backend_port = backend.port;

    let mut gateway = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("info")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("start gateway");

    provision_enforced_proxy(&gateway, backend_port, false).await;
    wait_for_proxy_status(&gateway, None, 401).await;

    assert_eq!(
        proxy_post(&gateway, None).await,
        401,
        "key_auth must reject an unauthenticated request before the row is corrupted"
    );
    assert_eq!(
        backend_hits(&hits),
        0,
        "a rejected request must never reach the backend"
    );
    assert_eq!(
        proxy_post(&gateway, Some(API_KEY)).await,
        200,
        "the configured credential must reach the backend before the row is corrupted"
    );
    assert_eq!(
        backend_hits(&hits),
        1,
        "the authenticated request is the only backend hit"
    );

    let db_url = gateway.db_url.clone().expect("sqlite db url");
    gateway.shutdown();

    let pool = sqlite_pool(&db_url).await;
    store_plugin_config(&pool, KEY_AUTH_PLUGIN_ID, MALFORMED_KEY_AUTH).await;
    pool.close().await;

    // Same database, no backup file: the full load is rejected by the runtime
    // contract and `src/modes/database.rs` returns the error before any
    // listener binds.
    let failure = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("info")
        .db_poll_interval_seconds(1)
        .max_attempts(1)
        .env("FERRUM_DB_URL", db_url.as_str())
        .spawn_expect_failure(Duration::from_secs(90))
        .await
        .expect("a malformed fail-closed plugin row must abort database-mode startup");

    let output = failure.combined_output();
    assert!(
        output.contains("Config rejected: Plugin <redacted scalar>")
            && output.contains("plugin_config_id=<redacted scalar>")
            && output.contains("scope=Proxy")
            && output.contains("key_auth: unknown configuration field(s): <redacted scalar>")
            && output.contains("allowed fields are `key_location` and `hide_credentials`"),
        "startup must retain the rejection and safe repair guidance; captured output was:\n{output}"
    );
    for withheld in [KEY_AUTH_PLUGIN_ID, PROXY_ID, API_KEY, "typo"] {
        assert!(
            !output.contains(withheld),
            "startup must withhold configured values; captured output was:\n{output}"
        );
    }
    assert!(
        !output.contains("serving without them"),
        "a FailClosed row must never be quarantined and served without; captured output was:\n{output}"
    );

    // The process exited non-zero (`spawn_expect_failure` asserts that), so no
    // proxy listener of this generation exists to answer at all.
    assert_eq!(
        backend_hits(&hits),
        1,
        "no request reached the backend after the fail-closed row was stored"
    );
}

// ============================================================================
// Test 2 — cold start with a backup: the backup generation still enforces
// ============================================================================

/// With a usable `FERRUM_DB_CONFIG_BACKUP_PATH`, a rejected stored snapshot is
/// backup-eligible: the gateway serves the backup generation — which still
/// carries `key_auth` — reports `config_rejected` on the authenticated health
/// tier, and keeps admin writes available for in-band repair. What it must not
/// do is serve the stored generation minus its authentication plugin.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn malformed_fail_closed_plugin_row_serves_backup_generation_still_enforcing_auth() {
    let (backend, hits) = spawn_http_counting_mutations()
        .await
        .expect("counting backend");
    let backend_port = backend.port;

    let mut gateway = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("info")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("start gateway");

    provision_enforced_proxy(&gateway, backend_port, false).await;
    wait_for_proxy_status(&gateway, None, 401).await;
    assert_eq!(
        proxy_post(&gateway, None).await,
        401,
        "key_auth must be enforced before the row is corrupted"
    );
    assert_eq!(backend_hits(&hits), 0, "no backend hit yet");

    // The backup is an externally provisioned file (the gateway never writes
    // one); it must outlive the first harness's temp dir.
    let backup_dir = TempDir::new().expect("backup dir");
    let backup_path = backup_dir.path().join("config-backup.json");
    std::fs::write(
        &backup_path,
        json!({
            "version": "1",
            "proxies": [{
                "id": PROXY_ID,
                "listen_path": LISTEN_PATH,
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "plugins": [{"plugin_config_id": KEY_AUTH_PLUGIN_ID}],
            }],
            "consumers": [{
                "id": CONSUMER_ID,
                "username": "quarantine-user",
                "credentials": {"keyauth": [{"key": API_KEY}]},
            }],
            "upstreams": [],
            "plugin_configs": [key_auth_plugin_body(VALID_KEY_AUTH)],
        })
        .to_string(),
    )
    .expect("write config backup");

    let db_url = gateway.db_url.clone().expect("sqlite db url");
    gateway.shutdown();

    let pool = sqlite_pool(&db_url).await;
    store_plugin_config(&pool, KEY_AUTH_PLUGIN_ID, MALFORMED_KEY_AUTH).await;
    pool.close().await;

    let restarted = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("info")
        .db_poll_interval_seconds(1)
        .env("FERRUM_DB_URL", db_url.as_str())
        .env(
            "FERRUM_DB_CONFIG_BACKUP_PATH",
            backup_path.to_string_lossy().as_ref(),
        )
        .spawn()
        .await
        .expect("backup bootstrap must bring the gateway up");

    // The spawn barrier already required authenticated `/health` with
    // `ready: true`; assert it explicitly so the readiness contract this test
    // depends on is visible.
    let health = authenticated_health(&restarted).await;
    assert_eq!(
        health.get("ready").and_then(serde_json::Value::as_bool),
        Some(true),
        "startup_ready must be exposed as /health ready: {health}"
    );
    assert!(
        config_rejected(&health),
        "a rejected stored snapshot must publish config_rejected: {health}"
    );

    let before = backend_hits(&hits);
    assert_eq!(
        proxy_post(&restarted, None).await,
        401,
        "the backup generation still enforces key_auth"
    );
    assert_eq!(
        backend_hits(&hits),
        before,
        "an unauthenticated request must not reach the backend"
    );
    assert_eq!(
        proxy_post(&restarted, Some(API_KEY)).await,
        200,
        "the configured credential still reaches the backend"
    );
    assert_eq!(
        backend_hits(&hits),
        before + 1,
        "exactly the authenticated request reached the backend"
    );
}

// ============================================================================
// Test 3 — hot reload: the prior generation survives; only optional rows are
// quarantined
// ============================================================================

/// A running gateway whose next authoritative full load contains an
/// unconstructible `key_auth` row keeps the entire previous runtime generation:
/// the unauthenticated request still gets 401 and the backend hit count does
/// not move. Repairing the row through the admin API clears `config_rejected`.
/// The same fixture then corrupts an `OptionalFailOpen` row to pin the
/// contrast: that one IS quarantined, the gateway keeps serving, and the
/// security plugin stays enforced.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn hot_reload_preserves_fail_closed_plugin_and_quarantines_only_optional_rows() {
    let (backend, hits) = spawn_http_counting_mutations()
        .await
        .expect("counting backend");
    let backend_port = backend.port;

    let mut gateway = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("info")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("start gateway");

    provision_enforced_proxy(&gateway, backend_port, true).await;
    wait_for_proxy_status(&gateway, None, 401).await;

    assert_eq!(
        proxy_post(&gateway, None).await,
        401,
        "key_auth enforced on the healthy generation"
    );
    assert_eq!(
        proxy_post(&gateway, Some(API_KEY)).await,
        200,
        "credential accepted on the healthy generation"
    );
    assert_eq!(backend_hits(&hits), 1, "one authenticated backend hit");
    assert!(
        !config_rejected(&authenticated_health(&gateway).await),
        "the healthy generation must not report config_rejected"
    );

    let db_url = gateway.db_url.clone().expect("sqlite db url");
    let pool = sqlite_pool(&db_url).await;

    // ── The fail-closed row goes bad under a running gateway ───────────────
    store_plugin_config(&pool, KEY_AUTH_PLUGIN_ID, MALFORMED_KEY_AUTH).await;
    seed_full_reload_change(&pool).await;
    wait_for_config_rejected(&gateway, true).await;

    assert!(
        gateway.is_running(),
        "a rejected reload must not terminate the gateway"
    );
    assert_eq!(
        proxy_post(&gateway, None).await,
        401,
        "the previous runtime generation keeps enforcing key_auth"
    );
    assert_eq!(
        backend_hits(&hits),
        1,
        "the unauthenticated request must not have reached the backend"
    );
    assert_eq!(
        proxy_post(&gateway, Some(API_KEY)).await,
        200,
        "the whole prior generation is preserved, not just the rejection"
    );
    assert_eq!(
        backend_hits(&hits),
        2,
        "only the authenticated request landed"
    );

    // ── In-band repair through the admin API ───────────────────────────────
    let response = reqwest::Client::new()
        .put(gateway.admin_url(&format!("/plugins/config/{KEY_AUTH_PLUGIN_ID}")))
        .header("Authorization", gateway.auth_header())
        .json(&key_auth_plugin_body(VALID_KEY_AUTH))
        .send()
        .await
        .expect("repair key_auth plugin config");
    assert!(
        response.status().is_success(),
        "admin writes must stay available for in-band repair: {}",
        response.status()
    );
    wait_for_config_rejected(&gateway, false).await;
    assert_eq!(
        proxy_post(&gateway, None).await,
        401,
        "key_auth stays enforced after repair"
    );
    assert_eq!(
        backend_hits(&hits),
        2,
        "no backend hit from the repaired rejection"
    );

    // ── Contrast: an OptionalFailOpen row IS quarantined ───────────────────
    store_plugin_config(&pool, STDOUT_PLUGIN_ID, MALFORMED_STDOUT_LOGGING).await;
    seed_full_reload_change(&pool).await;
    wait_for_config_rejected(&gateway, true).await;
    pool.close().await;

    assert!(
        gateway.is_running(),
        "an unconstructible optional plugin must not stop the gateway"
    );
    assert_eq!(
        proxy_post(&gateway, None).await,
        401,
        "quarantining an optional plugin must not disarm key_auth"
    );
    assert_eq!(
        backend_hits(&hits),
        2,
        "the unauthenticated request still never reached the backend"
    );
    assert_eq!(
        proxy_post(&gateway, Some(API_KEY)).await,
        200,
        "the gateway keeps serving with the optional plugin quarantined"
    );
    assert_eq!(
        backend_hits(&hits),
        3,
        "only the authenticated request landed"
    );
}
