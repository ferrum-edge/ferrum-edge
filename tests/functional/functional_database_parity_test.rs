//! Cross-backend database parity cells that need live PostgreSQL/MySQL.
//!
//! Complements the SQLite-only migrate/outage suites and the per-backend CRUD
//! / namespace / TLS entry points:
//! - baseline migrate `up` + idempotent re-run on PostgreSQL and MySQL
//! - connectivity recovery after pausing the CI database container
//!
//! Hosted CI provisions plaintext backends and sets
//! `FERRUM_DB_BACKENDS_REQUIRED=1`. Local runs skip when URLs/containers are
//! absent unless that flag is set.

use crate::common::{
    DbType, TestGateway, continue_if_backend_available, ensure_shared_sql_containers_resumed,
    host_port_from_db_url, mysql_test_url, postgres_test_url, provision_isolated_sql_database,
    tcp_endpoint_reachable,
};
use serde_json::json;
use std::process::Command;
use std::time::Duration;
use uuid::Uuid;

fn gateway_binary() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn run_migrate(action: &str, db_type: &str, db_url: &str) -> std::process::Output {
    Command::new(gateway_binary())
        .env("FERRUM_MODE", "migrate")
        .env("FERRUM_MIGRATE_ACTION", action)
        .env("FERRUM_DB_TYPE", db_type)
        .env("FERRUM_DB_URL", db_url)
        .env("FERRUM_LOG_LEVEL", "info")
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "functional-migrate-parity-secret-key-1234567890",
        )
        .output()
        .expect("spawn ferrum-edge migrate process")
}

fn redact_migrate_output(text: &str, db_url: &str) -> String {
    ferrum_edge::config::db_backend::redact_error_text(text, &[db_url])
}

async fn assert_migrate_up_idempotent(db_type: &str, db_url: &str) {
    let first = tokio::task::spawn_blocking({
        let db_type = db_type.to_string();
        let db_url = db_url.to_string();
        move || run_migrate("up", &db_type, &db_url)
    })
    .await
    .expect("join first migrate");
    let first_stderr = redact_migrate_output(&String::from_utf8_lossy(&first.stderr), db_url);
    assert!(
        first.status.success(),
        "{db_type} migrate up failed: {}\n{}",
        first.status,
        first_stderr
    );

    let second = tokio::task::spawn_blocking({
        let db_type = db_type.to_string();
        let db_url = db_url.to_string();
        move || run_migrate("up", &db_type, &db_url)
    })
    .await
    .expect("join second migrate");
    let second_stderr = redact_migrate_output(&String::from_utf8_lossy(&second.stderr), db_url);
    let second_stdout = redact_migrate_output(&String::from_utf8_lossy(&second.stdout), db_url);
    assert!(
        second.status.success(),
        "{db_type} migrate up idempotent re-run failed: {}\n{}",
        second.status,
        second_stderr
    );
    assert!(
        second_stdout.contains("up to date") || second_stdout.contains("No migrations applied"),
        "{db_type} second migrate up should report no pending migrations; got:\n{second_stdout}"
    );
}

#[tokio::test]
#[ignore]
async fn test_postgres_migrate_up_is_idempotent() {
    ensure_shared_sql_containers_resumed();
    let Some(url) = postgres_test_url() else {
        return;
    };
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "postgres",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not reachable at {host_port}"),
    ) {
        return;
    }
    // Isolate migrate onto a dedicated database so schema work cannot collide
    // with CRUD/namespace cells that share the CI container.
    let (url, _isolated_db) = provision_isolated_sql_database(&url);
    assert_migrate_up_idempotent("postgres", &url).await;
}

#[tokio::test]
#[ignore]
async fn test_mysql_migrate_up_is_idempotent() {
    ensure_shared_sql_containers_resumed();
    let Some(url) = mysql_test_url() else {
        return;
    };
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "mysql",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not reachable at {host_port}"),
    ) {
        return;
    }
    let (url, _isolated_db) = provision_isolated_sql_database(&url);
    assert_migrate_up_idempotent("mysql", &url).await;
}

struct DockerUnpauseGuard {
    container: String,
}

impl Drop for DockerUnpauseGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["unpause", &self.container])
            .output();
    }
}

fn docker_pause(container: &str) -> Option<DockerUnpauseGuard> {
    let output = Command::new("docker")
        .args(["pause", container])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(DockerUnpauseGuard {
        container: container.to_string(),
    })
}

fn recovery_proxy_payload(recovery_id: &str, recovered_listen_path: &str) -> serde_json::Value {
    json!({
        "id": recovery_id,
        "listen_path": recovered_listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9,
        "strip_listen_path": true
    })
}

fn recovery_proxy_matches_canonical(
    value: &serde_json::Value,
    recovery_id: &str,
    recovered_listen_path: &str,
) -> bool {
    value.get("id").and_then(|v| v.as_str()) == Some(recovery_id)
        && value.get("listen_path").and_then(|v| v.as_str()) == Some(recovered_listen_path)
        && value.get("backend_scheme").and_then(|v| v.as_str()) == Some("http")
        && value.get("backend_host").and_then(|v| v.as_str()) == Some("127.0.0.1")
        && value.get("backend_port").and_then(|v| v.as_u64()) == Some(9)
        && value.get("strip_listen_path").and_then(|v| v.as_bool()) == Some(true)
}

async fn recovery_proxy_committed(
    client: &reqwest::Client,
    gateway: &TestGateway,
    auth: &str,
    recovery_id: &str,
    recovered_listen_path: &str,
) -> Result<bool, String> {
    let response = client
        .get(gateway.admin_url(&format!("/proxies/{recovery_id}")))
        .header("Authorization", auth)
        .send()
        .await
        .map_err(|error| format!("GET /proxies/{recovery_id}: {error}"))?;
    let status = response.status();
    if status.as_u16() == 404 {
        return Ok(false);
    }
    if !status.is_success() {
        return Err(format!(
            "GET /proxies/{recovery_id} returned unexpected status {status}"
        ));
    }
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|error| format!("parse GET /proxies/{recovery_id} body: {error}"))?;
    if recovery_proxy_matches_canonical(&value, recovery_id, recovered_listen_path) {
        return Ok(true);
    }
    Err(format!(
        "GET /proxies/{recovery_id} returned non-canonical recovery proxy: {value}"
    ))
}

async fn run_connectivity_recovery(db: DbType, container: &str, label: &str) {
    ensure_shared_sql_containers_resumed();
    if !continue_if_backend_available(
        label,
        Command::new("docker")
            .args(["inspect", "--format", "{{.State.Running}}", container])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false),
        &format!("{container} is not running"),
    ) {
        return;
    }

    let gateway = TestGateway::builder()
        .mode_database(db)
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .unwrap_or_else(|error| panic!("spawn {label} gateway for connectivity recovery: {error}"));

    let client = reqwest::Client::new();
    let auth = gateway.auth_header();
    let proxy_id = format!("recovery-{}", Uuid::new_v4().simple());
    let listen_path = format!("/recovery-{}", Uuid::new_v4().simple());

    let create = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 9,
            "strip_listen_path": true
        }))
        .send()
        .await
        .expect("create proxy before outage");
    assert!(
        create.status().is_success(),
        "pre-outage create failed: {}",
        create.status()
    );

    let _guard = docker_pause(container).unwrap_or_else(|| {
        panic!("{label} connectivity recovery could not pause {container}");
    });

    // Give the pool a moment to observe the paused backend.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let during = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&json!({
            "id": format!("{proxy_id}-during"),
            "listen_path": format!("{listen_path}-during"),
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 9,
            "strip_listen_path": true
        }))
        .send()
        .await
        .expect("admin write during outage");
    assert!(
        during.status().as_u16() == 503 || during.status().is_server_error(),
        "admin write during paused DB should fail closed, got {}",
        during.status()
    );

    drop(_guard);
    // Wait for docker unpause + pool reconnect.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let recovery_id = format!("{proxy_id}-recovered");
    let recovered_listen_path = format!("{listen_path}-recovered");
    let recovery_payload = recovery_proxy_payload(&recovery_id, &recovered_listen_path);
    loop {
        let recovered = client
            .post(gateway.admin_url("/proxies"))
            .header("Authorization", &auth)
            .json(&recovery_payload)
            .send()
            .await
            .expect("admin write after recovery");
        let status = recovered.status();
        if status.is_success() {
            break;
        }
        if status.as_u16() == 409 {
            match recovery_proxy_committed(
                &client,
                &gateway,
                &auth,
                &recovery_id,
                &recovered_listen_path,
            )
            .await
            {
                Ok(true) => break,
                Ok(false) => {}
                Err(diagnostic) => panic!("{label} {diagnostic}"),
            }
        } else if status.as_u16() != 503 && !status.is_server_error() {
            let body = recovered.text().await.unwrap_or_default();
            panic!(
                "{label} admin write after unpause returned unexpected status {status}: {body}"
            );
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{label} admin writes did not recover within 30s after unpause (last status {})",
            status
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore]
async fn test_postgres_connectivity_recovery_after_container_pause() {
    // Resume before provisioning: `provision_isolated_sql_database` runs
    // `docker exec` against the shared container, which hangs on a container a
    // killed prior pause-cell left frozen. `run_connectivity_recovery` resumes
    // too, but only after that exec has already run.
    ensure_shared_sql_containers_resumed();
    let Some(url) = postgres_test_url() else {
        return;
    };
    let (url, _isolated_db) = provision_isolated_sql_database(&url);
    run_connectivity_recovery(DbType::Postgres(url), "ferrum-ci-postgres", "postgres").await;
}

#[tokio::test]
#[ignore]
async fn test_mysql_connectivity_recovery_after_container_pause() {
    // See the PostgreSQL cell: resume before the provisioning `docker exec`.
    ensure_shared_sql_containers_resumed();
    let Some(url) = mysql_test_url() else {
        return;
    };
    let (url, _isolated_db) = provision_isolated_sql_database(&url);
    run_connectivity_recovery(DbType::MySql(url), "ferrum-ci-mysql", "mysql").await;
}
