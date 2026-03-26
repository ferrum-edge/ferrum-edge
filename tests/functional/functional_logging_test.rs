//! Functional tests for gateway logging and stdout_logging plugin.
//!
//! Verifies:
//! 1. Gateway startup logs appear in JSON format with expected messages
//! 2. The stdout_logging plugin emits TransactionSummary JSON for proxied requests
//! 3. Transaction summaries contain correct fields (method, path, status, latencies, etc.)
//! 4. Rejected requests (e.g., auth-failed) log with rejection_phase metadata
//! 5. Multiple requests produce individual log entries
//!
//! Run with: cargo test --test functional_tests --all-features -- --ignored functional_logging

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Test Harness
// ============================================================================

struct LoggingTestHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    admin_port: u16,
    proxy_port: u16,
    db_path: String,
}

impl LoggingTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir
            .path()
            .join("test.db")
            .to_string_lossy()
            .to_string();
        let jwt_secret = "logging-test-secret-key-12345".to_string();
        let jwt_issuer = "ferrum-gateway-logging-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        Ok(Self {
            _temp_dir: temp_dir,
            gateway_process: None,
            proxy_base_url: format!("http://127.0.0.1:{}", proxy_port),
            admin_base_url: format!("http://127.0.0.1:{}", admin_port),
            jwt_secret,
            jwt_issuer,
            admin_port,
            proxy_port,
            db_path,
        })
    }

    async fn start_gateway(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let db_url = format!("sqlite:{}?mode=rwc", self.db_path);

        let build_status = Command::new("cargo").args(["build"]).status()?;
        if !build_status.success() {
            return Err("Failed to build ferrum-gateway".into());
        }

        let binary_path = if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
            "./target/debug/ferrum-gateway"
        } else {
            "./target/release/ferrum-gateway"
        };

        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("RUST_LOG", "info,access_log=info")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        self.gateway_process = Some(child);
        self.wait_for_health().await?;
        Ok(())
    }

    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);

        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway did not start within 30 seconds".into());
            }
            match reqwest::get(&health_url).await {
                Ok(response) if response.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    fn generate_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string()
        });
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        Ok(encode(&header, &claims, &key)?)
    }

    /// Create a plugin config via Admin API and return its ID.
    async fn create_plugin_config(
        &self,
        client: &reqwest::Client,
        auth_header: &str,
        proxy_id: &str,
        plugin_name: &str,
        config: Value,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let plugin_id = Uuid::new_v4().to_string();
        let plugin_data = json!({
            "id": plugin_id,
            "plugin_name": plugin_name,
            "proxy_id": proxy_id,
            "scope": "proxy",
            "enabled": true,
            "config": config
        });

        let resp = client
            .post(format!("{}/plugins/config", self.admin_base_url))
            .header("Authorization", auth_header)
            .json(&plugin_data)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Create plugin '{}' failed ({}): {}",
                plugin_name, status, body
            )
            .into());
        }
        Ok(plugin_id)
    }

    /// Create a proxy via Admin API, then attach plugin configs by updating it.
    /// The proxy must exist before plugin configs can be created (FK constraint),
    /// and plugin associations are set via the proxy's `plugins` field.
    async fn create_proxy_with_plugins(
        &self,
        client: &reqwest::Client,
        auth_header: &str,
        proxy_id: &str,
        listen_path: &str,
        backend_port: u16,
        plugin_specs: &[(&str, Value)], // (plugin_name, config)
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Step 1: Create the proxy (no plugins yet)
        let proxy_data = json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_protocol": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        });

        let resp = client
            .post(format!("{}/proxies", self.admin_base_url))
            .header("Authorization", auth_header)
            .json(&proxy_data)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Create proxy failed ({}): {}", status, body).into());
        }

        // Step 2: Create each plugin config (FK to proxy now satisfied)
        let mut plugin_config_ids = Vec::new();
        for (plugin_name, config) in plugin_specs {
            let id = self
                .create_plugin_config(client, auth_header, proxy_id, plugin_name, config.clone())
                .await?;
            plugin_config_ids.push(id);
        }

        // Step 3: Update proxy with plugin associations
        let plugins: Vec<Value> = plugin_config_ids
            .iter()
            .map(|id| json!({"plugin_config_id": id}))
            .collect();

        let update_data = json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_protocol": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "plugins": plugins,
        });

        let resp = client
            .put(format!("{}/proxies/{}", self.admin_base_url, proxy_id))
            .header("Authorization", auth_header)
            .json(&update_data)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Update proxy with plugins failed ({}): {}", status, body).into());
        }

        Ok(())
    }

    /// Kill gateway and collect all log output (stdout + stderr combined).
    /// Uses wait_with_output() to avoid pipe deadlock when both are piped.
    fn stop_and_collect_logs(&mut self) -> String {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();

            match child.wait_with_output() {
                Ok(output) => {
                    let mut all = String::from_utf8_lossy(&output.stderr).to_string();
                    let stdout_str = String::from_utf8_lossy(&output.stdout);
                    if !stdout_str.is_empty() {
                        all.push('\n');
                        all.push_str(&stdout_str);
                    }
                    all
                }
                Err(_) => String::new(),
            }
        } else {
            String::new()
        }
    }
}

impl Drop for LoggingTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ============================================================================
// Echo Backend
// ============================================================================

async fn start_echo_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();

                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }

                let mut headers = String::new();
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    headers.push_str(&line);
                }

                let body = r#"{"status":"ok","echo":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });

    Ok(handle)
}

// ============================================================================
// Helpers
// ============================================================================

/// Parse JSON log lines from gateway output.
fn parse_log_lines(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Extract access_log entries and parse their nested TransactionSummary JSON.
fn extract_access_logs(log_lines: &[Value]) -> Vec<Value> {
    log_lines
        .iter()
        .filter(|entry| {
            entry
                .get("target")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t == "access_log")
        })
        .filter_map(|entry| {
            let msg = entry
                .get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())?;
            serde_json::from_str::<Value>(msg).ok()
        })
        .collect()
}

/// Extract all message strings from log lines.
fn extract_messages(log_lines: &[Value]) -> Vec<String> {
    log_lines
        .iter()
        .filter_map(|entry| {
            entry
                .get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                .map(String::from)
        })
        .collect()
}

// ============================================================================
// Functional Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_logging_gateway_startup_logs() {
    println!("\n=== Test: Gateway Startup Logs ===\n");

    let mut harness = LoggingTestHarness::new()
        .await
        .expect("Failed to create harness");

    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    tokio::time::sleep(Duration::from_secs(1)).await;

    let logs = harness.stop_and_collect_logs();
    let log_lines = parse_log_lines(&logs);

    println!("Collected {} JSON log lines from gateway", log_lines.len());
    assert!(
        !log_lines.is_empty(),
        "Gateway should produce JSON log lines on startup"
    );

    // Verify all log lines have expected tracing-subscriber JSON fields
    for entry in &log_lines {
        assert!(
            entry.get("timestamp").is_some(),
            "Missing timestamp: {}",
            entry
        );
        assert!(entry.get("level").is_some(), "Missing level: {}", entry);
    }

    let all_messages = extract_messages(&log_lines);
    println!("Startup messages:");
    for msg in &all_messages {
        println!("  {}", msg);
    }

    assert!(
        all_messages
            .iter()
            .any(|m| m.contains("Ferrum Gateway starting")),
        "Should log gateway startup message"
    );
    assert!(
        all_messages.iter().any(|m| m.contains("Operating mode")),
        "Should log operating mode"
    );

    println!("Startup log verification passed!");
}

#[tokio::test]
#[ignore]
async fn test_logging_transaction_summary_on_proxied_request() {
    println!("\n=== Test: Transaction Summary Logging ===\n");

    let mut harness = LoggingTestHarness::new()
        .await
        .expect("Failed to create harness");

    // Start echo backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port)
        .await
        .expect("Failed to start backend");

    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    let client = reqwest::Client::new();
    let token = harness.generate_token().expect("Failed to generate token");
    let auth_header = format!("Bearer {}", token);

    // Create proxy with stdout_logging plugin
    let proxy_id = "logging-test-proxy";
    harness
        .create_proxy_with_plugins(
            &client,
            &auth_header,
            proxy_id,
            "/log-test",
            backend_port,
            &[("stdout_logging", json!({}))],
        )
        .await
        .expect("Failed to create proxy with plugins");

    // Wait for DB poll to pick up the new config
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Send a GET request through the proxy
    println!("Sending GET /log-test/hello ...");
    let proxy_resp = client
        .get(format!("{}/log-test/hello", harness.proxy_base_url))
        .header("User-Agent", "logging-test-agent/1.0")
        .send()
        .await
        .expect("Proxy request failed");
    assert_eq!(proxy_resp.status().as_u16(), 200, "GET should succeed");

    // Send a POST request through the proxy
    println!("Sending POST /log-test/submit ...");
    let proxy_resp = client
        .post(format!("{}/log-test/submit", harness.proxy_base_url))
        .header("User-Agent", "logging-test-agent/1.0")
        .body("test body")
        .send()
        .await
        .expect("POST proxy request failed");
    assert_eq!(proxy_resp.status().as_u16(), 200, "POST should succeed");

    // Delay for log flush
    tokio::time::sleep(Duration::from_millis(500)).await;

    let logs = harness.stop_and_collect_logs();
    let log_lines = parse_log_lines(&logs);
    let access_logs = extract_access_logs(&log_lines);

    println!(
        "Collected {} log lines, {} access_log entries",
        log_lines.len(),
        access_logs.len()
    );

    for (i, al) in access_logs.iter().enumerate() {
        println!(
            "Access log [{}]: {}",
            i,
            serde_json::to_string_pretty(al).unwrap()
        );
    }

    assert!(
        access_logs.len() >= 2,
        "Expected at least 2 access log entries (GET + POST), got {}",
        access_logs.len()
    );

    // Verify GET request transaction summary
    let get_log = access_logs
        .iter()
        .find(|al| {
            al.get("http_method")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m == "GET")
                && al
                    .get("request_path")
                    .and_then(|p| p.as_str())
                    .is_some_and(|p| p.contains("/log-test/hello"))
        })
        .expect("Should find GET /log-test/hello access log");

    // Verify required TransactionSummary fields
    assert_eq!(get_log["http_method"].as_str().unwrap(), "GET");
    assert!(
        get_log["request_path"]
            .as_str()
            .unwrap()
            .contains("/log-test/hello")
    );
    assert_eq!(get_log["response_status_code"].as_u64().unwrap(), 200);
    assert_eq!(get_log["matched_proxy_id"].as_str().unwrap(), proxy_id);
    assert!(get_log["client_ip"].as_str().is_some());
    assert!(get_log["timestamp_received"].as_str().is_some());

    // Verify latency fields
    let total_ms = get_log["latency_total_ms"].as_f64().unwrap();
    assert!(total_ms > 0.0, "latency_total_ms should be positive");
    assert!(get_log["latency_gateway_processing_ms"].as_f64().is_some());
    let backend_ttfb = get_log["latency_backend_ttfb_ms"].as_f64().unwrap();
    assert!(
        backend_ttfb > 0.0,
        "latency_backend_ttfb_ms should be positive"
    );
    // backend_total_ms is -1.0 for streamed responses (body still in-flight at log time)
    let backend_total = get_log["latency_backend_total_ms"].as_f64().unwrap();
    let is_streaming = get_log
        .get("response_streamed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_streaming {
        assert_eq!(
            backend_total, -1.0,
            "backend_total_ms should be -1.0 for streaming responses"
        );
    } else {
        assert!(
            backend_total > 0.0,
            "backend_total_ms should be positive for buffered responses"
        );
    }

    // Verify backend target and user agent
    assert!(get_log["backend_target_url"].as_str().is_some());
    assert_eq!(
        get_log["request_user_agent"].as_str().unwrap(),
        "logging-test-agent/1.0"
    );

    // Verify POST request log
    let post_log = access_logs
        .iter()
        .find(|al| {
            al.get("http_method")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m == "POST")
        })
        .expect("Should find POST access log");

    assert_eq!(post_log["http_method"].as_str().unwrap(), "POST");
    assert_eq!(post_log["response_status_code"].as_u64().unwrap(), 200);

    println!("Transaction summary log verification passed!");
}

#[tokio::test]
#[ignore]
async fn test_logging_rejected_request_has_rejection_phase() {
    println!("\n=== Test: Rejected Request Logging ===\n");

    let mut harness = LoggingTestHarness::new()
        .await
        .expect("Failed to create harness");

    // Start echo backend (won't be reached for rejected requests)
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port)
        .await
        .expect("Failed to start backend");

    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    let client = reqwest::Client::new();
    let token = harness.generate_token().expect("Failed to generate token");
    let auth_header = format!("Bearer {}", token);

    // Create proxy with key_auth + stdout_logging plugins
    let proxy_id = "auth-reject-proxy";
    harness
        .create_proxy_with_plugins(
            &client,
            &auth_header,
            proxy_id,
            "/auth-test",
            backend_port,
            &[
                (
                    "key_auth",
                    json!({"key_names": ["X-Api-Key"], "hide_credentials": false}),
                ),
                ("stdout_logging", json!({})),
            ],
        )
        .await
        .expect("Failed to create proxy with plugins");

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Send request WITHOUT an API key — should be rejected by key_auth
    println!("Sending unauthenticated request to /auth-test/data ...");
    let proxy_resp = client
        .get(format!("{}/auth-test/data", harness.proxy_base_url))
        .header("User-Agent", "reject-test-agent/1.0")
        .send()
        .await
        .expect("Request failed");

    let status = proxy_resp.status().as_u16();
    println!("Response status: {}", status);
    assert!(
        status == 401 || status == 403,
        "Unauthenticated request should be rejected with 401 or 403, got {}",
        status
    );

    tokio::time::sleep(Duration::from_millis(500)).await;

    let logs = harness.stop_and_collect_logs();
    let log_lines = parse_log_lines(&logs);
    let access_logs = extract_access_logs(&log_lines);

    println!(
        "Collected {} log lines, {} access_log entries",
        log_lines.len(),
        access_logs.len()
    );

    for (i, al) in access_logs.iter().enumerate() {
        println!(
            "Access log [{}]: {}",
            i,
            serde_json::to_string_pretty(al).unwrap()
        );
    }

    assert!(
        !access_logs.is_empty(),
        "Should have at least 1 access log for the rejected request"
    );

    // Find the rejected request log
    let rejected_log = access_logs
        .iter()
        .find(|al| {
            al.get("request_path")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains("/auth-test/data"))
        })
        .expect("Should find access log for /auth-test/data");

    // Verify rejection status
    let resp_status = rejected_log["response_status_code"].as_u64().unwrap();
    assert!(
        resp_status == 401 || resp_status == 403,
        "Logged status should be 401 or 403, got {}",
        resp_status
    );

    // Backend latencies should be -1.0 (no backend call made)
    assert_eq!(
        rejected_log["latency_backend_ttfb_ms"].as_f64().unwrap(),
        -1.0,
        "backend_ttfb_ms should be -1.0 for rejected requests"
    );
    assert_eq!(
        rejected_log["latency_backend_total_ms"].as_f64().unwrap(),
        -1.0,
        "backend_total_ms should be -1.0 for rejected requests"
    );

    // Verify rejection_phase metadata
    let metadata = rejected_log
        .get("metadata")
        .expect("metadata field should be present");
    assert!(
        metadata.get("rejection_phase").is_some(),
        "metadata should contain rejection_phase, got: {}",
        metadata
    );

    let phase = metadata["rejection_phase"].as_str().unwrap();
    println!("Rejection phase: {}", phase);
    assert!(
        phase == "authenticate" || phase == "authorize",
        "rejection_phase should be authenticate or authorize, got: {}",
        phase
    );

    println!("Rejected request log verification passed!");
}

#[tokio::test]
#[ignore]
async fn test_logging_no_match_request() {
    println!("\n=== Test: Unmatched Route Logging ===\n");

    let mut harness = LoggingTestHarness::new()
        .await
        .expect("Failed to create harness");

    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    let client = reqwest::Client::new();

    // Send a request to a path with no matching proxy — should get 404
    println!("Sending request to non-existent route /no-such-route ...");
    let proxy_resp = client
        .get(format!("{}/no-such-route", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        proxy_resp.status().as_u16(),
        404,
        "Unmatched route should return 404"
    );

    tokio::time::sleep(Duration::from_millis(500)).await;

    let logs = harness.stop_and_collect_logs();
    let log_lines = parse_log_lines(&logs);

    println!("Collected {} JSON log lines", log_lines.len());

    // Verify JSON format consistency
    for entry in &log_lines {
        assert!(
            entry.is_object(),
            "Every log line should be a valid JSON object"
        );
    }

    // No access_log entries expected (no logging plugin on unmatched routes)
    let access_logs = extract_access_logs(&log_lines);
    println!(
        "Access log entries for unmatched route: {}",
        access_logs.len()
    );

    println!("Unmatched route log verification passed!");
}

#[tokio::test]
#[ignore]
async fn test_logging_multiple_requests_produce_individual_entries() {
    println!("\n=== Test: Multiple Requests Produce Individual Log Entries ===\n");

    let mut harness = LoggingTestHarness::new()
        .await
        .expect("Failed to create harness");

    // Start echo backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port)
        .await
        .expect("Failed to start backend");

    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    let client = reqwest::Client::new();
    let token = harness.generate_token().expect("Failed to generate token");
    let auth_header = format!("Bearer {}", token);

    // Create proxy with stdout_logging plugin
    let proxy_id = "multi-log-proxy";
    harness
        .create_proxy_with_plugins(
            &client,
            &auth_header,
            proxy_id,
            "/multi",
            backend_port,
            &[("stdout_logging", json!({}))],
        )
        .await
        .expect("Failed to create proxy with plugins");

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Send 5 requests with different paths
    let request_count: usize = 5;
    for i in 0..request_count {
        let resp = client
            .get(format!("{}/multi/item-{}", harness.proxy_base_url, i))
            .header("User-Agent", format!("multi-test/{}", i))
            .send()
            .await
            .expect("Request failed");
        assert_eq!(resp.status().as_u16(), 200);
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let logs = harness.stop_and_collect_logs();
    let log_lines = parse_log_lines(&logs);
    let access_logs = extract_access_logs(&log_lines);

    println!(
        "Sent {} requests, got {} access log entries",
        request_count,
        access_logs.len()
    );

    assert_eq!(
        access_logs.len(),
        request_count,
        "Should have exactly {} access log entries",
        request_count
    );

    // Verify each request produced a unique log entry
    for i in 0..request_count {
        let expected_path_fragment = format!("/multi/item-{}", i);
        let found = access_logs.iter().any(|al| {
            al.get("request_path")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains(&expected_path_fragment))
        });
        assert!(
            found,
            "Should find access log for path containing {}",
            expected_path_fragment
        );
    }

    // Verify unique paths
    let paths: Vec<&str> = access_logs
        .iter()
        .filter_map(|al| al.get("request_path").and_then(|p| p.as_str()))
        .collect();
    let unique_paths: std::collections::HashSet<&&str> = paths.iter().collect();
    assert_eq!(
        unique_paths.len(),
        request_count,
        "All {} access logs should have unique request paths",
        request_count
    );

    println!("Multiple request log verification passed!");
}
