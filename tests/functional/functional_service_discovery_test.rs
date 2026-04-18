//! Functional tests for dynamic upstream target discovery.
//!
//! These tests verify that an upstream configured with a
//! `service_discovery` block is accepted by the file-mode loader and
//! that the gateway continues to serve traffic even when a service
//! discovery provider is unreachable (DNS-SD / Kubernetes / Consul).
//!
//! Scope (pragmatic minimum):
//!   1. Config validation — each of the three providers parses and the
//!      gateway reaches healthy state.
//!   2. Unreachable provider at startup does not crash the gateway,
//!      and traffic for other proxies not using the discovered upstream
//!      continues to work.
//!   3. End-to-end Consul discovery via a `wiremock` HTTP stub — the
//!      stub returns a single healthy service pointing at a local echo
//!      backend; a proxy referencing the upstream forwards a request
//!      to that backend.
//!
//! Run with:
//!   cargo test --test functional_tests -- --ignored \
//!       functional_service_discovery --nocapture

use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Echo server helper
// ============================================================================

/// Start a simple HTTP echo server on a pre-bound listener. Returns the
/// body `{"server":"sd-echo","path":"<path>"}` so the caller can verify
/// that the request actually reached the backend.
async fn start_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let body = format!(r#"{{"server":"sd-echo","path":"{}"}}"#, path);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

// ============================================================================
// Gateway startup helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

fn start_gateway_in_file_mode(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
) -> std::process::Child {
    let binary_path = gateway_binary_path();
    std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Retry-style gateway startup — fresh ephemeral ports per attempt, gateway
/// is killed before each retry. Matches the pattern used by other functional
/// tests in this crate.
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child = start_gateway_in_file_mode(config_path, proxy_port, admin_port);
        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (proxy_port={}, admin_port={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

fn write_config(temp_dir: &TempDir, content: &str) -> std::path::PathBuf {
    let path = temp_dir.path().join("config.yaml");
    let mut f = std::fs::File::create(&path).expect("Failed to create config file");
    f.write_all(content.as_bytes())
        .expect("Failed to write config file");
    drop(f);
    path
}

// ============================================================================
// Test 1: Config validation — each provider parses and gateway starts healthy
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_service_discovery_dns_sd_config_parses() {
    let temp_dir = TempDir::new().expect("temp dir");
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    // Proxy uses a direct backend (not the SD upstream) so we can still serve
    // traffic. SD upstream with DNS-SD provider just needs to parse/start.
    let config = format!(
        r#"
proxies:
  - id: "static-proxy"
    listen_path: "/static"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true

upstreams:
  - id: "sd-dns-upstream"
    name: "DNS-SD Upstream"
    algorithm: round_robin
    targets: []
    service_discovery:
      provider: "dns_sd"
      dns_sd:
        service_name: "_http._tcp.nonexistent.invalid"
        poll_interval_seconds: 60
      default_weight: 1

consumers: []
plugin_configs: []
"#
    );
    let path = write_config(&temp_dir, &config);
    let (mut gw, proxy_port, _admin_port) = start_gateway_with_retry(path.to_str().unwrap()).await;

    // Verify the unrelated static proxy still serves traffic even with a
    // DNS-SD upstream whose name will never resolve.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/static/ping", proxy_port))
        .send()
        .await
        .expect("request to static proxy failed");
    assert!(
        resp.status().is_success(),
        "static proxy should still serve traffic when DNS-SD upstream is unreachable, got {}",
        resp.status()
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(body.contains("sd-echo"), "unexpected body: {}", body);

    let _ = gw.kill();
    let _ = gw.wait();
    echo_task.abort();
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_service_discovery_kubernetes_config_parses() {
    let temp_dir = TempDir::new().expect("temp dir");
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    // The Kubernetes provider reads service account credentials and contacts
    // the cluster API server. In a test environment the client is built
    // against the gateway's default HTTP pool and simply fails at poll time;
    // startup must succeed without crashing.
    let config = format!(
        r#"
proxies:
  - id: "static-proxy"
    listen_path: "/static"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true

upstreams:
  - id: "sd-k8s-upstream"
    name: "K8s Upstream"
    algorithm: round_robin
    targets: []
    service_discovery:
      provider: "kubernetes"
      kubernetes:
        namespace: "default"
        service_name: "my-service"
        port_name: "http"
        poll_interval_seconds: 60
      default_weight: 1

consumers: []
plugin_configs: []
"#
    );
    let path = write_config(&temp_dir, &config);
    let (mut gw, proxy_port, _admin_port) = start_gateway_with_retry(path.to_str().unwrap()).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/static/ping", proxy_port))
        .send()
        .await
        .expect("request to static proxy failed");
    assert!(
        resp.status().is_success(),
        "static proxy should still serve traffic when k8s SD upstream is unreachable, got {}",
        resp.status()
    );

    let _ = gw.kill();
    let _ = gw.wait();
    echo_task.abort();
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_service_discovery_consul_unreachable_does_not_crash_gateway() {
    let temp_dir = TempDir::new().expect("temp dir");
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    // 127.0.0.1:1 is a reserved port — nothing will ever listen there. The
    // gateway must come up healthy, log poll failures as warnings, and keep
    // serving the unrelated static proxy below.
    let config = format!(
        r#"
proxies:
  - id: "static-proxy"
    listen_path: "/static"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true

upstreams:
  - id: "sd-consul-dead"
    name: "Consul (dead) Upstream"
    algorithm: round_robin
    targets: []
    service_discovery:
      provider: "consul"
      consul:
        address: "http://127.0.0.1:1"
        service_name: "my-service"
        healthy_only: true
        poll_interval_seconds: 1
      default_weight: 1

consumers: []
plugin_configs: []
"#
    );
    let path = write_config(&temp_dir, &config);
    let (mut gw, proxy_port, _admin_port) = start_gateway_with_retry(path.to_str().unwrap()).await;

    // Give the poller a chance to fail at least once.
    sleep(Duration::from_secs(2)).await;

    // Static proxy (not using the SD upstream) must still work.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/static/ping", proxy_port))
        .send()
        .await
        .expect("request to static proxy failed");
    assert!(
        resp.status().is_success(),
        "static proxy should still serve traffic while consul poll is failing, got {}",
        resp.status()
    );

    // Gateway process must still be alive.
    match gw.try_wait() {
        Ok(None) => {} // still running, good
        Ok(Some(status)) => panic!("gateway exited while consul was unreachable: {:?}", status),
        Err(e) => panic!("could not query gateway process state: {}", e),
    }

    let _ = gw.kill();
    let _ = gw.wait();
    echo_task.abort();
}

// ============================================================================
// Test 2: End-to-end — Consul stub (wiremock) resolves to a live echo backend
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_service_discovery_consul_stub_routes_to_discovered_target() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Backend echo server on an ephemeral port.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    // Consul HTTP stub — /v1/health/service/<name> returns a single passing
    // service pointing at 127.0.0.1:<echo_port>. wiremock picks its own
    // ephemeral port, so no port-race with the gateway listeners.
    let consul = MockServer::start().await;
    let service_body = serde_json::json!([
        {
            "Node": { "Address": "127.0.0.1" },
            "Service": {
                "Service": "echo",
                "Address": "127.0.0.1",
                "Port": echo_port,
                "Tags": [],
                "Weights": { "Passing": 1, "Warning": 1 }
            },
            "Checks": [ { "Status": "passing" } ]
        }
    ]);
    Mock::given(method("GET"))
        .and(path_regex(r"^/v1/health/service/.+$"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Consul-Index", "1")
                .insert_header("Content-Type", "application/json")
                .set_body_json(service_body),
        )
        .mount(&consul)
        .await;
    let consul_addr = consul.uri();

    let temp_dir = TempDir::new().expect("temp dir");
    // Proxy references the upstream via upstream_id. The upstream has NO
    // static targets — all targets must come from Consul. Short poll
    // interval so the first discovery completes quickly.
    let config = format!(
        r#"
proxies:
  - id: "sd-proxy"
    listen_path: "/sd"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: 1
    strip_listen_path: true
    upstream_id: "sd-consul-live"

upstreams:
  - id: "sd-consul-live"
    name: "Consul (live) Upstream"
    algorithm: round_robin
    targets: []
    service_discovery:
      provider: "consul"
      consul:
        address: "{consul_addr}"
        service_name: "echo"
        healthy_only: true
        poll_interval_seconds: 1
      default_weight: 1

consumers: []
plugin_configs: []
"#
    );
    let path = write_config(&temp_dir, &config);
    let (mut gw, proxy_port, _admin_port) = start_gateway_with_retry(path.to_str().unwrap()).await;

    // Poll for up to ~10s for the discovery loop to populate targets and
    // for a proxy request to succeed. The first poll happens at
    // poll_interval_seconds after startup (1s here).
    let client = reqwest::Client::new();
    let mut last_status: Option<reqwest::StatusCode> = None;
    let mut last_body = String::new();
    let mut success = false;
    for _ in 0..40 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/sd/hello", proxy_port))
            .send()
            .await;
        if let Ok(r) = resp {
            last_status = Some(r.status());
            let body = r.text().await.unwrap_or_default();
            last_body = body.clone();
            if last_status.map(|s| s.is_success()).unwrap_or(false) && body.contains("sd-echo") {
                success = true;
                break;
            }
        }
        sleep(Duration::from_millis(250)).await;
    }

    let _ = gw.kill();
    let _ = gw.wait();
    echo_task.abort();

    assert!(
        success,
        "proxy never routed through discovered Consul target. last_status={:?} last_body={:?}",
        last_status, last_body
    );
}
