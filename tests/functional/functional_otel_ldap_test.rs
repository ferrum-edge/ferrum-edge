//! Functional tests for OTel Tracing and LDAP Auth plugins.
//!
//! - **OTel Tracing**: Verifies the plugin injects a `traceparent` response header
//!   (W3C Trace Context) when configured in propagation-only mode.
//! - **LDAP Auth**: Verifies the plugin fails closed when the configured LDAP
//!   server is unreachable or its hostname rebinds to denied space (no silent
//!   bypass of authentication) — returning a 500 backend failure rather than a
//!   401 bad-credential result.
//!
//! Both tests use file mode with ephemeral ports.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_otel_ldap

use crate::scaffolding::port_registry::TestSocket;

use hickory_resolver::proto::{
    op::Message,
    rr::{RData, Record, RecordType},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Echo Server Helper
// ============================================================================

/// Start a simple HTTP echo server on a pre-bound listener that returns 200 with a JSON body.
async fn start_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

struct RebindingDnsServer {
    addr: SocketAddr,
    answers: Arc<RwLock<Vec<IpAddr>>>,
    query_count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl RebindingDnsServer {
    async fn spawn(initial_answers: Vec<IpAddr>) -> Self {
        let socket = tokio::net::UdpSocket::bind_test("127.0.0.1:0")
            .await
            .expect("bind functional DNS server");
        let addr = socket.local_addr().expect("functional DNS address");
        let answers = Arc::new(RwLock::new(initial_answers));
        let query_count = Arc::new(AtomicUsize::new(0));
        let task_answers = Arc::clone(&answers);
        let task_query_count = Arc::clone(&query_count);
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 2_048];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };
                let Ok(request) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let Some(query) = request.queries.first().cloned() else {
                    continue;
                };
                task_query_count.fetch_add(1, Ordering::Relaxed);
                let current_answers = task_answers
                    .read()
                    .expect("read functional DNS answers")
                    .clone();
                let mut response = request.into_response();
                for address in current_answers {
                    let data = match (query.query_type(), address) {
                        (RecordType::A, IpAddr::V4(address)) => RData::A(address.into()),
                        _ => continue,
                    };
                    response.add_answer(Record::from_rdata(query.name().clone(), 1, data));
                }
                let Ok(encoded) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&encoded, peer).await;
            }
        });
        Self {
            addr,
            answers,
            query_count,
            task,
        }
    }

    fn rebind_to(&self, address: IpAddr) {
        *self.answers.write().expect("write functional DNS answer") = vec![address];
    }

    fn queries(&self) -> usize {
        self.query_count.load(Ordering::Relaxed)
    }
}

impl Drop for RebindingDnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ============================================================================
// Gateway Helpers
// ============================================================================

/// Lease a non-ephemeral port for the gateway child to bind (D4, #7077).
async fn gateway_handoff_port() -> u16 {
    crate::scaffolding::ports::unbound_port()
        .await
        .expect("lease gateway handoff port")
}

/// Start the gateway in file mode with the given config and ports.
fn start_gateway_with_dns(
    config_path: &str,
    proxy_port: u16,
    admin_port: u16,
    dns_resolver: Option<SocketAddr>,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> Result<crate::common::GatewayChildGuard, Box<dyn std::error::Error>> {
    let binary_path = crate::common::gateway_binary_path();

    let mut command = std::process::Command::new(binary_path);
    crate::common::configure_coverage_gateway_command(&mut command);
    command.arg("run");
    // Per-attempt admin JWT secret/issuer and metrics bearer token: the
    // ownership proof `wait_for_owned_gateway` checks (issue #7076).
    identity.apply_to_command(&mut command);
    // Keep any managed-TLS store out of the checkout (issue #5706): the config
    // file lives in the attempt's TempDir, which outlives this child.
    let managed_store = std::path::Path::new(config_path).with_file_name("managed-tls");
    command
        .env("FERRUM_TLS_MANAGED_STORE_PATH", &managed_store)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_ACCEPT_THREADS", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(resolver) = dns_resolver {
        command
            .env("FERRUM_DNS_RESOLVER_ADDRESS", resolver.to_string())
            .env("FERRUM_DNS_TRY_TCP_ON_ERROR", "false");
    }
    Ok(crate::common::GatewayChildGuard::new(command.spawn()?))
}

fn start_gateway(
    config_path: &str,
    proxy_port: u16,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> Result<crate::common::GatewayChildGuard, Box<dyn std::error::Error>> {
    start_gateway_with_dns(config_path, proxy_port, admin_port, None, identity)
}

/// Prove *this* child owns its admin/proxy listeners before returning.
///
/// Bare unauthenticated `/health` is not identity (issue #2132 / #3428): the
/// released port reservation can let a parallel gateway answer on the admin
/// port while this child dies on proxy bind failure. `/health` detail alone is
/// not enough either: `FERRUM_METRICS_ALLOWED_CIDRS` can grant it to a foreign
/// gateway, so the barrier also requires HTTP 200 from JWT-only `GET /proxies`
/// under this attempt's admin JWT (`wait_for_owned_gateway_identity`, #7076).
async fn wait_for_owned_gateway(
    child: &mut std::process::Child,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
    proxy_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    crate::common::wait_for_owned_gateway_identity(child, admin_port, identity, STARTUP_TIMEOUT)
        .await?;
    crate::common::wait_for_child_tcp_accept(child, proxy_port, deadline).await
}

/// Start the gateway with retry logic to handle handoff port races.
/// Returns (gateway_process, echo_handle, proxy_port, admin_port, _temp_dir, _backend_listener).
async fn start_otel_gateway_with_retry(
    config_template: &str,
) -> (
    crate::common::GatewayChildGuard,
    tokio::task::JoinHandle<()>,
    u16,
    u16,
    TempDir,
    // Keep the backend listener alive indirectly via the spawned task
) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        // Allocate fresh ports each attempt
        let backend_listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().unwrap().port();

        let proxy_port = gateway_handoff_port().await;
        let admin_port = gateway_handoff_port().await;

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join("config.yaml");
        let config_content = config_template.replace("{backend_port}", &backend_port.to_string());
        std::fs::write(&config_path, config_content.as_bytes())
            .expect("Failed to write config file");

        // Start echo backend on the pre-bound listener (no port race)
        let echo_handle = tokio::spawn(start_echo_server_on(backend_listener));
        sleep(Duration::from_millis(200)).await;

        // Start gateway
        let identity = crate::common::SpawnedGatewayIdentity::mint("otel-ldap");
        let mut gateway_process = match start_gateway(
            &config_path.to_string_lossy(),
            proxy_port,
            admin_port,
            &identity,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };

        match wait_for_owned_gateway(
            gateway_process.child_mut(),
            admin_port,
            &identity,
            proxy_port,
        )
        .await
        {
            Ok(()) => {
                return (
                    gateway_process,
                    echo_handle,
                    proxy_port,
                    admin_port,
                    temp_dir,
                );
            }
            Err(e) => {
                eprintln!(
                    "Gateway startup attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                gateway_process.shutdown();
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ============================================================================
// OTel Tracing Tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_otel_tracing_injects_traceparent() {
    let config_template = r#"
version: "1"
proxies:
  - id: "traced-proxy"
    listen_path: "/traced"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "otel-1"

consumers: []

plugin_configs:
  - id: "otel-1"
    proxy_id: "traced-proxy"
    plugin_name: "otel_tracing"
    scope: "proxy"
    enabled: true
    config:
      service_name: "test-gateway"
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_otel_gateway_with_retry(config_template).await;

    // Send a request without a traceparent header — the plugin should generate one.
    //
    // On loaded CI runners the proxy route table may not be populated when
    // `/health` first returns 200. Retry on 404 to absorb that startup race.
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/traced/test", proxy_port);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let response = loop {
        let r = client.get(&url).send().await.expect("Request failed");
        if r.status().as_u16() != 404 || tokio::time::Instant::now() >= deadline {
            break r;
        }
        sleep(Duration::from_millis(250)).await;
    };

    assert_eq!(
        response.status().as_u16(),
        200,
        "Expected 200, got {}",
        response.status()
    );

    // The OTel plugin echoes traceparent back in the response headers
    let traceparent = response
        .headers()
        .get("traceparent")
        .expect("Response should contain traceparent header")
        .to_str()
        .expect("traceparent should be valid UTF-8");

    // W3C Trace Context format: version-trace_id-parent_id-flags
    // e.g. "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(
        parts.len(),
        4,
        "traceparent should have 4 dash-separated parts, got: {}",
        traceparent
    );
    assert_eq!(parts[0], "00", "traceparent version should be '00'");
    assert_eq!(
        parts[1].len(),
        32,
        "trace_id should be 32 hex chars, got {} chars: {}",
        parts[1].len(),
        parts[1]
    );
    assert_eq!(
        parts[2].len(),
        16,
        "span_id should be 16 hex chars, got {} chars: {}",
        parts[2].len(),
        parts[2]
    );
    assert_eq!(parts[3], "01", "traceparent flags should be '01'");

    // Cleanup
    gateway_process.shutdown();
    echo_handle.abort();
}

#[ignore]
#[tokio::test]
async fn test_otel_tracing_preserves_existing_traceparent() {
    let config_template = r#"
version: "1"
proxies:
  - id: "traced-proxy"
    listen_path: "/traced"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "otel-1"

consumers: []

plugin_configs:
  - id: "otel-1"
    proxy_id: "traced-proxy"
    plugin_name: "otel_tracing"
    scope: "proxy"
    enabled: true
    config:
      service_name: "test-gateway"
      trace_context_trust: trusted
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_otel_gateway_with_retry(config_template).await;

    // Send a request WITH an existing traceparent — the plugin should preserve the trace_id.
    //
    // On loaded CI runners the proxy route table may not be populated when
    // `/health` first returns 200. Retry on 404 to absorb that startup race.
    let existing_traceparent = "00-abcdef1234567890abcdef1234567890-1234567890abcdef-01";
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/traced/test", proxy_port);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let response = loop {
        let r = client
            .get(&url)
            .header("traceparent", existing_traceparent)
            .send()
            .await
            .expect("Request failed");
        if r.status().as_u16() != 404 || tokio::time::Instant::now() >= deadline {
            break r;
        }
        sleep(Duration::from_millis(250)).await;
    };

    assert_eq!(
        response.status().as_u16(),
        200,
        "Expected 200, got {}",
        response.status()
    );

    let traceparent = response
        .headers()
        .get("traceparent")
        .expect("Response should contain traceparent header")
        .to_str()
        .expect("traceparent should be valid UTF-8");

    // The trace_id should be preserved from the incoming traceparent
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(parts.len(), 4, "traceparent should have 4 parts");
    assert_eq!(
        parts[1], "abcdef1234567890abcdef1234567890",
        "trace_id should be preserved from the incoming traceparent"
    );

    // Cleanup
    gateway_process.shutdown();
    echo_handle.abort();
}

// ============================================================================
// LDAP Auth Tests
// ============================================================================

/// Start the gateway with retry logic for LDAP tests (echo backend + unreachable LDAP port).
async fn start_ldap_gateway_with_retry(
    config_template: &str,
) -> (
    crate::common::GatewayChildGuard,
    tokio::task::JoinHandle<()>,
    u16,
    u16,
    TempDir,
) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let backend_listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().unwrap().port();

        let proxy_port = gateway_handoff_port().await;
        let admin_port = gateway_handoff_port().await;

        // Use a port that we do NOT listen on — guaranteeing LDAP connection failure
        let ldap_listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind ldap");
        let ldap_port = ldap_listener.local_addr().unwrap().port();
        drop(ldap_listener);

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join("config.yaml");
        let config_content = config_template
            .replace("{backend_port}", &backend_port.to_string())
            .replace("{ldap_port}", &ldap_port.to_string());
        std::fs::write(&config_path, config_content.as_bytes())
            .expect("Failed to write config file");

        let echo_handle = tokio::spawn(start_echo_server_on(backend_listener));
        sleep(Duration::from_millis(200)).await;

        let identity = crate::common::SpawnedGatewayIdentity::mint("otel-ldap");
        let mut gateway_process = match start_gateway(
            &config_path.to_string_lossy(),
            proxy_port,
            admin_port,
            &identity,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };

        match wait_for_owned_gateway(
            gateway_process.child_mut(),
            admin_port,
            &identity,
            proxy_port,
        )
        .await
        {
            Ok(()) => {
                return (
                    gateway_process,
                    echo_handle,
                    proxy_port,
                    admin_port,
                    temp_dir,
                );
            }
            Err(e) => {
                eprintln!(
                    "Gateway startup attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, e
                );
                gateway_process.shutdown();
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

async fn start_ldap_rebinding_gateway_with_retry(
    config_template: &str,
    ldap_port: u16,
    dns_resolver: SocketAddr,
) -> (
    crate::common::GatewayChildGuard,
    tokio::task::JoinHandle<()>,
    u16,
    u16,
    TempDir,
) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let backend_listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind rebind-test backend");
        let backend_port = backend_listener.local_addr().unwrap().port();

        let proxy_port = gateway_handoff_port().await;
        let admin_port = gateway_handoff_port().await;

        let temp_dir = TempDir::new().expect("create rebind-test temp directory");
        let config_path = temp_dir.path().join("config.yaml");
        let config_content = config_template
            .replace("{backend_port}", &backend_port.to_string())
            .replace("{ldap_port}", &ldap_port.to_string());
        std::fs::write(&config_path, config_content.as_bytes()).expect("write rebind-test config");

        let echo_handle = tokio::spawn(start_echo_server_on(backend_listener));
        sleep(Duration::from_millis(200)).await;
        let identity = crate::common::SpawnedGatewayIdentity::mint("otel-ldap");
        let mut gateway_process = match start_gateway_with_dns(
            &config_path.to_string_lossy(),
            proxy_port,
            admin_port,
            Some(dns_resolver),
            &identity,
        ) {
            Ok(process) => process,
            Err(error) => {
                eprintln!(
                    "Gateway rebind-test spawn attempt {attempt}/{MAX_ATTEMPTS} failed: {error}"
                );
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };

        match wait_for_owned_gateway(
            gateway_process.child_mut(),
            admin_port,
            &identity,
            proxy_port,
        )
        .await
        {
            Ok(()) => {
                return (
                    gateway_process,
                    echo_handle,
                    proxy_port,
                    admin_port,
                    temp_dir,
                );
            }
            Err(error) => {
                eprintln!(
                    "Gateway rebind-test startup attempt {attempt}/{MAX_ATTEMPTS} failed: {error}"
                );
                gateway_process.shutdown();
                echo_handle.abort();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} rebind-test attempts");
}

#[ignore]
#[tokio::test]
async fn test_ldap_auth_returns_500_when_server_unreachable() {
    let config_template = r#"
version: "1"
proxies:
  - id: "auth-proxy"
    listen_path: "/secure"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ldap-1"

consumers: []

plugin_configs:
  - id: "ldap-1"
    proxy_id: "auth-proxy"
    plugin_name: "ldap_auth"
    scope: "proxy"
    enabled: true
    config:
      ldap_url: "ldap://127.0.0.1:{ldap_port}"
      bind_dn_template: "uid={{username}},ou=users,dc=example,dc=com"
      canonical_identity_attribute: "uid"
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_ldap_gateway_with_retry(config_template).await;

    // Send a request with Basic auth credentials — LDAP server is unreachable so auth must fail.
    //
    // On loaded CI runners the proxy route table may not be populated when
    // `/health` first returns 200. Retry on 404 to absorb that startup race.
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/secure/resource", proxy_port);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let response = loop {
        let r = client
            .get(&url)
            .basic_auth("testuser", Some("testpassword"))
            .send()
            .await
            .expect("Request failed");
        if r.status().as_u16() != 404 || tokio::time::Instant::now() >= deadline {
            break r;
        }
        sleep(Duration::from_millis(250)).await;
    };

    // Finding #32: an unreachable LDAP server is a backend/infrastructure
    // failure, not an invalid-credential outcome, so the plugin returns 500 —
    // not 401 — to avoid falsely telling the client its credentials are wrong.
    assert_eq!(
        response.status().as_u16(),
        500,
        "Expected 500 when LDAP server is unreachable, got {}",
        response.status()
    );

    let body = response.text().await.unwrap_or_default();
    assert!(
        body.contains("temporarily unavailable"),
        "Error body should indicate LDAP is temporarily unavailable, got: {}",
        body
    );

    // Cleanup
    gateway_process.shutdown();
    echo_handle.abort();
}

#[ignore]
#[tokio::test]
async fn test_ldap_auth_rejects_missing_credentials() {
    let config_template = r#"
version: "1"
proxies:
  - id: "auth-proxy"
    listen_path: "/secure"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ldap-1"

consumers: []

plugin_configs:
  - id: "ldap-1"
    proxy_id: "auth-proxy"
    plugin_name: "ldap_auth"
    scope: "proxy"
    enabled: true
    config:
      ldap_url: "ldap://127.0.0.1:{ldap_port}"
      bind_dn_template: "uid={{username}},ou=users,dc=example,dc=com"
      canonical_identity_attribute: "uid"
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_ldap_gateway_with_retry(config_template).await;

    // Send a request WITHOUT any auth credentials.
    //
    // On loaded CI runners the proxy route table may not be populated when
    // `/health` first returns 200 (the admin and proxy listeners start on
    // separate tasks). Retry on 404 to absorb that startup race.
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/secure/resource", proxy_port);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let response = loop {
        let r = client.get(&url).send().await.expect("Request failed");
        if r.status().as_u16() != 404 || tokio::time::Instant::now() >= deadline {
            break r;
        }
        sleep(Duration::from_millis(250)).await;
    };

    // The LDAP plugin should reject with 401 (no credentials provided)
    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected 401 when no credentials are provided, got {}",
        response.status()
    );

    // Cleanup
    gateway_process.shutdown();
    echo_handle.abort();
}

#[ignore]
#[tokio::test]
async fn test_ldap_auth_blocks_dial_time_dns_rebind() {
    let ldap_listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind LDAP rebind sentinel");
    let ldap_port = ldap_listener
        .local_addr()
        .expect("LDAP sentinel addr")
        .port();
    let dns = RebindingDnsServer::spawn(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;
    let config_template = r#"
version: "1"
proxies:
  - id: "auth-proxy"
    listen_path: "/secure"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ldap-1"

consumers: []

plugin_configs:
  - id: "ldap-1"
    proxy_id: "auth-proxy"
    plugin_name: "ldap_auth"
    scope: "proxy"
    enabled: true
    config:
      ldap_url: "ldap://directory.test:{ldap_port}"
      bind_dn_template: "uid={{username}},ou=users,dc=example,dc=com"
      canonical_identity_attribute: "uid"
      allow_plaintext: true
      connect_timeout_seconds: 1
"#;

    let (mut gateway_process, echo_handle, proxy_port, _admin_port, _temp_dir) =
        start_ldap_rebinding_gateway_with_retry(config_template, ldap_port, dns.addr).await;
    let queries_before_rebind = dns.queries();
    dns.rebind_to("169.254.169.254".parse().expect("metadata IP"));

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{proxy_port}/secure/resource");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let response = loop {
        let response = client
            .get(&url)
            .basic_auth("testuser", Some("end-user-secret"))
            .send()
            .await
            .expect("send LDAP rebind request");
        if response.status().as_u16() != 404 || tokio::time::Instant::now() >= deadline {
            break response;
        }
        sleep(Duration::from_millis(250)).await;
    };

    assert_eq!(response.status().as_u16(), 500);
    let body = response.text().await.expect("read LDAP rebind response");
    assert!(body.contains("temporarily unavailable"));
    assert!(!body.contains("end-user-secret"));
    assert!(
        dns.queries() >= queries_before_rebind + 2,
        "the request must issue fresh A and AAAA queries after warmup"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(500), ldap_listener.accept())
            .await
            .is_err(),
        "the LDAP listener must not receive a connection after the denied rebind"
    );

    gateway_process.shutdown();
    echo_handle.abort();
}
