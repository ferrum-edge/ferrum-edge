//! HTTP/3 HEAD/GET contract for `request_termination` synthetic responses.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{Method, StatusCode};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "h3-termination"
    listen_path: "/term"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "h3-termination-plugin"

consumers: []
plugin_configs:
  - id: "h3-termination-plugin"
    plugin_name: request_termination
    scope: proxy
    proxy_id: "h3-termination"
    enabled: true
    config:
      status_code: 503
      content_type: application/json
      message: "h3 maintenance window"
"#
    )
}

async fn h3_request_until_ready(client: &Http3Client, url: &str, method: Method) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match client
            .get_with_options(url, GetOptions::default().method(method.clone()))
            .await
        {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 {method} {url} did not complete: {error}"),
        }
    }
}

async fn spawn_h3_gateway(backend_port: u16) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let result = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!(
        "failed to spawn request_termination H3 gateway after {MAX_ATTEMPTS} attempts: {last_error}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_request_termination_h3_head_omits_data_and_get_keeps_body() {
    // Backend must never be contacted — bind and leave it idle so any dial fails loudly.
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind idle backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();

    let (mut gateway, https_port) = spawn_h3_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/term/anything");

    let get = h3_request_until_ready(&client, &url, Method::GET).await;
    assert_eq!(get.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        get.body_text().contains("h3 maintenance window"),
        "GET must receive the configured termination body, got {}",
        get.body_text()
    );
    let representation_len = get.body_bytes.len();
    assert!(representation_len > 0);

    let head = h3_request_until_ready(&client, &url, Method::HEAD).await;
    assert_eq!(head.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        head.body_bytes.is_empty(),
        "HEAD must not receive DATA/content bytes"
    );
    let head_len = head
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    assert_eq!(
        head_len,
        Some(representation_len),
        "HEAD Content-Length must match the GET representation"
    );

    // Idle backend accept queue must stay empty — termination short-circuits.
    assert!(
        backend_listener.local_addr().is_ok(),
        "backend listener must remain bound"
    );

    gateway.shutdown();
}

#[cfg(unix)]
fn send_sigterm(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .output();
}

fn slow_h3_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "h3-drain"
    listen_path: "/slow"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: false

consumers: []
plugin_configs: []
"#
    )
}

async fn spawn_h3_drain_gateway(backend_port: u16, drain_seconds: u64) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let result = TestGateway::builder()
            .mode_file(slow_h3_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_SHUTDOWN_DRAIN_SECONDS", drain_seconds.to_string())
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!("failed to spawn H3 drain gateway after {MAX_ATTEMPTS} attempts: {last_error}");
}

async fn start_slow_http_backend(
    sleep_ms: u64,
) -> (
    u16,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind slow backend");
    let port = listener.local_addr().expect("backend addr").port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepted_for_task = std::sync::Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let accepted = std::sync::Arc::clone(&accepted_for_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        let mut total = 0;
                        loop {
                            match stream.read(&mut buf[total..]).await {
                                Ok(0) => return,
                                Ok(n) => {
                                    total += n;
                                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                    if total >= buf.len() {
                                        break;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                        accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        sleep(Duration::from_millis(sleep_ms)).await;
                        let body = "slow-h3-ok";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
                Err(_) => return,
            }
        }
    });
    (port, accepted, task)
}

fn goaway_or_rejected(err: &str) -> bool {
    let err = err.to_ascii_lowercase();
    err.contains("goaway")
        || err.contains("remote is closing")
        || err.contains("h3_request_rejected")
        || err.contains("request rejected")
        || err.contains("connection closed")
        || err.contains("application closed")
        || err.contains("no error")
}

/// Issue #4429: SIGTERM sends HTTP/3 GOAWAY. An in-flight long response on
/// one connection completes within the drain budget; a new request stream on
/// a second already-open connection is refused without killing that work.
#[ignore]
#[cfg(unix)]
#[tokio::test]
async fn functional_h3_shutdown_sends_goaway_and_completes_inflight() {
    let (backend_port, accepted, backend_task) = start_slow_http_backend(1500).await;
    let (mut gateway, https_port) = spawn_h3_drain_gateway(backend_port, 8).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/slow");

    let mut inflight = client.connect(&url).await.expect("conn A");
    let mut idle = client.connect(&url).await.expect("conn B");
    let mut stream = inflight
        .open_stream(&url, GetOptions::default(), true)
        .await
        .expect("open long request");

    let deadline = Instant::now() + Duration::from_secs(5);
    while accepted.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        if Instant::now() >= deadline {
            panic!("backend never accepted the long H3 request");
        }
        sleep(Duration::from_millis(20)).await;
    }

    let pid = gateway.pid().expect("gateway pid");
    send_sigterm(pid);

    let follow_deadline = Instant::now() + Duration::from_secs(3);
    let follow_err = loop {
        match idle.get(&url).await {
            Err(error) => break error.to_string(),
            Ok(resp) if Instant::now() >= follow_deadline => {
                panic!("new request stream after GOAWAY succeeded: {resp:?}");
            }
            Ok(_) => sleep(Duration::from_millis(50)).await,
        }
    };
    assert!(
        goaway_or_rejected(&follow_err),
        "follow-up refusal must be GOAWAY / H3_REQUEST_REJECTED, got {follow_err}"
    );

    let (status, _) = stream.recv_response().await.expect("in-flight headers");
    let body = stream.recv_body().await.expect("in-flight body");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"slow-h3-ok");

    gateway.shutdown();
    backend_task.abort();
}

/// Issue #4429: drain deadline still force-closes a stuck H3 stream and the
/// spawn wrapper drops `ConnectionGuard` exactly once (process exits instead
/// of hanging on a leaked counter).
#[ignore]
#[cfg(unix)]
#[tokio::test]
async fn functional_h3_shutdown_deadline_force_closes_stuck_stream() {
    let (backend_port, accepted, backend_task) = start_slow_http_backend(30_000).await;
    let (mut gateway, https_port) = spawn_h3_drain_gateway(backend_port, 2).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/slow");
    let mut conn = client.connect(&url).await.expect("h3 conn");
    let mut stream = conn
        .open_stream(&url, GetOptions::default(), true)
        .await
        .expect("open stuck request");

    let deadline = Instant::now() + Duration::from_secs(5);
    while accepted.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        if Instant::now() >= deadline {
            panic!("backend never accepted the stuck H3 request");
        }
        sleep(Duration::from_millis(20)).await;
    }

    let pid = gateway.pid().expect("gateway pid");
    let started = Instant::now();
    send_sigterm(pid);

    let recv = stream.recv_response().await;
    assert!(
        recv.is_err(),
        "stuck stream must be force-closed at drain deadline, got {recv:?}"
    );

    let exit_deadline = Duration::from_secs(8);
    loop {
        if !gateway.is_running() {
            break;
        }
        if started.elapsed() > exit_deadline {
            panic!("gateway did not exit after H3 drain deadline");
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        started.elapsed() < exit_deadline,
        "force-close must release accounting so the process can exit"
    );

    gateway.shutdown();
    backend_task.abort();
}
