//! End-to-end replay fidelity for `load_testing` across H1 and H3 ingress.
//!
//! Issue #4164: replays are dialed at `127.0.0.1`, which operators routinely
//! list in `FERRUM_TRUSTED_PROXIES`, so a client-supplied `X-Real-IP` carried
//! into the synthetic header snapshot would be honored by
//! `client_ip::resolve_client_ip` on backend-bound traffic. Every trigger below
//! therefore sends a spoofed `X-Real-IP` that must appear in NO capture.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{Method, StatusCode};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const TRIGGER_KEY: &str = "functional-load-key-0123456789abcdef";
const RAW_QUERY: &str = "tag=red&tag=blue&q=a+b&prefix=a%2Fb&flag&empty=";
const MAX_REQUEST_BYTES: usize = 128 * 1024;
/// Client-asserted source address the gateway must refuse on both the original
/// request and every synthetic replay (issue #4164). The harness dials from
/// loopback, so this value can only have come from the trigger's header.
const SPOOFED_REAL_IP: &str = "10.0.0.7";

#[derive(Debug)]
struct CapturedRequest {
    request_target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct ReplayBackend {
    port: u16,
    receiver: mpsc::Receiver<CapturedRequest>,
    handle: Option<JoinHandle<()>>,
}

impl ReplayBackend {
    async fn spawn() -> std::io::Result<Self> {
        let listener = TcpListener::bind_test("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (sender, receiver) = mpsc::channel(64);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let sender = sender.clone();
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    let _ = sender.try_send(request);

                    // Keep the single load worker bounded to roughly ten
                    // requests per second so a fidelity test cannot create an
                    // unbounded capture backlog on a fast runner.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let body = b"ok";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(Self {
            port,
            receiver,
            handle: Some(handle),
        })
    }

    async fn collect(&mut self, expected_target: &str, count: usize) -> Vec<CapturedRequest> {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut captures = Vec::with_capacity(count);
        while captures.len() < count {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out after {} matching captures for {expected_target}",
                captures.len()
            );
            let request = tokio::time::timeout(remaining, self.receiver.recv())
                .await
                .expect("capture timeout")
                .expect("capture backend stopped");
            if request.request_target == expected_target {
                captures.push(request);
            }
        }
        captures
    }

    fn drain(&mut self) {
        while self.receiver.try_recv().is_ok() {}
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for ReplayBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

struct ReplayHarness {
    gateway: TestGateway,
    backend: ReplayBackend,
    https_port: u16,
}

impl ReplayHarness {
    async fn spawn() -> Self {
        let mut backend = ReplayBackend::spawn()
            .await
            .expect("spawn replay capture backend");
        let config = replay_config(backend.port);
        let mut last_error = String::new();

        for _ in 0..5 {
            let reservation = reserve_port().await.expect("reserve HTTPS port");
            let https_port = reservation.drop_and_take_port();
            match TestGateway::builder()
                .mode_file(config.clone())
                .log_level("warn")
                .max_attempts(1)
                .env("FERRUM_ENABLE_HTTP3", "true")
                .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
                .spawn()
                .await
            {
                Ok(mut gateway) => {
                    match gateway.wait_for_proxy_port(Duration::from_secs(5)).await {
                        Ok(()) => {
                            return Self {
                                gateway,
                                backend,
                                https_port,
                            };
                        }
                        Err(error) => {
                            last_error = error.to_string();
                            gateway.shutdown();
                        }
                    }
                }
                Err(error) => last_error = error.to_string(),
            }
        }

        backend.abort();
        panic!("start load-testing replay gateway after retries: {last_error}");
    }

    fn h3_url(&self, target: &str) -> String {
        format!("https://localhost:{}{target}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.backend.abort();
    }
}

#[ignore]
#[tokio::test]
async fn functional_load_testing_replays_exact_body_query_and_framing_from_h1_and_h3() {
    let mut harness = ReplayHarness::spawn().await;

    let h1_target = format!("/load-replay-h1?{RAW_QUERY}");
    let h1_body = Bytes::from_static(br#"{"sku":"A-123","note":"+"}"#);
    send_raw_h1_trigger(harness.gateway.proxy_port, &h1_target, &h1_body).await;

    let h1_captures = harness.backend.collect(&h1_target, 2).await;
    assert_replay_captures(&h1_captures, &h1_body);

    // The first cohort has an absolute one-second lifetime. Let it finish and
    // discard any extra bounded captures before starting the independent H3
    // plugin identity.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    harness.backend.drain();

    let h3_target = format!("/load-replay-h3?{RAW_QUERY}");
    let h3_body = Bytes::from_static(&[0x00, 0xff, b'a', b'+', b'%', b'2', b'F']);
    let h3_client = Http3Client::insecure().expect("H3 client");
    let h3_options = GetOptions::default()
        .method(Method::POST)
        .header("x-loadtesting-key", TRIGGER_KEY)
        .header("x-real-ip", SPOOFED_REAL_IP)
        .body(h3_body.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    let h3_response = loop {
        match h3_client
            .get_with_options(&harness.h3_url(&h3_target), h3_options.clone())
            .await
        {
            Ok(response) => break response,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 trigger request did not complete: {error}"),
        }
    };
    assert_eq!(h3_response.status, StatusCode::OK);
    assert_eq!(h3_response.body_bytes, Bytes::from_static(b"ok"));
    assert!(h3_response.body_error.is_none());

    let h3_captures = harness.backend.collect(&h3_target, 2).await;
    assert_replay_captures(&h3_captures, &h3_body);

    harness.shutdown();
}

fn assert_replay_captures(captures: &[CapturedRequest], expected_body: &[u8]) {
    assert!(
        captures.len() >= 2,
        "original plus synthetic request required"
    );
    let expected_content_length = expected_body.len().to_string();
    for capture in captures {
        assert_eq!(capture.body, expected_body);
        assert_eq!(
            capture.headers.get("content-length").map(String::as_str),
            Some(expected_content_length.as_str()),
            "framing must match replay bytes: {capture:?}"
        );
        assert!(!capture.headers.contains_key("transfer-encoding"));
        assert!(!capture.headers.contains_key("x-loadtesting-key"));
        assert!(!capture.headers.contains_key("x-loadtesting-fanout"));
        // Issue #4164: neither the original request nor the synthetic replay
        // may carry the untrusted peer's client-asserted source address.
        assert!(
            !capture.headers.contains_key("x-real-ip"),
            "client-asserted X-Real-IP survived into a load-test capture: {capture:?}"
        );
    }
}

async fn send_raw_h1_trigger(port: u16, target: &str, body: &[u8]) {
    let request_head = format!(
        "POST {target} HTTP/1.1\r\nHost: localhost\r\nX-Loadtesting-Key: {TRIGGER_KEY}\r\nX-Real-IP: {SPOOFED_REAL_IP}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect H1 gateway");
        stream
            .write_all(request_head.as_bytes())
            .await
            .expect("write H1 request head");
        stream.write_all(body).await.expect("write H1 request body");
        stream.flush().await.expect("flush H1 request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read H1 response");
        response
    })
    .await
    .expect("H1 trigger deadline");
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "unexpected H1 response: {}",
        String::from_utf8_lossy(&response)
    );
}

async fn read_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
        if request.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&chunk[..read]);
    };

    let header_text = std::str::from_utf8(&request[..header_end]).ok()?;
    let mut lines = header_text.split("\r\n");
    let request_target = lines.next()?.split_whitespace().nth(1)?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if header_end.checked_add(content_length)? > MAX_REQUEST_BYTES {
        return None;
    }
    while request.len() < header_end + content_length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&chunk[..read]);
    }

    Some(CapturedRequest {
        request_target,
        headers,
        body: request[header_end..header_end + content_length].to_vec(),
    })
}

fn replay_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [
            replay_proxy("load-replay-h1", "/load-replay-h1", backend_port, "load-plugin-h1"),
            replay_proxy("load-replay-h3", "/load-replay-h3", backend_port, "load-plugin-h3")
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            replay_plugin("load-plugin-h1", "load-replay-h1"),
            replay_plugin("load-plugin-h3", "load-replay-h3")
        ]
    });
    serde_yaml::to_string(&config).expect("serialize load-testing replay config")
}

fn replay_proxy(
    id: &str,
    listen_path: &str,
    backend_port: u16,
    plugin_config_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": [{"plugin_config_id": plugin_config_id}]
    })
}

fn replay_plugin(id: &str, proxy_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "plugin_name": "load_testing",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": {
            "key": TRIGGER_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "request_timeout_ms": 1000,
            "max_response_body_bytes": 1024
        }
    })
}
