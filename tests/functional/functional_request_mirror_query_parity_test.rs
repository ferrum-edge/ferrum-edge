//! Primary-vs-mirror request-target query parity across H1, H2, and H3.
//!
//! Issue #2444: absent intentional auth strips, `request_mirror` must forward
//! the exact raw query bytes the primary backend receives (repeated pairs,
//! order, flags, empty values, `+`, encoded delimiters, percent escapes, and
//! non-ASCII encoded octets).

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Raw query covering #2444 acceptance cases in one request-target.
const RAW_QUERY: &str =
    "tag=red&tag=blue&b=1&a=2&flag&empty=&q=a+b&path=%2Froot&k=a%26b&key=a%2Fb&name=%E2%9C%93";

#[ignore]
#[tokio::test]
async fn request_mirror_primary_and_mirror_request_targets_match_on_h1_h2_h3() {
    let mut harness = MirrorQueryParityHarness::spawn().await;

    for protocol in ["HTTP/1.1", "HTTP/2", "HTTP/3"] {
        harness.reset_captures();
        let status = match protocol {
            "HTTP/1.1" => http1_get(&harness).await,
            "HTTP/2" => h2_get(&harness).await,
            "HTTP/3" => h3_get(&harness).await,
            _ => unreachable!(),
        };
        assert_eq!(status, StatusCode::OK, "{protocol} client request failed");

        let (primary, mirror) = harness
            .wait_for_both_targets(Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("{protocol}: timed out waiting for primary and mirror"));

        assert_eq!(
            primary, mirror,
            "{protocol}: primary and mirror request-targets must match byte-for-byte\n  primary={primary}\n  mirror={mirror}"
        );
        assert!(
            primary.contains(&format!("?{RAW_QUERY}")),
            "{protocol}: request-target must preserve raw query exactly: {primary}"
        );
    }

    harness.shutdown();
}

struct CapturingBackend {
    port: u16,
    targets: Arc<Mutex<Vec<String>>>,
    notify: Arc<Notify>,
    handle: Option<JoinHandle<()>>,
}

impl CapturingBackend {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind capture backend");
        let port = listener.local_addr().expect("local addr").port();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let targets_task = targets.clone();
        let notify_task = notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let targets = targets_task.clone();
                        let notify = notify_task.clone();
                        tokio::spawn(async move {
                            let mut buf = Vec::new();
                            let mut chunk = [0u8; 4096];
                            loop {
                                match stream.read(&mut chunk).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        buf.extend_from_slice(&chunk[..n]);
                                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                            break;
                                        }
                                    }
                                    Err(_) => return,
                                }
                            }
                            let head = String::from_utf8_lossy(&buf);
                            let request_line = head.lines().next().unwrap_or("");
                            let target = request_line
                                .split_whitespace()
                                .nth(1)
                                .unwrap_or("")
                                .to_string();
                            targets.lock().expect("targets lock").push(target);
                            notify.notify_waiters();
                            let _ = stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                                )
                                .await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Self {
            port,
            targets,
            notify,
            handle: Some(handle),
        }
    }

    fn first_target(&self) -> Option<String> {
        self.targets
            .lock()
            .expect("targets lock")
            .first()
            .cloned()
    }

    fn clear(&self) {
        self.targets.lock().expect("targets lock").clear();
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for CapturingBackend {
    fn drop(&mut self) {
        self.abort();
    }
}

struct MirrorQueryParityHarness {
    gateway: TestGateway,
    primary: CapturingBackend,
    mirror: CapturingBackend,
    https_port: u16,
}

impl MirrorQueryParityHarness {
    async fn spawn() -> Self {
        let primary = CapturingBackend::spawn().await;
        let mirror = CapturingBackend::spawn().await;
        let https_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve https port");
        let https_port = https_listener.local_addr().expect("https addr").port();
        drop(https_listener);

        let gateway = TestGateway::builder()
            .mode_file(mirror_query_config(primary.port, mirror.port))
            .log_level("warn")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .spawn()
            .await
            .expect("start request_mirror query parity gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy port ready");

        Self {
            gateway,
            primary,
            mirror,
            https_port,
        }
    }

    fn reset_captures(&self) {
        self.primary.clear();
        self.mirror.clear();
    }

    async fn wait_for_both_targets(&self, timeout: Duration) -> Option<(String, String)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let (Some(primary), Some(mirror)) =
                (self.primary.first_target(), self.mirror.first_target())
            {
                return Some((primary, mirror));
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = self.primary.notify.notified() => {}
                _ = self.mirror.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    fn http1_url(&self) -> String {
        self.gateway.proxy_url(&format!("/resource?{RAW_QUERY}"))
    }

    fn h2_uri(&self) -> String {
        format!(
            "http://127.0.0.1:{}/resource?{RAW_QUERY}",
            self.gateway.proxy_port
        )
    }

    fn h3_url(&self) -> String {
        format!("https://localhost:{}/resource?{RAW_QUERY}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.primary.abort();
        self.mirror.abort();
    }
}

fn mirror_query_config(primary_port: u16, mirror_port: u16) -> String {
    // listen_path `/` with strip disabled keeps the client path on both the
    // primary backend URL and the default mirror path, so request-target
    // comparison isolates query fidelity (#2444).
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "mirror-query-parity",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": primary_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "mirror-query-plugin"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "mirror-query-plugin",
            "plugin_name": "request_mirror",
            "scope": "proxy",
            "proxy_id": "mirror-query-parity",
            "enabled": true,
            "config": {
                "mirror_host": "127.0.0.1",
                "mirror_port": mirror_port,
                "mirror_protocol": "http",
                "percentage": 100.0,
                "mirror_request_body": false
            }
        }]
    });
    serde_yaml::to_string(&config).expect("serialize mirror query parity config")
}

async fn http1_get(harness: &MirrorQueryParityHarness) -> StatusCode {
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    client
        .get(harness.http1_url())
        .send()
        .await
        .expect("http1 request")
        .status()
}

async fn h2_get(harness: &MirrorQueryParityHarness) -> StatusCode {
    let stream = TcpStream::connect(("127.0.0.1", harness.gateway.proxy_port))
        .await
        .expect("connect h2c");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .uri(harness.h2_uri())
        .body(Empty::<Bytes>::new())
        .expect("build h2 request");
    let response = sender.send_request(request).await.expect("send h2 request");
    let status = response.status();
    let _ = response
        .into_body()
        .collect()
        .await
        .expect("collect h2 body");
    drop(sender);
    conn_task.abort();
    status
}

async fn h3_get(harness: &MirrorQueryParityHarness) -> StatusCode {
    let client = Http3Client::insecure().expect("h3 client");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match client
            .get_with_options(&harness.h3_url(), GetOptions::default().method(Method::GET))
            .await
        {
            Ok(response) => return response.status,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 mirror query request did not complete: {error}"),
        }
    }
}
