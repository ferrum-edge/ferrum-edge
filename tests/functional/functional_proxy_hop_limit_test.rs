//! Request-time proxy hop limit (issue #6109) against a real gateway.
//!
//! A route whose upstream is the gateway's own listener turns every request
//! into a loop. With `FERRUM_MAX_PROXY_HOPS` set, each pass through the
//! gateway increments the gateway-owned `X-Ferrum-Hops` request header, and
//! the pass that receives a count at the limit answers `508 Loop Detected`
//! instead of forwarding again. A second route to an ordinary recording
//! origin pins the forwarded count, the direct refusal, and the malformed
//! field refusal.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::ports::reserve_port;

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const MAX_PROXY_HOPS: u8 = 3;
const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;

/// Loopback HTTP/1.1 origin that records the `X-Ferrum-Hops` field lines of
/// every request it receives and answers `200`.
struct HopRecordingOrigin {
    port: u16,
    seen: Arc<Mutex<Vec<Vec<String>>>>,
    handle: Option<JoinHandle<()>>,
}

impl HopRecordingOrigin {
    async fn spawn() -> std::io::Result<Self> {
        let listener = TcpListener::bind_test("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::spawn(serve_origin_connection(stream, Arc::clone(&recorder)));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        });
        Ok(Self {
            port,
            seen,
            handle: Some(handle),
        })
    }

    async fn seen(&self) -> Vec<Vec<String>> {
        self.seen.lock().await.clone()
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for HopRecordingOrigin {
    fn drop(&mut self) {
        self.abort();
    }
}

async fn serve_origin_connection(mut stream: TcpStream, recorder: Arc<Mutex<Vec<Vec<String>>>>) {
    let Some(head) = read_request_head(&mut stream).await else {
        return;
    };
    let head = String::from_utf8_lossy(&head);
    let hops = head
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("x-ferrum-hops"))
        .map(|(_, value)| value.trim().to_string())
        .collect::<Vec<_>>();
    recorder.lock().await.push(hops);
    let body = r#"{"ok":true}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn read_request_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    while request.len() < MAX_REQUEST_HEAD_BYTES {
        let remaining = MAX_REQUEST_HEAD_BYTES - request.len();
        let read_len = remaining.min(chunk.len());
        match stream.read(&mut chunk[..read_len]).await {
            Ok(0) => break,
            Ok(size) => request.extend_from_slice(&chunk[..size]),
            Err(_) => return None,
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Some(request);
        }
    }
    None
}

fn gateway_config(gateway_port: u16, origin_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [
            // The upstream is this gateway's own plaintext listener, and the
            // forwarded path matches the same route again: a request loop.
            {
                "id": "self-loop",
                "listen_path": "/loop",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": gateway_port,
                "strip_listen_path": false,
                "pool_enable_http2": false
            },
            {
                "id": "origin",
                "listen_path": "/origin",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": origin_port,
                "strip_listen_path": false,
                "pool_enable_http2": false
            }
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    serde_yaml::to_string(&config).expect("serialize hop-limit config")
}

struct HopLimitHarness {
    gateway: TestGateway,
    origin: HopRecordingOrigin,
}

impl HopLimitHarness {
    async fn spawn() -> Self {
        let mut origin = HopRecordingOrigin::spawn()
            .await
            .expect("spawn recording origin");
        let mut last_error = String::new();
        for _ in 0..5 {
            // The route's upstream is the gateway's own port, so the port must
            // be fixed before the config is written; this loop owns retries.
            let reservation = reserve_port().await.expect("reserve proxy port");
            let gateway_port = reservation.drop_and_take_port();
            let spawn = TestGateway::builder()
                .mode_file(gateway_config(gateway_port, origin.port))
                .log_level("warn")
                .max_attempts(1)
                .env("FERRUM_PROXY_HTTP_PORT", gateway_port.to_string())
                .env("FERRUM_MAX_PROXY_HOPS", MAX_PROXY_HOPS.to_string())
                // Warmup would dial both upstreams before the first case.
                .env("FERRUM_POOL_WARMUP_ENABLED", "false")
                .spawn()
                .await;
            match spawn {
                Ok(mut gateway) => {
                    match gateway.wait_for_proxy_port(Duration::from_secs(5)).await {
                        Ok(()) => return Self { gateway, origin },
                        Err(error) => {
                            last_error = error.to_string();
                            gateway.shutdown();
                        }
                    }
                }
                Err(error) => last_error = error.to_string(),
            }
        }
        origin.abort();
        panic!("start hop-limit gateway after retries: {last_error}");
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.origin.abort();
    }
}

fn http1_client() -> reqwest::Client {
    reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("http1 client")
}

#[ignore]
#[tokio::test]
async fn functional_proxy_hop_limit_refuses_a_self_referencing_route() {
    let mut harness = HopLimitHarness::spawn().await;
    let client = http1_client();

    // The loop terminates: the pass that receives `X-Ferrum-Hops: 3` refuses
    // with 508 and every earlier pass relays that answer back to the client.
    let looped = client
        .get(harness.gateway.proxy_url("/loop"))
        .send()
        .await
        .expect("self-loop request completes instead of looping");
    assert_eq!(looped.status().as_u16(), 508);
    let body = looped.text().await.expect("self-loop body");
    assert!(
        body.contains("Proxy hop limit exceeded"),
        "unexpected self-loop body: {body}"
    );

    // An ordinary route forwards `received + 1`; an absent field is hop 0.
    let forwarded = client
        .get(harness.gateway.proxy_url("/origin"))
        .send()
        .await
        .expect("origin request");
    assert_eq!(forwarded.status().as_u16(), 200);
    let forwarded = client
        .get(harness.gateway.proxy_url("/origin"))
        .header("x-ferrum-hops", "2")
        .send()
        .await
        .expect("origin request below the limit");
    assert_eq!(forwarded.status().as_u16(), 200);
    assert_eq!(
        harness.origin.seen().await,
        vec![vec!["1".to_string()], vec!["3".to_string()]],
        "the origin sees exactly one gateway-written count per request"
    );

    // A count at the limit is refused before routing with the gateway token,
    // and the origin is never contacted.
    let refused = client
        .get(harness.gateway.proxy_url("/origin"))
        .header("x-ferrum-hops", MAX_PROXY_HOPS.to_string())
        .send()
        .await
        .expect("origin request at the limit");
    assert_eq!(refused.status().as_u16(), 508);
    assert_eq!(
        refused
            .headers()
            .get("x-gateway-error")
            .and_then(|value| value.to_str().ok()),
        Some("loop_detected")
    );

    // A malformed field is refused rather than reset to zero.
    let malformed = client
        .get(harness.gateway.proxy_url("/origin"))
        .header("x-ferrum-hops", "zero")
        .send()
        .await
        .expect("origin request with a malformed count");
    assert_eq!(malformed.status().as_u16(), 400);
    assert!(
        malformed.headers().get("x-gateway-error").is_none(),
        "a client-caused 400 carries no gateway error token"
    );
    assert_eq!(
        harness.origin.seen().await.len(),
        2,
        "refused requests never reach the origin"
    );

    harness.shutdown();
}
