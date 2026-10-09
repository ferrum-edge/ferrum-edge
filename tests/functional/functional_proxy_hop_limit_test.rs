//! Request-time proxy hop limit (issue #6109) against a real gateway.
//!
//! A route whose upstream is the gateway's own listener turns every request
//! into a loop. With `FERRUM_MAX_PROXY_HOPS` set, each pass through the
//! gateway increments the gateway-owned `X-Ferrum-Hops` request header, and
//! the pass that receives a count at the limit answers `508 Loop Detected`
//! instead of forwarding again. A second route to an ordinary recording
//! origin pins the forwarded count, the direct refusal, and the malformed
//! field refusal. A native gRPC case over HTTP/2 (h2c frontend and backend,
//! the raw-map merge builder) pins the same count on the H2 transport.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{ServeHandles, ServeOptions};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::watch;
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
    // Only the innermost pass authors `loop_detected`; every outer pass
    // relays a backend 5xx and labels it `backend_error`.
    assert_eq!(
        looped
            .headers()
            .get("x-gateway-error")
            .and_then(|value| value.to_str().ok()),
        Some("backend_error")
    );
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

const GRPC_NAMESPACE: &str = "ferrum";
const GRPC_JWT_SECRET: &str = "ferrum-edge-hop-limit-grpc-test-secret";
const GRPC_JWT_ISSUER: &str = "ferrum-edge-hop-limit-grpc-test";

/// Native gRPC over HTTP/2: the h2c backend behind the native gRPC pool
/// receives exactly one gateway-written `X-Ferrum-Hops` field carrying
/// `received + 1`, and a refused request never reaches it.
#[ignore]
#[tokio::test]
async fn functional_proxy_hop_limit_h2_grpc_backend_receives_one_incremented_count() {
    let backend = GrpcHopRecordingBackend::spawn().await;
    let gateway = start_grpc_gateway(grpc_gateway_config(backend.port))
        .await
        .expect("start H2 gRPC hop-limit gateway");
    let addr = format!("127.0.0.1:{}", gateway.http_port);

    let absent = send_h2_grpc(&addr, None)
        .await
        .expect("H2 gRPC request without a count");
    assert_grpc_status(&absent, "0", "absent count");
    let below = send_h2_grpc(&addr, Some("1"))
        .await
        .expect("H2 gRPC request below the limit");
    assert_grpc_status(&below, "0", "count below the limit");
    assert_eq!(
        backend.seen().await,
        vec![vec!["1".to_string()], vec!["2".to_string()]],
        "the gRPC backend sees exactly one gateway-written count per request"
    );

    // At the limit: Trailers-Only FAILED_PRECONDITION before routing.
    let limit = MAX_PROXY_HOPS.to_string();
    let refused = send_h2_grpc(&addr, Some(&limit))
        .await
        .expect("H2 gRPC request at the limit");
    assert_grpc_status(&refused, "9", "count at the limit");
    assert!(
        refused.body.is_empty(),
        "the gRPC loop refusal must be trailers-only"
    );

    // Malformed: Trailers-Only INVALID_ARGUMENT.
    let malformed = send_h2_grpc(&addr, Some("zero"))
        .await
        .expect("H2 gRPC request with a malformed count");
    assert_grpc_status(&malformed, "3", "malformed count");
    assert_eq!(
        backend.seen().await.len(),
        2,
        "refused gRPC requests never reach the backend"
    );

    gateway.shutdown().await;
}

struct GrpcHopRecordingBackend {
    port: u16,
    seen: Arc<Mutex<Vec<Vec<String>>>>,
    handle: JoinHandle<()>,
}

impl GrpcHopRecordingBackend {
    async fn spawn() -> Self {
        let reservation = reserve_port().await.expect("reserve gRPC backend port");
        let port = reservation.port;
        let listener = reservation.into_listener();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle = tokio::spawn(run_grpc_hop_backend(listener, Arc::clone(&seen)));
        Self { port, seen, handle }
    }

    async fn seen(&self) -> Vec<Vec<String>> {
        self.seen.lock().await.clone()
    }
}

impl Drop for GrpcHopRecordingBackend {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn run_grpc_hop_backend(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<String>>>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let seen = Arc::clone(&seen);
                async move {
                    let hops = request
                        .headers()
                        .get_all("x-ferrum-hops")
                        .iter()
                        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                        .collect::<Vec<_>>();
                    seen.lock().await.push(hops);
                    let _ = request.into_body().collect().await;
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "0")
                            .body(Full::new(Bytes::new()))
                            .expect("build gRPC backend response"),
                    )
                }
            });
            let _ = Http2ServerBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn grpc_gateway_config(backend_port: u16) -> GatewayConfig {
    serde_json::from_value(serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "hop-limit-grpc",
            "namespace": GRPC_NAMESPACE,
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    }))
    .expect("hop-limit gRPC config is valid")
}

struct RunningGrpcGateway {
    http_port: u16,
    shutdown_tx: watch::Sender<bool>,
    handles: ServeHandles,
}

impl RunningGrpcGateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), self.handles.join())
            .await
            .expect("hop-limit gRPC gateway shutdown timed out")
            .expect("hop-limit gRPC gateway listener failed");
    }
}

async fn start_grpc_gateway(
    config: GatewayConfig,
) -> Result<RunningGrpcGateway, Box<dyn std::error::Error + Send + Sync>> {
    let http = reserve_port().await?;
    let admin = reserve_port().await?;
    let http_port = http.port;
    let env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: "warn".to_string(),
        proxy_http_port: http_port,
        proxy_https_port: 0,
        admin_http_port: admin.port,
        admin_https_port: 0,
        admin_jwt_secret: Some(GRPC_JWT_SECRET.to_string()),
        admin_jwt_issuer: GRPC_JWT_ISSUER.to_string(),
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        max_proxy_hops: MAX_PROXY_HOPS,
        namespace: GRPC_NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    let jwt_manager = JwtManager::new(JwtConfig {
        secret: GRPC_JWT_SECRET.to_string(),
        issuer: GRPC_JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let options = ServeOptions {
        proxy_http: Some(http.into_listener()),
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };
    let (shutdown_tx, _) = watch::channel(false);
    let handles =
        ferrum_edge::modes::file::serve(env_config, config, options, shutdown_tx.clone()).await?;
    Ok(RunningGrpcGateway {
        http_port,
        shutdown_tx,
        handles,
    })
}

struct H2GrpcResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn send_h2_grpc(
    gateway_addr: &str,
    hops: Option<&str>,
) -> Result<H2GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/hop.Limit/Call"))
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if let Some(hops) = hops {
        request = request.header("x-ferrum-hops", hops);
    }
    let request = request.body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await?.to_bytes();
    drop(sender);
    connection_task.abort();
    Ok(H2GrpcResponse {
        status,
        headers,
        body,
    })
}

fn assert_grpc_status(response: &H2GrpcResponse, expected: &str, case: &str) {
    assert_eq!(response.status, StatusCode::OK, "{case}: gRPC HTTP status");
    assert_eq!(
        response
            .headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some(expected),
        "{case}: grpc-status"
    );
}
