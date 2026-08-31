//! Functional coverage for backend-effective gRPC method enforcement before
//! deferred external hooks on the shared H1/H2 and H3 request paths.

use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};
use crate::scaffolding::{reserve_colocated_tcp_udp, reserve_port};
use bytes::Bytes;
use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{ServeHandles, ServeOptions};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder as Http1ServerBuilder;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const TEST_NAMESPACE: &str = "ferrum";
const TEST_JWT_SECRET: &str = "ferrum-edge-grpc-pre-hook-test-secret";
const TEST_JWT_ISSUER: &str = "ferrum-edge-grpc-pre-hook-test";

#[ignore]
#[tokio::test]
async fn functional_grpc_method_rate_limit_precedes_external_hook_on_h2_and_h3() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_grpc_backend().await;
    let (function_port, function_hits, function_task) = spawn_counting_function().await;
    let gateway = start_gateway(test_config(backend_port, function_port))
        .await
        .expect("start H2/H3 gRPC method-policy gateway");

    let h2_addr = format!("127.0.0.1:{}", gateway.http_port);
    let allowed_h2 = send_h2_grpc(&h2_addr, "/test.Policy/H2")
        .await
        .expect("allowed H2 gRPC request");
    assert_grpc_success(
        allowed_h2.status,
        &allowed_h2.headers,
        &allowed_h2.body,
        "H2",
    );
    assert_eq!(function_hits.load(Ordering::SeqCst), 1);
    assert_eq!(backend_hits.load(Ordering::SeqCst), 1);

    let rejected_h2 = send_h2_grpc(&h2_addr, "/test.Policy/H2")
        .await
        .expect("rate-limited H2 gRPC request");
    assert_grpc_rate_reject(
        rejected_h2.status,
        &rejected_h2.headers,
        &rejected_h2.body,
        "H2",
    );
    assert_eq!(
        function_hits.load(Ordering::SeqCst),
        1,
        "H2 method rejection must precede the deferred serverless invocation"
    );
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "H2 method rejection must also precede backend dispatch"
    );

    let h3_client = Http3Client::insecure().expect("H3 client");
    let h3_url = format!("https://localhost:{}/test.Policy/H3", gateway.https_port);
    let allowed_h3 = send_h3_grpc(&h3_client, &h3_url)
        .await
        .expect("allowed H3 gRPC request");
    assert_eq!(allowed_h3.status, StatusCode::OK);
    assert_eq!(allowed_h3.grpc_status(), Some(0));
    assert!(allowed_h3.body_error.is_none());
    assert_eq!(function_hits.load(Ordering::SeqCst), 2);
    assert_eq!(backend_hits.load(Ordering::SeqCst), 2);

    let rejected_h3 = send_h3_grpc(&h3_client, &h3_url)
        .await
        .expect("rate-limited H3 gRPC request");
    assert_h3_grpc_rate_reject(&rejected_h3);
    assert_eq!(
        function_hits.load(Ordering::SeqCst),
        2,
        "H3 method rejection must precede the deferred serverless invocation"
    );
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        2,
        "H3 method rejection must also precede backend dispatch"
    );

    gateway.shutdown().await;
    backend_task.abort();
    function_task.abort();
}

struct RunningGateway {
    http_port: u16,
    https_port: u16,
    shutdown_tx: watch::Sender<bool>,
    handles: ServeHandles,
}

impl RunningGateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), self.handles.join())
            .await
            .expect("gRPC method-policy gateway shutdown timed out")
            .expect("gRPC method-policy gateway listener failed");
    }
}

async fn start_gateway(
    config: GatewayConfig,
) -> Result<RunningGateway, Box<dyn std::error::Error + Send + Sync>> {
    let http = reserve_port().await?;
    let (https_tcp, https_udp) = reserve_colocated_tcp_udp().await?;
    let admin = reserve_port().await?;
    let http_port = http.port;
    let https_port = https_tcp.port;
    assert_eq!(https_port, https_udp.port);

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: "warn".to_string(),
        proxy_http_port: http_port,
        proxy_https_port: https_port,
        admin_http_port: admin.port,
        admin_https_port: 0,
        admin_jwt_secret: Some(TEST_JWT_SECRET.to_string()),
        admin_jwt_issuer: TEST_JWT_ISSUER.to_string(),
        frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
        frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
        enable_http3: true,
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: TEST_NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    let jwt_manager = JwtManager::new(JwtConfig {
        secret: TEST_JWT_SECRET.to_string(),
        issuer: TEST_JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let options = ServeOptions {
        proxy_http: Some(http.into_listener()),
        proxy_https: Some(https_tcp.into_listener()),
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };
    drop(https_udp);

    let (shutdown_tx, _) = watch::channel(false);
    let handles =
        ferrum_edge::modes::file::serve(env_config, config, options, shutdown_tx.clone()).await?;

    Ok(RunningGateway {
        http_port,
        https_port,
        shutdown_tx,
        handles,
    })
}

fn test_config(backend_port: u16, function_port: u16) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-method-pre-hook",
            "namespace": TEST_NAMESPACE,
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "plugins": [
                {"plugin_config_id": "grpc-method-policy"},
                {"plugin_config_id": "deferred-serverless-hook"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "grpc-method-policy",
                "namespace": TEST_NAMESPACE,
                "plugin_name": "grpc_method_router",
                "scope": "proxy",
                "proxy_id": "grpc-method-pre-hook",
                "enabled": true,
                "config": {
                    "method_rate_limits": {
                        "test.Policy/H2": {
                            "max_requests": 1,
                            "window_seconds": 60
                        },
                        "test.Policy/H3": {
                            "max_requests": 1,
                            "window_seconds": 60
                        }
                    }
                }
            },
            {
                "id": "deferred-serverless-hook",
                "namespace": TEST_NAMESPACE,
                "plugin_name": "serverless_function",
                "scope": "proxy",
                "proxy_id": "grpc-method-pre-hook",
                "enabled": true,
                "config": {
                    "provider": "gcp_cloud_functions",
                    "mode": "pre_proxy",
                    "function_url": format!("http://127.0.0.1:{function_port}/invoke"),
                    "timeout_ms": 5000,
                    "on_error": "reject"
                }
            }
        ]
    }))
    .expect("gRPC method pre-hook config is valid")
}

struct H2GrpcResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn send_h2_grpc(
    gateway_addr: &str,
    path: &str,
) -> Result<H2GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::new()))?;
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

async fn send_h3_grpc(
    client: &Http3Client,
    url: &str,
) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
    client
        .get_with_options(
            url,
            GetOptions::default()
                .method(Method::POST)
                .header("content-type", "application/grpc"),
        )
        .await
}

fn assert_grpc_success(status: StatusCode, headers: &HeaderMap, body: &Bytes, protocol: &str) {
    assert_eq!(status, StatusCode::OK, "{protocol} gRPC HTTP status");
    assert_eq!(
        headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0"),
        "{protocol} allowed request should reach the fake gRPC backend"
    );
    assert!(body.is_empty(), "{protocol} fake backend returns no DATA");
}

fn assert_grpc_rate_reject(status: StatusCode, headers: &HeaderMap, body: &Bytes, protocol: &str) {
    assert_eq!(status, StatusCode::OK, "{protocol} gRPC rejection status");
    assert!(
        body.is_empty(),
        "{protocol} gRPC rate rejection must be trailers-only"
    );
    assert_eq!(
        headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("8"),
        "{protocol} rate rejection must be RESOURCE_EXHAUSTED"
    );
    assert!(
        headers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|message| message.contains("Rate limit exceeded")),
        "{protocol} rate rejection must preserve the plugin message"
    );
}

fn assert_h3_grpc_rate_reject(response: &Http3Response) {
    assert_eq!(response.status, StatusCode::OK, "H3 gRPC rejection status");
    assert!(
        response.body_bytes.is_empty(),
        "H3 gRPC rate rejection must be trailers-only"
    );
    assert!(
        response.body_error.is_none(),
        "H3 gRPC rate rejection must terminate cleanly"
    );
    assert_eq!(
        response.grpc_status(),
        Some(8),
        "H3 rate rejection must be RESOURCE_EXHAUSTED"
    );
    assert!(
        response
            .grpc_message()
            .is_some_and(|message| message.contains("Rate limit exceeded")),
        "H3 rate rejection must preserve the plugin message"
    );
}

async fn spawn_counting_function() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve function port");
    let port = reservation.port;
    let listener = reservation.into_listener();
    let hits = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_counting_function(listener, Arc::clone(&hits)));
    (port, hits, task)
}

async fn run_counting_function(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let _ = request.into_body().collect().await;
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from_static(
                                br#"{"headers":{"x-hook-called":"true"}}"#,
                            )))
                            .expect("build function response"),
                    )
                }
            });
            let _ = Http1ServerBuilder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn spawn_counting_grpc_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve gRPC backend port");
    let port = reservation.port;
    let listener = reservation.into_listener();
    let hits = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_counting_grpc_backend(listener, Arc::clone(&hits)));
    (port, hits, task)
}

async fn run_counting_grpc_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
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
