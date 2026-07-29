//! Functional coverage for serverless_function terminate mode on native gRPC.

use crate::scaffolding::reserve_port;
use bytes::Bytes;
use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{ServeHandles, ServeOptions};
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder as Http1ServerBuilder;
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
const TEST_JWT_SECRET: &str = "ferrum-edge-serverless-grpc-terminate-secret";
const TEST_JWT_ISSUER: &str = "ferrum-edge-serverless-grpc-terminate";

#[ignore]
#[tokio::test]
async fn functional_serverless_terminate_frames_native_grpc_unary() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_grpc_backend().await;
    let (function_port, function_hits, function_task) = spawn_grpc_terminate_function().await;
    let gateway = start_gateway(test_config(backend_port, function_port))
        .await
        .expect("start serverless gRPC terminate gateway");

    let h2_addr = format!("127.0.0.1:{}", gateway.http_port);
    let response = send_h2_grpc(&h2_addr, "/test.Service/Unary")
        .await
        .expect("native gRPC terminate request");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response
            .trailers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        response
            .trailers
            .get("x-function")
            .and_then(|v| v.to_str().ok()),
        Some("terminate")
    );
    assert_eq!(response.body.as_ref(), b"\x00\x00\x00\x00\x02\x08\x01");
    assert_eq!(function_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        0,
        "terminate must not reach the gRPC backend"
    );

    gateway.shutdown().await;
    backend_task.abort();
    function_task.abort();
}

struct RunningGateway {
    http_port: u16,
    shutdown_tx: watch::Sender<bool>,
    handles: ServeHandles,
}

impl RunningGateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), self.handles.join())
            .await
            .expect("serverless gRPC terminate gateway shutdown timed out")
            .expect("serverless gRPC terminate gateway listener failed");
    }
}

async fn start_gateway(
    config: GatewayConfig,
) -> Result<RunningGateway, Box<dyn std::error::Error + Send + Sync>> {
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
        admin_jwt_secret: Some(TEST_JWT_SECRET.to_string()),
        admin_jwt_issuer: TEST_JWT_ISSUER.to_string(),
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
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = watch::channel(false);
    let handles =
        ferrum_edge::modes::file::serve(env_config, config, options, shutdown_tx.clone()).await?;

    Ok(RunningGateway {
        http_port,
        shutdown_tx,
        handles,
    })
}

fn test_config(backend_port: u16, function_port: u16) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "serverless-grpc-terminate",
            "namespace": TEST_NAMESPACE,
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "plugins": [
                {"plugin_config_id": "serverless-grpc-terminate"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "serverless-grpc-terminate",
                "namespace": TEST_NAMESPACE,
                "plugin_name": "serverless_function",
                "scope": "proxy",
                "proxy_id": "serverless-grpc-terminate",
                "enabled": true,
                "config": {
                    "provider": "gcp_cloud_functions",
                    "mode": "terminate",
                    "function_url": format!("http://127.0.0.1:{function_port}/invoke"),
                    "timeout_ms": 5000,
                    "on_error": "reject"
                }
            }
        ]
    }))
    .expect("serverless gRPC terminate config is valid")
}

struct H2GrpcResponse {
    status: StatusCode,
    body: Bytes,
    trailers: HeaderMap,
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
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x00")))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let collected = response.into_body().collect().await?;
    let trailers = collected.trailers().cloned().unwrap_or_default();
    let body = collected.to_bytes();
    drop(sender);
    connection_task.abort();

    Ok(H2GrpcResponse {
        status,
        body,
        trailers,
    })
}

async fn spawn_counting_grpc_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits_clone = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/grpc")
                                .header("grpc-status", "0")
                                .body(Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x00")))
                                .expect("backend response"),
                        )
                    }
                });
                let _ = Http1ServerBuilder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    (port, hits, task)
}

async fn spawn_grpc_terminate_function() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind function");
    let port = listener.local_addr().expect("function addr").port();
    let hits_clone = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let body = json!({
                            "grpc_status": 0,
                            "message_base64": "CAE=",
                            "trailers": { "x-function": "terminate" }
                        })
                        .to_string();
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .expect("function response"),
                        )
                    }
                });
                let _ = Http1ServerBuilder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    (port, hits, task)
}
