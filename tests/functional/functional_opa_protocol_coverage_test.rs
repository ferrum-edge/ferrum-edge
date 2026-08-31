//! End-to-end OPA authorization on HTTP, WebSocket-upgrade, and native gRPC traffic.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::{TestGateway, spawn_http_counting_mutations};

const DECISION_PATH: &str = "/v1/data/ferrum/authz/allow";
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

#[ignore]
#[tokio::test]
async fn opa_policy_denial_applies_to_http_websocket_upgrade_and_grpc() {
    let opa = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": false})))
        .mount(&opa)
        .await;

    let (mut backend, mutations) = spawn_http_counting_mutations()
        .await
        .expect("start counting backend");
    let config = opa_deny_config(backend.port, &opa.uri());
    let mut gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start OPA protocol-coverage gateway");
    let client = reqwest::Client::new();

    let plain = client
        .post(gateway.proxy_url("/x"))
        .send()
        .await
        .expect("plain HTTP request completes");
    assert_eq!(plain.status(), StatusCode::FORBIDDEN);

    let websocket_upgrade = client
        .post(gateway.proxy_url("/x"))
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", WS_KEY)
        .header("sec-websocket-version", "13")
        .send()
        .await
        .expect("WebSocket-upgrade request completes");
    assert_eq!(websocket_upgrade.status(), StatusCode::FORBIDDEN);

    let gateway_addr = format!("127.0.0.1:{}", gateway.proxy_port);
    let (grpc_status, grpc_headers, grpc_body) = send_grpc_request(&gateway_addr, "/x", b"")
        .await
        .expect("native gRPC request completes");
    assert_eq!(grpc_status, 200, "native gRPC rejections are trailers-only");
    assert!(
        grpc_body.is_empty(),
        "native gRPC rejections must not forward a body"
    );
    assert_eq!(
        grpc_headers.get("grpc-status").map(String::as_str),
        Some("7"),
        "OPA policy denial should map HTTP 403 to grpc-status 7"
    );

    assert_eq!(
        mutations.load(Ordering::SeqCst),
        0,
        "OPA must deny before any backend mutation is observed"
    );

    gateway.shutdown();
    backend.abort();
}

async fn send_grpc_request(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(error) = conn.await {
            eprintln!("client h2 connection error: {error}");
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            headers.insert(name.as_str().to_string(), value.to_string());
        }
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .unwrap_or_default();

    Ok((status, headers, body_bytes))
}

fn opa_deny_config(backend_port: u16, opa_host: &str) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "opa-protocol-coverage",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "plugins": [{"plugin_config_id": "opa-authz"}]
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "opa-authz",
            "plugin_name": "opa",
            "scope": "proxy",
            "proxy_id": "opa-protocol-coverage",
            "enabled": true,
            "config": {
                "opa_host": opa_host,
                "policy_path": "ferrum/authz/allow"
            }
        }]
    });
    serde_yaml::to_string(&config).expect("serialize OPA protocol-coverage config")
}
