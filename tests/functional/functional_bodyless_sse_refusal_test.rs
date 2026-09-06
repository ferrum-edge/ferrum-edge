//! H1/H2/H3 wire regressions for whole-body SSE refusal on no-content replies (#4648).

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http::{HeaderMap, Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

const TIMEOUT: Duration = Duration::from_secs(10);
const ROUTES: [&str; 3] = ["size", "validator", "both"];

fn cases() -> Vec<(Method, &'static str, u16)> {
    vec![
        (Method::HEAD, "200", 200),
        (Method::HEAD, "204", 204),
        (Method::HEAD, "205", 205),
        (Method::HEAD, "304", 304),
        (Method::GET, "204", 204),
        (Method::GET, "205", 205),
        (Method::GET, "304", 304),
        (Method::HEAD, "json", 200),
        (Method::GET, "200", 502),
    ]
}

fn gateway_builder(port: u16) -> TestGatewayBuilder {
    let mut proxies = Vec::new();
    let mut configs = Vec::new();
    for route in ROUTES {
        let mut attached = Vec::new();
        for (name, config) in [
            (
                "response_size_limiting",
                json!({"max_bytes": 1000, "require_buffered_check": true}),
            ),
            (
                "body_validator",
                json!({"response_json_schema": {"type": "object"}}),
            ),
            (
                "response_transformer",
                json!({"rules": [{
                    "operation": "add", "target": "header",
                    "key": "x-bodyless-checked", "value": "yes"
                }]}),
            ),
        ] {
            if (route == "size" && name == "body_validator")
                || (route == "validator" && name == "response_size_limiting")
            {
                continue;
            }
            let id = format!("{route}-{name}");
            attached.push(json!({"plugin_config_id": id}));
            configs.push(json!({
                "id": id, "proxy_id": route, "plugin_name": name,
                "scope": "proxy", "enabled": true, "config": config
            }));
        }
        proxies.push(json!({
            "id": route, "listen_path": format!("/{route}"),
            "backend_scheme": "http", "backend_host": "127.0.0.1", "backend_port": port,
            "strip_listen_path": true, "pool_enable_http2": false,
            "response_body_mode": "stream", "plugins": attached
        }));
    }
    let config = json!({
        "version": "1", "proxies": proxies, "plugin_configs": configs,
        "consumers": [], "upstreams": []
    });
    TestGateway::builder()
        .mode_file(serde_yaml::to_string(&config).expect("serialize config"))
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .log_level("warn")
}

async fn backend() -> (u16, JoinHandle<()>) {
    let reservation = reserve_port().await.expect("reserve backend port");
    let port = reservation.port;
    let listener = reservation.into_listener();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.expect("request head");
                    request.push(byte[0]);
                    assert!(request.len() < 16384, "bounded request headers");
                }
                let request = String::from_utf8(request).expect("ASCII request");
                let mut parts = request.split_whitespace();
                let method = parts.next().expect("method");
                let path = parts.next().expect("path");
                // The backend capability refresh probes h2c with the HTTP/2
                // prior-knowledge preface (`PRI * HTTP/2.0`); this backend
                // speaks HTTP/1.1 only, so the probe is dropped, not answered.
                if method == "PRI" {
                    return;
                }
                let status = match path {
                    "/204" => "204 No Content",
                    "/205" => "205 Reset Content",
                    "/304" => "304 Not Modified",
                    "/200" | "/json" => "200 OK",
                    _ => panic!("unexpected backend path {path}"),
                };
                let content_type = if path == "/json" {
                    "application/json"
                } else {
                    "text/event-stream"
                };
                let body = if method == "HEAD" || path != "/200" {
                    ""
                } else {
                    "data: hello\n\n"
                };
                let length = match path {
                    "/204" | "/304" => String::new(),
                    "/205" => "Content-Length: 0\r\n".into(),
                    _ if method == "HEAD" => "Content-Length: 128\r\n".into(),
                    _ => format!("Content-Length: {}\r\n", body.len()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n\
                     {length}Connection: close\r\n\r\n{body}"
                );
                stream.write_all(response.as_bytes()).await.expect("reply");
                stream.shutdown().await.expect("finish reply");
            });
        }
    });
    (port, task)
}

fn assert_bodyless_headers(headers: &HeaderMap, method: &Method, status: u16) {
    assert_eq!(headers["x-bodyless-checked"], "yes");
    if status == 205 && *method != Method::HEAD {
        // `ProxyBody::empty_for_response_status` frames a 205 with an
        // unknown-length, immediately-EOF body so no `Content-Length` is
        // synthesized: on H1 hyper writes `Transfer-Encoding: chunked` with an
        // empty chunked body, on H2/H3 END_STREAM with neither header.
        assert!(
            headers
                .get("transfer-encoding")
                .is_none_or(|value| value == "chunked")
        );
    } else {
        assert!(!headers.contains_key("transfer-encoding"));
    }
    if *method == Method::HEAD && status == 200 {
        assert_eq!(headers["content-length"], "128");
    } else if status == 204 || status == 304 {
        assert!(!headers.contains_key("content-length"));
    } else if status == 205 {
        assert!(
            headers
                .get("content-length")
                .is_none_or(|value| value == "0")
        );
    }
}

#[ignore]
#[tokio::test]
async fn bodyless_sse_http1_wire() {
    let (port, task) = backend().await;
    let mut gateway = gateway_builder(port).spawn().await.expect("gateway");
    for route in ROUTES {
        for (method, path, expected) in cases() {
            let mut stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port))
                .await
                .expect("H1 connect");
            let request = format!(
                "{method} /{route}/{path} HTTP/1.1\r\n\
                 Host: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                gateway.proxy_port
            );
            stream.write_all(request.as_bytes()).await.expect("H1 send");
            let mut wire = Vec::new();
            tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut wire))
                .await
                .expect("H1 reply deadline")
                .expect("H1 reply");
            let end = wire
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("head");
            let head = std::str::from_utf8(&wire[..end]).expect("ASCII headers");
            let mut lines = head.split("\r\n");
            let status = lines.next().expect("status line");
            assert!(
                status.starts_with(&format!("HTTP/1.1 {expected} ")),
                "{status}"
            );
            if expected != 502 {
                let mut headers = HeaderMap::new();
                for line in lines {
                    let (name, value) = line.split_once(':').expect("header");
                    headers.append(
                        http::header::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                        value.trim().parse().expect("value"),
                    );
                }
                assert_bodyless_headers(&headers, &method, expected);
                let chunked_empty =
                    expected == 205 && headers.contains_key("transfer-encoding");
                let trailing = &wire[end + 4..];
                assert!(
                    trailing.is_empty() || (chunked_empty && trailing == b"0\r\n\r\n"),
                    "{route}/{method}/{path} sent bytes"
                );
            }
        }
    }
    gateway.shutdown();
    task.abort();
}

#[ignore]
#[tokio::test]
async fn bodyless_sse_http2_wire() {
    let (port, task) = backend().await;
    let mut gateway = gateway_builder(port).spawn().await.expect("gateway");
    let stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port))
        .await
        .expect("H2 connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("H2 handshake");
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    for route in ROUTES {
        for (method, path, expected) in cases() {
            let request = Request::builder()
                .method(method.clone())
                .uri(gateway.proxy_url(&format!("/{route}/{path}")))
                .body(Empty::<Bytes>::new())
                .expect("H2 request");
            let response = tokio::time::timeout(TIMEOUT, sender.send_request(request))
                .await
                .expect("H2 header deadline")
                .expect("H2 reply");
            assert_eq!(
                response.status().as_u16(),
                expected,
                "{route}/{method}/{path}"
            );
            if expected != 502 {
                assert_bodyless_headers(response.headers(), &method, expected);
            }
            let body = tokio::time::timeout(TIMEOUT, response.into_body().collect())
                .await
                .expect("H2 body deadline")
                .expect("H2 body without reset")
                .to_bytes();
            if expected != 502 {
                assert!(body.is_empty(), "{route}/{method}/{path} sent DATA");
            }
        }
    }
    drop(sender);
    connection_task.abort();
    gateway.shutdown();
    task.abort();
}

#[ignore]
#[tokio::test]
async fn bodyless_sse_http3_wire() {
    let (port, task) = backend().await;
    let mut gateway = gateway_builder(port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .spawn()
        .await
        .expect("H3 gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("HTTPS port");
    let client = Http3Client::insecure().expect("H3 client");
    for route in ROUTES {
        for (method, path, expected) in cases() {
            let url = format!("https://127.0.0.1:{https_port}/{route}/{path}");
            let response = tokio::time::timeout(
                TIMEOUT,
                client.get_with_options(&url, GetOptions::default().method(method.clone())),
            )
            .await
            .expect("H3 reply deadline")
            .expect("H3 reply without reset");
            assert_eq!(
                response.status.as_u16(),
                expected,
                "{route}/{method}/{path}"
            );
            if expected != 502 {
                assert_bodyless_headers(&response.headers, &method, expected);
                assert!(
                    response.body_bytes.is_empty(),
                    "{route}/{method}/{path} sent DATA"
                );
            }
        }
    }
    gateway.shutdown();
    task.abort();
}
