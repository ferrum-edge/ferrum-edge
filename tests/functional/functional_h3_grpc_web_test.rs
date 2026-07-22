//! End-to-end regressions for HTTP/3 gRPC-Web request classification.
//!
//! The shared wire classifier intentionally leaves `application/grpc-web*`
//! as plain HTTP so the grpc_web plugin owns body translation. The H3 server
//! must nevertheless promote the request to effective gRPC for method policy,
//! early reject shaping, and plugin selection. Backend transport is promoted
//! only after the grpc_web plugin stamps its trusted translation marker;
//! plugin-free deployments retain their original pass-through transport.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http::{Method, StatusCode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::scaffolding::backends::{
    GrpcStep, MatchRpc, ScriptedGrpcBackend, ScriptedTlsBackend, TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_port, unbound_port};

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

fn grpc_web_frames(body: &[u8]) -> Vec<(u8, &[u8])> {
    let mut frames = Vec::new();
    let mut remaining = body;
    while remaining.len() >= 5 {
        let flag = remaining[0];
        let len =
            u32::from_be_bytes([remaining[1], remaining[2], remaining[3], remaining[4]]) as usize;
        if remaining.len() < 5 + len {
            break;
        }
        frames.push((flag, &remaining[5..5 + len]));
        remaining = &remaining[5 + len..];
    }
    frames
}

fn assert_grpc_web_error(response: &Http3Response, grpc_status: &str, expected_content_type: &str) {
    assert_eq!(
        response.status,
        StatusCode::OK,
        "gRPC-Web errors ride HTTP 200"
    );
    assert_eq!(
        response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some(expected_content_type)
    );
    assert!(
        response.body_error.is_none(),
        "unexpected H3 body error: {:?}",
        response.body_error
    );
    assert!(
        response.trailers.is_none(),
        "gRPC-Web must not emit native H3 trailers"
    );
    assert!(
        !response.headers.contains_key("grpc-status")
            && !response.headers.contains_key("grpc-message"),
        "terminal gRPC-Web metadata must remain in the body trailer frame"
    );
    let decoded_body;
    let wire_body = if expected_content_type.starts_with("application/grpc-web-text") {
        decoded_body = BASE64
            .decode(&response.body_bytes)
            .expect("decode gRPC-Web text response");
        decoded_body.as_slice()
    } else {
        response.body_bytes.as_ref()
    };
    let trailer_payload = grpc_web_frames(wire_body)
        .into_iter()
        .find_map(|(flag, payload)| (flag == 0x80).then_some(payload))
        .unwrap_or_else(|| {
            panic!(
                "missing gRPC-Web trailer frame in {:?}",
                response.body_bytes
            )
        });
    let trailer_text = String::from_utf8_lossy(trailer_payload);
    assert!(
        trailer_text.contains(&format!("grpc-status: {grpc_status}\r\n")),
        "unexpected gRPC-Web trailer payload: {trailer_text}"
    );
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-grpc-web-gateway").expect("gateway CA");
    let (cert, key) = ca.valid().expect("gateway leaf");
    let cert_path = scratch.join("gateway.cert.pem");
    let key_path = scratch.join("gateway.key.pem");
    std::fs::write(&cert_path, cert).expect("write gateway cert");
    std::fs::write(&key_path, key).expect("write gateway key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

async fn spawn_h3_gateway(config: Value) -> (GatewayHarness, u16, tempfile::TempDir) {
    let yaml = serde_yaml::to_string(&config).expect("serialize H3 gRPC-Web config");
    let mut last_error = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve H3 listener port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("gateway scratch dir");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        match GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("warn")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(harness) => return (harness, https_port, scratch),
            Err(error) => last_error = error.to_string(),
        }
    }
    panic!("failed to spawn H3 gRPC-Web gateway after retries: {last_error}");
}

async fn request_with_retry(client: &Http3Client, url: &str, options: GetOptions) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Err(error) => panic!("H3 request never completed: {error}"),
        }
    }
}

fn reject_config(backend_port: u16) -> Value {
    let proxy = |id: &str, path: &str, plugin_ids: &[&str]| {
        json!({
            "id": id,
            "listen_path": path,
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 500,
            "backend_read_timeout_ms": 1000,
            "backend_write_timeout_ms": 1000,
            "backend_tls_verify_server_cert": false,
            "plugins": plugin_ids
                .iter()
                .map(|plugin_config_id| json!({"plugin_config_id": plugin_config_id}))
                .collect::<Vec<_>>(),
        })
    };
    json!({
        "version": "1",
        "proxies": [
            proxy(
                "h3-grpc-web-received",
                "/received",
                &[
                    "grpc-web-received",
                    "grpc-web-cors",
                    "grpc-web-cors-narrow",
                    "received-reject",
                ],
            ),
            proxy(
                "h3-grpc-web-authenticate",
                "/authenticate",
                &["grpc-web-authenticate", "authenticate-reject"],
            ),
            proxy(
                "h3-grpc-web-authorize",
                "/authorize",
                &["grpc-web-authorize", "authorize-reject"],
            ),
            proxy(
                "h3-grpc-web-method-before-deadline",
                "/method-policy",
                &[
                    "grpc-web-method-policy",
                    "grpc-method-policy",
                    "grpc-method-deadline",
                ],
            ),
            proxy(
                "h3-grpc-web-deadline-only",
                "/deadline-only",
                &["grpc-web-deadline-only", "grpc-deadline-only"],
            ),
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "grpc-web-received",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-received",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-web-cors",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-received",
                "enabled": true,
                "config": {"allowed_origins": ["https://app.example"]},
            },
            {
                "id": "grpc-web-cors-narrow",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-received",
                "enabled": true,
                "config": {
                    "allowed_origins": ["https://app.example"],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "forward"
                },
            },
            {
                "id": "received-reject",
                "plugin_name": "request_termination",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-received",
                "enabled": true,
                "config": {
                    "status_code": 418,
                    "content_type": "application/json",
                    "message": "received phase rejected",
                },
            },
            {
                "id": "grpc-web-authenticate",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authenticate",
                "enabled": true,
                "config": {},
            },
            {
                "id": "authenticate-reject",
                "plugin_name": "basic_auth",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authenticate",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-web-authorize",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authorize",
                "enabled": true,
                "config": {},
            },
            {
                "id": "authorize-reject",
                "plugin_name": "access_control",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-authorize",
                "enabled": true,
                "config": {"allowed_consumers": ["allowed-user"]},
            },
            {
                "id": "grpc-web-method-policy",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-method-before-deadline",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-method-policy",
                "plugin_name": "grpc_method_router",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-method-before-deadline",
                "enabled": true,
                "config": {"deny_methods": ["pkg.Service/Denied"]},
            },
            {
                "id": "grpc-method-deadline",
                "plugin_name": "grpc_deadline",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-method-before-deadline",
                "enabled": true,
                "config": {"reject_no_deadline": true},
            },
            {
                "id": "grpc-web-deadline-only",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-deadline-only",
                "enabled": true,
                "config": {},
            },
            {
                "id": "grpc-deadline-only",
                "plugin_name": "grpc_deadline",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-deadline-only",
                "enabled": true,
                "config": {"reject_no_deadline": true},
            },
        ],
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_web_rejects_and_negative_controls_use_client_wire_flavor() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reject sentinel backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_hits_task = Arc::clone(&backend_hits);
    let backend_task = tokio::spawn(async move {
        while let Ok((stream, _)) = backend_listener.accept().await {
            backend_hits_task.fetch_add(1, Ordering::Relaxed);
            drop(stream);
        }
    });

    let (_gateway, https_port, _scratch) = spawn_h3_gateway(reject_config(backend_port)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let backend_connections_before_requests = backend_hits.load(Ordering::Relaxed);
    let client = Http3Client::insecure().expect("H3 client");
    let grpc_web = |method| {
        GetOptions::default()
            .method(method)
            .header("content-type", "application/grpc-web+proto")
            .body(Bytes::from(grpc_frame(b"ping")))
    };

    let non_post = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        grpc_web(Method::GET),
    )
    .await;
    assert_grpc_web_error(&non_post, "3", "application/grpc-web+proto");

    let received = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        grpc_web(Method::POST).header("origin", "https://app.example"),
    )
    .await;
    // The second CORS instance carries Istio's omitted method/header lists.
    // Those empty preflight lists must not reject this actual gRPC-Web POST or
    // its Content-Type header before request_termination shapes the response.
    assert_grpc_web_error(&received, "13", "application/grpc-web+proto");
    assert_eq!(
        received
            .headers
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.example")
    );

    let disallowed_origin = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        grpc_web(Method::POST).header("origin", "https://blocked.example"),
    )
    .await;
    assert_grpc_web_error(&disallowed_origin, "7", "application/grpc-web+proto");
    assert!(
        !disallowed_origin
            .headers
            .contains_key("access-control-allow-origin")
    );

    let authenticate = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/authenticate/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web-text+proto")
            .body(Bytes::from(BASE64.encode(grpc_frame(b"ping")))),
    )
    .await;
    assert_grpc_web_error(&authenticate, "16", "application/grpc-web-text+proto");

    let authorize = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/authorize/echo.Echo/Unary"),
        grpc_web(Method::POST),
    )
    .await;
    assert_grpc_web_error(&authorize, "16", "application/grpc-web+proto");

    let method_policy = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/method-policy/pkg.Service/Denied"),
        grpc_web(Method::POST).header("grpc-timeout", "5S"),
    )
    .await;
    assert_grpc_web_error(&method_policy, "7", "application/grpc-web+proto");

    let deadline_only = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/deadline-only/pkg.Service/Allowed"),
        grpc_web(Method::POST),
    )
    .await;
    assert_grpc_web_error(&deadline_only, "3", "application/grpc-web+proto");

    let native_method_policy = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/method-policy/pkg.Service/Denied"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc")
            .header("grpc-timeout", "5S")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;
    assert_eq!(native_method_policy.status, StatusCode::OK);
    assert_eq!(native_method_policy.grpc_status(), Some(7));
    assert!(native_method_policy.body_bytes.is_empty());
    assert!(native_method_policy.trailers.is_none());

    // Negative control: the same received-phase reject remains ordinary HTTP
    // for an unrelated content type.
    let plain = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/plain"),
        GetOptions::default().header("content-type", "application/json"),
    )
    .await;
    assert_eq!(plain.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        plain
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert!(plain.body_text().contains("received phase rejected"));

    // Negative control: native gRPC keeps native trailers-only rejection
    // shaping and never acquires a gRPC-Web body frame.
    let native_grpc = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/received/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;
    assert_eq!(native_grpc.status, StatusCode::OK);
    assert_eq!(
        native_grpc
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
    assert!(native_grpc.body_bytes.is_empty());
    assert_eq!(native_grpc.grpc_status(), Some(13));
    assert!(native_grpc.trailers.is_none());

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        backend_connections_before_requests,
        "method and plugin rejects must not create a backend connection"
    );
    backend_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_web_without_translation_plugin_keeps_plain_backend_transport() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind pass-through backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_ca = TestCa::new("h3-grpc-web-pass-through").expect("backend CA");
    let (backend_cert, backend_key) = backend_ca.valid().expect("backend leaf");
    let backend = ScriptedTlsBackend::builder(
        backend_listener,
        TlsConfig::new(backend_cert, backend_key).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 12\r\nconnection: close\r\n\r\npass-through"
            .to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn pass-through backend");
    let unavailable_port = unbound_port()
        .await
        .expect("reserve unavailable backend port");

    let config = json!({
        "version": "1",
        "proxies": [
            {
                "id": "h3-grpc-web-pass-through",
                "listen_path": "/pass-through",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 2000,
                "backend_read_timeout_ms": 5000,
                "backend_write_timeout_ms": 5000,
                "backend_tls_verify_server_cert": false,
                "plugins": [],
            },
            {
                "id": "h3-grpc-web-pass-through-policy",
                "listen_path": "/denied",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 2000,
                "backend_read_timeout_ms": 5000,
                "backend_write_timeout_ms": 5000,
                "backend_tls_verify_server_cert": false,
                "plugins": [{"plugin_config_id": "pass-through-method-policy"}],
            },
            {
                "id": "h3-grpc-web-pass-through-unavailable",
                "listen_path": "/unavailable",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": unavailable_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 500,
                "backend_read_timeout_ms": 1000,
                "backend_write_timeout_ms": 1000,
                "backend_tls_verify_server_cert": false,
                "plugins": [],
            },
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "pass-through-method-policy",
            "plugin_name": "grpc_method_router",
            "scope": "proxy",
            "proxy_id": "h3-grpc-web-pass-through-policy",
            "enabled": true,
            "config": {"deny_methods": ["echo.Echo/Unary"]},
        }],
    });
    let (_gateway, https_port, _scratch) = spawn_h3_gateway(config).await;
    let client = Http3Client::insecure().expect("H3 client");
    let request = || {
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+proto")
            .body(Bytes::from(grpc_frame(b"ping")))
    };

    let pass_through = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/pass-through/echo.Echo/Unary"),
        request(),
    )
    .await;
    assert_eq!(pass_through.status, StatusCode::OK);
    assert_eq!(
        pass_through
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/plain")
    );
    assert_eq!(pass_through.body_bytes.as_ref(), b"pass-through");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let pass_through_connections = backend.accepted_connections();
    assert!(
        pass_through_connections >= 1,
        "the pass-through request must reach the ordinary HTTP backend"
    );

    let denied = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/denied/echo.Echo/Unary"),
        request(),
    )
    .await;
    assert_grpc_web_error(&denied, "7", "application/grpc-web+proto");

    let unavailable = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/unavailable/echo.Echo/Unary"),
        request(),
    )
    .await;
    assert_grpc_web_error(&unavailable, "14", "application/grpc-web+proto");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let step_errors = backend.step_errors().await;
    assert!(
        step_errors
            .iter()
            .all(|error| error.contains("peer closed connection without sending TLS close_notify")),
        "unexpected pass-through backend script errors: {step_errors:?}"
    );
    assert_eq!(backend.accepted_connections(), pass_through_connections);
    assert_eq!(backend.handshakes_completed(), pass_through_connections);
    let negotiated_alpn = backend.last_alpn().await;
    assert!(
        negotiated_alpn.is_none() || negotiated_alpn.as_deref() == Some(b"http/1.1".as_slice()),
        "unexpected pass-through backend ALPN: {negotiated_alpn:?}"
    );
    let received = String::from_utf8_lossy(&backend.received_bytes().await).to_ascii_lowercase();
    assert!(received.starts_with("post /echo.echo/unary http/1.1\r\n"));
    assert!(received.contains("content-type: application/grpc-web+proto\r\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn streaming_h3_grpc_web_deadline_cancels_withheld_backend_headers() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled pass-through backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_ca = TestCa::new("h3-grpc-web-deadline-stall").expect("backend CA");
    let (backend_cert, backend_key) = backend_ca.valid().expect("backend leaf");
    let backend = ScriptedTlsBackend::builder(
        backend_listener,
        TlsConfig::new(backend_cert, backend_key).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    // Withhold response headers while continuing to read. The sentinel cannot
    // occur in this request, so the step exits only when deadline cancellation
    // closes the backend transport.
    .step(TcpStep::ReadUntil(
        b"ferrum-grpc-deadline-backend-never-sends-response".to_vec(),
    ))
    .spawn()
    .expect("spawn stalled pass-through backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-grpc-web-deadline-stall",
            "listen_path": "/deadline-stall",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "plugins": [{"plugin_config_id": "grpc-deadline-stall"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "grpc-deadline-stall",
            "plugin_name": "grpc_deadline",
            "scope": "proxy",
            "proxy_id": "h3-grpc-web-deadline-stall",
            "enabled": true,
            "config": {"max_deadline_ms": 1000},
        }],
    });
    let (_gateway, https_port, _scratch) = spawn_h3_gateway(config).await;
    let client = Http3Client::insecure().expect("H3 client");
    let started_at = Instant::now();
    let response = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/deadline-stall/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+proto")
            .header("grpc-timeout", "100m")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;

    assert_grpc_web_error(&response, "4", "application/grpc-web+proto");
    assert!(
        started_at.elapsed() < Duration::from_secs(3),
        "the absolute RPC deadline must win before the five-second backend read timeout"
    );
    let released_connections = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let accepted = backend.accepted_connections();
            let errors = backend.step_errors().await;
            if accepted > 0 && errors.len() >= accepted as usize {
                return (accepted, errors);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    let (backend_connections, _release_errors) = match released_connections {
        Ok(released) => released,
        Err(_) => panic!(
            "deadline dispatch did not promptly release every backend connection: {} accepted, \
             errors: {:?}",
            backend.accepted_connections(),
            backend.step_errors().await,
        ),
    };
    assert!(
        backend_connections >= 1,
        "the withheld-response-header backend path must be reached"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_web_success_uses_grpc_backend_and_preserves_trailer_frame() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_ca = TestCa::new("h3-grpc-web-backend").expect("backend CA");
    let (backend_cert, backend_key) = backend_ca.valid().expect("backend leaf");
    let backend = ScriptedGrpcBackend::builder_tls(backend_listener, &backend_cert, &backend_key)
        .expect("backend TLS")
        .step(GrpcStep::AcceptRpc(MatchRpc::custom(|request| {
            request.method == "POST"
                && request.path == "/echo.Echo/Unary"
                && request.header("content-type") == Some("application/grpc")
        })))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .step(GrpcStep::AcceptRpc(MatchRpc::custom(|request| {
            request.method == "POST"
                && request.path == "/echo.Echo/Unary"
                && request.header("content-type") == Some("application/grpc")
        })))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondStatus {
            code: 7,
            message: "permission denied",
        })
        .spawn()
        .expect("spawn gRPC backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-grpc-web-success",
            "listen_path": "/success",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "auth_mode": "single",
            "plugins": [
                {"plugin_config_id": "grpc-web-success"},
                {"plugin_config_id": "grpc-web-success-sibling"},
                {"plugin_config_id": "grpc-web-success-key-auth"},
                {"plugin_config_id": "grpc-web-success-chargeback"}
            ],
        }],
        "consumers": [{
            "id": "h3-grpc-web-chargeback-consumer",
            "username": "h3-grpc-web-chargeback-user",
            "credentials": {
                "keyauth": [{"key": "h3-grpc-web-chargeback-key-99887766"}]
            }
        }],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "grpc-web-success",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-success",
                "enabled": true,
                "priority_override": 250,
                "config": {"expose_headers": ["x-grpc-web-owner"]},
            },
            {
                "id": "grpc-web-success-sibling",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-success",
                "enabled": true,
                "priority_override": 270,
                "config": {"expose_headers": ["x-grpc-web-sibling"]},
            },
            {
                "id": "grpc-web-success-key-auth",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-success",
                "enabled": true,
                "config": {"key_location": "header:x-api-key"},
            },
            {
                "id": "grpc-web-success-chargeback",
                "plugin_name": "api_chargeback",
                "scope": "proxy",
                "proxy_id": "h3-grpc-web-success",
                "enabled": true,
                "config": {
                    "pricing_tiers": [
                        {"status_codes": [200], "price_per_call": 0.001},
                        {"status_codes": [403], "price_per_call": 0.007}
                    ],
                    "render_cache_ttl_seconds": 0,
                    "cache_invalidation_min_age_ms": 0,
                    "cleanup_interval_seconds": 0,
                },
            },
            {
                "id": "grpc-web-errors-only",
                "plugin_name": "stdout_logging",
                "scope": "global",
                "enabled": true,
                "config": {"filter": {"errors_only": true}},
            },
        ],
    });
    let (gateway, https_port, _scratch) = spawn_h3_gateway(config).await;
    let client = Http3Client::insecure().expect("H3 client");
    let response = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/success/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+json")
            .header(
                "accept",
                "text/html, Application/Grpc-Web-Text+Json; charset=utf-8; Q=0.8",
            )
            .header("x-api-key", "h3-grpc-web-chargeback-key-99887766")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web-text+json")
    );
    assert!(
        response
            .headers
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|vary| vary.split(',').any(|token| token.trim() == "Accept"))
    );
    let expose_headers = response
        .headers
        .get("access-control-expose-headers")
        .and_then(|value| value.to_str().ok())
        .expect("gRPC-Web expose headers");
    assert!(expose_headers.contains("x-grpc-web-owner"));
    assert!(expose_headers.contains("x-grpc-web-sibling"));
    assert!(
        response.trailers.is_none(),
        "gRPC-Web must not leak native H3 trailers"
    );
    let decoded_response = BASE64
        .decode(&response.body_bytes)
        .expect("Accept-negotiated H3 response must be base64 text");
    let frames = grpc_web_frames(&decoded_response);
    assert_eq!(
        frames.iter().filter(|(flag, _)| *flag & 0x80 != 0).count(),
        1,
        "two effective H3 grpc_web instances must emit one terminal frame"
    );
    assert_eq!(
        frames.first().map(|(flag, body)| (*flag, *body)),
        Some((0, b"pong".as_slice()))
    );
    let trailer_payload = frames
        .iter()
        .find_map(|(flag, payload)| (*flag == 0x80).then_some(*payload))
        .expect("successful gRPC-Web response trailer frame");
    assert!(
        String::from_utf8_lossy(trailer_payload).contains("grpc-status: 0\r\n"),
        "success status must be embedded in the gRPC-Web trailer frame"
    );

    let failure = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/success/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web-text+custom")
            .header("accept", "application/grpc-web; q=1")
            .header("x-api-key", "h3-grpc-web-chargeback-key-99887766")
            .body(Bytes::from(BASE64.encode(grpc_frame(b"ping")))),
    )
    .await;
    assert_grpc_web_error(&failure, "7", "application/grpc-web+custom");

    let unacceptable = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/success/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+proto")
            .header("accept", "application/grpc-web;q=broken")
            .header("x-api-key", "h3-grpc-web-chargeback-key-99887766")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;
    assert_eq!(unacceptable.status, StatusCode::NOT_ACCEPTABLE);
    assert_eq!(
        unacceptable
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        unacceptable
            .headers
            .get("vary")
            .and_then(|value| value.to_str().ok()),
        Some("Accept")
    );
    assert!(
        !unacceptable
            .headers
            .contains_key("x-ferrum-grpc-web-accept-rejected")
    );
    assert!(String::from_utf8_lossy(&unacceptable.body_bytes).contains("Not Acceptable"));

    let logs = gateway
        .wait_for_log_contains(
            |logs| {
                logs.lines().any(|line| {
                    serde_json::from_str::<Value>(line).is_ok_and(|entry| {
                        entry["proxy_id"] == "h3-grpc-web-success" && entry["grpc_status"] == 7
                    })
                })
            },
            Duration::from_secs(5),
        )
        .await;
    let access_logs: Vec<Value> = logs
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["proxy_id"] == "h3-grpc-web-success")
        .collect();
    assert_eq!(
        access_logs.len(),
        1,
        "errors_only must exclude translated status 0 and emit translated status 7; logs:\n{logs}"
    );
    assert_eq!(access_logs[0]["response_status_code"], 200);
    assert_eq!(access_logs[0]["grpc_status"], 7);

    let deadline = Instant::now() + Duration::from_secs(5);
    let charges = loop {
        let charges = gateway
            .get_admin_json("/charges?format=json")
            .await
            .expect("fetch H3 gRPC-Web chargeback JSON");
        let by_status = &charges["consumers"]["h3-grpc-web-chargeback-user"]["proxies"]["h3-grpc-web-success"]
            ["by_status"];
        if by_status["200"]["calls"].as_u64() == Some(1)
            && by_status["403"]["calls"].as_u64() == Some(1)
        {
            break charges;
        }
        assert!(
            Instant::now() < deadline,
            "H3 gRPC-Web chargeback did not settle: {charges:#?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let by_status = &charges["consumers"]["h3-grpc-web-chargeback-user"]["proxies"]["h3-grpc-web-success"]
        ["by_status"];
    let ok_charge = by_status["200"]["charges"]
        .as_f64()
        .expect("status 200 charge");
    let denied_charge = by_status["403"]["charges"]
        .as_f64()
        .expect("status 403 charge");
    assert!((ok_charge - 0.001).abs() < 1e-12, "{charges:#?}");
    assert!((denied_charge - 0.007).abs() < 1e-12, "{charges:#?}");
    assert_eq!(
        charges["consumers"]["h3-grpc-web-chargeback-user"]["total_calls"].as_u64(),
        Some(2),
        "{charges:#?}"
    );

    backend.assert_no_matcher_mismatches().await;
    backend.assert_no_step_errors().await;
    let requests = backend.received_streams().await;
    assert_eq!(
        requests.len(),
        2,
        "exactly two native gRPC backend requests expected"
    );
    assert_eq!(requests[0].body, grpc_frame(b"ping"));
    assert_eq!(requests[1].body, grpc_frame(b"ping"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_web_preserves_ascii_custom_trailers_binary_and_text() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_ca = TestCa::new("h3-grpc-web-custom-trailers").expect("backend CA");
    let (backend_cert, backend_key) = backend_ca.valid().expect("backend leaf");
    let custom_trailers = vec![
        ("request-id", "abc-123".into()),
        ("request-id", "abc-456".into()),
        ("trace-proto-bin", "AQID".into()),
        ("proxy-authenticate", "Basic realm=backend".into()),
    ];
    let backend = ScriptedGrpcBackend::builder_tls(backend_listener, &backend_cert, &backend_key)
        .expect("backend TLS")
        .step(GrpcStep::AcceptRpc(MatchRpc::custom(|request| {
            request.method == "POST"
                && request.path == "/echo.Echo/Unary"
                && request.header("content-type") == Some("application/grpc")
        })))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatusWithTrailers {
            code: 0,
            message: "",
            trailers: custom_trailers.clone(),
        })
        .step(GrpcStep::AcceptRpc(MatchRpc::custom(|request| {
            request.method == "POST"
                && request.path == "/echo.Echo/Unary"
                && request.header("content-type") == Some("application/grpc")
        })))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatusWithTrailers {
            code: 0,
            message: "",
            trailers: custom_trailers,
        })
        .spawn()
        .expect("spawn gRPC backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-grpc-web-custom-trailers",
            "listen_path": "/custom",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "auth_mode": "single",
            "plugins": [{"plugin_config_id": "grpc-web-custom-trailers"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "grpc-web-custom-trailers",
            "plugin_name": "grpc_web",
            "scope": "proxy",
            "proxy_id": "h3-grpc-web-custom-trailers",
            "enabled": true,
            "config": {},
        }],
    });
    let (_gateway, https_port, _scratch) = spawn_h3_gateway(config).await;
    let client = Http3Client::insecure().expect("H3 client");

    let assert_payload = |payload: &str| {
        assert!(payload.contains("grpc-status: 0\r\n"), "{payload}");
        assert!(payload.contains("request-id: abc-123\r\n"), "{payload}");
        assert!(payload.contains("request-id: abc-456\r\n"), "{payload}");
        assert!(payload.contains("trace-proto-bin: AQID\r\n"), "{payload}");
        assert!(
            !payload.contains("proxy-authenticate"),
            "hop-by-hop trailer leaked: {payload}"
        );
    };

    let binary = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/custom/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web+proto")
            .body(Bytes::from(grpc_frame(b"ping"))),
    )
    .await;
    assert_eq!(binary.status, StatusCode::OK);
    assert!(
        binary.trailers.is_none(),
        "must not emit native H3 trailers"
    );
    let binary_frames = grpc_web_frames(&binary.body_bytes);
    let binary_trailer = binary_frames
        .iter()
        .find_map(|(flag, payload)| (*flag == 0x80).then_some(*payload))
        .expect("binary gRPC-Web trailer frame");
    assert_payload(&String::from_utf8_lossy(binary_trailer));

    let text = request_with_retry(
        &client,
        &format!("https://127.0.0.1:{https_port}/custom/echo.Echo/Unary"),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc-web-text+proto")
            .body(Bytes::from(BASE64.encode(grpc_frame(b"ping")))),
    )
    .await;
    assert_eq!(text.status, StatusCode::OK);
    assert!(text.trailers.is_none(), "must not emit native H3 trailers");
    let decoded = BASE64
        .decode(&text.body_bytes)
        .expect("text mode body is base64");
    let text_frames = grpc_web_frames(&decoded);
    let text_trailer = text_frames
        .iter()
        .find_map(|(flag, payload)| (*flag == 0x80).then_some(*payload))
        .expect("text gRPC-Web trailer frame");
    assert_payload(&String::from_utf8_lossy(text_trailer));

    backend.assert_no_matcher_mismatches().await;
    backend.assert_no_step_errors().await;
}
