//! End-to-end tests for the HTTP/3 frontend → non-H3 (H2/h2c) gRPC backend
//! STREAMING-request bridge (`cross_protocol::dispatch_grpc_streaming`).
//!
//! Before this path existed, an H3 gRPC request was fully drained into memory
//! (`drain_h3_body`) before the gateway dialed the backend, so the backend saw
//! no request messages until the client half-closed — breaking true
//! client-streaming / bidirectional RPCs. These tests prove the gateway now
//! forwards request DATA incrementally and, crucially, that a backend can
//! respond BEFORE the H3 client half-closes (the bidi case that previously
//! deadlocked).
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests h3_grpc_streaming -- --ignored --nocapture
//! ```

use std::time::Duration;

use crate::scaffolding::backends::{
    GrpcStep, H2Step, MatchHeaders, MatchRpc, ScriptedGrpcBackend, ScriptedH2Backend,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use serde_json::json;
use tokio::net::TcpListener;

/// Build a frontend TLS cert + CA PEMs and write them to a scratch dir.
/// Returns `(cert_path, key_path)`.
fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-grpc-stream-gw").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let cert_path = scratch.join("gw.cert.pem");
    let key_path = scratch.join("gw.key.pem");
    std::fs::write(&cert_path, &cert).expect("write cert");
    std::fs::write(&key_path, &key).expect("write key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// File-mode YAML for one HTTPS proxy (gRPC is a runtime flavor of `https`)
/// pointing at `(127.0.0.1, backend_port)`.
fn file_mode_yaml_with_response_buffering(
    backend_port: u16,
    buffer_response: bool,
    remove_buffered_trailer_fields: bool,
    override_existing_security_headers: bool,
) -> String {
    let mut proxy = json!({
        "id": "h3-grpc-stream",
        "listen_path": "/api",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
        "backend_tls_verify_server_cert": false,
    });
    if buffer_response {
        proxy["response_body_mode"] = json!("buffer");
    }
    let mut security_config = json!({
        "override_existing": override_existing_security_headers,
        "hsts": true,
        "set": {
            "X-Security-Policy": "gateway-enforced",
        },
        "remove": [],
    });
    let mut plugin_configs = Vec::new();
    if override_existing_security_headers {
        security_config["set"]["Grpc-Status"] = json!("0");
        security_config["set"]["Grpc-Message"] = json!("policy override");
    } else if remove_buffered_trailer_fields {
        plugin_configs.push(json!({
            "id": "h3-grpc-cookie-transformer",
            "plugin_name": "response_transformer",
            "config": {
                "rules": [{
                    "target": "header",
                    "operation": "update",
                    "key": "Set-Cookie",
                    "value": "session=mutated",
                }],
            },
            "scope": "global",
            "enabled": true,
        }));
        security_config["remove"] =
            json!(["Set-Cookie", "X-Powered-By", "Grpc-Status", "Grpc-Message",]);
        security_config["set"] = json!({
            "X-Security-Policy": "gateway-enforced",
        });
    }
    plugin_configs.push(json!({
        "id": "h3-grpc-security-headers",
        "plugin_name": "security_headers",
        "config": security_config,
        "scope": "global",
        "enabled": true,
    }));
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": plugin_configs,
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// Spawn an H3 frontend gateway pointing at `backend_port`. Returns the harness
/// and the HTTPS/QUIC port. `extra_env` lets a test tune e.g. the gRPC recv
/// ceiling. The backend must already be listening on `backend_port`.
async fn spawn_h3_grpc_gateway(
    backend_port: u16,
    extra_env: &[(&str, String)],
) -> (GatewayHarness, u16) {
    spawn_h3_grpc_gateway_with_response_buffering(backend_port, extra_env, false, false, false)
        .await
}

async fn spawn_buffered_h3_grpc_gateway(backend_port: u16) -> (GatewayHarness, u16) {
    spawn_h3_grpc_gateway_with_response_buffering(backend_port, &[], true, false, false).await
}

async fn spawn_buffered_h3_grpc_gateway_with_hostile_terminal_set(
    backend_port: u16,
) -> (GatewayHarness, u16) {
    spawn_h3_grpc_gateway_with_response_buffering(backend_port, &[], true, false, true).await
}

async fn spawn_buffered_h3_grpc_gateway_with_security_removals(
    backend_port: u16,
) -> (GatewayHarness, u16) {
    spawn_h3_grpc_gateway_with_response_buffering(backend_port, &[], true, true, false).await
}

async fn spawn_h3_grpc_gateway_with_response_buffering(
    backend_port: u16,
    extra_env: &[(&str, String)],
    buffer_response: bool,
    remove_buffered_trailer_fields: bool,
    override_existing_security_headers: bool,
) -> (GatewayHarness, u16) {
    // Outer retry (codex P3): `FERRUM_PROXY_HTTPS_PORT` is a fixed port we
    // reserve-then-drop before the subprocess binds it, so a parallel test can
    // steal it in the bind-drop-rebind window. Re-reserve a FRESH port (and fresh
    // certs) and re-spawn on failure rather than retrying the same stolen port —
    // per the testing.md "port allocation must retry" rule.
    let mut last_err = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());

        let mut builder = GatewayHarness::builder()
            .file_config(file_mode_yaml_with_response_buffering(
                backend_port,
                buffer_response,
                remove_buffered_trailer_fields,
                override_existing_security_headers,
            ))
            .log_level("info")
            .capture_output()
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            // gRPC always uses the cross-protocol bridge (never the native-H3 pool),
            // so the capability registry is irrelevant — skip the warmup probe.
            .env("FERRUM_POOL_WARMUP_ENABLED", "false");
        for (k, v) in extra_env {
            builder = builder.env(*k, v.clone());
        }
        match builder.spawn().await {
            Ok(harness) => {
                // Keep the cert files alive for the gateway's lifetime.
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    panic!("failed to spawn H3 gRPC gateway after retries: {last_err}");
}

/// Length-prefix a gRPC message (1-byte flag + 4-byte BE length + payload).
fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

/// Open an H3 gRPC stream, retrying the QUIC handshake briefly so the test does
/// not race the gateway's listener coming up.
async fn open_grpc_stream_with_retry(
    client: &Http3Client,
    url: &str,
) -> crate::scaffolding::clients::Http3GrpcStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match client.open_grpc_stream(url).await {
            Ok(stream) => return stream,
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    panic!("open_grpc_stream never succeeded: {e}");
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
}

// A route-resolved native-H3 gRPC method rejection must use the same
// initial-response policy as H1/H2 instead of rejecting before routing with an
// empty policy slice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_non_post_method_reject_applies_route_policy() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
    let response = client
        .get_with_options(
            &url,
            GetOptions::default().header("content-type", "application/grpc"),
        )
        .await
        .expect("non-POST gRPC request");

    assert_eq!(response.status, http::StatusCode::OK);
    assert!(response.body_bytes.is_empty());
    assert_eq!(
        response
            .headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("3")
    );
    assert_eq!(
        response
            .headers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Regression: unary H3 → H2 gRPC still succeeds through the streaming path,
//    including grpc-status / grpc-message trailers.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_streaming_unary_roundtrip() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-unary-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200, "gRPC rides on HTTP 200");
    assert_eq!(
        headers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
    assert_eq!(
        headers
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
    assert_eq!(
        body.as_ref(),
        grpc_frame(b"pong").as_slice(),
        "backend response message must reach the H3 client intact"
    );
    assert_eq!(
        trailers.get("grpc-status").map(|v| v.to_str().unwrap()),
        Some("0"),
        "grpc-status trailer must be preserved through the streaming bridge"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_streaming_forwards_sanitized_request_trailers() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-request-trailers-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Trailers");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    let mut request_trailers = http::HeaderMap::new();
    request_trailers.insert(
        "x-request-checksum",
        http::HeaderValue::from_static("sha256:test"),
    );
    // Request trailers cross the initial-header boundary later; the bridge must
    // not let them reintroduce a client-forged gateway assertion.
    request_trailers.insert(
        "x-consumer-username",
        http::HeaderValue::from_static("forged"),
    );
    request_trailers.insert("x-geo-country", http::HeaderValue::from_static("XX"));
    request_trailers.insert(
        "x-forwarded-for",
        http::HeaderValue::from_static("203.0.113.44"),
    );
    request_trailers.insert(
        "forwarded",
        http::HeaderValue::from_static("for=203.0.113.45;proto=http"),
    );
    request_trailers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer forged-late-token"),
    );
    request_trailers.insert("via", http::HeaderValue::from_static("attacker-proxy"));
    request_trailers.insert("early-data", http::HeaderValue::from_static("1"));
    stream
        .send_request_trailers(request_trailers)
        .await
        .expect("send request trailers");
    stream.finish().await.expect("finish");

    let (status, _) = stream.recv_response().await.expect("recv response");
    let (_, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );

    let received = backend.received_streams().await;
    let request = received.first().expect("backend request");
    assert_eq!(
        request
            .trailers
            .iter()
            .find(|(name, _)| name == "x-request-checksum")
            .map(|(_, value)| value.as_str()),
        Some("sha256:test"),
        "application request trailers must survive H3-to-H2 translation"
    );
    assert!(
        request.trailers.iter().all(|(name, _)| !matches!(
            name.as_str(),
            "x-consumer-username"
                | "x-geo-country"
                | "x-forwarded-for"
                | "forwarded"
                | "via"
                | "early-data"
                | "authorization"
        )),
        "client request trailers must not restate credentials or forge gateway identity"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_buffered_grpc_security_policy_preserves_initial_and_trailer_provenance() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-buffered-policy-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from(grpc_frame(b"buffered-reply")),
            end_stream: false,
        })
        .step(H2Step::RespondTrailers(vec![
            ("grpc-status", "0".into()),
            ("grpc-message", "OK".into()),
            ("x-security-policy", "backend-trailer-value".into()),
            ("x-application-trailer", "application-value".into()),
        ]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_buffered_h3_grpc_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200);
    assert_eq!(body.as_ref(), grpc_frame(b"buffered-reply").as_slice());
    assert_eq!(
        headers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
    assert_eq!(
        headers
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
    assert!(headers.get("grpc-status").is_none());
    assert!(headers.get("grpc-message").is_none());
    assert!(headers.get("x-application-trailer").is_none());
    assert_eq!(
        trailers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("backend-trailer-value")
    );
    assert_eq!(
        trailers
            .get("x-application-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("application-value")
    );
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        trailers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("OK")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_buffered_grpc_security_removal_wins_over_cookie_rehome_and_trailer_replay() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-buffered-removal-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
            ("x-powered-by", "backend-header".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from(grpc_frame(b"buffered-removal-reply")),
            end_stream: false,
        })
        .step(H2Step::RespondTrailers(vec![
            ("grpc-status", "0".into()),
            ("grpc-message", "OK".into()),
            ("set-cookie", "session=backend".into()),
            ("x-powered-by", "backend-trailer".into()),
        ]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) =
        spawn_buffered_h3_grpc_gateway_with_security_removals(backend_port).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        body.as_ref(),
        grpc_frame(b"buffered-removal-reply").as_slice()
    );
    assert!(
        headers.get("set-cookie").is_none(),
        "final H3 security policy must suppress the transformed trailer cookie after rehoming"
    );
    assert!(
        headers.get("x-powered-by").is_none(),
        "final H3 security policy must suppress the shadowed initial header"
    );
    assert!(
        trailers.get("set-cookie").is_none(),
        "final H3 security policy must suppress the transformed application trailer"
    );
    assert!(
        trailers.get("x-powered-by").is_none(),
        "final H3 security policy must not restore removed shadowed metadata"
    );
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0"),
        "terminal status must remain on the H3 trailer channel"
    );
    assert_eq!(
        trailers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("OK")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_buffered_grpc_empty_split_response_keeps_terminal_metadata_in_trailers() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-empty-split-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondTrailers(vec![
            ("grpc-status", "0".into()),
            ("grpc-message", "OK".into()),
            ("x-application-trailer", "application-value".into()),
        ]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_buffered_h3_grpc_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200);
    assert!(body.is_empty());
    assert!(headers.get("grpc-status").is_none());
    assert!(headers.get("grpc-message").is_none());
    assert!(headers.get("x-application-trailer").is_none());
    assert_eq!(
        headers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        trailers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("OK")
    );
    assert_eq!(
        trailers
            .get("x-application-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("application-value")
    );
}

async fn assert_h3_buffered_grpc_trailers_only_preserves_initial_terminal_status(
    remove_terminal_metadata: bool,
) {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-trailers-only-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeadersEndStream(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
            ("grpc-status", "7".into()),
            ("grpc-message", "permission denied".into()),
        ]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = if remove_terminal_metadata {
        spawn_buffered_h3_grpc_gateway_with_security_removals(backend_port).await
    } else {
        spawn_buffered_h3_grpc_gateway_with_hostile_terminal_set(backend_port).await
    };
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200);
    assert!(body.is_empty());
    assert!(trailers.is_empty());
    assert_eq!(
        headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("7")
    );
    assert_eq!(
        headers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("permission denied")
    );
    assert_eq!(
        headers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_buffered_grpc_trailers_only_resists_hostile_terminal_set() {
    assert_h3_buffered_grpc_trailers_only_preserves_initial_terminal_status(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_buffered_grpc_trailers_only_resists_terminal_removal() {
    assert_h3_buffered_grpc_trailers_only_preserves_initial_terminal_status(true).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 2. THE KILLER TEST — bidi: the backend observes request DATA and responds
//    BEFORE the H3 client half-closes. With the old buffered path the gateway
//    waited for the client's END_STREAM before dialing the backend, so this
//    deadlocked (recv_response timed out). The streaming path forwards the
//    first DATA frame immediately, so the response arrives while the request
//    stream is still open.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_streaming_server_responds_before_client_half_close() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-bidi-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    // Raw H2 script: consume one DATA frame and respond without waiting for
    // request EOF — i.e. before the client half-closes.
    let _backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::ReadRequestData)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from(grpc_frame(b"early-reply")),
            end_stream: false,
        })
        .step(H2Step::RespondTrailers(vec![("grpc-status", "0".into())]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Bidi");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;

    // Send the first request message but DO NOT finish — leave the request
    // stream open, exactly like a bidi client awaiting the server's reply.
    stream.send_message(b"hello").await.expect("send message");

    // The whole exchange must complete well within the test budget; on the old
    // buffered path this block hangs until the per-call timeout fires.
    let (status, body, trailers) = tokio::time::timeout(Duration::from_secs(10), async {
        let (status, _headers) = stream.recv_response().await.expect("recv response");
        let (body, trailers) = stream
            .recv_body_and_trailers()
            .await
            .expect("recv body+trailers");
        (status, body, trailers)
    })
    .await
    .expect("backend must respond BEFORE the client half-closes (streaming bridge)");

    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        body.as_ref(),
        grpc_frame(b"early-reply").as_slice(),
        "server-streamed message must reach the client before half-close"
    );
    assert_eq!(
        trailers.get("grpc-status").map(|v| v.to_str().unwrap()),
        Some("0"),
    );

    // The proof above is decisive: the full response (headers + message +
    // grpc-status trailer) arrived while the request stream was still open, which
    // is impossible on the old buffered path. The client now half-closes
    // best-effort — once the RPC completes the gateway STOP_SENDINGs the request
    // upload (the RPC is over; no more request DATA is wanted), so a late
    // `finish()` may legitimately observe the already-closed stream.
    let _ = stream.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_backend_error_arrives_before_client_half_close() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-early-error-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::ReadRequestData)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondTrailers(vec![
            ("grpc-status", "13".into()),
            ("grpc-message", "rejected early".into()),
        ]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/BidiError");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"first").await.expect("send message");

    let (status, _) = stream.recv_response().await.expect("recv response");
    let (_, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers before request EOF");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("13")
    );
    assert_eq!(
        trailers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("rejected early")
    );
    assert!(
        backend
            .received_streams()
            .await
            .first()
            .is_some_and(|request| !request.body.is_empty()),
        "backend error must follow observed request DATA, not just request headers"
    );
    let _ = stream.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_large_slow_upload_reaches_backend_before_eof() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-slow-large-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::ReadRequestData)
        .step(H2Step::AwaitTestSignal)
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondTrailers(vec![("grpc-status", "0".into())]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/ClientStream");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    let payload = vec![b'x'; 32 * 1024];
    stream
        .send_message(&payload)
        .await
        .expect("send first message");

    tokio::time::timeout(Duration::from_secs(10), async {
        while backend.awaiting_test_signal() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("backend must observe request DATA before downstream EOF");
    let observed_before_eof = backend.received_streams().await;
    assert!(
        observed_before_eof
            .first()
            .is_some_and(|request| !request.body.is_empty()),
        "backend must record DATA while the H3 upload remains open"
    );
    backend.release_test_signal();

    // Continue as a slow client-streaming upload after proving the first DATA
    // reached the backend. The aggregate is about 1 MiB and remains bounded by
    // QUIC/H2 flow control plus the bridge channel rather than one retained body.
    for _ in 1..32 {
        stream.send_message(&payload).await.expect("send message");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    stream.finish().await.expect("finish upload");
    let (status, _) = stream.recv_response().await.expect("recv response");
    let (_, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );

    let received = backend.received_streams().await;
    let expected_bytes = 32 * (payload.len() + 5);
    assert_eq!(
        received.first().expect("backend request").body.len(),
        expected_bytes
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_client_upload_cancellation_resets_backend_stream() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-cancel-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::ReadRequestData)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::ExpectReset(Duration::from_secs(10)))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Cancel");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"partial").await.expect("send message");

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if backend
                .received_streams()
                .await
                .first()
                .is_some_and(|request| !request.body.is_empty())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("backend must observe DATA before client cancellation");
    stream.cancel_request_upload();

    tokio::time::timeout(Duration::from_secs(10), async {
        while backend.stream_reset_count() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client upload cancellation must reset the H2 backend stream");
    backend.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_response_cancellation_resets_open_backend_upload() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-response-cancel-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::ReadRequestData)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::AwaitTestSignal)
        .step(H2Step::RespondData {
            data: Bytes::from(grpc_frame(b"response-after-cancel")),
            end_stream: false,
        })
        .step(H2Step::ExpectReset(Duration::from_secs(10)))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/CancelResponse");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"partial").await.expect("send message");

    let (status, _) = stream.recv_response().await.expect("recv response");
    assert_eq!(status.as_u16(), 200);
    stream.cancel_response_download();
    backend.release_test_signal();

    tokio::time::timeout(Duration::from_secs(10), async {
        while backend.stream_reset_count() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("response cancellation must reset the still-open H2 request upload");
    backend.assert_no_step_errors().await;
}

// ────────────────────────────────────────────────────────────────────────────
// 3. The max gRPC request size is enforced INCREMENTALLY while streaming (the
//    H3 client sends no Content-Length, so the size ceiling is checked frame by
//    frame in `GrpcBody::Channel`, not via the header fast path). An oversized
//    upload must surface as gRPC RESOURCE_EXHAUSTED (status 8), not a transport
//    error.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_streaming_enforces_max_request_size_incrementally() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-size-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    // The backend would happily reply, but the gateway must reject the oversized
    // upload mid-stream before the RPC can complete.
    let _backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"unexpected")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    // 32-byte gRPC recv ceiling; the framed message below is far larger.
    let (_harness, https_port) = spawn_h3_grpc_gateway(
        backend_port,
        &[("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", "32".into())],
    )
    .await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Big");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(&vec![b'x'; 4096]).await.expect("send");
    stream.finish().await.expect("finish");

    let (status, headers) = stream.recv_response().await.expect("recv response");
    // The gateway emits a trailers-only gRPC error: HTTP 200 + grpc-status in the
    // header block (8 = RESOURCE_EXHAUSTED). Drain any body to a clean close.
    let _ = stream.recv_body_and_trailers().await;
    assert_eq!(status.as_u16(), 200, "gRPC errors ride on HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|v| v.to_str().unwrap()),
        Some("8"),
        "oversized streaming upload must map to RESOURCE_EXHAUSTED (8)"
    );
    assert_eq!(
        headers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced"),
        "synthesized H3 gRPC errors must carry initial-response policy"
    );
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
}
