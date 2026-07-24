//! Issue #2472: native gRPC `request_mirror` shadows must use HTTP/2.
//!
//! Cleartext mirrors speak h2c prior knowledge; TLS mirrors negotiate ALPN h2.
//! Both paths must carry synthesised `te: trailers` after the canonical
//! secondary-request header strip.
//!
//! ## Acceptance matrix mapping (issue #2472)
//!
//! Live functional coverage in this file:
//! - Unary h2c / TLS+h2 TE + transport handshake
//! - TLS native-gRPC transport rejects an HTTP/1.1-only ALPN endpoint
//! - Client-streaming multi-frame ingress shape (h2c + TLS+h2), with exact
//!   mirrored-byte preservation covered by the h2c plugin network unit test
//! - Server-streaming and bidirectional method/path shapes (h2c + TLS+h2)
//! - Missing client `te` and client-supplied `te: trailers` (h2c).
//!   Non-canonical client `te` (e.g. `gzip`) → re-synthesis is covered by
//!   `test_mirror_h2_h3_parity_and_grpc_te_resynthesis` (unit; live H2
//!   admission rejects non-trailers TE before the mirror runs).
//! - Mirror response error status isolation from the primary RPC
//! - HTTP/2 connection reuse across sequential mirrored RPCs (where the
//!   shared plugin HTTP/2 pool reuses the companion connection)
//!
//! Covered by existing unit / lifecycle tests (not duplicated here):
//! - Ordinary HTTP/1.1 mirror retention:
//!   `tests/unit/plugins/request_mirror_tests.rs::test_ordinary_http_mirror_still_uses_http1`
//! - Mirror timeout / cancellation / max_in_flight drop metadata:
//!   `backend_read_timeout_emits_explicit_mirror_error`,
//!   `closed_task_channel_returns_seeded_failure_result`,
//!   `max_in_flight_drop_emits_explicit_mirror_result`
//! - Plugin HTTP/2 companion prior knowledge:
//!   `tests/unit/plugins/plugin_http_client_tests.rs::get_http2_companion_speaks_h2c_prior_knowledge`
//!
//! Run with:
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests request_mirror_grpc_transport \
//!     -- --ignored --nocapture
//! ```

use std::time::Duration;

use crate::scaffolding::backends::{
    GrpcStep, MatchRpc, ReceivedStream, ScriptedGrpcBackend, ScriptedTlsBackend, TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GrpcClient, GrpcResponse};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::{BufMut, Bytes, BytesMut};
use h2::client as h2_client;
use http::Request;
use serde_json::json;
use tokio::net::TcpStream;

const UNARY_PATH: &str = "/helloworld.Greeter/SayHello";
const CLIENT_STREAM_PATH: &str = "/helloworld.Greeter/RecordRoute";
const SERVER_STREAM_PATH: &str = "/helloworld.Greeter/ListFeatures";
const BIDI_PATH: &str = "/helloworld.Greeter/RouteChat";
const UNARY_BODY: &[u8] = b"mirror-unary";

fn grpc_mirror_yaml(
    primary_port: u16,
    mirror_port: u16,
    mirror_protocol: &str,
    mirror_request_body: bool,
    backend_read_timeout_ms: u64,
) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-mirror-transport",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": primary_port,
            "strip_listen_path": false,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": backend_read_timeout_ms,
            "backend_write_timeout_ms": 5000,
            "plugins": [{ "plugin_config_id": "request-mirror" }],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "request-mirror",
            "plugin_name": "request_mirror",
            "scope": "proxy",
            "proxy_id": "grpc-mirror-transport",
            "enabled": true,
            "config": {
                "mirror_host": "127.0.0.1",
                "mirror_port": mirror_port,
                "mirror_protocol": mirror_protocol,
                "percentage": 100.0,
                // Isolate #2472 outbound transport from shared #2190 prebuffer
                // primary-dispatch concerns when the body is not required.
                "mirror_request_body": mirror_request_body,
            },
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn gateway_http_port(harness: &GatewayHarness) -> u16 {
    harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .expect("gateway http port")
}

fn unary_ok_script() -> Vec<GrpcStep> {
    vec![
        GrpcStep::AcceptRpc(MatchRpc::method(UNARY_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"ok")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
    ]
}

fn encode_grpc_frames(messages: &[&[u8]]) -> Bytes {
    let mut buf = BytesMut::new();
    for message in messages {
        buf.put_u8(0);
        buf.put_u32(message.len() as u32);
        buf.extend_from_slice(message);
    }
    buf.freeze()
}

async fn wait_for_mirror_streams(
    mirror: &ScriptedGrpcBackend,
    count: usize,
) -> Vec<ReceivedStream> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let streams = mirror.received_streams().await;
            if streams.len() >= count {
                return streams;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {count} gRPC mirror request(s); saw {}",
            mirror.received_stream_count()
        )
    })
}

fn assert_mirror_grpc_headers(observed: &ReceivedStream, expected_path: &str) {
    assert_eq!(observed.path, expected_path);
    assert_eq!(
        observed.header("content-type"),
        Some("application/grpc"),
        "headers={:?}",
        observed.headers
    );
    assert_eq!(
        observed.header("te"),
        Some("trailers"),
        "gRPC mirror must carry te: trailers; headers={:?}",
        observed.headers
    );
}

/// Speak h2c gRPC to the gateway with explicit control over default `te`.
///
/// Unlike [`GrpcClient::unary`], this can omit `te` or send multiple length-
/// prefixed frames in one DATA write (client-streaming body shape).
async fn h2c_grpc_request(
    target: &str,
    path: &str,
    body: Bytes,
    extra_headers: &[(&str, &str)],
    include_default_te: bool,
) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("bad target {target}"))?;
    let port: u16 = port_str.parse()?;
    let tcp = TcpStream::connect((host, port)).await?;
    let (mut send_req, connection) = h2_client::handshake(tcp).await?;
    let conn_task = tokio::spawn(connection);

    let mut req_builder = Request::builder()
        .method("POST")
        .uri(format!("http://{host}:{port}{path}"))
        .header("content-type", "application/grpc");
    if include_default_te {
        req_builder = req_builder.header("te", "trailers");
    }
    for (name, value) in extra_headers {
        req_builder = req_builder.header(*name, *value);
    }
    let request = req_builder.body(())?;
    let (response_fut, mut req_body) = send_req.send_request(request, false)?;
    let _ = req_body.send_data(body, true);

    let response = tokio::time::timeout(Duration::from_secs(20), response_fut).await??;
    let http_status = response.status().as_u16();
    let headers = response.headers().clone();
    let (_parts, mut body_stream) = response.into_parts();

    let mut raw_frames = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let bytes = chunk?;
        let _ = body_stream.flow_control().release_capacity(bytes.len());
        raw_frames.push(bytes);
    }
    let trailers = body_stream.trailers().await?;
    conn_task.abort();

    let mut messages = Vec::new();
    let mut joined = BytesMut::new();
    for frame in &raw_frames {
        joined.extend_from_slice(frame);
    }
    let joined = joined.freeze();
    let mut i = 0;
    while i + 5 <= joined.len() {
        let len = u32::from_be_bytes([joined[i + 1], joined[i + 2], joined[i + 3], joined[i + 4]])
            as usize;
        if i + 5 + len > joined.len() {
            break;
        }
        messages.push(joined.slice(i + 5..i + 5 + len));
        i += 5 + len;
    }

    Ok(GrpcResponse {
        http_status,
        headers,
        messages,
        raw_body_frames: raw_frames,
        trailers,
        stream_error: None,
        request_send_error: None,
    })
}

async fn spawn_plain_backend(steps: Vec<GrpcStep>) -> (u16, ScriptedGrpcBackend) {
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .steps(steps)
        .spawn()
        .expect("spawn plain grpc backend");
    (port, backend)
}

fn concatenate_grpc_scripts(scripts: Vec<Vec<GrpcStep>>) -> Vec<GrpcStep> {
    scripts.into_iter().flatten().collect()
}

async fn spawn_tls_backend(steps: Vec<GrpcStep>) -> (u16, ScriptedGrpcBackend, TestCa) {
    let ca = TestCa::new("request-mirror-grpc-tls").expect("ca");
    let (cert_pem, key_pem) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;
    let backend =
        ScriptedGrpcBackend::builder_tls(reservation.into_listener(), &cert_pem, &key_pem)
            .expect("tls builder")
            .steps(steps)
            .spawn()
            .expect("spawn tls grpc backend");
    (port, backend, ca)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_h2c_prior_knowledge_carries_te_trailers() {
    let (primary_port, _primary) = spawn_plain_backend(unary_ok_script()).await;
    let (mirror_port, mirror) = spawn_plain_backend(unary_ok_script()).await;

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "http",
            /* mirror_request_body */ false,
            5000,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(UNARY_PATH, Bytes::from_static(UNARY_BODY))
        .await
        .expect("unary rpc");
    assert_eq!(response.grpc_status(), Some(0), "response={response:?}");

    let observed = wait_for_mirror_streams(&mirror, 1).await;
    assert_mirror_grpc_headers(&observed[0], UNARY_PATH);
    assert!(
        mirror.handshakes_completed() >= 1,
        "mirror must complete an h2c handshake"
    );
    mirror.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_tls_alpn_h2_carries_te_trailers() {
    let (primary_port, _primary) = spawn_plain_backend(unary_ok_script()).await;
    let (mirror_port, mirror, _ca) = spawn_tls_backend(unary_ok_script()).await;

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "https",
            /* mirror_request_body */ false,
            5000,
        ))
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(UNARY_PATH, Bytes::from_static(UNARY_BODY))
        .await
        .expect("unary rpc");
    assert_eq!(response.grpc_status(), Some(0), "response={response:?}");

    let observed = wait_for_mirror_streams(&mirror, 1).await;
    assert_mirror_grpc_headers(&observed[0], UNARY_PATH);
    assert!(
        mirror.handshakes_completed() >= 1,
        "mirror must complete an ALPN h2 handshake"
    );
    mirror.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_tls_rejects_http1_only_alpn() {
    let (primary_port, _primary) = spawn_plain_backend(unary_ok_script()).await;
    let ca = TestCa::new("request-mirror-grpc-http1-only").expect("ca");
    let (cert_pem, key_pem) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("port");
    let mirror_port = reservation.port;
    // This endpoint is a valid TLS HTTP/1.1 mirror sink. The default
    // all-version plugin client would negotiate HTTP/1.1 and send the request,
    // while the native-gRPC companion offers only ALPN h2 and must fail the TLS
    // handshake before any HTTP/1.1 bytes are written.
    let mirror = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn HTTP/1.1-only TLS mirror");

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "https",
            /* mirror_request_body */ false,
            5000,
        ))
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(UNARY_PATH, Bytes::from_static(UNARY_BODY))
        .await
        .expect("primary unary rpc");
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "mirror transport failure must not affect the primary response: {response:?}"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let errors = loop {
        let errors = mirror.step_errors().await;
        if !errors.is_empty() || tokio::time::Instant::now() >= deadline {
            break errors;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(
        mirror.accepted_connections() >= 1,
        "native gRPC mirror must attempt the configured TLS destination"
    );
    assert_eq!(
        mirror.handshakes_completed(),
        0,
        "HTTP/2 companion must not negotiate the HTTP/1.1-only ALPN endpoint"
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("TLS handshake failed")),
        "expected an ALPN-mismatch TLS failure, got {errors:?}"
    );
    assert!(
        mirror.received_bytes().await.is_empty(),
        "native gRPC mirror must not fall back to an HTTP/1.1 request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_h2c_streaming_shapes_and_multiframe_body() {
    // Client-streaming exercises a multi-frame ingress request. Exact mirrored
    // byte preservation is covered by the focused h2c plugin network unit test.
    // Server-streaming and bidi use headers-only mirrors so the half-open bidi
    // request remains outside shared prebuffer issue #2190.
    let primary_scripts = vec![
        vec![
            GrpcStep::AcceptRpc(MatchRpc::method(CLIENT_STREAM_PATH)),
            GrpcStep::SendInitialHeaders,
            GrpcStep::RespondMessage(Bytes::from_static(b"primary-client-stream-ok")),
            GrpcStep::RespondStatus {
                code: 0,
                message: "",
            },
        ],
        vec![
            GrpcStep::AcceptRpc(MatchRpc::method(SERVER_STREAM_PATH)),
            GrpcStep::SendInitialHeaders,
            GrpcStep::RespondMessage(Bytes::from_static(b"feature-1")),
            GrpcStep::RespondMessage(Bytes::from_static(b"feature-2")),
            GrpcStep::RespondStatus {
                code: 0,
                message: "",
            },
        ],
        vec![
            GrpcStep::AcceptStreamingRpc(MatchRpc::method(BIDI_PATH)),
            GrpcStep::SendInitialHeaders,
            GrpcStep::RespondMessage(Bytes::from_static(b"bidi-note")),
            GrpcStep::RespondStatus {
                code: 0,
                message: "",
            },
        ],
    ];
    let mirror_steps = vec![
        GrpcStep::AcceptRpc(MatchRpc::method(CLIENT_STREAM_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-client-stream-ok")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
        GrpcStep::AcceptRpc(MatchRpc::method(SERVER_STREAM_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-feature")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
        GrpcStep::AcceptRpc(MatchRpc::method(BIDI_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-bidi")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
    ];

    // Ferrum's primary gRPC pool reuses one HTTP/2 connection across these
    // sequential RPCs, so the fixture must expose one sequential stream script.
    let (primary_port, _primary) =
        spawn_plain_backend(concatenate_grpc_scripts(primary_scripts)).await;
    let (mirror_port, mirror) = spawn_plain_backend(mirror_steps).await;

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "http",
            /* mirror_request_body */ false,
            5000,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let gw = format!("127.0.0.1:{}", gateway_http_port(&harness));
    let client = GrpcClient::h2c(gw.clone());
    let multi_frame = encode_grpc_frames(&[b"point-a", b"point-b", b"point-c"]);

    let client_stream = h2c_grpc_request(&gw, CLIENT_STREAM_PATH, multi_frame.clone(), &[], true)
        .await
        .expect("client-stream rpc");
    assert_eq!(
        client_stream.grpc_status(),
        Some(0),
        "response={client_stream:?}"
    );

    let server_stream = client
        .unary(SERVER_STREAM_PATH, Bytes::from_static(b"bbox"))
        .await
        .expect("server-stream rpc");
    assert_eq!(
        server_stream.grpc_status(),
        Some(0),
        "response={server_stream:?}"
    );
    assert!(
        server_stream.messages.len() >= 2,
        "primary server-stream must deliver multiple messages: {server_stream:?}"
    );

    let bidi = client
        .bidi_with_headers(BIDI_PATH, Bytes::from_static(b"note-1"), &[])
        .await
        .expect("bidi rpc");
    assert_eq!(bidi.grpc_status(), Some(0), "response={bidi:?}");

    let observed = wait_for_mirror_streams(&mirror, 3).await;
    assert_mirror_grpc_headers(&observed[0], CLIENT_STREAM_PATH);
    assert!(observed[0].body.is_empty());
    assert_mirror_grpc_headers(&observed[1], SERVER_STREAM_PATH);
    assert_mirror_grpc_headers(&observed[2], BIDI_PATH);
    assert!(
        mirror.handshakes_completed() >= 1,
        "streaming-shape mirrors must complete an h2c handshake"
    );
    // Sequential mirrors against one companion client should reuse the HTTP/2
    // connection when the pool keeps it warm.
    assert!(
        mirror.handshakes_completed() <= mirror.received_stream_count(),
        "handshakes={} streams={}",
        mirror.handshakes_completed(),
        mirror.received_stream_count()
    );
    mirror.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_tls_streaming_shapes_and_multiframe_body() {
    let primary_scripts = vec![
        vec![
            GrpcStep::AcceptRpc(MatchRpc::method(CLIENT_STREAM_PATH)),
            GrpcStep::SendInitialHeaders,
            GrpcStep::RespondMessage(Bytes::from_static(b"primary-client-stream-ok")),
            GrpcStep::RespondStatus {
                code: 0,
                message: "",
            },
        ],
        vec![
            GrpcStep::AcceptRpc(MatchRpc::method(SERVER_STREAM_PATH)),
            GrpcStep::SendInitialHeaders,
            GrpcStep::RespondMessage(Bytes::from_static(b"feature-1")),
            GrpcStep::RespondMessage(Bytes::from_static(b"feature-2")),
            GrpcStep::RespondStatus {
                code: 0,
                message: "",
            },
        ],
        vec![
            GrpcStep::AcceptStreamingRpc(MatchRpc::method(BIDI_PATH)),
            GrpcStep::SendInitialHeaders,
            GrpcStep::RespondMessage(Bytes::from_static(b"bidi-note")),
            GrpcStep::RespondStatus {
                code: 0,
                message: "",
            },
        ],
    ];
    let mirror_steps = vec![
        GrpcStep::AcceptRpc(MatchRpc::method(CLIENT_STREAM_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-client-stream-ok")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
        GrpcStep::AcceptRpc(MatchRpc::method(SERVER_STREAM_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-feature")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
        GrpcStep::AcceptRpc(MatchRpc::method(BIDI_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-bidi")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
    ];

    // Ferrum's primary gRPC pool reuses one HTTP/2 connection across these
    // sequential RPCs, so the fixture must expose one sequential stream script.
    let (primary_port, _primary) =
        spawn_plain_backend(concatenate_grpc_scripts(primary_scripts)).await;
    let (mirror_port, mirror, _ca) = spawn_tls_backend(mirror_steps).await;

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "https",
            /* mirror_request_body */ false,
            5000,
        ))
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let gw = format!("127.0.0.1:{}", gateway_http_port(&harness));
    let client = GrpcClient::h2c(gw.clone());
    let multi_frame = encode_grpc_frames(&[b"tls-a", b"tls-b"]);

    let client_stream = h2c_grpc_request(&gw, CLIENT_STREAM_PATH, multi_frame.clone(), &[], true)
        .await
        .expect("tls client-stream rpc");
    assert_eq!(
        client_stream.grpc_status(),
        Some(0),
        "response={client_stream:?}"
    );

    let server_stream = client
        .unary(SERVER_STREAM_PATH, Bytes::from_static(b"bbox"))
        .await
        .expect("tls server-stream rpc");
    assert_eq!(
        server_stream.grpc_status(),
        Some(0),
        "response={server_stream:?}"
    );

    let bidi = client
        .bidi_with_headers(BIDI_PATH, Bytes::from_static(b"note-1"), &[])
        .await
        .expect("tls bidi rpc");
    assert_eq!(bidi.grpc_status(), Some(0), "response={bidi:?}");

    let observed = wait_for_mirror_streams(&mirror, 3).await;
    assert_mirror_grpc_headers(&observed[0], CLIENT_STREAM_PATH);
    assert!(observed[0].body.is_empty());
    assert_mirror_grpc_headers(&observed[1], SERVER_STREAM_PATH);
    assert_mirror_grpc_headers(&observed[2], BIDI_PATH);
    assert!(
        mirror.handshakes_completed() >= 1,
        "TLS streaming-shape mirrors must complete an ALPN h2 handshake"
    );
    mirror.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_h2c_missing_and_client_supplied_te() {
    let (primary_port, _primary) = spawn_plain_backend(concatenate_grpc_scripts(vec![
        unary_ok_script(),
        unary_ok_script(),
    ]))
    .await;
    let (mirror_port, mirror) = spawn_plain_backend(vec![
        GrpcStep::AcceptRpc(MatchRpc::any()),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-ok")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
        GrpcStep::AcceptRpc(MatchRpc::any()),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-ok")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
    ])
    .await;

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "http",
            /* mirror_request_body */ false,
            5000,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let gw = format!("127.0.0.1:{}", gateway_http_port(&harness));
    let body = encode_grpc_frames(&[b"te-case"]);

    let missing_te = h2c_grpc_request(
        &gw,
        UNARY_PATH,
        body.clone(),
        &[],
        /* include_default_te */ false,
    )
    .await
    .expect("missing-te rpc");
    assert_eq!(missing_te.grpc_status(), Some(0), "response={missing_te:?}");

    // Client-supplied canonical TE still survives the strip/re-synthesis path.
    // Non-canonical TE (`gzip`, etc.) is rejected by live H2 admission; the
    // unit suite covers that strip → `te: trailers` re-synthesis directly.
    let client_te = h2c_grpc_request(
        &gw,
        UNARY_PATH,
        body,
        &[("te", "trailers")],
        /* include_default_te */ false,
    )
    .await
    .expect("client-te rpc");
    assert_eq!(client_te.grpc_status(), Some(0), "response={client_te:?}");

    let observed = wait_for_mirror_streams(&mirror, 2).await;
    for stream in &observed {
        assert_eq!(
            stream.header("te"),
            Some("trailers"),
            "mirror must synthesise te: trailers whether the client omitted te or supplied it; headers={:?}",
            stream.headers
        );
    }
    mirror.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_h2c_mirror_error_status_does_not_affect_primary() {
    let (primary_port, _primary) = spawn_plain_backend(unary_ok_script()).await;
    let (mirror_port, mirror) = spawn_plain_backend(vec![
        GrpcStep::AcceptRpc(MatchRpc::method(UNARY_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondStatus {
            code: 14, // UNAVAILABLE
            message: "shadow-down",
        },
    ])
    .await;

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "http",
            /* mirror_request_body */ false,
            5000,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(UNARY_PATH, Bytes::from_static(UNARY_BODY))
        .await
        .expect("unary rpc");
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "primary must stay healthy when the fire-and-forget mirror returns a gRPC error: {response:?}"
    );

    let observed = wait_for_mirror_streams(&mirror, 1).await;
    assert_mirror_grpc_headers(&observed[0], UNARY_PATH);
    mirror.assert_no_step_errors().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_grpc_h2c_reuses_http2_connection_across_mirrors() {
    let (primary_port, _primary) = spawn_plain_backend(concatenate_grpc_scripts(vec![
        unary_ok_script(),
        unary_ok_script(),
    ]))
    .await;
    let (mirror_port, mirror) = spawn_plain_backend(vec![
        GrpcStep::AcceptRpc(MatchRpc::method(UNARY_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-1")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
        GrpcStep::AcceptRpc(MatchRpc::method(UNARY_PATH)),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"mirror-2")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
    ])
    .await;

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(grpc_mirror_yaml(
            primary_port,
            mirror_port,
            "http",
            /* mirror_request_body */ false,
            5000,
        ))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let first = client
        .unary(UNARY_PATH, Bytes::from_static(UNARY_BODY))
        .await
        .expect("first unary rpc");
    assert_eq!(first.grpc_status(), Some(0), "response={first:?}");
    let first_observed = wait_for_mirror_streams(&mirror, 1).await;
    assert_eq!(first_observed.len(), 1);

    let second = client
        .unary(UNARY_PATH, Bytes::from_static(UNARY_BODY))
        .await
        .expect("second unary rpc");
    assert_eq!(second.grpc_status(), Some(0), "response={second:?}");

    let observed = wait_for_mirror_streams(&mirror, 2).await;
    assert_eq!(observed.len(), 2);
    assert_eq!(
        mirror.handshakes_completed(),
        1,
        "two sequential fire-and-forget gRPC mirrors should reuse one h2c companion connection; accepted={} handshakes={} streams={}",
        mirror.accepted_connections(),
        mirror.handshakes_completed(),
        mirror.received_stream_count()
    );
    mirror.assert_no_step_errors().await;
}
