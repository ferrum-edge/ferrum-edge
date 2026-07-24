//! Issue #2532 — streamed terminal latency contract.
//!
//! Slow-backend and slow-client streaming responses must not report unknown
//! concurrent body/client lifetime as gateway processing or gateway overhead.
//! Coverage matrix (clean completion + client disconnect):
//! - HTTP/1.1 frontend
//! - HTTP/2 frontend (h2c prior knowledge)
//! - native HTTP/3 frontend (QUIC listener → `src/http3/server.rs`)
//! - streamed gRPC (h2c)
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_streaming_latency -- --ignored --nocapture

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    GrpcStep, HttpStep, MatchRpc, RequestMatcher, ScriptedGrpcBackend, ScriptedHttp1Backend,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, GrpcClient, Http2Client, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http::Request;
use reqwest::StatusCode;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BODY_DELAY: Duration = Duration::from_millis(400);
const STREAM_UNKNOWN: f64 = -1.0;
const H3_SLOW_CLIENT_STREAM_WINDOW_BYTES: u32 = 16 * 1024;
/// Slow-client body for H2/H3 frontends. Exceeds Ferrum's 256 KiB H2 stream
/// window (and the 16 KiB H3 test window) so withheld credit creates real
/// downstream backpressure. H1 needs a separate, larger payload because TCP
/// buffering — not stream windows — is the backpressure mechanism there.
const SLOW_CLIENT_PAYLOAD_BYTES: usize = 512 * 1024;
/// H1-only: must exceed hosted loopback/gateway TCP send buffering even with
/// a capped client SO_RCVBUF. 512 KiB was fully absorbed (~3 ms totals) in CI;
/// 16 MiB repeatedly truncated around ~7 MiB under the 60s backend timeouts
/// when post-stall SO_RCVBUF restore did not yield full loopback throughput.
const H1_SLOW_CLIENT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Bounded gRPC DATA frames that together exceed the 256 KiB H2 stream window
/// without one oversized message (which triggered internal stream errors).
const GRPC_SLOW_CLIENT_MESSAGE_BYTES: usize = 64 * 1024;
const GRPC_SLOW_CLIENT_MESSAGE_COUNT: usize = 8;

#[derive(Clone, Copy)]
enum Pace {
    SlowBackend,
    SlowClient,
}

#[derive(Clone, Copy)]
enum Outcome {
    Complete,
    Disconnect,
}

impl Pace {
    fn as_str(self) -> &'static str {
        match self {
            Pace::SlowBackend => "slow-backend",
            Pace::SlowClient => "slow-client",
        }
    }
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Complete => "complete",
            Outcome::Disconnect => "disconnect",
        }
    }

    fn expect_disconnect(self) -> bool {
        matches!(self, Outcome::Disconnect)
    }
}

fn scenario_marker(protocol: &str, pace: Pace, outcome: Outcome) -> String {
    format!("{protocol}-{}-{}", pace.as_str(), outcome.as_str())
}

fn scenario_path(protocol: &str, pace: Pace, outcome: Outcome) -> String {
    format!("/api/{}", scenario_marker(protocol, pace, outcome))
}

fn logging_proxy_config(
    backend_port: u16,
    proxy_id: &str,
    listen_path: &str,
    extra_proxy_fields: serde_json::Value,
) -> String {
    let mut proxy = json!({
        "id": proxy_id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        // Slow-client completion intentionally stalls then drains multi-MiB
        // bodies; keep these above the stall+drain window used by the fixtures.
        "backend_read_timeout_ms": 60000,
        "backend_write_timeout_ms": 60000,
        "response_body_mode": "stream",
    });
    if let Some(obj) = extra_proxy_fields.as_object() {
        for (k, v) in obj {
            proxy[k] = v.clone();
        }
    }
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "stream-latency-logger",
            "plugin_name": "stdout_logging",
            "scope": "global",
            "enabled": true,
            "config": {},
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn extract_f64_field(text: &str, field: &str) -> Option<f64> {
    for sep in ["\":", "\\\":"] {
        let needle = format!("{field}{sep}");
        if let Some(pos) = text.find(&needle) {
            let tail = text[pos + needle.len()..].trim_start();
            let end = tail
                .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e'))
                .unwrap_or(tail.len());
            if let Ok(v) = tail[..end].parse::<f64>() {
                return Some(v);
            }
        }
    }
    None
}

fn extract_bool_field(text: &str, field: &str) -> Option<bool> {
    for sep in ["\":", "\\\":"] {
        let needle = format!("{field}{sep}");
        if let Some(pos) = text.find(&needle) {
            let tail = text[pos + needle.len()..].trim_start();
            if tail.starts_with("true") {
                return Some(true);
            }
            if tail.starts_with("false") {
                return Some(false);
            }
        }
    }
    None
}

/// Select the intended transaction summary by unique path/proxy marker.
/// Do not take the first similarly-named field from unrelated probe/startup lines.
fn find_summary_for_marker<'a>(logs: &'a str, marker: &str) -> Option<&'a str> {
    for line in logs.lines() {
        // The scenario marker is unique in request_path / proxy_id; a bare
        // contains(marker) already selects the structured summary line.
        if line.contains(marker)
            && line.contains("latency_gateway_overhead_ms")
            && (line.contains("\"response_streamed\":true")
                || line.contains("\\\"response_streamed\\\":true")
                || line.contains("response_streamed\":true")
                || line.contains("response_streamed\\\":true"))
        {
            return Some(line);
        }
    }
    // Fallback: multi-line / concatenated capture without clean newlines.
    if let Some(pos) = logs.find(marker) {
        let mut window_start = pos.saturating_sub(200);
        while window_start > 0 && !logs.is_char_boundary(window_start) {
            window_start -= 1;
        }
        let window = &logs[window_start..];
        if window.contains("latency_gateway_overhead_ms") {
            return Some(window);
        }
    }
    None
}

fn assert_streamed_unknown_gateway_contract(
    scenario: &str,
    summary: &str,
    expect_disconnect: bool,
) {
    let streamed = extract_bool_field(summary, "response_streamed").unwrap_or(false);
    assert!(
        streamed,
        "{scenario}: expected response_streamed=true; summary:\n{summary}"
    );

    let backend_total = extract_f64_field(summary, "latency_backend_total_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_backend_total_ms missing"));
    let gateway_processing = extract_f64_field(summary, "latency_gateway_processing_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_gateway_processing_ms missing"));
    let gateway_overhead = extract_f64_field(summary, "latency_gateway_overhead_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_gateway_overhead_ms missing"));
    let total = extract_f64_field(summary, "latency_total_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_total_ms missing"));
    let ttfb = extract_f64_field(summary, "latency_backend_ttfb_ms")
        .unwrap_or_else(|| panic!("{scenario}: latency_backend_ttfb_ms missing"));

    assert_eq!(
        backend_total, STREAM_UNKNOWN,
        "{scenario}: streaming backend total must stay unknown; summary:\n{summary}"
    );
    assert_eq!(
        gateway_processing, STREAM_UNKNOWN,
        "{scenario}: gateway processing must not absorb streamed body lifetime; summary:\n{summary}"
    );
    assert_eq!(
        gateway_overhead, STREAM_UNKNOWN,
        "{scenario}: gateway overhead must not absorb streamed body lifetime; summary:\n{summary}"
    );
    assert!(
        total >= BODY_DELAY.as_secs_f64() * 1000.0 * 0.5,
        "{scenario}: total should reflect streamed lifetime (>= ~half the injected delay); total={total}; summary:\n{summary}"
    );
    assert!(
        ttfb >= 0.0 && ttfb < total,
        "{scenario}: TTFB should remain a first-byte observation below terminal total (ttfb={ttfb}, total={total}); summary:\n{summary}"
    );

    if expect_disconnect {
        assert_eq!(
            extract_bool_field(summary, "client_disconnected"),
            Some(true),
            "{scenario}: expected client_disconnected; summary:\n{summary}"
        );
    } else {
        assert_eq!(
            extract_bool_field(summary, "body_completed"),
            Some(true),
            "{scenario}: expected body_completed; summary:\n{summary}"
        );
    }
}

async fn wait_for_marked_summary(harness: &GatewayHarness, marker: &str) -> String {
    harness
        .wait_for_log_contains(
            &|logs: &str| find_summary_for_marker(logs, marker).is_some(),
            Duration::from_secs(12),
        )
        .await
}

fn large_payload(nbytes: usize) -> Vec<u8> {
    vec![b'x'; nbytes]
}

fn gateway_http_port(harness: &GatewayHarness) -> u16 {
    harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("gateway port")
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("stream-latency-h3-frontend").expect("ca");
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

async fn spawn_native_h3_logging_gateway(
    backend_port: u16,
    proxy_id: &str,
) -> (GatewayHarness, u16, tempfile::TempDir) {
    let mut last_err = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        let yaml = logging_proxy_config(backend_port, proxy_id, "/api", json!({}));

        match GatewayHarness::builder()
            .file_config(yaml)
            .log_level("info")
            .capture_output()
            .env("RUST_LOG", "info")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(harness) => {
                // Keep TempDir alive for the gateway lifetime; caller drops it
                // after the harness so cert files are cleaned up.
                return (harness, https_port, scratch);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    panic!("failed to spawn native H3 logging gateway after retries: {last_err}");
}

fn spawn_http1_scripted(
    listener: tokio::net::TcpListener,
    pace: Pace,
    outcome: Outcome,
    slow_client_payload_bytes: usize,
) -> ScriptedHttp1Backend {
    let mut builder = ScriptedHttp1Backend::builder(listener)
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Transfer-Encoding".into(),
            value: "chunked".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Type".into(),
            value: "application/octet-stream".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        });

    match pace {
        Pace::SlowBackend => {
            let stall = if outcome.expect_disconnect() {
                Duration::from_secs(5)
            } else {
                BODY_DELAY
            };
            builder = builder
                .step(HttpStep::RespondBodyChunk(b"5\r\nhello\r\n".to_vec()))
                .step(HttpStep::Sleep(stall))
                .step(HttpStep::RespondBodyChunk(b"5\r\nworld\r\n".to_vec()))
                .step(HttpStep::RespondBodyChunk(b"0\r\n\r\n".to_vec()))
                .step(HttpStep::RespondBodyEnd);
        }
        Pace::SlowClient => {
            // Emit many bounded chunks instead of one giant write_all. A single
            // multi-MiB write blocks the scripted backend for the whole pipe
            // fill and interacts badly with gateway read timeouts under an
            // 8 KiB client SO_RCVBUF; chunked writes resume cleanly once the
            // client drains after the intentional stall.
            const CHUNK_BYTES: usize = 256 * 1024;
            let body = large_payload(slow_client_payload_bytes);
            for chunk in body.chunks(CHUNK_BYTES) {
                let chunk_header = format!("{:x}\r\n", chunk.len());
                let mut framed = Vec::with_capacity(chunk_header.len() + chunk.len() + 2);
                framed.extend_from_slice(chunk_header.as_bytes());
                framed.extend_from_slice(chunk);
                framed.extend_from_slice(b"\r\n");
                builder = builder.step(HttpStep::RespondBodyChunk(framed));
            }
            builder = builder
                .step(HttpStep::RespondBodyChunk(b"0\r\n\r\n".to_vec()))
                .step(HttpStep::RespondBodyEnd);
        }
    }

    builder.spawn().expect("spawn http1 backend")
}

fn spawn_grpc_scripted(
    listener: tokio::net::TcpListener,
    pace: Pace,
    outcome: Outcome,
) -> ScriptedGrpcBackend {
    let mut builder = ScriptedGrpcBackend::builder_plain(listener)
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders);

    match pace {
        Pace::SlowBackend => {
            let stall = if outcome.expect_disconnect() {
                Duration::from_secs(5)
            } else {
                BODY_DELAY
            };
            builder = builder
                .step(GrpcStep::RespondMessage(Bytes::from_static(b"a")))
                .step(GrpcStep::Sleep(stall))
                .step(GrpcStep::RespondStatus {
                    code: 0,
                    message: "",
                });
        }
        Pace::SlowClient => {
            // Multiple bounded messages exhaust H2 flow-control credit; a
            // single oversized message previously failed completion drains
            // with "unexpected internal error encountered".
            //
            // Keep the scripted H2 connection driver alive across the client
            // stall: queueing DATA+trailers and returning lets run_h2_connection
            // Stop/abort the driver after 500ms while WINDOW_UPDATE is still
            // withheld, which surfaces as INTERNAL_ERROR on completion.
            let message = Bytes::from(large_payload(GRPC_SLOW_CLIENT_MESSAGE_BYTES));
            for _ in 0..GRPC_SLOW_CLIENT_MESSAGE_COUNT {
                builder = builder.step(GrpcStep::RespondMessage(message.clone()));
            }
            builder = builder
                .step(GrpcStep::Sleep(BODY_DELAY + Duration::from_millis(800)))
                .step(GrpcStep::RespondStatus {
                    code: 0,
                    message: "",
                });
        }
    }

    builder.spawn().expect("spawn grpc backend")
}

async fn h1_drive(harness: &GatewayHarness, path: &str, pace: Pace, outcome: Outcome) {
    let url = harness.proxy_url(path);
    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let client = harness.http_client().expect("client");
            let resp = client.get(&url).await.expect("response");
            assert_eq!(resp.status, StatusCode::OK);
            assert!(resp.body_text().contains("hello"));
            assert!(resp.body_text().contains("world"));
        }
        (Pace::SlowBackend, Outcome::Disconnect) => {
            // Read the first backend chunk, keep the stream open during the
            // backend stall, then disconnect mid-stream.
            h1_slow_client_raw(&url, Outcome::Disconnect).await;
        }
        (Pace::SlowClient, outcome) => {
            h1_slow_client_raw(&url, outcome).await;
        }
    }
}

async fn h1_slow_client_raw(url: &str, outcome: Outcome) {
    let parsed: http::Uri = url.parse().expect("url");
    let host = parsed.host().unwrap_or("127.0.0.1");
    let port = parsed.port_u16().expect("port");
    let path = parsed.path_and_query().map(|p| p.as_str()).unwrap_or("/");

    let mut stream = TcpStream::connect((host, port))
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    socket2::SockRef::from(&stream)
        .set_recv_buffer_size(8 * 1024)
        .expect("cap slow-client receive buffer");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write req");

    let mut buf = vec![0u8; 16 * 1024];
    let mut collected = Vec::new();
    // Read response headers + an initial body slice so the gateway has begun
    // streaming, then stop reading to create TCP backpressure.
    loop {
        let n = stream.read(&mut buf).await.expect("read");
        assert!(n > 0, "unexpected EOF before headers");
        collected.extend_from_slice(&buf[..n]);
        if collected.windows(4).any(|w| w == b"\r\n\r\n") && collected.len() > 64 {
            break;
        }
        assert!(
            collected.len() < H1_SLOW_CLIENT_PAYLOAD_BYTES,
            "headers never arrived"
        );
    }

    tokio::time::sleep(BODY_DELAY).await;

    match outcome {
        Outcome::Disconnect => {
            // Drop without draining — gateway should observe client disconnect.
            drop(stream);
        }
        Outcome::Complete => {
            // Restore a normal receive buffer before draining. Keeping the 8 KiB
            // SO_RCVBUF through the full multi-MiB body made hosted CI truncate
            // well short of completion under backend read/write timeouts.
            socket2::SockRef::from(&stream)
                .set_recv_buffer_size(1024 * 1024)
                .expect("restore slow-client receive buffer for drain");
            loop {
                let n = stream.read(&mut buf).await.expect("drain");
                if n == 0 {
                    break;
                }
                collected.extend_from_slice(&buf[..n]);
            }
            // Headers + chunk framing inflate wire size above the raw payload;
            // require a clear majority so partial timeout truncations fail.
            assert!(
                collected.len() > H1_SLOW_CLIENT_PAYLOAD_BYTES / 2,
                "expected large streamed body, got {} bytes",
                collected.len()
            );
        }
    }
}

async fn h2_drive(harness: &GatewayHarness, path: &str, pace: Pace, outcome: Outcome) {
    let port = gateway_http_port(harness);
    let url = format!("http://127.0.0.1:{port}{path}");
    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
            let resp = client.get(&url).await.expect("h2 response");
            assert_eq!(resp.status, StatusCode::OK);
        }
        (Pace::SlowBackend, Outcome::Disconnect) => {
            h2_live_stream(&url, /*slow_read=*/ false, Outcome::Disconnect).await;
        }
        (Pace::SlowClient, outcome) => {
            h2_live_stream(&url, /*slow_read=*/ true, outcome).await;
        }
    }
}

async fn h2_live_stream(url: &str, slow_read: bool, outcome: Outcome) {
    use h2::client as h2_client;

    let parsed: http::Uri = url.parse().expect("url");
    let host = parsed.host().unwrap_or("127.0.0.1").to_string();
    let port = parsed.port_u16().expect("port");
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .expect("connect h2c");
    let _ = stream.set_nodelay(true);
    let (mut send_req, connection) = h2_client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(connection);

    let request = Request::builder()
        .method("GET")
        .uri(url)
        .body(())
        .expect("build request");
    let (response_fut, _) = send_req.send_request(request, true).expect("send_request");
    let response = tokio::time::timeout(Duration::from_secs(20), response_fut)
        .await
        .expect("response timeout")
        .expect("response error");
    assert_eq!(response.status(), http::StatusCode::OK);
    let (_parts, mut body_stream) = response.into_parts();

    let first = tokio::time::timeout(Duration::from_secs(10), body_stream.data())
        .await
        .expect("first frame timeout")
        .expect("first frame missing")
        .expect("first frame error");
    if !slow_read {
        let _ = body_stream.flow_control().release_capacity(first.len());
    }

    // Slow-client cases withhold WINDOW_UPDATE so flow control creates real
    // backpressure; slow-backend disconnects stay attached during the
    // injected backend stall.
    tokio::time::sleep(BODY_DELAY).await;

    match outcome {
        Outcome::Disconnect => {
            drop(body_stream);
            drop(send_req);
            conn_task.abort();
        }
        Outcome::Complete => {
            if slow_read {
                let _ = body_stream.flow_control().release_capacity(first.len());
            }
            loop {
                match body_stream.data().await {
                    Some(Ok(chunk)) => {
                        let _ = body_stream.flow_control().release_capacity(chunk.len());
                    }
                    Some(Err(error)) => panic!("H2 completion stream failed: {error}"),
                    None => break,
                }
            }
            drop(send_req);
            conn_task.abort();
        }
    }
}

async fn h3_drive(https_port: u16, path: &str, pace: Pace, outcome: Outcome) {
    let client =
        Http3Client::insecure_with_stream_receive_window(H3_SLOW_CLIENT_STREAM_WINDOW_BYTES)
            .expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}{path}");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);

    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let resp = loop {
                match client.get(&url).await {
                    Ok(r) => break r,
                    Err(e) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "h3 get never succeeded: {e}"
                        );
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            };
            assert_eq!(resp.status, http::StatusCode::OK);
        }
        (Pace::SlowBackend, Outcome::Disconnect) | (Pace::SlowClient, _) => {
            let mut stream = loop {
                match client
                    .open_response_stream(&url, GetOptions::default())
                    .await
                {
                    Ok(s) => break s,
                    Err(e) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "open_response_stream never succeeded: {e}"
                        );
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            };
            let (status, _headers) = stream.recv_response().await.expect("recv response");
            assert_eq!(status, http::StatusCode::OK);
            let first = stream.recv_data().await.expect("first data");
            assert!(first.is_some(), "expected first body chunk");

            // Slow-client cases withhold QUIC stream credit; slow-backend
            // disconnect cases stay attached during the injected stall.
            tokio::time::sleep(BODY_DELAY).await;

            match outcome {
                Outcome::Disconnect => {
                    drop(stream);
                }
                Outcome::Complete => {
                    let _ = stream.drain_body().await.expect("drain body");
                }
            }
        }
    }
}

async fn grpc_drive(harness: &GatewayHarness, path: &str, pace: Pace, outcome: Outcome) {
    let port = gateway_http_port(harness);
    match (pace, outcome) {
        (Pace::SlowBackend, Outcome::Complete) => {
            let client = GrpcClient::h2c(format!("127.0.0.1:{port}"));
            let resp = client
                .unary(path, Bytes::from_static(b"x"))
                .await
                .expect("grpc response");
            assert_eq!(resp.http_status, 200);
            assert_eq!(resp.grpc_status(), Some(0));
            assert!(
                resp.stream_error.is_none(),
                "gRPC completion stream failed: {:?}",
                resp.stream_error
            );
        }
        (Pace::SlowBackend, Outcome::Disconnect) | (Pace::SlowClient, _) => {
            grpc_live_stream(port, path, matches!(pace, Pace::SlowClient), outcome).await;
        }
    }
}

async fn grpc_live_stream(port: u16, path: &str, slow_read: bool, outcome: Outcome) {
    use h2::client as h2_client;
    use http::HeaderMap;

    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect grpc h2c");
    let _ = stream.set_nodelay(true);
    let (mut send_req, connection) = h2_client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(connection);

    let request = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("build grpc request");
    let (response_fut, mut req_body) = send_req.send_request(request, false).expect("send_request");
    let mut framed = bytes::BytesMut::with_capacity(6);
    framed.extend_from_slice(&[0, 0, 0, 0, 1, b'x']);
    req_body
        .send_data(framed.freeze(), true)
        .expect("send grpc data");

    let response = tokio::time::timeout(Duration::from_secs(20), response_fut)
        .await
        .expect("response timeout")
        .expect("response error");
    assert_eq!(response.status().as_u16(), 200);
    let (_parts, mut body_stream) = response.into_parts();

    let first = tokio::time::timeout(Duration::from_secs(10), body_stream.data())
        .await
        .expect("first frame timeout")
        .expect("first frame missing")
        .expect("first frame error");
    // Intentionally do NOT release capacity yet on the slow-client path so the
    // stream window creates real backpressure.
    if !slow_read {
        let _ = body_stream.flow_control().release_capacity(first.len());
    }

    // Slow-client cases withhold H2 WINDOW_UPDATE; slow-backend disconnect
    // cases stay attached during the injected backend stall.
    tokio::time::sleep(BODY_DELAY).await;

    match outcome {
        Outcome::Disconnect => {
            drop(body_stream);
            drop(send_req);
            conn_task.abort();
        }
        Outcome::Complete => {
            if slow_read {
                let _ = body_stream.flow_control().release_capacity(first.len());
            }
            loop {
                match body_stream.data().await {
                    Some(Ok(chunk)) => {
                        let _ = body_stream.flow_control().release_capacity(chunk.len());
                    }
                    Some(Err(error)) => panic!("gRPC completion stream failed: {error}"),
                    None => break,
                }
            }
            let trailers: HeaderMap = body_stream
                .trailers()
                .await
                .expect("gRPC trailers error")
                .expect("gRPC completion missing trailers");
            assert_eq!(
                trailers
                    .get("grpc-status")
                    .and_then(|value| value.to_str().ok()),
                Some("0"),
                "gRPC completion must retain grpc-status=0"
            );
            drop(send_req);
            conn_task.abort();
        }
    }
}

async fn run_http_family(protocol: &str, pace: Pace, outcome: Outcome) {
    let marker = scenario_marker(protocol, pace, outcome);
    let path = scenario_path(protocol, pace, outcome);
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let listener = backend_res.into_listener();
    // H2 frontend coverage proxies to the stable HTTP/1 scripted backend.
    // Acceptance is frontend H2; an unconfigured H2 backend transport is out
    // of scope and previously returned 502 for all four H2 cases.
    let slow_client_payload_bytes = match protocol {
        "h1" => H1_SLOW_CLIENT_PAYLOAD_BYTES,
        _ => SLOW_CLIENT_PAYLOAD_BYTES,
    };
    let _backend = spawn_http1_scripted(listener, pace, outcome, slow_client_payload_bytes);

    let proxy_id = format!("stream-latency-{marker}");
    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(
            backend_port,
            &proxy_id,
            "/api",
            json!({}),
        ))
        .log_level("info")
        .env("RUST_LOG", "info")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    match protocol {
        "h1" => h1_drive(&harness, &path, pace, outcome).await,
        "h2" => h2_drive(&harness, &path, pace, outcome).await,
        other => panic!("unexpected protocol {other}"),
    }

    let logs = wait_for_marked_summary(&harness, &marker).await;
    let summary = find_summary_for_marker(&logs, &marker)
        .unwrap_or_else(|| panic!("{marker}: missing marked streamed summary; logs:\n{logs}"));
    assert_streamed_unknown_gateway_contract(&marker, summary, outcome.expect_disconnect());
}

async fn run_native_h3(pace: Pace, outcome: Outcome) {
    let marker = scenario_marker("h3", pace, outcome);
    let path = scenario_path("h3", pace, outcome);
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = spawn_http1_scripted(
        backend_res.into_listener(),
        pace,
        outcome,
        SLOW_CLIENT_PAYLOAD_BYTES,
    );

    let proxy_id = format!("stream-latency-{marker}");
    let (harness, https_port, cert_dir) =
        spawn_native_h3_logging_gateway(backend_port, &proxy_id).await;

    h3_drive(https_port, &path, pace, outcome).await;

    let logs = wait_for_marked_summary(&harness, &marker).await;
    let summary = find_summary_for_marker(&logs, &marker)
        .unwrap_or_else(|| panic!("{marker}: missing marked streamed summary; logs:\n{logs}"));
    assert_streamed_unknown_gateway_contract(&marker, summary, outcome.expect_disconnect());
    // Stop the gateway before TempDir deletes the frontend cert/key files.
    drop(harness);
    drop(cert_dir);
}

async fn run_grpc(pace: Pace, outcome: Outcome) {
    let marker = scenario_marker("grpc", pace, outcome);
    // gRPC paths are method paths; keep the unique marker in the service path.
    let path = format!("/grpc/{marker}.Service/Get");
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = spawn_grpc_scripted(backend_res.into_listener(), pace, outcome);

    let proxy_id = format!("stream-latency-{marker}");
    let harness = GatewayHarness::builder()
        .file_config(logging_proxy_config(
            backend_port,
            &proxy_id,
            "/grpc",
            json!({}),
        ))
        .log_level("info")
        .env("RUST_LOG", "info")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    grpc_drive(&harness, &path, pace, outcome).await;

    let logs = wait_for_marked_summary(&harness, &marker).await;
    let summary = find_summary_for_marker(&logs, &marker)
        .unwrap_or_else(|| panic!("{marker}: missing marked streamed summary; logs:\n{logs}"));
    assert_streamed_unknown_gateway_contract(&marker, summary, outcome.expect_disconnect());
}

// ── HTTP/1.1 ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowBackend, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowBackend, Outcome::Disconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowClient, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h1", Pace::SlowClient, Outcome::Disconnect).await;
}

// ── HTTP/2 frontend ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowBackend, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowBackend, Outcome::Disconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowClient, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_http_family("h2", Pace::SlowClient, Outcome::Disconnect).await;
}

// ── Native HTTP/3 frontend ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowBackend, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowBackend, Outcome::Disconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowClient, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_native_h3(Pace::SlowClient, Outcome::Disconnect).await;
}

// ── Streamed gRPC ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_backend_stream_completion_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowBackend, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_backend_stream_disconnect_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowBackend, Outcome::Disconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_client_stream_completion_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowClient, Outcome::Complete).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_slow_client_stream_disconnect_keeps_gateway_sentinel() {
    run_grpc(Pace::SlowClient, Outcome::Disconnect).await;
}
