//! gRPC-Web over the HTTP/1.1 and HTTP/2 frontends (issue #5758).
//!
//! A route WITHOUT the `grpc_web` plugin passes gRPC-Web through to a backend
//! that already answers in gRPC-Web. The client must receive the backend's body
//! byte for byte — its own trailer frame and no second, synthesized one — and
//! the transaction log must carry the status from that frame. A route WITH the
//! plugin translates a native gRPC backend and still emits exactly one trailer
//! frame whose status the log also reports.
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests functional_grpc_web_passthrough -- --ignored --nocapture`.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use serde_json::{Value, json};

use crate::scaffolding::backends::{H2Step, MatchHeaders, ScriptedH2Backend};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use crate::scaffolding::to_file_mode_yaml;

fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(flag);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// The complete gRPC-Web body a pass-through backend writes itself.
fn passthrough_binary_body() -> Vec<u8> {
    let mut body = frame(0x00, b"pong");
    body.extend_from_slice(&frame(0x80, b"grpc-status: 7\r\ngrpc-message: denied\r\n"));
    body
}

/// gRPC-Web text as a backend flushes it: each segment independently padded.
fn passthrough_text_body() -> Vec<u8> {
    let mut body = BASE64.encode(frame(0x00, b"pong")).into_bytes();
    let trailer = BASE64.encode(frame(0x80, b"grpc-status: 12\r\n"));
    body.extend_from_slice(trailer.as_bytes());
    body
}

fn trailer_frames(body: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut rest = body;
    while rest.len() >= 5 {
        let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        assert!(
            rest.len() >= 5 + len,
            "truncated gRPC-Web frame in {body:?}"
        );
        if rest[0] == 0x80 {
            frames.push(rest[5..5 + len].to_vec());
        }
        rest = &rest[5 + len..];
    }
    assert!(rest.is_empty(), "trailing partial frame in {body:?}");
    frames
}

async fn spawn_h2c_backend(content_type: &'static str, body: Vec<u8>) -> (ScriptedH2Backend, u16) {
    let reservation = reserve_port().await.expect("reserve backend port");
    let port = reservation.port;
    let backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", content_type.into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from(body),
            end_stream: true,
        })
        .spawn()
        .expect("spawn h2c backend");
    (backend, port)
}

/// A pass-through backend that writes `body` as several DATA frames split at
/// `cuts`, pausing between them so the gateway reads each one separately.
async fn spawn_split_h2c_backend(
    content_type: &'static str,
    body: &[u8],
    cuts: &[usize],
) -> (ScriptedH2Backend, u16) {
    let mut data_steps = Vec::new();
    let mut start = 0;
    for &cut in cuts {
        data_steps.push(H2Step::RespondData {
            data: Bytes::copy_from_slice(&body[start..cut]),
            end_stream: false,
        });
        data_steps.push(H2Step::Sleep(Duration::from_millis(20)));
        start = cut;
    }
    data_steps.push(H2Step::RespondData {
        data: Bytes::copy_from_slice(&body[start..]),
        end_stream: true,
    });
    let reservation = reserve_port().await.expect("reserve backend port");
    let port = reservation.port;
    let backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", content_type.into()),
        ]))
        .steps(data_steps)
        .spawn()
        .expect("spawn split h2c backend");
    (backend, port)
}

async fn spawn_native_grpc_backend() -> (ScriptedH2Backend, u16) {
    let reservation = reserve_port().await.expect("reserve backend port");
    let port = reservation.port;
    let backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::DrainRequestBody)
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from(frame(0x00, b"pong")),
            end_stream: false,
        })
        .step(H2Step::RespondTrailers(vec![
            ("grpc-status", "5".into()),
            ("grpc-message", "missing".into()),
        ]))
        .spawn()
        .expect("spawn native gRPC backend");
    (backend, port)
}

fn route(id: &str, backend_port: u16, plugins: Value) -> Value {
    json!({
        "id": id,
        "listen_path": format!("/{id}"),
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
        "plugins": plugins,
    })
}

/// The same route with `response_body_mode: buffer`, which sends pass-through
/// gRPC-Web through the native gRPC BUFFERED branch.
fn buffered_route(id: &str, backend_port: u16) -> Value {
    let mut buffered = route(id, backend_port, json!([]));
    buffered["response_body_mode"] = json!("buffer");
    buffered
}

fn logged_metadata(logs: &str, proxy_id: &str, key: &str) -> Vec<Value> {
    logs.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["proxy_id"] == proxy_id)
        .map(|entry| entry["metadata"][key].clone())
        .collect()
}

fn logged_grpc_status(logs: &str, proxy_id: &str) -> Vec<Value> {
    logs.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["proxy_id"] == proxy_id)
        .map(|entry| entry["grpc_status"].clone())
        .collect()
}

async fn post_grpc_web(
    client: &reqwest::Client,
    url: &str,
    content_type: &str,
    body: Vec<u8>,
) -> (reqwest::Version, reqwest::header::HeaderMap, Vec<u8>) {
    post_grpc_web_with_headers(client, url, content_type, body, &[]).await
}

async fn post_grpc_web_with_headers(
    client: &reqwest::Client,
    url: &str,
    content_type: &str,
    body: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> (reqwest::Version, reqwest::header::HeaderMap, Vec<u8>) {
    let mut request = client
        .post(url)
        .header("content-type", content_type)
        .header("x-grpc-web", "1");
    for (name, value) in extra_headers {
        request = request.header(*name, *value);
    }
    let response = request.body(body).send().await.expect("gRPC-Web request");
    assert_eq!(response.status(), reqwest::StatusCode::OK, "url={url}");
    let version = response.version();
    let headers = response.headers().clone();
    let body = response.bytes().await.expect("gRPC-Web body").to_vec();
    (version, headers, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_web_passthrough_and_translation_on_h1_and_h2_frontends() {
    let (_binary_backend, binary_port) =
        spawn_h2c_backend("application/grpc-web+proto", passthrough_binary_body()).await;
    let (_text_backend, text_port) =
        spawn_h2c_backend("application/grpc-web-text+proto", passthrough_text_body()).await;
    let (_native_backend, native_port) = spawn_native_grpc_backend().await;

    let translated = |id: &str| json!([{"plugin_config_id": format!("{id}-grpc-web")}]);
    let translator = |proxy_id: &str| {
        json!({
            "id": format!("{proxy_id}-grpc-web"),
            "plugin_name": "grpc_web",
            "config": {},
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
        })
    };
    let config = json!({
        "version": "1",
        "proxies": [
            route("bin-h1", binary_port, json!([])),
            route("bin-h2", binary_port, json!([])),
            route("text-h1", text_port, json!([])),
            route("text-h2", text_port, json!([])),
            route("translated-h1", native_port, translated("translated-h1")),
            route("translated-h2", native_port, translated("translated-h2")),
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "access-log",
                "plugin_name": "stdout_logging",
                "config": {},
                "scope": "global",
                "enabled": true,
            },
            translator("translated-h1"),
            translator("translated-h2"),
        ],
    });
    let harness = GatewayHarness::builder()
        .file_config(to_file_mode_yaml(&config))
        .log_level("info")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");
    let base = harness.proxy_base_url().to_string();

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let request = frame(0x00, b"ping");

    for (client, version, suffix) in [
        (&h1, reqwest::Version::HTTP_11, "h1"),
        (&h2, reqwest::Version::HTTP_2, "h2"),
    ] {
        // Binary pass-through: the backend's bytes, its trailer frame included,
        // reach the client unchanged and nothing is appended.
        let (got_version, headers, body) = post_grpc_web(
            client,
            &format!("{base}/bin-{suffix}/echo.Echo/Unary"),
            "application/grpc-web+proto",
            request.clone(),
        )
        .await;
        assert_eq!(got_version, version);
        assert_eq!(
            body,
            passthrough_binary_body(),
            "{suffix}: pass-through gRPC-Web must be byte-identical"
        );
        assert_eq!(trailer_frames(&body).len(), 1, "{suffix}: one trailer");
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/grpc-web+proto")
        );

        // Text pass-through: the base64 body is not encoded a second time.
        let (_, _, body) = post_grpc_web(
            client,
            &format!("{base}/text-{suffix}/echo.Echo/Unary"),
            "application/grpc-web-text+proto",
            BASE64.encode(&request).into_bytes(),
        )
        .await;
        assert_eq!(
            body,
            passthrough_text_body(),
            "{suffix}: pass-through gRPC-Web text must be byte-identical"
        );

        // Translated: the native backend's trailers become exactly one frame.
        let (_, headers, body) = post_grpc_web(
            client,
            &format!("{base}/translated-{suffix}/echo.Echo/Unary"),
            "application/grpc-web+proto",
            request.clone(),
        )
        .await;
        assert!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("application/grpc-web")),
            "{suffix}: translated response must be gRPC-Web: {headers:?}"
        );
        assert!(
            body.starts_with(&frame(0x00, b"pong")),
            "{suffix}: body={body:?}"
        );
        let trailers = trailer_frames(&body);
        assert_eq!(trailers.len(), 1, "{suffix}: exactly one trailer frame");
        assert!(
            String::from_utf8_lossy(&trailers[0]).contains("grpc-status: 5\r\n"),
            "{suffix}: {:?}",
            String::from_utf8_lossy(&trailers[0])
        );
    }

    let expected = [
        ("bin-h1", 7),
        ("bin-h2", 7),
        ("text-h1", 12),
        ("text-h2", 12),
        ("translated-h1", 5),
        ("translated-h2", 5),
    ];
    let logs = harness
        .wait_for_log_contains(
            |logs| {
                expected
                    .iter()
                    .all(|(proxy_id, _)| !logged_grpc_status(logs, proxy_id).is_empty())
            },
            Duration::from_secs(10),
        )
        .await;
    for (proxy_id, status) in expected {
        assert_eq!(
            logged_grpc_status(&logs, proxy_id),
            vec![json!(status)],
            "{proxy_id}: the logged grpc_status must come from the delivered trailer frame; \
             logs:\n{logs}"
        );
    }
}

/// A backend whose final frame is a COMPRESSED trailer frame (flag `0x81`):
/// its status is on the wire, but the gateway cannot read it.
fn compressed_trailer_body() -> Vec<u8> {
    let mut body = frame(0x00, b"pong");
    body.extend_from_slice(&frame(0x81, b"deflated-trailer"));
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_web_passthrough_buffered_deadline_split_and_unreadable_status() {
    let binary = passthrough_binary_body();
    let (_binary_backend, binary_port) =
        spawn_h2c_backend("application/grpc-web+proto", binary.clone()).await;
    let (_text_backend, text_port) =
        spawn_h2c_backend("application/grpc-web-text+proto", passthrough_text_body()).await;
    // Cuts inside the message frame header, the trailer frame header, and the
    // trailer's `grpc-status` line.
    let (_split_backend, split_port) =
        spawn_split_h2c_backend("application/grpc-web+proto", &binary, &[3, 11, 20]).await;
    let (_compressed_backend, compressed_port) =
        spawn_h2c_backend("application/grpc-web+proto", compressed_trailer_body()).await;

    let mut proxies = Vec::new();
    for suffix in ["h1", "h2"] {
        let id = |route_id: &str| format!("{route_id}-{suffix}");
        proxies.push(buffered_route(&id("buf-bin"), binary_port));
        proxies.push(buffered_route(&id("buf-text"), text_port));
        proxies.push(route(&id("deadline"), binary_port, json!([])));
        proxies.push(route(&id("split"), split_port, json!([])));
        proxies.push(buffered_route(&id("split-buf"), split_port));
        proxies.push(route(&id("zip"), compressed_port, json!([])));
        proxies.push(buffered_route(&id("zip-buf"), compressed_port));
    }
    let config = json!({
        "version": "1",
        "proxies": proxies,
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "access-log",
            "plugin_name": "stdout_logging",
            "config": {},
            "scope": "global",
            "enabled": true,
        }],
    });
    let harness = GatewayHarness::builder()
        .file_config(to_file_mode_yaml(&config))
        .log_level("info")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");
    let base = harness.proxy_base_url().to_string();

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let request = frame(0x00, b"ping");
    let binary_type = "application/grpc-web+proto";

    for (client, suffix) in [(&h1, "h1"), (&h2, "h2")] {
        // Native BUFFERED branch: the collected body is still the backend's own.
        let (_, _, body) = post_grpc_web(
            client,
            &format!("{base}/buf-bin-{suffix}/echo.Echo/Unary"),
            binary_type,
            request.clone(),
        )
        .await;
        assert_eq!(body, binary, "{suffix}: buffered is byte-identical");
        assert_eq!(trailer_frames(&body).len(), 1, "{suffix}: one trailer");

        let (_, _, body) = post_grpc_web(
            client,
            &format!("{base}/buf-text-{suffix}/echo.Echo/Unary"),
            "application/grpc-web-text+proto",
            BASE64.encode(&request).into_bytes(),
        )
        .await;
        assert_eq!(
            body,
            passthrough_text_body(),
            "{suffix}: buffered text pass-through is not encoded again"
        );

        // A client deadline stacks its wrapper under the relay; a deadline that
        // does not fire leaves the backend's bytes untouched.
        let (_, _, body) = post_grpc_web_with_headers(
            client,
            &format!("{base}/deadline-{suffix}/echo.Echo/Unary"),
            binary_type,
            request.clone(),
            &[("grpc-timeout", "30S")],
        )
        .await;
        assert_eq!(body, binary, "{suffix}: deadline is byte-identical");

        // The backend's body arrives in several DATA frames, split inside both
        // frame headers and the status line; streamed and buffered alike.
        for route_id in ["split", "split-buf"] {
            let (_, _, body) = post_grpc_web(
                client,
                &format!("{base}/{route_id}-{suffix}/echo.Echo/Unary"),
                binary_type,
                request.clone(),
            )
            .await;
            assert_eq!(body, binary, "{route_id}-{suffix}: split body");
        }

        // A compressed final trailer frame is relayed unchanged, too.
        for route_id in ["zip", "zip-buf"] {
            let (_, _, body) = post_grpc_web(
                client,
                &format!("{base}/{route_id}-{suffix}/echo.Echo/Unary"),
                binary_type,
                request.clone(),
            )
            .await;
            assert_eq!(body, compressed_trailer_body(), "{route_id}-{suffix}");
        }
    }

    let readable = [
        ("buf-bin", 7),
        ("buf-text", 12),
        ("deadline", 7),
        ("split", 7),
        ("split-buf", 7),
    ];
    let unreadable = ["zip", "zip-buf"];
    let mut proxy_ids = Vec::new();
    for suffix in ["h1", "h2"] {
        for (route_id, _) in readable {
            proxy_ids.push(format!("{route_id}-{suffix}"));
        }
        for route_id in unreadable {
            proxy_ids.push(format!("{route_id}-{suffix}"));
        }
    }
    let logs = harness
        .wait_for_log_contains(
            |logs| {
                proxy_ids
                    .iter()
                    .all(|proxy_id| !logged_grpc_status(logs, proxy_id).is_empty())
            },
            Duration::from_secs(10),
        )
        .await;
    for suffix in ["h1", "h2"] {
        for (route_id, status) in readable {
            let proxy_id = format!("{route_id}-{suffix}");
            assert_eq!(
                logged_grpc_status(&logs, &proxy_id),
                vec![json!(status)],
                "{proxy_id}: the logged grpc_status must come from the delivered trailer \
                 frame; logs:\n{logs}"
            );
        }
        // Present but unreadable: no status at all rather than a synthesized
        // UNKNOWN (2), and the log names why.
        for route_id in unreadable {
            let proxy_id = format!("{route_id}-{suffix}");
            assert_eq!(
                logged_grpc_status(&logs, &proxy_id),
                vec![Value::Null],
                "{proxy_id}: an unreadable status stays unset; logs:\n{logs}"
            );
            assert_eq!(
                logged_metadata(&logs, &proxy_id, "grpc_status_unreadable"),
                vec![json!("compressed_trailer_frame")],
                "{proxy_id}: logs:\n{logs}"
            );
        }
    }
}

/// Issue #5784: pass-through gRPC-Web over the GENERIC relay path. A
/// `mesh.unix_socket` HTTP/1.1 target makes the native gRPC branch fall through
/// (`grpc_mesh_dispatch_falls_through`), so the H1/H2 response funnel's generic
/// relay carries the backend body, with the client `grpc-timeout` deadline
/// wrapper stacked beneath the pass-through relay.
#[cfg(unix)]
mod generic_relay_mesh_fall_through {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ferrum_edge::config::EnvConfig;
    use serde_json::Value;
    use tempfile::TempDir;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixListener};

    use crate::common::{TrustedProjectedGateway, TrustedProjectedGatewayOptions};
    use crate::scaffolding::port_registry::TestSocket;

    use super::{frame, passthrough_binary_body, post_grpc_web_with_headers, trailer_frames};

    const PROXY_ID: &str = "grpc-web-unix";
    const SINK_OK: &[u8] = b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n";

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Read one HTTP/1.1 request, head and body (`Content-Length` or chunked).
    async fn read_http1_request<S>(stream: &mut S) -> Option<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(head_end) = find(&request, b"\r\n\r\n") {
                let request_head = String::from_utf8_lossy(&request[..head_end]);
                let request_head = request_head.to_ascii_lowercase();
                let body = &request[head_end + 4..];
                let complete = if request_head.contains("transfer-encoding: chunked") {
                    find(body, b"0\r\n\r\n").is_some()
                } else {
                    let length = request_head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    body.len() >= length
                };
                if complete {
                    return Some(request);
                }
            }
            let read = stream.read(&mut buf);
            match tokio::time::timeout_at(deadline, read).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
                Ok(Ok(n)) => request.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// An HTTP/1.1 gRPC-Web backend on a Unix-domain socket that answers every
    /// complete request with `body`.
    fn spawn_unix_grpc_web_backend(listener: UnixListener, body: Vec<u8>) {
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    if read_http1_request(&mut stream).await.is_none() {
                        return;
                    }
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(&body);
                    let _ = stream.write_all(&response).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
    }

    /// Minimal HTTP/1.1 sink recording the JSON transaction summaries the
    /// `http_logging` plugin posts (the in-process gateway's stdout is not
    /// captured).
    async fn start_http_logging_sink() -> (u16, Arc<Mutex<Vec<Value>>>) {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind http_logging sink");
        let port = listener.local_addr().expect("sink addr").port();
        let entries = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&entries);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let captured = Arc::clone(&captured);
                tokio::spawn(async move {
                    let Some(request) = read_http1_request(&mut stream).await else {
                        return;
                    };
                    if let Some(head_end) = find(&request, b"\r\n\r\n") {
                        let posted = &request[head_end + 4..];
                        if let Ok(posted) = serde_json::from_slice::<Value>(posted)
                            && let Ok(mut guard) = captured.lock()
                        {
                            match posted {
                                Value::Array(batch) => guard.extend(batch),
                                entry => guard.push(entry),
                            }
                        }
                    }
                    let _ = stream.write_all(SINK_OK).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (port, entries)
    }

    fn logged_entries(entries: &Mutex<Vec<Value>>) -> Vec<Value> {
        let Ok(guard) = entries.lock() else {
            return Vec::new();
        };
        guard
            .iter()
            .filter(|entry| entry["proxy_id"] == PROXY_ID)
            .cloned()
            .collect()
    }

    /// Trusted-projected fixture: one route whose only target carries the
    /// reserved `mesh.unix_socket` tag, plus an `http_logging` sink.
    fn fixture_yaml(socket_path: &str, placeholder_port: u16, sink_port: u16) -> String {
        format!(
            r#"version: "1"
proxies:
  - id: "{PROXY_ID}"
    listen_path: "/{PROXY_ID}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {placeholder_port}
    upstream_id: "{PROXY_ID}-upstream"
    strip_listen_path: true
    pool_enable_http2: false
    updated_at: "2026-09-26T00:00:00Z"
upstreams:
  - id: "{PROXY_ID}-upstream"
    name: "{PROXY_ID}-upstream"
    algorithm: round_robin
    updated_at: "2026-09-26T00:00:00Z"
    targets:
      - host: "127.0.0.1"
        port: {placeholder_port}
        weight: 1
        tags:
          mesh.unix_socket: "{socket_path}"
          mesh.unix_socket_h2c: "false"
consumers: []
plugin_configs:
  - id: "{PROXY_ID}-http-log"
    plugin_name: http_logging
    scope: global
    enabled: true
    config:
      endpoint_url: "http://127.0.0.1:{sink_port}/logs"
      batch_size: 1
      flush_interval_ms: 100
"#
        )
    }

    #[ignore]
    #[test]
    fn grpc_web_passthrough_generic_relay_with_grpc_timeout_over_mesh_fall_through() {
        crate::common::run_trusted_projected_gateway_test(generic_relay_inner);
    }

    async fn generic_relay_inner() {
        let temp = TempDir::new().expect("temp dir");
        // The dial-time containment gate compares the symlink-resolved path.
        let root = temp
            .path()
            .canonicalize()
            .expect("canonicalize the unix-socket containment root");
        let socket_path = root.join("grpc-web.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind unix socket");
        let backend_body = passthrough_binary_body();
        spawn_unix_grpc_web_backend(listener, backend_body.clone());
        let (sink_port, entries) = start_http_logging_sink().await;
        // Never dialed: a TCP fallback would hit this idle listener instead.
        let placeholder = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind placeholder port");
        let placeholder_port = placeholder.local_addr().expect("placeholder addr").port();

        let socket = socket_path.to_str().expect("utf-8 socket path");
        let config = fixture_yaml(socket, placeholder_port, sink_port);
        let root = root.to_str().expect("utf-8 containment root").to_string();
        let mut gateway = TrustedProjectedGateway::spawn_from_yaml(
            &config,
            TrustedProjectedGatewayOptions {
                env: EnvConfig {
                    pool_warmup_enabled: false,
                    log_level: "warn".into(),
                    ..Default::default()
                },
                mesh_unix_socket_allowed_roots: vec![root],
                ..TrustedProjectedGatewayOptions::default()
            },
        )
        .await
        .expect("start trusted projected gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        let client = reqwest::Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("h1 client");
        let url = gateway.proxy_url(&format!("/{PROXY_ID}/echo.Echo/Unary"));
        let (_, _, body) = post_grpc_web_with_headers(
            &client,
            &url,
            "application/grpc-web+proto",
            frame(0x00, b"ping"),
            &[("grpc-timeout", "30S")],
        )
        .await;
        assert_eq!(
            body, backend_body,
            "the generic relay forwards the backend body byte for byte"
        );
        assert_eq!(
            trailer_frames(&body).len(),
            1,
            "only the backend's own trailer frame; the relay appends none"
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let logged = loop {
            let logged = logged_entries(&entries);
            if !logged.is_empty() || tokio::time::Instant::now() >= deadline {
                break logged;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(logged.len(), 1, "one transaction summary: {logged:?}");
        assert_eq!(
            logged[0]["grpc_status"], 7,
            "the logged status comes from the backend's trailer frame: {logged:?}"
        );
        gateway.shutdown().await;
    }
}
