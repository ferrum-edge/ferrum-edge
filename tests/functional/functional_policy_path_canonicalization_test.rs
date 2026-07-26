//! End-to-end canonical policy path parity across HTTP/1.1, HTTP/2, and
//! HTTP/3 (private advisory GHSA-69xf-42xm-4w4f).
//!
//! Each case is a single request target checked against three things at once:
//! the client-visible status, whether a policy plugin
//! (`request_termination`) fired, and — through a raw-TCP backend that
//! records the request line it actually received — the path the backend would
//! execute. That triple is what the advisory says must never diverge.
//!
//! Every case runs identically over all three frontend protocols, because a
//! per-protocol difference is itself a bypass.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use bytes::Bytes;
use ferrum_edge::tls::acme::{
    AcmeHttp01ChallengeRecord, AcmeHttp01OrderInput, AcmeOrderRecord, AcmeOrderStatus,
    AcmeOrderStore,
};
use http::{HeaderMap, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

// ============================================================================
// Request-target recording backend
// ============================================================================

/// Raw-TCP HTTP/1.1 backend that records the request target of every request
/// line it receives. Raw on purpose: a typed client would re-encode the target
/// and hide exactly the difference under test.
struct RecordingBackend {
    port: u16,
    targets: Arc<Mutex<Vec<String>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl RecordingBackend {
    async fn start() -> Self {
        // Hold the bound listener rather than drop-and-rebind, so parallel
        // tests cannot steal the port between reservation and use.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("backend addr").port();
        let targets: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&targets);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 1024];
                    // Read until the end of the header block; these requests
                    // carry no body.
                    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let text = String::from_utf8_lossy(&buffer).into_owned();
                    let target = text
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string();
                    recorded.lock().expect("targets lock").push(target.clone());

                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        target.len(),
                        target
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });

        Self {
            port,
            targets,
            handle,
        }
    }

    fn targets(&self) -> Vec<String> {
        self.targets.lock().expect("targets lock").clone()
    }

    fn take_targets(&self) -> Vec<String> {
        std::mem::take(&mut *self.targets.lock().expect("targets lock"))
    }
}

impl Drop for RecordingBackend {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ============================================================================
// Gateway
// ============================================================================

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "canon"
    listen_path: "/canon"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "canon-termination"
  - id: "strip"
    listen_path: "/strip"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: false

consumers: []
plugin_configs:
  - id: "canon-termination"
    plugin_name: request_termination
    scope: proxy
    proxy_id: "canon"
    enabled: true
    config:
      status_code: 403
      content_type: application/json
      message: "blocked by policy"
      trigger:
        path_prefix: "/canon/blocked"
"#
    )
}

/// Spawn the gateway against `backend_port`.
///
/// `acme_store_dir` points the child's process-global ACME order store at a
/// caller-owned directory, so a pending HTTP-01 order seeded before the spawn is
/// the one the child resolves. `None` leaves the ambient default store path
/// alone.
async fn spawn_gateway(
    backend_port: u16,
    acme_store_dir: Option<&std::path::Path>,
) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        // Reserve a fresh HTTPS/QUIC port per attempt (functional-test rule:
        // every retry gets fresh ports).
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let mut builder = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false");
        if let Some(store_dir) = acme_store_dir {
            builder = builder.env(
                "FERRUM_TLS_MANAGED_STORE_PATH",
                store_dir.to_string_lossy().into_owned(),
            );
        }
        let result = builder.spawn().await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!("failed to spawn policy-path gateway after {MAX_ATTEMPTS} attempts: {last_error}");
}

// ============================================================================
// Per-protocol senders — each puts `target` on the wire verbatim
// ============================================================================

/// HTTP/1.1 over a raw socket: the only way to control the request-line bytes
/// exactly, including targets no URL type would round-trip (`/canon/%zz`).
async fn send_h1(proxy_port: u16, target: &str) -> u16 {
    send_h1_full(proxy_port, target).await.0
}

/// The same raw HTTP/1.1 exchange, keeping the response body. The ACME cases
/// need it: an HTTP-01 challenge is proven by the key-authorization bytes, and a
/// refusal is proven by a fixed body that does not echo the target.
async fn send_h1_full(proxy_port: u16, target: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h1");
    let _ = stream.set_nodelay(true);
    let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write h1 request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read h1 response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let body = match text.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => String::new(),
    };
    (h1_status(&text, target), body)
}

fn h1_status(text: &str, target: &str) -> u16 {
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in H1 response for {target:?}: {text:?}"))
}

/// HTTP/2 cleartext with prior knowledge. `http::Uri` preserves percent
/// escapes verbatim, so `:path` carries the spelling under test.
async fn send_h2(proxy_port: u16, target: &str) -> u16 {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h2");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{proxy_port}{target}"))
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let response = sender.send_request(request).await.expect("send h2 request");
    let status = response.status().as_u16();
    let _ = response.into_body().collect().await;

    drop(sender);
    conn_task.abort();
    status
}

async fn send_h3(client: &Http3Client, https_port: u16, target: &str) -> u16 {
    let url = format!("https://127.0.0.1:{https_port}{target}");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match client.get(&url).await {
            Ok(response) => return response.status.as_u16(),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 GET {url} did not complete: {error}"),
        }
    }
}

struct RpcResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn collect_rpc_response(response: hyper::Response<hyper::body::Incoming>) -> RpcResponse {
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .expect("collect RPC rejection body")
        .to_bytes();
    RpcResponse {
        status: parts.status,
        headers: parts.headers,
        body,
    }
}

async fn send_h1_rpc(proxy_port: u16, target: &str, content_type: &str) -> RpcResponse {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h1 RPC");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("h1 RPC handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(target)
        .header("host", format!("127.0.0.1:{proxy_port}"))
        .header("content-type", content_type)
        .body(Full::new(Bytes::new()))
        .expect("build h1 RPC request");
    let response = sender
        .send_request(request)
        .await
        .expect("send h1 RPC request");
    let response = collect_rpc_response(response).await;
    drop(sender);
    conn_task.abort();
    response
}

async fn send_h2_rpc(proxy_port: u16, target: &str, content_type: &str) -> RpcResponse {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h2 RPC");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 RPC handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://127.0.0.1:{proxy_port}{target}"))
        .header("content-type", content_type)
        .body(Full::new(Bytes::new()))
        .expect("build h2 RPC request");
    let response = sender
        .send_request(request)
        .await
        .expect("send h2 RPC request");
    let response = collect_rpc_response(response).await;
    drop(sender);
    conn_task.abort();
    response
}

async fn send_h3_rpc(
    client: &Http3Client,
    https_port: u16,
    target: &str,
    content_type: &str,
) -> Http3Response {
    let url = format!("https://127.0.0.1:{https_port}{target}");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let options = GetOptions::default()
            .method(Method::POST)
            .header("content-type", content_type);
        match client.get_with_options(&url, options).await {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 RPC {url} did not complete: {error}"),
        }
    }
}

// ============================================================================
// Cases
// ============================================================================

/// What the recording backend must have seen once the response arrives.
enum Backend {
    /// The request must never reach a backend — the gateway answered it.
    Never,
    /// The backend must have executed exactly this request target.
    Exact(&'static str),
}

struct Case {
    /// Request target exactly as it goes on the wire.
    target: &'static str,
    status: u16,
    backend_target: Backend,
    why: &'static str,
}

const CASES: &[Case] = &[
    // Ordinary single encoding of a character that is legal literally in a
    // path: the advisory's headline bypass. Policy and backend must both see
    // `/canon/admin`.
    Case {
        target: "/canon/%61dmin",
        status: 200,
        backend_target: Backend::Exact("/canon/admin"),
        why: "single-encoded legal character decodes for policy and backend alike",
    },
    Case {
        target: "/canon/%61%64%6D%69%6E",
        status: 200,
        backend_target: Backend::Exact("/canon/admin"),
        why: "fully encoded spelling is the same policy path",
    },
    // An escape of a byte outside the `pchar` decode set is refused: decoding it
    // would emit a byte the backend URL parser cannot carry or re-encodes, and
    // keeping it escaped would leave policy reading `/canon/a%20b` while a
    // decoding backend resolves `/canon/a b`.
    Case {
        target: "/canon/a%20b",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded space cannot be forwarded literally",
    },
    Case {
        target: "/canon/a%7Bb",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded brace cannot be forwarded literally",
    },
    Case {
        target: "/canon/caf%C3%A9",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded non-ASCII bytes cannot be forwarded literally",
    },
    Case {
        target: "/canon/a%2fb",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded separator is refused, not folded",
    },
    Case {
        target: "/canon/a%5Cb",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded backslash is a separator to several backends",
    },
    Case {
        target: "/canon/a%252Fb",
        status: 400,
        backend_target: Backend::Never,
        why: "double encoding cannot survive a second decode",
    },
    Case {
        target: "/canon/%2e%2e/secret",
        status: 400,
        backend_target: Backend::Never,
        why: "escape-synthesized dot segment is ambiguous",
    },
    Case {
        target: "/canon/%zz",
        status: 400,
        backend_target: Backend::Never,
        why: "non-hex escape has no single reading",
    },
    Case {
        target: "/canon/%2",
        status: 400,
        backend_target: Backend::Never,
        why: "truncated escape has no single reading",
    },
    Case {
        target: "/canon/caf%C3%28",
        status: 400,
        backend_target: Backend::Never,
        why: "escaped non-ASCII bytes are refused, valid UTF-8 or not",
    },
    Case {
        target: "/canon/%00",
        status: 400,
        backend_target: Backend::Never,
        why: "encoded NUL truncates the path in several runtimes",
    },
    // `request_termination` is configured with `path_prefix: /canon/blocked`.
    // The encoded spelling must hit the same rule as the plain one.
    Case {
        target: "/canon/blocked/thing",
        status: 403,
        backend_target: Backend::Never,
        why: "plain spelling trips the termination prefix",
    },
    Case {
        target: "/canon/%62locked/thing",
        status: 403,
        backend_target: Backend::Never,
        why: "encoded spelling trips the same termination prefix",
    },
    // Listen-path stripping is measured in the canonical coordinate, so the
    // forwarded remainder matches the routing decision.
    Case {
        target: "/strip/%74ail",
        status: 200,
        backend_target: Backend::Exact("/tail"),
        why: "strip_listen_path shares the canonical coordinate with routing",
    },
    Case {
        target: "/%73trip/tail",
        status: 200,
        backend_target: Backend::Exact("/tail"),
        why: "an encoded listen-path prefix still routes and strips identically",
    },
    // Literal dot segments are rejected as well as escape-synthesized ones.
    // The backend URL is parsed by the `url` crate, which removes dot segments,
    // so passing `/canon/a/../b` through would leave policy evaluating it while
    // the backend request line resolved `/canon/b`.
    Case {
        target: "/canon/a/../b",
        status: 400,
        backend_target: Backend::Never,
        why: "a literal dot segment resolves away in the forwarded request line",
    },
    Case {
        target: "/canon/./b",
        status: 400,
        backend_target: Backend::Never,
        why: "a literal single-dot segment resolves away the same way",
    },
    Case {
        target: "/canon/%61/../b",
        status: 400,
        backend_target: Backend::Never,
        why: "the literal rules apply to targets that also carry escapes",
    },
    // A literal backslash is rejected as well as `%5C`. All three senders can
    // carry it verbatim: the raw H1 socket writes the request line byte for
    // byte, and `http::Uri` — which the H2 and H3 senders parse their target
    // with — permits `\` (0x5C) in the path component, so `:path` reaches the
    // gateway as written.
    Case {
        target: "/canon/a\\b",
        status: 400,
        backend_target: Backend::Never,
        why: "a literal backslash is a path separator to the URL parser",
    },
    Case {
        target: "/canon\\blocked/thing",
        status: 400,
        backend_target: Backend::Never,
        why: "a literal backslash is refused before the termination rule runs",
    },
];

fn assert_case(protocol: &str, case: &Case, status: u16, observed: Vec<String>) {
    assert_eq!(
        status, case.status,
        "{protocol} {}: expected {} ({}), got {status}",
        case.target, case.status, case.why
    );
    match case.backend_target {
        Backend::Exact(expected) => assert_eq!(
            observed,
            vec![expected.to_string()],
            "{protocol} {}: backend must execute {expected:?} ({})",
            case.target,
            case.why
        ),
        Backend::Never => assert!(
            observed.is_empty(),
            "{protocol} {}: request must never reach a backend ({}), backend saw {observed:?}",
            case.target,
            case.why
        ),
    }
}

#[ignore]
#[tokio::test]
async fn functional_policy_path_canonicalization_is_identical_across_h1_h2_h3() {
    let backend = RecordingBackend::start().await;
    let (mut gateway, https_port) = spawn_gateway(backend.port, None).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(15))
        .await
        .expect("proxy port ready");
    let proxy_port = gateway.proxy_port;

    // Drain anything a readiness probe may have produced before the matrix.
    let _ = backend.take_targets();

    for case in CASES {
        let status = send_h1(proxy_port, case.target).await;
        assert_case("H1", case, status, backend.take_targets());
    }

    for case in CASES {
        let status = send_h2(proxy_port, case.target).await;
        assert_case("H2", case, status, backend.take_targets());
    }

    let h3 = Http3Client::insecure().expect("H3 client");
    for case in CASES {
        let status = send_h3(&h3, https_port, case.target).await;
        assert_case("H3", case, status, backend.take_targets());
    }

    assert!(
        backend.targets().is_empty(),
        "no stray backend traffic should remain"
    );

    gateway.shutdown();
}

fn assert_native_grpc_path_rejection(
    protocol: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) {
    assert_eq!(status, StatusCode::OK, "{protocol}: gRPC uses HTTP 200");
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc"),
        "{protocol}: native gRPC content type"
    );
    assert_eq!(
        headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("3"),
        "{protocol}: canonical-path rejection is INVALID_ARGUMENT"
    );
    assert!(body.is_empty(), "{protocol}: trailers-only body");
}

fn assert_grpc_web_path_rejection(
    protocol: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) {
    assert_eq!(
        status,
        StatusCode::OK,
        "{protocol}: gRPC-Web errors use HTTP 200"
    );
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web+proto"),
        "{protocol}: gRPC-Web response representation"
    );
    assert!(
        !headers.contains_key("grpc-status") && !headers.contains_key("grpc-message"),
        "{protocol}: terminal metadata stays in the body trailer frame"
    );

    let mut remaining = body;
    let mut trailer = None;
    while remaining.len() >= 5 {
        let flag = remaining[0];
        let length =
            u32::from_be_bytes([remaining[1], remaining[2], remaining[3], remaining[4]]) as usize;
        assert!(
            remaining.len() >= 5 + length,
            "{protocol}: complete gRPC-Web frame"
        );
        let payload = &remaining[5..5 + length];
        if flag == 0x80 {
            trailer = Some(payload);
            break;
        }
        remaining = &remaining[5 + length..];
    }
    let trailer = trailer.unwrap_or_else(|| panic!("{protocol}: missing gRPC-Web trailer frame"));
    let trailer = String::from_utf8_lossy(trailer);
    assert!(
        trailer.contains("grpc-status: 3\r\n"),
        "{protocol}: canonical-path rejection is INVALID_ARGUMENT: {trailer:?}"
    );
    assert!(
        !trailer.contains("%2F"),
        "{protocol}: response must not echo attacker-controlled target bytes"
    );
}

#[ignore]
#[tokio::test]
async fn functional_policy_path_rejection_preserves_rpc_wire_shapes() {
    const TARGET: &str = "/canon/a%2Fb";
    const GRPC: &str = "application/grpc";
    const GRPC_WEB: &str = "application/grpc-web+proto";

    let backend = RecordingBackend::start().await;
    let (mut gateway, https_port) = spawn_gateway(backend.port, None).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(15))
        .await
        .expect("proxy port ready");
    let proxy_port = gateway.proxy_port;
    let _ = backend.take_targets();

    let h1_web = send_h1_rpc(proxy_port, TARGET, GRPC_WEB).await;
    assert_grpc_web_path_rejection("H1 gRPC-Web", h1_web.status, &h1_web.headers, &h1_web.body);

    let h2_grpc = send_h2_rpc(proxy_port, TARGET, GRPC).await;
    assert_native_grpc_path_rejection("H2 gRPC", h2_grpc.status, &h2_grpc.headers, &h2_grpc.body);
    let h2_web = send_h2_rpc(proxy_port, TARGET, GRPC_WEB).await;
    assert_grpc_web_path_rejection("H2 gRPC-Web", h2_web.status, &h2_web.headers, &h2_web.body);

    let h3 = Http3Client::insecure().expect("H3 client");
    let h3_grpc = send_h3_rpc(&h3, https_port, TARGET, GRPC).await;
    assert_native_grpc_path_rejection(
        "H3 gRPC",
        h3_grpc.status,
        &h3_grpc.headers,
        &h3_grpc.body_bytes,
    );
    assert!(
        h3_grpc.trailers.is_none(),
        "H3 gRPC rejection is trailers-only initial headers"
    );
    let h3_web = send_h3_rpc(&h3, https_port, TARGET, GRPC_WEB).await;
    assert_grpc_web_path_rejection(
        "H3 gRPC-Web",
        h3_web.status,
        &h3_web.headers,
        &h3_web.body_bytes,
    );
    assert!(
        h3_web.trailers.is_none(),
        "H3 gRPC-Web must not emit native trailers"
    );

    assert!(
        backend.take_targets().is_empty(),
        "canonical-path RPC rejects must never reach a backend"
    );
    gateway.shutdown();
}

// ============================================================================
// ACME HTTP-01 shares the one canonical coordinate
// ============================================================================

/// Token and key authorization of the order seeded below. The token is
/// deliberately spellable with escapes of `pchar`-legal bytes (`%74` = `t`,
/// `%5F` = `_`, `%2D` = `-`), which is what makes the raw-path regression
/// reachable.
const ACME_TOKEN: &str = "tok_ABC-123";
const ACME_KEY_AUTHORIZATION: &str = "tok_ABC-123.policy-path-thumbprint";

/// Persist a pending HTTP-01 order before the child opens its process-global
/// order store, using the same `AcmeOrderStore` mechanism production order
/// creation uses.
fn seed_pending_http01_order(store_dir: &std::path::Path) {
    let store = AcmeOrderStore::open(store_dir).expect("open ACME order store");
    let order = AcmeOrderRecord::new_http01(AcmeHttp01OrderInput {
        id: "policy-path-http01-order".to_string(),
        certificate_id: None,
        domains: vec!["policy-path.example.com".to_string()],
        directory_url: "https://acme.test/directory".to_string(),
        account_id: None,
        account_credentials_json: None,
        order_url: Some("https://acme.test/order/policy-path".to_string()),
        status: AcmeOrderStatus::PendingChallenges,
        http01_challenges: vec![AcmeHttp01ChallengeRecord {
            identifier: "policy-path.example.com".to_string(),
            token: ACME_TOKEN.to_string(),
            key_authorization: ACME_KEY_AUTHORIZATION.to_string(),
        }],
        tls_alpn01_challenges: Vec::new(),
        dns01_challenges: Vec::new(),
        error: None,
    })
    .expect("build ACME order");
    store
        .upsert_order(order, false)
        .expect("persist ACME order");
}

/// What an ACME-shaped target must produce.
enum Acme {
    /// The pending challenge is served: exactly the key-authorization bytes.
    KeyAuthorization,
    /// The central canonicalization boundary refuses it with this fixed body.
    /// ACME must not have normalized or accepted the spelling on the way past.
    Refused(&'static str),
    /// No challenge, no rejection: the request continues through the single
    /// request boundary onto ordinary routing, which has no such route.
    RoutedAndUnmatched,
}

struct AcmeCase {
    target: &'static str,
    status: u16,
    outcome: Acme,
    why: &'static str,
}

/// HTTP-01 is answered before overload admission, so it is the one handler that
/// establishes its own request coordinate. These cases pin it to the *same*
/// coordinate everything else uses. Only HTTP/1.1 is exercised: the ACME lookup
/// lives in `handle_proxy_request_on_frontend_port`, which H1 and H2 enter
/// identically, and H3 never serves HTTP-01 at all — the per-protocol parity
/// that does matter is the canonicalizer itself, covered by the matrix above.
const ACME_CASES: &[AcmeCase] = &[
    AcmeCase {
        target: "/.well-known/acme-challenge/tok_ABC-123",
        status: 200,
        outcome: Acme::KeyAuthorization,
        why: "the literal challenge coordinate is still served",
    },
    // The regression: before the ACME lookup consumed the canonical path, an
    // escaped-but-legal spelling missed the handler, canonicalized a moment
    // later, and fell through to routing and backend handling.
    AcmeCase {
        target: "/%2Ewell-known/acme-challenge/tok_ABC-123",
        status: 200,
        outcome: Acme::KeyAuthorization,
        why: "an escaped prefix byte resolves the same challenge",
    },
    AcmeCase {
        target: "/.well-known/acme-challenge/tok%5FABC-123",
        status: 200,
        outcome: Acme::KeyAuthorization,
        why: "an escaped base64url token byte resolves the same challenge",
    },
    AcmeCase {
        target: "/%2ewell-known/acme-challenge/%74ok%5fABC%2D123",
        status: 200,
        outcome: Acme::KeyAuthorization,
        why: "escapes throughout, in mixed hex case, are one coordinate",
    },
    // Ambiguous ACME-shaped targets still reach the central rejection. ACME is
    // not a second place that decides what a path means.
    AcmeCase {
        target: "/.well-known/acme-challenge/tok%2FABC-123",
        status: 400,
        outcome: Acme::Refused(r#"{"error":"Request path contains an encoded path separator"}"#),
        why: "an encoded separator is refused, not folded into a token",
    },
    AcmeCase {
        target: "/.well-known/acme-challenge/tok%20ABC-123",
        status: 400,
        outcome: Acme::Refused(
            r#"{"error":"Request path contains an unrepresentable percent-escape"}"#,
        ),
        why: "an unrepresentable escape is refused for an ACME-shaped target too",
    },
    AcmeCase {
        target: "/.well-known/acme-challenge/../canon/blocked",
        status: 400,
        outcome: Acme::Refused(r#"{"error":"Request path contains a dot segment"}"#),
        why: "a dot segment is refused before it can escape the challenge prefix",
    },
    AcmeCase {
        target: "/.well-known/acme-challenge/tok%252FABC-123",
        status: 400,
        outcome: Acme::Refused(
            r#"{"error":"Request path contains a double-encoded percent-escape"}"#,
        ),
        why: "a double encoding cannot survive a second decode",
    },
    // No live challenge: the request must continue through the ordinary
    // coordinate rather than be answered by ACME either way.
    AcmeCase {
        target: "/.well-known/acme-challenge/not_a_live_token",
        status: 404,
        outcome: Acme::RoutedAndUnmatched,
        why: "an unknown token falls through to routing",
    },
    AcmeCase {
        target: "/%2Ewell-known/acme-challenge/not_a_live_token",
        status: 404,
        outcome: Acme::RoutedAndUnmatched,
        why: "an escaped spelling of an unknown token falls through identically",
    },
];

#[ignore]
#[tokio::test]
async fn functional_acme_http01_shares_the_canonical_policy_path() {
    let store_dir = TempDir::new().expect("acme store temp dir");
    seed_pending_http01_order(store_dir.path());

    let backend = RecordingBackend::start().await;
    let (mut gateway, _https_port) = spawn_gateway(backend.port, Some(store_dir.path())).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(15))
        .await
        .expect("proxy port ready");
    let proxy_port = gateway.proxy_port;

    let _ = backend.take_targets();

    for case in ACME_CASES {
        let (status, body) = send_h1_full(proxy_port, case.target).await;
        assert_eq!(
            status, case.status,
            "{}: expected {} ({}), got {status} with body {body:?}",
            case.target, case.status, case.why
        );
        match case.outcome {
            Acme::KeyAuthorization => assert_eq!(
                body, ACME_KEY_AUTHORIZATION,
                "{}: must serve the key authorization ({})",
                case.target, case.why
            ),
            Acme::Refused(expected_body) => {
                assert_eq!(
                    body, expected_body,
                    "{}: must carry the fixed rejection body ({})",
                    case.target, case.why
                );
                assert!(
                    !body.contains('%') && !body.contains(ACME_TOKEN),
                    "{}: the rejection body must not echo request bytes",
                    case.target
                );
            }
            Acme::RoutedAndUnmatched => assert!(
                body.contains("Not Found"),
                "{}: must fall through to routing ({}), got body {body:?}",
                case.target,
                case.why
            ),
        }
        assert!(
            backend.take_targets().is_empty(),
            "{}: no ACME-shaped target may reach a backend ({})",
            case.target,
            case.why
        );
    }

    gateway.shutdown();
}
