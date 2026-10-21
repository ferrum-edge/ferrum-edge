//! **Transport-level** coverage for Unix-domain-socket backends (issue #3261).
//!
//! These tests exercise the dispatch half of the feature: given a route whose
//! upstream target carries the reserved `mesh.unix_socket` tag, the HTTP path
//! must dial a `tokio::net::UnixStream` (never the placeholder `host:port`),
//! preserve the request target and headers, fail closed on an absent socket, and
//! survive reload/update/delete.
//!
//! Tags are applied through the **trusted projection** boundary
//! (`TrustedProjectedGateway` → in-process `file::serve` /
//! `ProxyState::update_config`), the same path production mesh materialization
//! uses. Operator file-mode / admin inputs must continue rejecting every
//! `mesh.*` tag; that fail-closed contract is covered by unit tests under
//! `tests/unit/config/`. The end-to-end Sidecar `ingress[]` translation path
//! remains in `functional_mesh_sidecar_ingress_unix_socket_serves_live_traffic`.
//!
//! Every test configures `FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` (via env
//! config) to its own temp directory. With no roots configured the containment
//! gate refuses every Unix backend, which is the shipped default. The temp path
//! is canonicalized first because the dial-time gate compares the
//! SYMLINK-RESOLVED path against the roots (macOS `/var` → `/private/var`
//! would otherwise read as an escape).
//!
//! Unix-only: there is no Unix-domain socket transport on Windows.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{TrustedProjectedGateway, TrustedProjectedGatewayOptions};

use ferrum_edge::config::EnvConfig;
use ferrum_edge::proxy::ConfigApplyOutcome;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};

/// A minimal HTTP/1.1 server on a Unix-domain stream socket. Answers every
/// request with `name` so a test can prove WHICH socket served it.
struct UnixBackend {
    path: PathBuf,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl UnixBackend {
    async fn start(dir: &Path, file_name: &str, name: &'static str) -> Self {
        let path = dir.join(file_name);
        let listener = UnixListener::bind(&path).expect("bind unix backend socket");
        let hits = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve_unix_backend(listener, name, Arc::clone(&hits)));
        Self { path, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for UnixBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_unix_backend(listener: UnixListener, name: &'static str, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            hits.fetch_add(1, Ordering::SeqCst);
            let request_line = request.lines().next().unwrap_or("").to_string();
            let host = request
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                .map(|line| line["host:".len()..].trim().to_string())
                .unwrap_or_default();
            let body = format!("{name}|{request_line}|{host}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        });
    }
}

/// Trusted-projected fixture YAML: one HTTP route per named upstream, each
/// upstream's single target carrying the `mesh.unix_socket` tag for
/// `socket_path`.
///
/// `backend_host`/`backend_port` are the same never-dialed placeholder the mesh
/// materializer stamps: a bound-but-unused loopback port. If the Unix transport
/// gate ever regressed to a TCP fallback, the request would hit that port
/// instead — which is exactly why the tests below assert on the socket's own
/// response body rather than merely on a 200.
fn build_config(entries: &[(&str, &str, &str)], placeholder_port: u16, generation: u32) -> String {
    let stamp = format!("2026-08-08T00:00:{generation:02}Z");
    let mut proxies = String::new();
    let mut upstreams = String::new();
    for (id, listen_path, socket_path) in entries {
        proxies.push_str(&format!(
            r#"  - id: "{id}"
    listen_path: "{listen_path}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {placeholder_port}
    upstream_id: "{id}-upstream"
    strip_listen_path: false
    preserve_host_header: true
    pool_enable_http2: false
    updated_at: "{stamp}"
"#
        ));
        upstreams.push_str(&format!(
            r#"  - id: "{id}-upstream"
    name: "{id}-upstream"
    algorithm: round_robin
    updated_at: "{stamp}"
    targets:
      - host: "127.0.0.1"
        port: {placeholder_port}
        weight: 1
        tags:
          mesh.unix_socket: "{socket_path}"
          mesh.unix_socket_h2c: "false"
"#
        ));
    }
    format!(
        r#"version: "1"
proxies:
{proxies}
upstreams:
{upstreams}
consumers: []
plugin_configs: []
"#
    )
}

async fn wait_for_body(
    client: &reqwest::Client,
    url: &str,
    context: &str,
    mut ready: impl FnMut(u16, &str) -> bool,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let last = match client.get(url).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if ready(status, &body) {
                    return body;
                }
                format!("status={status} body={body:?}")
            }
            Err(err) => format!("request error: {err}"),
        };
        if Instant::now() >= deadline {
            panic!("{context}: behavior did not appear; last observation: {last}");
        }
        sleep(Duration::from_millis(150)).await;
    }
}

fn containment_root(temp: &TempDir) -> PathBuf {
    temp.path()
        .canonicalize()
        .expect("canonicalize temp dir for the unix-socket containment root")
}

async fn reserve_placeholder_port() -> (u16, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind placeholder port");
    let port = listener.local_addr().expect("placeholder addr").port();
    (port, listener)
}

async fn spawn_unix_gateway(config: String, root: &Path) -> TrustedProjectedGateway {
    let env = EnvConfig {
        pool_warmup_enabled: false,
        log_level: "warn".into(),
        ..Default::default()
    };
    TrustedProjectedGateway::spawn_from_yaml(
        &config,
        TrustedProjectedGatewayOptions {
            env,
            mesh_unix_socket_allowed_roots: vec![
                root.to_str().expect("utf-8 containment root").to_string(),
            ],
            ..TrustedProjectedGatewayOptions::default()
        },
    )
    .await
    .expect("start trusted projected unix gateway")
}

#[tokio::test]
#[ignore]
async fn unix_socket_backend_serves_requests_over_a_real_socket() {
    let temp = TempDir::new().expect("temp dir");
    let root = containment_root(&temp);
    let backend = UnixBackend::start(&root, "app.sock", "alpha").await;
    let (placeholder_port, _placeholder) = reserve_placeholder_port().await;

    let config = build_config(
        &[(
            "unix-route",
            "/unix",
            backend.path.to_str().expect("utf-8 socket path"),
        )],
        placeholder_port,
        0,
    );
    let mut gateway = spawn_unix_gateway(config, &root).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");
    let body = wait_for_body(
        &client,
        &gateway.proxy_url("/unix?q=1"),
        "unix backend first response",
        |status, _| status == 200,
    )
    .await;

    let parts: Vec<&str> = body.split('|').collect();
    assert_eq!(parts[0], "alpha", "the unix socket served the request");
    assert_eq!(
        parts[1], "GET /unix?q=1 HTTP/1.1",
        "the request target (path + query) is preserved byte-for-byte over the unix transport"
    );
    assert!(
        !parts[2].is_empty(),
        "the gateway forwards a Host header to the unix backend, got {body:?}"
    );
    assert!(backend.hits() >= 1, "the unix socket observed the request");
    gateway.shutdown().await;
}

#[tokio::test]
#[ignore]
async fn unix_socket_backend_fails_closed_when_the_socket_is_absent() {
    let temp = TempDir::new().expect("temp dir");
    let root = containment_root(&temp);
    let missing = root.join("absent.sock");
    let (placeholder_port, _placeholder) = reserve_placeholder_port().await;

    let config = build_config(
        &[(
            "unix-route",
            "/unix",
            missing.to_str().expect("utf-8 socket path"),
        )],
        placeholder_port,
        0,
    );
    let mut gateway = spawn_unix_gateway(config, &root).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");
    let response = client
        .get(gateway.proxy_url("/unix"))
        .send()
        .await
        .expect("gateway answers");
    assert_eq!(
        response.status().as_u16(),
        502,
        "a missing unix socket is a pre-wire backend failure, not a TCP fallback"
    );
    gateway.shutdown().await;
}

/// Reload/update/delete via trusted `update_config` (mesh projection boundary),
/// not SIGHUP/file-loader — operator file reload must keep rejecting `mesh.*`.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn unix_socket_backend_survives_reload_update_and_delete() {
    let temp = TempDir::new().expect("temp dir");
    let root = containment_root(&temp);
    let alpha = UnixBackend::start(&root, "alpha.sock", "alpha").await;
    let beta = UnixBackend::start(&root, "beta.sock", "beta").await;
    let (placeholder_port, _placeholder) = reserve_placeholder_port().await;

    let alpha_path = alpha.path.to_str().expect("utf-8 socket path").to_string();
    let beta_path = beta.path.to_str().expect("utf-8 socket path").to_string();

    let mut gateway = spawn_unix_gateway(
        build_config(&[("unix-route", "/unix", &alpha_path)], placeholder_port, 0),
        &root,
    )
    .await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");

    wait_for_body(
        &client,
        &gateway.proxy_url("/unix"),
        "initial alpha socket",
        |status, body| status == 200 && body.starts_with("alpha|"),
    )
    .await;

    // UPDATE: re-point the same route at a different socket.
    let outcome = gateway.apply_projected_yaml(&build_config(
        &[("unix-route", "/unix", &beta_path)],
        placeholder_port,
        1,
    ));
    assert!(
        matches!(outcome, ConfigApplyOutcome::Applied),
        "unix backend retarget must apply via trusted projection, got {outcome:?}"
    );
    wait_for_body(
        &client,
        &gateway.proxy_url("/unix"),
        "reloaded beta socket",
        |status, body| status == 200 && body.starts_with("beta|"),
    )
    .await;
    assert!(beta.hits() >= 1, "the re-pointed socket served traffic");

    // DELETE: remove the route entirely; the path must stop resolving rather
    // than keep dialing a stale socket.
    let outcome = gateway.apply_projected_yaml(&build_config(
        &[("other-route", "/other", &alpha_path)],
        placeholder_port,
        2,
    ));
    assert!(
        matches!(outcome, ConfigApplyOutcome::Applied),
        "unix backend route replacement must apply via trusted projection, got {outcome:?}"
    );
    wait_for_body(
        &client,
        &gateway.proxy_url("/unix"),
        "deleted unix route",
        |status, _| status == 404,
    )
    .await;

    // The surviving route still works, proving the delete was surgical.
    wait_for_body(
        &client,
        &gateway.proxy_url("/other"),
        "surviving unix route",
        |status, body| status == 200 && body.starts_with("alpha|"),
    )
    .await;
    gateway.shutdown().await;
}

/// Trusted-projected fixture: one native-gRPC route on an h2c Unix-socket
/// target, with a retry policy so the gateway buffers the upload before
/// dispatch.
fn grpc_h2c_config(socket_path: &str, placeholder_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "unix-grpc"
    listen_path: "/grpc"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {placeholder_port}
    upstream_id: "unix-grpc-upstream"
    strip_listen_path: true
    retry:
      max_retries: 1
      retry_on_connect_failure: true
    updated_at: "2026-10-09T00:00:00Z"
upstreams:
  - id: "unix-grpc-upstream"
    name: "unix-grpc-upstream"
    algorithm: round_robin
    updated_at: "2026-10-09T00:00:00Z"
    targets:
      - host: "127.0.0.1"
        port: {placeholder_port}
        weight: 1
        tags:
          mesh.unix_socket: "{socket_path}"
          mesh.unix_socket_h2c: "true"
consumers: []
plugin_configs: []
"#
    )
}

/// Issue #6022: a native gRPC upload the request-buffer budget cannot admit,
/// refused at a backend-dispatch seam (here the Unix-socket body preparation),
/// is a Trailers-Only `RESOURCE_EXHAUSTED`, not a bare `503` its client would
/// read as `UNAVAILABLE`. The upload's retained ceiling
/// (`max_grpc_recv_size_bytes`, 1 GiB) is larger than the whole request-buffer
/// budget (256 MiB by default; the in-process gateway never resizes it), so the
/// refusal is deterministic and comes before any byte is read or the socket is
/// dialed.
#[tokio::test]
#[ignore]
async fn unix_h2c_grpc_buffer_capacity_refusal_is_resource_exhausted() {
    assert_unix_grpc_buffer_capacity_refusal(false).await;
}

#[tokio::test]
#[ignore]
async fn unix_h2c_translated_grpc_web_buffer_capacity_refusal_is_resource_exhausted() {
    assert_unix_grpc_buffer_capacity_refusal(true).await;
}

async fn assert_unix_grpc_buffer_capacity_refusal(grpc_web: bool) {
    use bytes::Bytes;

    let temp = TempDir::new().expect("temp dir");
    let root = containment_root(&temp);
    let socket_path = root.join("grpc.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind grpc socket");
    let dials = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&dials);
    let acceptor = tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
        }
    });
    let (placeholder_port, _placeholder) = reserve_placeholder_port().await;

    let mut config = grpc_h2c_config(
        socket_path.to_str().expect("utf-8 socket path"),
        placeholder_port,
    );
    if grpc_web {
        config = config.replace(
            "    strip_listen_path: true",
            "    strip_listen_path: true\n    plugins:\n      - plugin_config_id: \"grpc-web\"",
        );
        config = config.replace(
            "plugin_configs: []",
            r#"plugin_configs:
  - id: "grpc-web"
    plugin_name: "grpc_web"
    scope: "proxy"
    proxy_id: "unix-grpc"
    enabled: true
    config: {}"#,
        );
    }
    let env = EnvConfig {
        pool_warmup_enabled: false,
        log_level: "warn".into(),
        max_grpc_recv_size_bytes: 1 << 30,
        ..Default::default()
    };
    let mut gateway = TrustedProjectedGateway::spawn_from_yaml(
        &config,
        TrustedProjectedGatewayOptions {
            env,
            mesh_unix_socket_allowed_roots: vec![
                root.to_str().expect("utf-8 containment root").to_string(),
            ],
            ..TrustedProjectedGatewayOptions::default()
        },
    )
    .await
    .expect("start trusted projected unix gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let port = gateway.proxy_http_port;
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("h2c socket");
    let (client, connection) = h2::client::handshake(socket).await.expect("frontend h2");
    let driver = tokio::spawn(connection);
    let mut client = client.ready().await.expect("client ready");
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}/grpc/echo.Echo/Upload"))
        .header(
            "content-type",
            if grpc_web {
                "application/grpc-web+proto"
            } else {
                "application/grpc"
            },
        )
        .header("te", "trailers")
        .body(())
        .expect("request");
    let (response, mut upload) = client.send_request(request, false).expect("open RPC");
    let message = Bytes::from_static(&[0, 0, 0, 0, 4, b'p', b'i', b'n', b'g']);
    upload.send_data(message, true).expect("unary message");
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("response timeout")
        .expect("response");
    // gRPC errors ride HTTP 200.
    assert_eq!(response.status(), http::StatusCode::OK);
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    if grpc_web {
        assert_eq!(
            header("content-type").as_deref(),
            Some("application/grpc-web+proto")
        );
        assert_eq!(header("grpc-status"), None);
        assert_eq!(header("grpc-message"), None);
        assert_eq!(header("grpc-status-details-bin"), None);
    } else {
        assert_eq!(header("grpc-status").as_deref(), Some("8"));
        assert_eq!(
            header("grpc-message").as_deref(),
            Some("Request buffering capacity exceeded")
        );
    }
    let mut body = response.into_body();
    let data = tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("response DATA");
            body.flow_control()
                .release_capacity(chunk.len())
                .expect("release capacity");
            bytes.extend_from_slice(&chunk);
        }
        bytes
    })
    .await
    .expect("response body timeout");
    if grpc_web {
        assert!(data.len() >= 5, "a complete gRPC-Web frame header");
        assert_eq!(data[0], 0x80, "one gRPC-Web trailer frame");
        assert_eq!(
            u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize,
            data.len() - 5
        );
        let trailers = std::str::from_utf8(&data[5..]).expect("terminal metadata");
        assert!(trailers.contains("grpc-status: 8\r\n"));
        assert!(trailers.contains("grpc-message: Request buffering capacity exceeded\r\n"));
        assert!(body.trailers().await.expect("HTTP trailers").is_none());
    } else {
        assert!(data.is_empty(), "a Trailers-Only response has no DATA");
    }
    assert_eq!(
        dials.load(Ordering::SeqCst),
        0,
        "the refused upload must never dial the unix socket"
    );

    driver.abort();
    acceptor.abort();
    gateway.shutdown().await;
}

// ── Issue #6776: relayed client upload aborts are not backend failures ────
//
// The Unix-socket pool (HTTP/1.1) and the Sidecar `ingress[]` h2c transport
// (which runs the sidecar mesh-mTLS dispatcher) hand the client upload to a
// pooled hyper client. When the client disappears mid-upload, the gateway
// relays that failure into the backend exchange, and `send_request` fails
// before any response head. That failure is the client's, so a hair-trigger
// circuit breaker must stay closed. The controls prove the same breaker DOES
// open when the backend itself fails the upload, so the negative assertion is
// not vacuous.

/// What the upload backend does once the first upload bytes arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UploadBackendMode {
    /// Keep reading the upload; answer `200 complete` only if it completes.
    HoldUntilComplete,
    /// Fail the exchange itself: close the HTTP/1.1 connection, or reset the
    /// h2c stream with `CANCEL`.
    FailMidUpload,
}

/// Backend events, in order: `upload_head` once the first upload bytes
/// arrived, `upload_aborted` once the gateway ended the upload.
type BackendEvents = mpsc::UnboundedSender<&'static str>;

const COMPLETE_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ncomplete";

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn handle_upload_h1(
    mut stream: tokio::net::UnixStream,
    mode: UploadBackendMode,
    events: BackendEvents,
) {
    let mut seen = Vec::new();
    let mut buf = vec![0u8; 8192];
    let head_end = loop {
        if let Some(pos) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    };
    if seen.starts_with(b"GET ") {
        let _ = stream.write_all(COMPLETE_RESPONSE).await;
        let _ = stream.flush().await;
        return;
    }
    let _ = events.send("upload_head");
    if mode == UploadBackendMode::FailMidUpload {
        drop(stream);
        return;
    }
    loop {
        if contains_subslice(&seen[head_end..], b"0\r\n\r\n") {
            let _ = stream.write_all(COMPLETE_RESPONSE).await;
            let _ = stream.flush().await;
            return;
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = events.send("upload_aborted");
                return;
            }
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
}

async fn handle_upload_h2c(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    mode: UploadBackendMode,
    events: BackendEvents,
) {
    let complete = |mut respond: h2::server::SendResponse<bytes::Bytes>| {
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("complete response");
        if let Ok(mut send) = respond.send_response(response, false) {
            let _ = send.send_data(bytes::Bytes::from_static(b"complete"), true);
        }
    };
    if *request.method() == http::Method::GET {
        complete(respond);
        return;
    }
    let mut body = request.into_body();
    match body.data().await {
        Some(Ok(chunk)) => {
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        _ => return,
    }
    let _ = events.send("upload_head");
    if mode == UploadBackendMode::FailMidUpload {
        respond.send_reset(h2::Reason::CANCEL);
        return;
    }
    loop {
        match body.data().await {
            Some(Ok(chunk)) => {
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            Some(Err(_)) => {
                let _ = events.send("upload_aborted");
                return;
            }
            None => {
                complete(respond);
                return;
            }
        }
    }
}

async fn serve_upload_backend(
    listener: UnixListener,
    h2c: bool,
    mode: UploadBackendMode,
    events: BackendEvents,
) {
    while let Ok((stream, _)) = listener.accept().await {
        let events = events.clone();
        if h2c {
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                while let Some(Ok((request, respond))) = connection.accept().await {
                    tokio::spawn(handle_upload_h2c(request, respond, mode, events.clone()));
                }
            });
        } else {
            tokio::spawn(handle_upload_h1(stream, mode, events));
        }
    }
}

/// One HTTP route on a Unix-socket target with a hair-trigger circuit breaker:
/// a single `502` / `504` (or connection error) opens it for the rest of the
/// test, so every later request would be refused with `503`. An `http_logging`
/// sink receives every terminal transaction summary, which is the barrier the
/// tests wait on: the summary is emitted only after the dispatch outcome has
/// been fed to the circuit breaker.
fn circuit_breaker_unix_config(
    socket_path: &str,
    placeholder_port: u16,
    h2c: bool,
    sink_port: u16,
) -> String {
    let h1_only = if h2c {
        ""
    } else {
        "\n    pool_enable_http2: false"
    };
    format!(
        r#"version: "1"
proxies:
  - id: "unix-cb"
    listen_path: "/unix-cb"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {placeholder_port}
    upstream_id: "unix-cb-upstream"
    strip_listen_path: false
    preserve_host_header: true{h1_only}
    circuit_breaker:
      failure_threshold: 1
      timeout_seconds: 300
      failure_status_codes: [400, 499, 502, 504]
      trip_on_connection_errors: true
    updated_at: "2026-10-21T00:00:00Z"
upstreams:
  - id: "unix-cb-upstream"
    name: "unix-cb-upstream"
    algorithm: round_robin
    updated_at: "2026-10-21T00:00:00Z"
    targets:
      - host: "127.0.0.1"
        port: {placeholder_port}
        weight: 1
        tags:
          mesh.unix_socket: "{socket_path}"
          mesh.unix_socket_h2c: "{h2c}"
consumers: []
plugin_configs:
  - id: "unix-cb-http-log"
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

/// Request path of the upload under test, as the transaction summary logs it.
const UPLOAD_PATH: &str = "/unix-cb/upload";

/// Open a raw HTTP/1.1 chunked upload through the gateway and send its first
/// chunk, leaving the body unfinished.
async fn start_chunked_upload(proxy_port: u16) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to the gateway");
    stream
        .write_all(
            b"POST /unix-cb/upload HTTP/1.1\r\nHost: unix-cb.test\r\n\
              Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
        )
        .await
        .expect("send the request head and first chunk");
    stream.flush().await.expect("flush the first chunk");
    stream
}

/// Read the gateway's response head from a raw upload connection.
async fn read_response_head(upload: &mut tokio::net::TcpStream) -> String {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(10), async {
        while !contains_subslice(&head, b"\r\n\r\n") {
            match upload.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await
    .expect("the gateway answers the failed upload");
    String::from_utf8_lossy(&head).into_owned()
}

async fn expect_backend_event(
    events: &mut mpsc::UnboundedReceiver<&'static str>,
    expected: &'static str,
) {
    let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for backend event {expected}"))
        .expect("backend event channel open");
    assert_eq!(event, expected, "unexpected backend event order");
}

type LoggedSummaries = Arc<std::sync::Mutex<Vec<serde_json::Value>>>;

/// Minimal HTTP/1.1 sink recording the JSON transaction summaries the
/// `http_logging` plugin posts (the in-process gateway's stdout is not
/// captured).
async fn start_http_logging_sink() -> (u16, LoggedSummaries) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind http_logging sink");
    let port = listener.local_addr().expect("sink addr").port();
    let entries: LoggedSummaries = Arc::default();
    let captured = Arc::clone(&entries);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let captured = Arc::clone(&captured);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                let body = loop {
                    if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..pos]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if request.len() >= pos + 4 + length {
                            break request[pos + 4..pos + 4 + length].to_vec();
                        }
                    }
                    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
                    {
                        Ok(Ok(n)) if n > 0 => request.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                };
                if let Ok(posted) = serde_json::from_slice::<serde_json::Value>(&body)
                    && let Ok(mut guard) = captured.lock()
                {
                    match posted {
                        serde_json::Value::Array(batch) => guard.extend(batch),
                        entry => guard.push(entry),
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, entries)
}

struct UploadFixture {
    _temp: TempDir,
    _placeholder: tokio::net::TcpListener,
    backend: tokio::task::JoinHandle<()>,
    events: mpsc::UnboundedReceiver<&'static str>,
    summaries: LoggedSummaries,
    gateway: TrustedProjectedGateway,
    client: reqwest::Client,
}

impl UploadFixture {
    async fn start(h2c: bool, mode: UploadBackendMode) -> Self {
        let temp = TempDir::new().expect("temp dir");
        let root = containment_root(&temp);
        let socket_path = root.join("upload.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind upload socket");
        let (events_tx, events) = mpsc::unbounded_channel();
        let backend = tokio::spawn(serve_upload_backend(listener, h2c, mode, events_tx));
        let (placeholder_port, placeholder) = reserve_placeholder_port().await;
        let (sink_port, summaries) = start_http_logging_sink().await;
        let config = circuit_breaker_unix_config(
            socket_path.to_str().expect("utf-8 socket path"),
            placeholder_port,
            h2c,
            sink_port,
        );
        let mut gateway = spawn_unix_gateway(config, &root).await;
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build client");
        // A complete request is served before anything else happens.
        wait_for_body(
            &client,
            &gateway.proxy_url("/unix-cb/ready"),
            "unix upload backend first response",
            |status, body| status == 200 && body == "complete",
        )
        .await;
        Self {
            _temp: temp,
            _placeholder: placeholder,
            backend,
            events,
            summaries,
            gateway,
            client,
        }
    }

    async fn get_status(&self, path: &str) -> u16 {
        self.client
            .get(self.gateway.proxy_url(path))
            .send()
            .await
            .expect("gateway answers")
            .status()
            .as_u16()
    }

    /// Wait for the upload's terminal transaction summary, the positive
    /// barrier that its dispatch outcome has already reached the circuit
    /// breaker, and return it after checking it is the only one.
    async fn upload_summary(&self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let uploads: Vec<serde_json::Value> = self
                .summaries
                .lock()
                .map(|guard| {
                    guard
                        .iter()
                        .filter(|entry| entry["request_path"] == UPLOAD_PATH)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            if !uploads.is_empty() {
                // Give a duplicate a chance to show up before asserting one.
                sleep(Duration::from_millis(300)).await;
                let uploads: Vec<serde_json::Value> = self
                    .summaries
                    .lock()
                    .map(|guard| {
                        guard
                            .iter()
                            .filter(|entry| entry["request_path"] == UPLOAD_PATH)
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                assert_eq!(
                    uploads.len(),
                    1,
                    "exactly one terminal summary for the upload: {uploads:?}"
                );
                return uploads[0].clone();
            }
            assert!(
                Instant::now() < deadline,
                "the upload's terminal transaction summary was never logged"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    async fn assert_breaker_closed(&self, context: &str) {
        for attempt in 0..3 {
            assert_eq!(
                self.get_status("/unix-cb/after").await,
                200,
                "{context}: the backend's circuit breaker must stay closed (attempt {attempt})"
            );
        }
    }

    async fn shutdown(mut self) {
        self.backend.abort();
        self.gateway.shutdown().await;
    }
}

async fn assert_client_upload_abort_is_not_charged(h2c: bool) {
    let mut fixture = UploadFixture::start(h2c, UploadBackendMode::HoldUntilComplete).await;

    let upload = start_chunked_upload(fixture.gateway.proxy_http_port).await;
    expect_backend_event(&mut fixture.events, "upload_head").await;
    // The client's connection is reset while the backend is still reading its
    // upload and before any response head: typed proof it is gone, which the
    // gateway relays into the backend.
    upload.set_zero_linger().expect("set abortive close");
    drop(upload);
    expect_backend_event(&mut fixture.events, "upload_aborted").await;

    let summary = fixture.upload_summary().await;
    assert_eq!(
        summary["response_status_code"], 499,
        "h2c={h2c}: a proven client abort is a client-closed request: {summary}"
    );
    assert_eq!(summary["error_class"], "client_disconnect", "{summary}");
    assert_eq!(
        summary["client_disconnected"], true,
        "h2c={h2c}: the proven abort reaches the disconnect accounting: {summary}"
    );
    fixture
        .assert_breaker_closed(&format!("h2c={h2c}: a relayed client upload abort"))
        .await;
    fixture.shutdown().await;
}

async fn assert_half_closed_client_upload_is_a_400_not_charged(h2c: bool) {
    let mut fixture = UploadFixture::start(h2c, UploadBackendMode::HoldUntilComplete).await;

    let mut upload = start_chunked_upload(fixture.gateway.proxy_http_port).await;
    expect_backend_event(&mut fixture.events, "upload_head").await;
    // The client ends its write side mid-chunk but keeps reading: an
    // incomplete request, not proof the client left, so the response must
    // still be delivered and it is never a 499.
    upload.shutdown().await.expect("half-close the write side");
    let head = read_response_head(&mut upload).await;
    assert!(
        head.starts_with("HTTP/1.1 400"),
        "h2c={h2c}: a half-closed client still reading gets a bad request, never 499: {head:?}"
    );
    expect_backend_event(&mut fixture.events, "upload_aborted").await;

    let summary = fixture.upload_summary().await;
    assert_eq!(summary["response_status_code"], 400, "{summary}");
    assert_eq!(summary["error_class"], "client_disconnect", "{summary}");
    assert!(
        summary.get("client_disconnected").is_none(),
        "h2c={h2c}: a half-closed upload is not a disconnect: {summary}"
    );
    fixture
        .assert_breaker_closed(&format!("h2c={h2c}: a half-closed client upload"))
        .await;
    drop(upload);
    fixture.shutdown().await;
}

async fn assert_malformed_client_upload_is_a_400_not_charged(h2c: bool) {
    let mut fixture = UploadFixture::start(h2c, UploadBackendMode::HoldUntilComplete).await;

    let mut upload = start_chunked_upload(fixture.gateway.proxy_http_port).await;
    expect_backend_event(&mut fixture.events, "upload_head").await;
    // The client stays connected and reading, but its next chunk-size line is
    // not hex: the frontend codec rejects the upload as malformed.
    upload
        .write_all(b"zz\r\n")
        .await
        .expect("send a malformed chunk");
    upload.flush().await.expect("flush the malformed chunk");
    let head = read_response_head(&mut upload).await;
    assert!(
        head.starts_with("HTTP/1.1 400"),
        "h2c={h2c}: a connected client with a malformed upload gets a bad request, \
         never 499: {head:?}"
    );
    expect_backend_event(&mut fixture.events, "upload_aborted").await;

    let summary = fixture.upload_summary().await;
    assert_eq!(summary["response_status_code"], 400, "{summary}");
    assert_eq!(summary["error_class"], "client_disconnect", "{summary}");
    assert!(
        summary.get("client_disconnected").is_none(),
        "h2c={h2c}: a malformed upload is not a disconnect: {summary}"
    );
    fixture
        .assert_breaker_closed(&format!("h2c={h2c}: a malformed client upload"))
        .await;
    drop(upload);
    fixture.shutdown().await;
}

async fn assert_backend_upload_failure_is_charged(h2c: bool) {
    let mut fixture = UploadFixture::start(h2c, UploadBackendMode::FailMidUpload).await;

    let mut upload = start_chunked_upload(fixture.gateway.proxy_http_port).await;
    expect_backend_event(&mut fixture.events, "upload_head").await;
    // The client keeps its upload open; the backend ends the exchange.
    let head = read_response_head(&mut upload).await;
    assert!(
        head.starts_with("HTTP/1.1 502"),
        "h2c={h2c}: a backend that fails the upload is a backend failure: {head:?}"
    );
    let summary = fixture.upload_summary().await;
    assert_eq!(summary["response_status_code"], 502, "{summary}");
    assert!(summary.get("client_disconnected").is_none(), "{summary}");

    // The summary is emitted after the breaker feedback, so it is open now.
    assert_eq!(
        fixture.get_status("/unix-cb/after").await,
        503,
        "h2c={h2c}: the backend's own upload failure must open the circuit breaker"
    );
    drop(upload);
    fixture.shutdown().await;
}

#[test]
#[ignore]
fn unix_h1_client_upload_abort_is_not_charged_to_the_backend() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_client_upload_abort_is_not_charged(false)
    });
}

#[test]
#[ignore]
fn unix_h1_malformed_client_upload_is_a_400_not_charged() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_malformed_client_upload_is_a_400_not_charged(false)
    });
}

#[test]
#[ignore]
fn unix_h1_backend_close_mid_upload_is_still_charged() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_backend_upload_failure_is_charged(false)
    });
}

#[test]
#[ignore]
fn unix_h2c_client_upload_abort_is_not_charged_to_the_backend() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_client_upload_abort_is_not_charged(true)
    });
}

#[test]
#[ignore]
fn unix_h2c_malformed_client_upload_is_a_400_not_charged() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_malformed_client_upload_is_a_400_not_charged(true)
    });
}

#[test]
#[ignore]
fn unix_h2c_backend_cancel_mid_upload_is_still_charged() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_backend_upload_failure_is_charged(true)
    });
}

#[test]
#[ignore]
fn unix_h1_half_closed_client_upload_is_a_400_not_charged() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_half_closed_client_upload_is_a_400_not_charged(false)
    });
}

#[test]
#[ignore]
fn unix_h2c_half_closed_client_upload_is_a_400_not_charged() {
    crate::common::run_trusted_projected_gateway_test(|| {
        assert_half_closed_client_upload_is_a_400_not_charged(true)
    });
}
