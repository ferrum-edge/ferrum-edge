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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
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
