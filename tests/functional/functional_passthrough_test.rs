//! Functional tests for TLS/DTLS passthrough mode on stream proxies.
//!
//! Passthrough proxies forward encrypted client bytes directly to the
//! backend without TLS termination. The gateway peeks at the ClientHello
//! for SNI but never decrypts application data.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_passthrough --ignored --nocapture

use std::process::Child;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ── Helpers ───────────────────────────────────────────────────────────────

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Plain TCP echo server — reads data, echoes it back, and closes.
async fn start_tcp_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind TCP echo");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }
}

/// TLS-wrapped TCP echo server — clients perform TLS handshake, then echo.
async fn start_tls_echo_server(port: u16, cert_pem: &str, key_pem: &str) {
    use rustls::ServerConfig;
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;
    use std::sync::Arc;
    use tokio_rustls::TlsAcceptor;

    let cert_chain: Vec<_> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .filter_map(|r| r.ok())
        .collect();
    let key = private_key(&mut BufReader::new(key_pem.as_bytes()))
        .unwrap()
        .unwrap();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("bad tls config");

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind TLS echo");

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        match tls_stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if tls_stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            });
        }
    }
}

fn generate_self_signed_cert() -> (String, String) {
    use rcgen::{CertificateParams, KeyPair};
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

/// Names of the captured gateway output files inside a harness `TempDir`.
const GATEWAY_STDOUT_LOG: &str = "gateway.stdout.log";
const GATEWAY_STDERR_LOG: &str = "gateway.stderr.log";

/// Everything the gateway has written so far, both streams concatenated.
fn gateway_logs(dir: &std::path::Path) -> String {
    let mut combined = String::new();
    for name in [GATEWAY_STDOUT_LOG, GATEWAY_STDERR_LOG] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            combined.push_str(&text);
        }
    }
    combined
}

/// Poll the captured gateway logs until `needle` appears, up to `within`.
///
/// This is the state observation that replaces "sleep and hope": a test can
/// wait for a specific gateway-side transition (a circuit breaker opening, a
/// connection being rejected) instead of guessing how long it takes.
async fn wait_for_gateway_log(dir: &std::path::Path, needle: &str, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if gateway_logs(dir).contains(needle) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(25)).await;
    }
}

/// Kills the gateway child on every exit path, including panics.
struct GatewayProcess(std::process::Child);

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Per-spawn `FERRUM_METRICS_BEARER_TOKEN` so authenticated `/health` can prove
/// this child owns the admin port (issue #3428). Never logged.
fn mint_observability_token() -> String {
    format!(
        "ferrum-edge-passthrough-probe-{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// Wait until `child` owns its admin listener and reports fully ready.
///
/// Unauthenticated `/health` success is not identity and is not readiness: a
/// foreign process can answer the released admin port, and that probe does not
/// require JSON `ready: true`. `ready` flips only after every listener bind,
/// including the stream listener this file actually dials.
///
/// Barrier (same contract as `TestGateway` / `wait_for_owned_gateway`):
/// 1. `Child::try_wait` around every probe — a dead child voids the attempt.
/// 2. Authenticated `/health` detail tier for this attempt's bearer token with
///    `ready: true`.
///
/// No synthetic stream-port connection is made here: passthrough listeners
/// treat every accepted socket as real traffic, so such a probe can dial the
/// configured backend and corrupt backend-accept assertions. Authenticated
/// `ready: true` is already published only after every required listener bind.
async fn wait_for_owned_gateway(
    child: &mut Child,
    admin_port: u16,
    observability_token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const STARTUP_TIMEOUT_SECS: u64 = 30;
    const PROBE_SLICE: Duration = Duration::from_secs(1);
    let deadline = Instant::now() + Duration::from_secs(STARTUP_TIMEOUT_SECS);
    let mut last_observation = String::from("no response yet");
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "passthrough gateway exited during startup with {status} \
                 (last observation: {last_observation})"
            )
            .into());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "passthrough gateway did not prove ownership of admin port {admin_port} \
                 within {STARTUP_TIMEOUT_SECS} seconds (last observation: {last_observation})"
            )
            .into());
        }
        match crate::common::probe_gateway_identity(
            admin_port,
            observability_token,
            remaining.min(PROBE_SLICE),
        )
        .await
        {
            Ok(()) => {
                if let Some(status) = child.try_wait()? {
                    return Err(format!(
                        "passthrough gateway exited after reporting ready with {status}"
                    )
                    .into());
                }
                return Ok(());
            }
            Err(err) => last_observation = err.to_string(),
        }
    }
}

/// Start the gateway with retry on port-binding failures.
///
/// Allocates fresh ephemeral proxy listen, HTTP, and admin ports on each attempt
/// to handle the bind-drop-rebind port race.  The `write_config` closure receives
/// `(proxy_listen_port, dir)` and must write the config file, returning
/// `(config_path_string, TempDir)`.
///
/// Returns (child, proxy_listen_port, http_port, admin_port, TempDir).
async fn start_gateway_with_retry<F>(
    write_config: F,
) -> (std::process::Child, u16, u16, u16, TempDir)
where
    F: Fn(u16, &std::path::Path) -> String,
{
    start_gateway_with_retry_env(write_config, &[]).await
}

/// Variant of `start_gateway_with_retry` that lets the caller add extra env
/// variables (e.g. `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`) without
/// duplicating the port-allocation + retry scaffolding.
async fn start_gateway_with_retry_env<F>(
    write_config: F,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16, u16, u16, TempDir)
where
    F: Fn(u16, &std::path::Path) -> String,
{
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_listen_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        drop(http_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_content = write_config(proxy_listen_port, dir.path());
        std::fs::write(&config_path, &config_content).unwrap();

        // Redirect the gateway's output into files inside the temp dir rather
        // than /dev/null. Files (not pipes — an unread pipe deadlocks, see the
        // functional-test rules) let a test observe gateway-side state
        // transitions instead of sleeping and hoping. Tests that don't read
        // them are unaffected.
        let stdout_log = std::fs::File::create(dir.path().join(GATEWAY_STDOUT_LOG)).unwrap();
        let stderr_log = std::fs::File::create(dir.path().join(GATEWAY_STDERR_LOG)).unwrap();
        let observability_token = mint_observability_token();

        let mut cmd = std::process::Command::new(gateway_binary_path());
        cmd.env("FERRUM_MODE", "file")
            .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
            .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_ADMIN_HTTPS_PORT", "0")
            .env("FERRUM_ACCEPT_THREADS", "1")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_LOG_LEVEL", "debug")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(stdout_log))
            .stderr(std::process::Stdio::from(stderr_log));
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        // Identity proof is last so extra_env cannot replace this child's token
        // with a leaked parent-shell credential or CIDR allowlist.
        cmd.env("FERRUM_METRICS_BEARER_TOKEN", &observability_token)
            .env_remove("FERRUM_METRICS_ALLOWED_CIDRS");
        let mut child = cmd.spawn().expect("Failed to start gateway");

        match wait_for_owned_gateway(&mut child, admin_port, &observability_token).await {
            Ok(()) => return (child, proxy_listen_port, http_port, admin_port, dir),
            Err(error) => {
                eprintln!(
                    "Gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed \
                     (ports: stream={proxy_listen_port}, http={http_port}, \
                     admin={admin_port}): {error}"
                );
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} attempts");
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_plain_echo() {
    // Backend: plain TCP echo (same-process, no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    tokio::spawn(start_tcp_echo_server(backend_port));

    // Start gateway with retry to handle ephemeral port races
    let (mut gateway, proxy_listen_port, _http_port, _admin_port, _dir) =
        start_gateway_with_retry(|stream_port, _dir_path| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-passthrough"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        })
        .await;

    // Connect through the gateway's stream proxy port
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("Failed to connect to passthrough proxy");

    let msg = b"hello passthrough";
    stream.write_all(msg).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read error");

    assert_eq!(&buf[..n], msg, "echo response should match");

    gateway.kill().ok();
    gateway.wait().ok();
}

/// An attempt at the passthrough circuit-breaker scenario could not establish
/// its preconditions because something outside the gateway interfered with the
/// backend port. Distinct from a product failure, which panics on the spot.
struct PortRaced(String);

/// Circuit-breaker ordering on the passthrough path.
///
/// Production order (`src/proxy/tcp_proxy.rs`): the passthrough branch calls
/// `circuit_breaker_cache.can_execute()` *before* DNS resolution and the
/// backend dial, and records the connect failure via `inspect_err` on
/// `connect_candidates` *before* the error propagates and the client socket is
/// dropped. So a second connection that starts after the first one's client
/// socket has closed is deterministically admitted-or-rejected against a
/// settled breaker — there is no product-side window.
///
/// The old test could not see that ordering. It discarded the first client
/// read's result (so a first attempt that had not finished — or had never even
/// been dialed — still counted as "breaker tripped"), then rebound the backend
/// port and slept a second before reading an accept counter. Any accept in that
/// window failed the test, including one from an unrelated process that grabbed
/// the port during the deliberate refusal window (issue #3431).
///
/// This version instead:
///   * requires the first client connection to actually end (EOF/error) rather
///     than ignoring a timeout,
///   * waits for the gateway to *report* the breaker opening before the backend
///     listener is installed, so the failed dial provably precedes the rebind,
///   * proves the rejection positively (the gateway logs the breaker-open
///     rejection) instead of only inferring it from an absent accept, and
///   * attributes any backend accept by payload: only a connection carrying
///     this attempt's unique marker proves the gateway dialed. An
///     unattributable accept, or a port that was taken during the refusal
///     window, retries the scenario with fresh ports instead of reporting a
///     product failure that did not happen.
async fn try_passthrough_circuit_breaker_scenario(attempt: u32) -> Result<(), PortRaced> {
    // Reserve a backend port and release it: the first gateway dial must get a
    // real ECONNREFUSED so the breaker trips on a connection error. This
    // release/rebind window is inherent to the scenario; everything below
    // detects interference in it rather than misreporting it.
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let first_marker = format!("ferrum-cb-first-{attempt}-{backend_port}");
    let second_marker = format!("ferrum-cb-second-{attempt}-{backend_port}");

    let (gateway, proxy_listen_port, _http_port, _admin_port, dir) =
        start_gateway_with_retry(|stream_port, _dir_path| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-passthrough-cb"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true
    backend_connect_timeout_ms: 200
    circuit_breaker:
      failure_threshold: 1
      success_threshold: 1
      timeout_seconds: 60
      failure_status_codes: [500, 502, 503]
      half_open_max_requests: 1
      trip_on_connection_errors: true

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        })
        .await;
    let _gateway = GatewayProcess(gateway);

    // ── Step 1: the first attempt must fail and must be observed failing ──
    let mut first = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect to passthrough proxy");
    first.write_all(first_marker.as_bytes()).await.ok();
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(10), first.read(&mut buf)).await {
        // EOF or a transport error: the gateway finished handling the
        // connection, which on this path means the dial failed and the
        // failure was recorded before the socket was dropped.
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => {
            return Err(PortRaced(format!(
                "backend port {backend_port} was serving during the refusal window: \
                 the first passthrough attempt read back {n} byte(s) ({:?})",
                String::from_utf8_lossy(&buf[..n])
            )));
        }
        Err(_) => {
            return Err(PortRaced(format!(
                "the first passthrough attempt never completed within 10s \
                 (backend port {backend_port} was most likely taken by another \
                 process and accepted the dial without replying)"
            )));
        }
    }

    // ── Step 2: the breaker transition must be observable BEFORE the port is
    // rebound, so the failed dial provably precedes the backend listener ──
    if !wait_for_gateway_log(
        dir.path(),
        "Circuit breaker opening",
        Duration::from_secs(10),
    )
    .await
    {
        return Err(PortRaced(format!(
            "the first connection ended but the gateway never reported the \
             circuit breaker opening (backend port {backend_port} may have been \
             accepted and closed by another process during the refusal window). \
             Gateway log:\n{}",
            gateway_logs(dir.path())
        )));
    }

    // ── Step 3: install the backend listener now that the breaker is open ──
    let backend_listener = match TcpListener::bind(format!("127.0.0.1:{backend_port}")).await {
        Ok(listener) => listener,
        Err(e) => {
            return Err(PortRaced(format!(
                "backend port {backend_port} was taken by another process during \
                 the refusal window: {e}"
            )));
        }
    };
    // ── Step 4: the second connection must be rejected before any dial ──
    let mut second = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect to passthrough proxy while breaker is open");
    second.write_all(second_marker.as_bytes()).await.ok();
    let second_outcome = tokio::time::timeout(Duration::from_secs(10), second.read(&mut buf)).await;
    assert!(
        matches!(&second_outcome, Ok(Ok(0)) | Ok(Err(_))),
        "with the breaker open the gateway must close the client connection \
         immediately; instead the connection stayed open (outcome={second_outcome:?}), \
         which means it was relayed to the backend. Gateway log:\n{}",
        gateway_logs(dir.path())
    );

    // Positive proof of the rejection. Without this, a gateway that dropped the
    // connection for some unrelated reason (or never handled it at all) would
    // leave the accept assertion below passing vacuously.
    assert!(
        wait_for_gateway_log(
            dir.path(),
            "TCP passthrough connection rejected: circuit breaker open",
            Duration::from_secs(10),
        )
        .await,
        "the gateway closed the second connection but never reported a \
         circuit-breaker rejection, so the accept count below would prove \
         nothing. Gateway log:\n{}",
        gateway_logs(dir.path())
    );

    // ── Step 5: no backend dial happened ──
    // A successful TCP connect is queued in this listener's kernel backlog
    // even if this task has not yet been scheduled to call `accept()`. Awaiting
    // the listener directly therefore closes the old false-green window where
    // an atomically sampled counter could still be zero while the accept task
    // had not run. The bounded quiet window is the negative assertion itself,
    // not a scheduling sleep.
    match tokio::time::timeout(Duration::from_secs(2), backend_listener.accept()).await {
        Err(_) => {}
        Ok(Err(e)) => panic!(
            "backend listener on port {backend_port} failed while checking for \
             a forbidden gateway dial: {e}"
        ),
        Ok(Ok((mut stream, peer))) => {
            let mut probe = vec![0u8; 512];
            let observed =
                match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut probe)).await {
                    Ok(Ok(n)) => probe[..n].to_vec(),
                    _ => Vec::new(),
                };
            let relayed = observed
                .windows(second_marker.len())
                .any(|window| window == second_marker.as_bytes());
            assert!(
                !relayed,
                "open passthrough circuit breaker must reject before backend dial, but \
                 the backend received this client's payload from {peer}. Gateway log:\n{}",
                gateway_logs(dir.path())
            );
            return Err(PortRaced(format!(
                "backend port {backend_port} received an unattributable connection \
                 from {peer} that did not carry this attempt's marker: {:?}",
                String::from_utf8_lossy(&observed)
            )));
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_circuit_breaker_rejects_without_backend_dial() {
    const MAX_ATTEMPTS: u32 = 3;
    let mut races = Vec::new();
    for attempt in 1..=MAX_ATTEMPTS {
        match try_passthrough_circuit_breaker_scenario(attempt).await {
            Ok(()) => return,
            Err(PortRaced(reason)) => {
                eprintln!("attempt {attempt}/{MAX_ATTEMPTS}: {reason}");
                races.push(reason);
            }
        }
    }
    panic!(
        "could not establish the passthrough circuit-breaker preconditions in \
         {MAX_ATTEMPTS} attempts (the backend port was interfered with every \
         time): {races:?}"
    );
}

#[tokio::test]
#[ignore]
async fn test_tcp_tls_passthrough_forwards_encrypted_data() {
    let (cert_pem, key_pem) = generate_self_signed_cert();

    // Backend: TLS echo server (same-process, no port race)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let cert_clone = cert_pem.clone();
    let key_clone = key_pem.clone();
    tokio::spawn(async move {
        start_tls_echo_server(backend_port, &cert_clone, &key_clone).await;
    });

    // Start gateway with retry to handle ephemeral port races
    let (mut gateway, proxy_listen_port, _http_port, _admin_port, _dir) =
        start_gateway_with_retry(|stream_port, _dir_path| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tls-passthrough"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        })
        .await;

    // Connect via raw TCP to the proxy port, then do TLS handshake.
    // The gateway passes bytes through without TLS termination;
    // the TLS handshake reaches the backend directly.
    let tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("Failed to connect to passthrough proxy");

    // Build a TLS client that trusts our self-signed cert
    let cert_chain: Vec<_> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
            .filter_map(|r| r.ok())
            .collect();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(cert_chain);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake through passthrough should succeed");

    // Send data through the TLS tunnel (through the gateway passthrough)
    let msg = b"encrypted passthrough data";
    tls_stream.write_all(msg).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read error");

    assert_eq!(
        &buf[..n],
        msg,
        "TLS echo through passthrough should return same data"
    );

    gateway.kill().ok();
    gateway.wait().ok();
}

/// Slow-loris defense: a peer that opens a TCP connection to a passthrough
/// listener and never writes a ClientHello must NOT park a connection-handler
/// task indefinitely. The peek is bounded by
/// `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`.
///
/// Before the fix, the gateway sits forever at `TcpStream::peek()` waiting for
/// the silent peer's first byte and never even attempts the backend connect.
/// After the fix, the peek returns `None` once the deadline expires and the
/// gateway proceeds with whatever bytes were available (zero) — at which
/// point the backend connection is initiated and the backend's accept queue
/// records a new connection.
///
/// We assert on the backend-side accept count: it must reach 1 within
/// roughly `timeout + slack`. If the bug were still present, the accept
/// count would stay at 0 indefinitely.
#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_sni_peek_timeout_drops_silent_peer() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Backend that just counts accepted connections and holds them open
    // (so the OS doesn't reset them, and the gateway doesn't see EOF early).
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicU32::new(0));
    let accepts_for_task = accepts.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = backend_listener.accept().await {
                accepts_for_task.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _hold = stream;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                });
            }
        }
    });

    // Gateway: 2-second handshake timeout for the passthrough SNI peek.
    let (mut gateway, proxy_listen_port, _http_port, _admin_port, _dir) =
        start_gateway_with_retry_env(
            |stream_port, _dir_path| {
                format!(
                    r#"
version: "1"
proxies:
  - id: "tcp-passthrough-slow-loris"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {stream_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
                )
            },
            &[("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "2")],
        )
        .await;

    // Connect and never send anything — classic slow-loris.
    let _silent = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("connect to gateway");

    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(5); // 2s timeout + 3s slack
    let mut accept_observed = false;
    while std::time::Instant::now() < deadline {
        if accepts.load(Ordering::Relaxed) >= 1 {
            accept_observed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let elapsed = started.elapsed();

    assert!(
        accept_observed,
        "Backend never saw a connection within {:?}; SNI peek timeout did not fire (slow-loris bug regressed)",
        elapsed
    );
    // Sanity: the timeout shouldn't fire much earlier than the configured 2s.
    assert!(
        elapsed >= Duration::from_millis(1500),
        "Backend connection observed too early ({elapsed:?}) — peek timeout may be wired to the wrong knob"
    );

    gateway.kill().ok();
    gateway.wait().ok();
}

// ── Issue #3264: general opaque-TLS SNI L4 routing ───────────────────────────
//
// These exercise the routing plane OUTSIDE the passthrough special case: an
// ordinary `tcp` stream listener (`passthrough: false`, `frontend_tls: false`)
// relays client bytes verbatim, so declaring `hosts` makes it SNI-routed
// without terminating TLS. They are deliberately H1-independent: the payload is
// a raw TLS ClientHello and the backends are byte recorders, so nothing here
// depends on an HTTP frontend.

/// Minimal, standards-shaped TLS 1.2 ClientHello carrying `server_name`.
///
/// Hand-built rather than driven through rustls so the test owns the exact
/// bytes on the wire and can assert the backend received them unmodified.
fn opaque_client_hello(hostname: &str) -> Vec<u8> {
    let name = hostname.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes()); // list len
    sni_ext.push(0x00); // name_type = host_name
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0x2a; 32]); // random
    body.push(0); // session_id_len
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1); // compression_methods_len
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    handshake.push((body.len() >> 16) as u8);
    handshake.push((body.len() >> 8) as u8);
    handshake.push(body.len() as u8);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Backend that reports every accepted connection and the first chunk of bytes
/// it is handed, so a test can prove WHICH backend was dialed (an accept alone
/// is the fail-closed assertion — a refused connection must never reach one)
/// and separately that the relayed bytes are exact.
struct RecordingBackend {
    accepts: tokio::sync::mpsc::UnboundedReceiver<()>,
    bytes: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
}

fn spawn_recording_backend(listener: TcpListener) -> RecordingBackend {
    let (accept_tx, accepts) = tokio::sync::mpsc::unbounded_channel();
    let (byte_tx, bytes) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let _ = accept_tx.send(());
            let byte_tx = byte_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                if let Ok(n) = stream.read(&mut buf).await
                    && n > 0
                {
                    let _ = byte_tx.send(buf[..n].to_vec());
                }
                // Hold the connection so the gateway does not observe an early
                // backend EOF while the test is still asserting.
                sleep(Duration::from_secs(30)).await;
            });
        }
    });
    RecordingBackend { accepts, bytes }
}

/// Two ordinary `tcp` listeners (NOT passthrough) sharing one port, separated
/// only by SNI. Before #3264 this configuration was rejected outright, so an
/// opaque TLS fanout could only be expressed through `passthrough: true`.
///
/// Asserts three things at once: the right backend is chosen, the other backend
/// sees nothing, and the ClientHello arrives byte-for-byte (the gateway peeks
/// without consuming and never terminates TLS).
#[tokio::test]
#[ignore]
async fn test_opaque_tcp_sni_fanout_routes_by_sni_and_preserves_bytes() {
    let backend_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_a_port = backend_a.local_addr().unwrap().port();
    let backend_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_b_port = backend_b.local_addr().unwrap().port();
    let mut backend_a = spawn_recording_backend(backend_a);
    let mut backend_b = spawn_recording_backend(backend_b);

    let (mut gateway, proxy_listen_port, _http, _admin, _dir) =
        start_gateway_with_retry(move |stream_port, _dir| {
            format!(
                r#"
version: "1"
proxies:
  - id: "opaque-a"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_a_port}
    listen_port: {stream_port}
    hosts:
      - "tenant-a.example.com"
  - id: "opaque-b"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_b_port}
    listen_port: {stream_port}
    hosts:
      - "*.tenant-b.example.com"

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        })
        .await;

    // Exact-host route.
    let hello_a = opaque_client_hello("tenant-a.example.com");
    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect for tenant-a");
    client.write_all(&hello_a).await.unwrap();
    client.flush().await.unwrap();

    let received_a = tokio::time::timeout(Duration::from_secs(10), backend_a.bytes.recv())
        .await
        .expect("tenant-a backend must be selected by SNI")
        .expect("backend channel open");
    assert_eq!(
        received_a, hello_a,
        "the peeked ClientHello must reach the backend byte-for-byte"
    );
    assert!(
        backend_b.accepts.try_recv().is_err(),
        "tenant-b must not observe tenant-a's connection"
    );

    // Wildcard route on the same listener.
    let hello_b = opaque_client_hello("shard1.tenant-b.example.com");
    let mut client_b = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect for tenant-b");
    client_b.write_all(&hello_b).await.unwrap();
    client_b.flush().await.unwrap();

    let received_b = tokio::time::timeout(Duration::from_secs(10), backend_b.bytes.recv())
        .await
        .expect("wildcard SNI must select the tenant-b backend")
        .expect("backend channel open");
    assert_eq!(received_b, hello_b);

    gateway.kill().ok();
    gateway.wait().ok();
}

/// Security regression for the core #3264 defect: on an SNI-routed listener,
/// a ClientHello that never finishes arriving must be REFUSED, not silently
/// handed to the group's default route. The truncated hello declared
/// `tenant-a.example.com`; routing it to the catch-all would put one tenant's
/// connection on another tenant's backend.
///
/// Also covers the determinate non-TLS case, which fails closed unless the
/// operator authorizes a plaintext fallback.
#[tokio::test]
#[ignore]
async fn test_opaque_tls_sni_listener_fails_closed_on_indeterminate_and_non_tls() {
    let named_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let named_port = named_backend.local_addr().unwrap().port();
    let default_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let default_port = default_backend.local_addr().unwrap().port();
    let mut named = spawn_recording_backend(named_backend);
    let mut default_route = spawn_recording_backend(default_backend);

    let (mut gateway, proxy_listen_port, _http, _admin, _dir) = start_gateway_with_retry_env(
        move |stream_port, _dir| {
            format!(
                r#"
version: "1"
proxies:
  - id: "named"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {named_port}
    listen_port: {stream_port}
    hosts:
      - "tenant-a.example.com"
  - id: "default-route"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {default_port}
    listen_port: {stream_port}

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        },
        // Short handshake clock so the truncated hello resolves quickly.
        &[("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "2")],
    )
    .await;

    // 1. Truncated ClientHello: cut inside the random bytes, before SNI.
    let hello = opaque_client_hello("tenant-a.example.com");
    let mut truncated_client =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
            .await
            .expect("connect with truncated hello");
    truncated_client.write_all(&hello[..20]).await.unwrap();
    truncated_client.flush().await.unwrap();
    // 2s handshake deadline + slack for the refusal to land.
    sleep(Duration::from_secs(5)).await;
    assert!(
        default_route.accepts.try_recv().is_err(),
        "a truncated ClientHello must NOT be downgraded onto the default route"
    );
    assert!(
        named.accepts.try_recv().is_err(),
        "a truncated ClientHello must not reach a named route either"
    );

    // 2. Provably non-TLS bytes with no authorized fallback.
    let mut plaintext_client =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
            .await
            .expect("connect with plaintext");
    plaintext_client
        .write_all(b"GET / HTTP/1.1\r\nHost: tenant-a.example.com\r\n\r\n")
        .await
        .unwrap();
    plaintext_client.flush().await.unwrap();
    sleep(Duration::from_secs(2)).await;
    assert!(
        default_route.accepts.try_recv().is_err(),
        "non-TLS bytes must fail closed unless a plaintext fallback is authorized"
    );

    // 3. A well-formed hello for the named host still routes — the listener is
    //    fail-closed, not broken.
    let mut good_client = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect with valid hello");
    good_client.write_all(&hello).await.unwrap();
    good_client.flush().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(10), named.bytes.recv())
        .await
        .expect("a complete ClientHello must still route")
        .expect("backend channel open");
    assert_eq!(received, hello);

    gateway.kill().ok();
    gateway.wait().ok();
}

/// The plaintext fallback is opt-in and, when authorized, sends provably
/// non-TLS bytes to the group's declared default route — the pre-#3264
/// behavior, now only reachable by explicit configuration.
#[tokio::test]
#[ignore]
async fn test_opaque_tls_sni_listener_honors_authorized_plaintext_fallback() {
    let named_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let named_port = named_backend.local_addr().unwrap().port();
    let default_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let default_port = default_backend.local_addr().unwrap().port();
    let mut named = spawn_recording_backend(named_backend);
    let mut default_route = spawn_recording_backend(default_backend);

    let (mut gateway, proxy_listen_port, _http, _admin, _dir) = start_gateway_with_retry_env(
        move |stream_port, _dir| {
            format!(
                r#"
version: "1"
proxies:
  - id: "named"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {named_port}
    listen_port: {stream_port}
    hosts:
      - "tenant-a.example.com"
  - id: "default-route"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {default_port}
    listen_port: {stream_port}

consumers: []
plugin_configs: []
upstreams: []
"#,
            )
        },
        &[
            ("FERRUM_STREAM_SNI_PLAINTEXT_FALLBACK", "true"),
            ("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "2"),
        ],
    )
    .await;

    let payload = b"PLAIN-TCP-CLIENT".to_vec();
    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect with plaintext");
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), default_route.bytes.recv())
        .await
        .expect("authorized plaintext fallback must reach the default route")
        .expect("backend channel open");
    assert_eq!(received, payload, "plaintext bytes relay unmodified");
    default_route
        .accepts
        .try_recv()
        .expect("the authorized plaintext connection must record one backend accept");

    // The authorization is scoped to non-TLS bytes only: a truncated hello is
    // still refused.
    let hello = opaque_client_hello("tenant-a.example.com");
    let mut truncated = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_listen_port}"))
        .await
        .expect("connect with truncated hello");
    truncated.write_all(&hello[..20]).await.unwrap();
    truncated.flush().await.unwrap();
    sleep(Duration::from_secs(5)).await;
    assert!(
        default_route.accepts.try_recv().is_err(),
        "the plaintext fallback must not rescue an indeterminate ClientHello"
    );
    assert!(named.accepts.try_recv().is_err());

    gateway.kill().ok();
    gateway.wait().ok();
}

/// A bound, non-listening socket reserves the failed endpoint without a port
/// reuse race. Least-connections deterministically picks that first target at
/// zero active connections; only connect-phase rotation can reach the TLS echo.
#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_rotates_before_forwarding_client_hello() {
    use std::sync::Arc;

    let (cert_pem, key_pem) = generate_self_signed_cert();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
        .unwrap()
        .unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(certs.clone());
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    ));

    for (retry_enabled, max_retries, succeeds) in
        [(true, 1, true), (false, 1, false), (true, 0, false)]
    {
        let refused = tokio::net::TcpSocket::new_v4().unwrap();
        refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let refused_port = refused.local_addr().unwrap().port();
        let healthy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let healthy_port = healthy.local_addr().unwrap().port();
        let (gateway, proxy_port, _, _, dir) = start_gateway_with_retry(|stream_port, _| {
            format!(
                r#"
version: "1"
proxies:
  - id: "passthrough-retry"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {refused_port}
    listen_port: {stream_port}
    passthrough: true
    upstream_id: "passthrough-retry-targets"
    retry:
      retry_on_connect_failure: {retry_enabled}
      max_retries: {max_retries}
      backoff: !fixed
        delay_ms: 1
upstreams:
  - id: "passthrough-retry-targets"
    algorithm: least_connections
    targets:
      - host: "127.0.0.1"
        port: {refused_port}
      - host: "127.0.0.1"
        port: {healthy_port}
consumers: []
plugin_configs: []
"#
            )
        })
        .await;
        let _gateway = GatewayProcess(gateway);
        if succeeds {
            // Two successive streams also prove the failed target's connection
            // guard is released, so the second selection still reaches it first.
            for _ in 0..2 {
                let server = async {
                    let (socket, _) = healthy.accept().await.unwrap();
                    let mut stream = acceptor.accept(socket).await.unwrap();
                    let mut data = [0; 15];
                    stream.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"retry tls bytes");
                    stream.write_all(&data).await.unwrap();
                    stream.shutdown().await.unwrap();
                };
                let client = async {
                    let socket = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
                        .await
                        .unwrap();
                    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                    let mut stream = connector.connect(name, socket).await.unwrap();
                    stream.write_all(b"retry tls bytes").await.unwrap();
                    let mut response = [0; 15];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"retry tls bytes");
                    stream.shutdown().await.unwrap();
                };
                tokio::time::timeout(Duration::from_secs(10), async {
                    tokio::join!(server, client);
                })
                .await
                .expect("TLS retry and echo finish within the bound");
            }
            assert_eq!(
                gateway_logs(dir.path())
                    .matches("TCP passthrough setup failed")
                    .count(),
                2,
                "each stream should retry the first target exactly once"
            );
        } else {
            let socket = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
                .await
                .unwrap();
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let result =
                tokio::time::timeout(Duration::from_secs(5), connector.connect(name, socket))
                    .await
                    .expect("disabled or exhausted retries fail promptly");
            assert!(
                result.is_err(),
                "retry controls must prevent target rotation"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), healthy.accept())
                    .await
                    .is_err(),
                "the alternate target must not be dialed"
            );
            assert!(!gateway_logs(dir.path()).contains("TCP passthrough setup failed"));
        }
    }
}
