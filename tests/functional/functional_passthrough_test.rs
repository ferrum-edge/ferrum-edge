//! Functional tests for TLS/DTLS passthrough mode on stream proxies.
//!
//! Passthrough proxies forward encrypted client bytes directly to the
//! backend without TLS termination. The gateway peeks at the ClientHello
//! for SNI but never decrypts application data.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_passthrough --ignored --nocapture

use std::time::Duration;
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

/// Wait for the gateway health endpoint to respond.
/// Returns true if healthy, false if timed out.
async fn wait_for_health(admin_port: u16) -> bool {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = std::time::SystemTime::now() + Duration::from_secs(30);
    loop {
        if std::time::SystemTime::now() >= deadline {
            return false;
        }
        match reqwest::get(&health_url).await {
            Ok(r) if r.status().is_success() => return true,
            _ => sleep(Duration::from_millis(500)).await,
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

        let mut cmd = std::process::Command::new(gateway_binary_path());
        cmd.env("FERRUM_MODE", "file")
            .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
            .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "debug")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("Failed to start gateway");

        if wait_for_health(admin_port).await {
            return (child, proxy_listen_port, http_port, admin_port, dir);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (ports: stream={}, http={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_listen_port, http_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
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
    backend_port: {backend_port: ''}
    listen_port: {stream_port: ''}
    passthrough: true
consumers: []
plugin_configs: []
upstreams: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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

#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_circuit_breaker_rejects_without_backend_dial() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Reserve a backend port, then drop the listener so the first gateway
    // connection gets ECONNREFUSED and trips the passthrough breaker.
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let (mut gateway, proxy_listen_port, _http_port, _admin_port, _dir) =
        start_gateway_with_retry(|stream_port, _dir_path| {
            format!(
                r#"
version: "1"
proxies:
  - id: "tcp-passthrough-cb"
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    listen_port: {stream_port: ''}
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
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#,
            )
        })
        .await;

    let mut first = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("connect to passthrough proxy");
    first.write_all(b"trip breaker").await.ok();
    let mut buf = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(5), first.read(&mut buf)).await;

    // Bring up a backend on the same port after the breaker is open. If the
    // passthrough path skips can_execute, the next client will be accepted here.
    let backend_listener = TcpListener::bind(format!("127.0.0.1:{backend_port}"))
        .await
        .expect("bind backend after breaker trip");
    let accepts = Arc::new(AtomicU32::new(0));
    let accepts_for_task = accepts.clone();
    tokio::spawn(async move {
        while let Ok((_stream, _)) = backend_listener.accept().await {
            accepts_for_task.fetch_add(1, Ordering::Relaxed);
        }
    });

    let mut second = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_listen_port))
        .await
        .expect("connect to passthrough proxy while breaker is open");
    second.write_all(b"must not reach backend").await.ok();
    let _ = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf)).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        0,
        "open passthrough circuit breaker must reject before backend dial"
    );

    gateway.kill().ok();
    gateway.wait().ok();
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
    backend_port: {backend_port: ''}
    listen_port: {stream_port: ''}
    passthrough: true
consumers: []
plugin_configs: []
upstreams: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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
    backend_port: {backend_port: ''}
    listen_port: {stream_port: ''}
    passthrough: true
consumers: []
plugin_configs: []
upstreams: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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
