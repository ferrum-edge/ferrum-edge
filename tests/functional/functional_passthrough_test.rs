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

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_tcp_passthrough_plain_echo() {
    // Backend: plain TCP echo
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    tokio::spawn(start_tcp_echo_server(backend_port));

    // Gateway listen port for the stream proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_listen_port = proxy_listener.local_addr().unwrap().port();
    drop(proxy_listener);

    // HTTP port (required by gateway, unused in this test)
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    drop(http_listener);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    drop(admin_listener);

    let dir = TempDir::new().unwrap();
    let config = format!(
        r#"
proxies:
  - id: "tcp-passthrough"
    listen_path: "/unused"
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {proxy_listen_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
    );
    let config_path = dir.path().join("config.yaml");
    std::fs::write(&config_path, &config).unwrap();

    let mut gateway = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway");

    sleep(Duration::from_secs(3)).await;

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
async fn test_tcp_tls_passthrough_forwards_encrypted_data() {
    let (cert_pem, key_pem) = generate_self_signed_cert();

    // Backend: TLS echo server (the backend terminates TLS, not the gateway)
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let cert_clone = cert_pem.clone();
    let key_clone = key_pem.clone();
    tokio::spawn(async move {
        start_tls_echo_server(backend_port, &cert_clone, &key_clone).await;
    });

    // Gateway ports
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
    let config = format!(
        r#"
proxies:
  - id: "tls-passthrough"
    listen_path: "/unused"
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    listen_port: {proxy_listen_port}
    passthrough: true

consumers: []
plugin_configs: []
upstreams: []
"#,
    );
    let config_path = dir.path().join("config.yaml");
    std::fs::write(&config_path, &config).unwrap();

    let mut gateway = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway");

    sleep(Duration::from_secs(3)).await;

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
