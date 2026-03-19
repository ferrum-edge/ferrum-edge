//! Functional test for WebSocket proxying through Ferrum Gateway.
//!
//! This test:
//! 1. Starts a local WebSocket echo server as the backend
//! 2. Starts the gateway in file mode with a ws:// proxy config
//! 3. Connects a WebSocket client through the gateway
//! 4. Verifies end-to-end echo round-trips for text and binary messages
//! 5. Tests both plaintext (ws://) and TLS (wss://) connections
//!
//! This test is marked with #[ignore] as it requires the binary to be built
//! and should be run with: cargo test --test functional_tests functional_websocket -- --ignored --nocapture

use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::Message;

// ============================================================================
// Helpers
// ============================================================================

/// Allocate a free port by binding to port 0 and returning the assigned port.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Start a WebSocket echo server on the given port.
/// Echoes text messages with "Echo: " prefix and binary messages with "Echo binary: N bytes".
async fn start_ws_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind WS echo server");

    loop {
        if let Ok((stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let (mut sink, mut source) = ws_stream.split();

                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        Message::Text(text) => {
                            let echo = format!("Echo: {}", text);
                            if sink.send(Message::Text(echo)).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(data) => {
                            let echo = format!("Echo binary: {} bytes", data.len());
                            if sink.send(Message::Text(echo)).await.is_err() {
                                break;
                            }
                        }
                        Message::Ping(data) => {
                            if sink.send(Message::Pong(data)).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    }
}

/// Build the gateway binary (debug profile).
fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("cargo")
        .args(["build", "--bin", "ferrum-gateway"])
        .output()?;
    if !output.status.success() {
        eprintln!("Build stderr: {}", String::from_utf8_lossy(&output.stderr));
        return Err("Failed to build gateway binary".into());
    }
    Ok(())
}

/// Find the gateway binary path.
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
        "./target/debug/ferrum-gateway"
    } else {
        "./target/release/ferrum-gateway"
    }
}

/// Start the gateway in file mode with optional TLS configuration.
fn start_gateway(
    config_path: &str,
    http_port: u16,
    https_port: Option<u16>,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "ferrum_gateway=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some(port) = https_port {
        cmd.env("FERRUM_PROXY_HTTPS_PORT", port.to_string());
    }
    if let Some(cert) = tls_cert_path {
        cmd.env("FERRUM_PROXY_TLS_CERT_PATH", cert);
    }
    if let Some(key) = tls_key_path {
        cmd.env("FERRUM_PROXY_TLS_KEY_PATH", key);
    }

    Ok(cmd.spawn()?)
}

/// Write a YAML config file with a WebSocket proxy pointing to the given backend port.
fn write_ws_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
proxies:
  - id: "ws-echo-proxy"
    listen_path: "/ws-echo"
    backend_protocol: ws
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Build a rustls ClientConfig that accepts any certificate (for self-signed test certs).
fn insecure_tls_client_config() -> tokio_tungstenite::Connector {
    use std::sync::Arc;

    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("Failed to set protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    tokio_tungstenite::Connector::Rustls(Arc::new(config))
}

/// A certificate verifier that accepts everything (for testing with self-signed certs).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test plaintext WebSocket (ws://) proxying: client → gateway → backend echo.
#[ignore]
#[tokio::test]
async fn test_websocket_plaintext_echo() {
    // Allocate ports
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    // Start echo backend
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(
        config_path.to_str().unwrap(),
        gateway_port,
        None,
        None,
        None,
    )
    .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect WebSocket client through the gateway
    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Test text echo
    ws.send(Message::Text("hello world".into()))
        .await
        .expect("Failed to send text");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo: hello world".into()));

    // Test binary echo
    ws.send(Message::Binary(vec![1, 2, 3, 4, 5]))
        .await
        .expect("Failed to send binary");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo binary: 5 bytes".into()));

    // Clean close
    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_plaintext_echo PASSED");
}

/// Test TLS WebSocket (wss://) proxying: client →(TLS)→ gateway → backend echo.
/// The gateway terminates TLS; the backend connection is plaintext ws://.
#[ignore]
#[tokio::test]
async fn test_websocket_tls_echo() {
    // Allocate ports
    let backend_port = free_port().await;
    let gateway_http_port = free_port().await;
    let gateway_https_port = free_port().await;

    // Start plaintext echo backend (gateway handles TLS termination)
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway with TLS
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    // Use existing test certs
    let cert_path = "tests/certs/server.crt";
    let key_path = "tests/certs/server.key";

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(
        config_path.to_str().unwrap(),
        gateway_http_port,
        Some(gateway_https_port),
        Some(cert_path),
        Some(key_path),
    )
    .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect with TLS (accept self-signed cert)
    let url = format!("wss://localhost:{}/ws-echo", gateway_https_port);
    let connector = insecure_tls_client_config();
    let (mut ws, _response) =
        tokio_tungstenite::connect_async_tls_with_config(&url, None, false, Some(connector))
            .await
            .expect("Failed to connect WebSocket over TLS");

    // Test text echo
    ws.send(Message::Text("hello tls".into()))
        .await
        .expect("Failed to send text");
    let reply = ws
        .next()
        .await
        .expect("No reply")
        .expect("Error reading reply");
    assert_eq!(reply, Message::Text("Echo: hello tls".into()));

    // Clean close
    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_tls_echo PASSED");
}

/// Test multiple sequential WebSocket messages through the gateway.
#[ignore]
#[tokio::test]
async fn test_websocket_multiple_messages() {
    // Allocate ports
    let backend_port = free_port().await;
    let gateway_port = free_port().await;

    // Start echo backend
    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let mut gateway = start_gateway(
        config_path.to_str().unwrap(),
        gateway_port,
        None,
        None,
        None,
    )
    .expect("Failed to start gateway");
    sleep(Duration::from_secs(3)).await;

    // Connect
    let url = format!("ws://127.0.0.1:{}/ws-echo", gateway_port);
    let (mut ws, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Send multiple text messages
    for i in 0..10 {
        let msg = format!("message {}", i);
        ws.send(Message::Text(msg.clone()))
            .await
            .expect("Failed to send");
        let reply = ws.next().await.expect("No reply").expect("Error reading");
        assert_eq!(reply, Message::Text(format!("Echo: {}", msg)));
    }

    // Send multiple binary messages
    for size in [0, 1, 100, 1000] {
        let data = vec![0xABu8; size];
        ws.send(Message::Binary(data))
            .await
            .expect("Failed to send binary");
        let reply = ws.next().await.expect("No reply").expect("Error reading");
        assert_eq!(reply, Message::Text(format!("Echo binary: {} bytes", size)));
    }

    // Clean close
    ws.send(Message::Close(None))
        .await
        .expect("Failed to send close");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_websocket_multiple_messages PASSED");
}
