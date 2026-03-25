//! DTLS (Datagram Transport Layer Security) support for UDP stream proxies.
//!
//! Provides helpers to build DTLS client configurations for backend connections
//! and DTLS server configurations for frontend termination. Uses the `dtls`
//! crate (webrtc-rs) which supports DTLS 1.2 with ECDSA P-256 and Ed25519 keys.

use std::sync::Arc;

use tracing::debug;
use webrtc_dtls::config::Config as DtlsConfig;
use webrtc_dtls::crypto::Certificate as DtlsCertificate;

use crate::config::types::Proxy;

/// Build a DTLS client config for backend connections (gateway → backend).
///
/// Maps the proxy's `backend_tls_*` fields to DTLS `Config`:
/// - `backend_tls_verify_server_cert` → `insecure_skip_verify` (inverted)
/// - `backend_tls_server_ca_cert_path` → `roots_cas`
/// - `backend_tls_client_cert_path` + `backend_tls_client_key_path` → `certificates`
pub fn build_backend_dtls_config(
    proxy: &Proxy,
    backend_host: &str,
) -> Result<DtlsConfig, anyhow::Error> {
    let mut config = DtlsConfig {
        insecure_skip_verify: !proxy.backend_tls_verify_server_cert,
        server_name: backend_host.to_string(),
        ..Default::default()
    };

    // Load root CA for server cert verification
    if let Some(ca_path) = &proxy.backend_tls_server_ca_cert_path {
        let ca_data = std::fs::read(ca_path)
            .map_err(|e| anyhow::anyhow!("Failed to read DTLS CA cert {}: {}", ca_path, e))?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &ca_data[..])
                .filter_map(|r| r.ok())
                .collect();
        for cert in certs {
            config
                .roots_cas
                .add(cert)
                .map_err(|e| anyhow::anyhow!("Failed to add DTLS CA cert: {}", e))?;
        }
    }

    // Load client certificate for mutual TLS
    if let (Some(cert_path), Some(key_path)) = (
        &proxy.backend_tls_client_cert_path,
        &proxy.backend_tls_client_key_path,
    ) {
        let cert = load_dtls_certificate(cert_path, key_path)?;
        config.certificates = vec![cert];
    }

    debug!(
        proxy_id = %proxy.id,
        server_name = %backend_host,
        skip_verify = config.insecure_skip_verify,
        "Built DTLS backend client config"
    );

    Ok(config)
}

/// Build a DTLS server config for frontend termination (client → gateway).
///
/// Requires ECDSA P-256 or Ed25519 certificates (DTLS does not support RSA).
#[allow(dead_code)]
pub fn build_frontend_dtls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<DtlsConfig, anyhow::Error> {
    let cert = load_dtls_certificate(cert_path, key_path)?;
    let config = DtlsConfig {
        certificates: vec![cert],
        ..Default::default()
    };
    Ok(config)
}

/// Load a DTLS certificate from PEM files.
///
/// The `dtls` crate only supports ECDSA P-256 and Ed25519 private keys.
/// RSA keys will produce an error.
fn load_dtls_certificate(
    cert_path: &str,
    key_path: &str,
) -> Result<DtlsCertificate, anyhow::Error> {
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read DTLS key {}: {}", key_path, e))?;
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| anyhow::anyhow!("Failed to read DTLS cert {}: {}", cert_path, e))?;

    // dtls crate expects PEM in format: PRIVATE_KEY block first, then CERTIFICATE blocks
    let combined_pem = format!("{}\n{}", key_pem.trim(), cert_pem.trim());
    DtlsCertificate::from_pem(&combined_pem).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse DTLS certificate (note: only ECDSA P-256 and Ed25519 keys \
             are supported, RSA is not): {}",
            e
        )
    })
}

/// Generate a self-signed DTLS certificate for testing.
///
/// Uses ECDSA P-256 by default (supported by the dtls crate).
#[allow(dead_code)]
pub fn generate_self_signed_cert() -> Result<DtlsCertificate, anyhow::Error> {
    DtlsCertificate::generate_self_signed(vec!["localhost".to_string()])
        .map_err(|e| anyhow::anyhow!("Failed to generate self-signed DTLS cert: {}", e))
}

/// Create a DTLS connection to a backend server.
///
/// Wraps an existing connected `tokio::net::UdpSocket` with DTLS encryption.
pub async fn connect_dtls_backend(
    socket: tokio::net::UdpSocket,
    config: DtlsConfig,
) -> Result<Arc<webrtc_dtls::conn::DTLSConn>, anyhow::Error> {
    let conn: Arc<dyn webrtc_util::Conn + Send + Sync> = Arc::new(socket);
    let dtls_conn = webrtc_dtls::conn::DTLSConn::new(conn, config, true, None)
        .await
        .map_err(|e| anyhow::anyhow!("DTLS backend handshake failed: {}", e))?;
    Ok(Arc::new(dtls_conn))
}

/// Start a DTLS listener for frontend termination.
///
/// Returns a `DTLSListener` that accepts DTLS connections from clients and
/// performs the DTLS handshake automatically. Each accepted connection yields
/// an `Arc<dyn Conn>` with transparent encryption/decryption.
#[allow(dead_code)]
pub async fn start_dtls_listener(
    addr: std::net::SocketAddr,
    config: DtlsConfig,
) -> Result<webrtc_dtls::listener::DTLSListener, anyhow::Error> {
    use webrtc_util::conn::conn_udp_listener::ListenConfig;

    let mut lc = ListenConfig::default();
    let parent = Arc::new(
        lc.listen(addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind DTLS listener on {}: {}", addr, e))?,
    );

    let listener = webrtc_dtls::listener::DTLSListener::new(parent, config)
        .map_err(|e| anyhow::anyhow!("Failed to create DTLS listener: {}", e))?;

    Ok(listener)
}
