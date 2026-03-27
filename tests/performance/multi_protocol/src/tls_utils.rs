use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::{CertificateDer, ServerName};

// ── Certificate generation ───────────────────────────────────────────────────

/// Generate a self-signed cert+key pair and write them to `dir/cert.pem` and `dir/key.pem`.
/// Returns `(cert_path, key_path)`.
pub fn generate_self_signed_certs(dir: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    // rcgen needs a crypto provider installed
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    std::fs::create_dir_all(dir).context("creating cert directory")?;

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("generating ECDSA P-256 key pair")?;

    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .context("creating cert params")?;
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));

    let cert = params
        .self_signed(&key_pair)
        .context("self-signing certificate")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    std::fs::write(&cert_path, cert_pem.as_bytes()).context("writing cert.pem")?;
    std::fs::write(&key_path, key_pem.as_bytes()).context("writing key.pem")?;

    Ok((cert_path, key_path))
}

// ── TLS server config ────────────────────────────────────────────────────────

/// Build a `rustls::ServerConfig` from PEM cert+key files with ALPN `["h2", "http/1.1"]`.
pub fn make_server_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<rustls::ServerConfig> {
    let cert_bytes = std::fs::read(cert_path).context("reading server cert")?;
    let key_bytes = std::fs::read(key_path).context("reading server key")?;

    let certs = rustls_pemfile::certs(&mut &cert_bytes[..])
        .collect::<Result<Vec<_>, _>>()
        .context("parsing PEM certs")?;
    let key = rustls_pemfile::private_key(&mut &key_bytes[..])
        .context("parsing PEM key")?
        .context("no private key found in PEM")?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building server TLS config")?;

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

// ── TLS client config (insecure – skip server cert verification) ─────────────

/// Create a `rustls::ClientConfig` that skips server certificate verification.
/// ALPN is set to `["h2", "http/1.1"]`.
pub fn make_client_tls_config_insecure() -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

// ── HTTP/3 (QUIC) configs ────────────────────────────────────────────────────

/// Build a `quinn::ServerConfig` from PEM cert+key files for HTTP/3.
pub fn make_h3_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<quinn::ServerConfig> {
    let cert_bytes = std::fs::read(cert_path).context("reading h3 server cert")?;
    let key_bytes = std::fs::read(key_path).context("reading h3 server key")?;

    let certs = rustls_pemfile::certs(&mut &cert_bytes[..])
        .collect::<Result<Vec<_>, _>>()
        .context("parsing PEM certs for h3")?;
    let key = rustls_pemfile::private_key(&mut &key_bytes[..])
        .context("parsing PEM key for h3")?
        .context("no private key found")?;

    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("h3 server TLS config")?;

    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg)
            .context("quinn crypto config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.stream_receive_window((2 * 1024 * 1024u32).into());
    transport.receive_window((16 * 1024 * 1024u32).into());
    transport.send_window(16 * 1024 * 1024);
    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

/// Create a `quinn::ClientConfig` that skips server certificate verification.
pub fn make_h3_client_config_insecure() -> quinn::ClientConfig {
    let mut tls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let quic_cfg =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg).expect("quic client config");
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.stream_receive_window((2 * 1024 * 1024u32).into());
    transport.receive_window((16 * 1024 * 1024u32).into());
    transport.send_window(16 * 1024 * 1024);
    client_cfg.transport_config(Arc::new(transport));
    client_cfg
}

// ── NoCertVerifier ───────────────────────────────────────────────────────────

/// A `ServerCertVerifier` that accepts any certificate. **Test use only.**
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
