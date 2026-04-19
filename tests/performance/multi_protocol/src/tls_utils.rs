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
    // Mark the self-signed cert as a CA (with the basicConstraints CA:TRUE
    // extension) so strict validators — Kong's `ca_certificates`
    // declarative entity, Envoy's validation_context, and tonic's root
    // store — will accept it as a trust anchor. Without the CA basic
    // constraint, Kong rejects the entity outright:
    //   "certificate does not appear to be a CA because it is missing the
    //   \"CA\" basic constraint".
    // This cert is used ONLY by the bench — it doesn't affect production
    // code paths. It still serves as its own leaf cert (all gateways
    // present it as their TLS server identity), which is standard for
    // self-signed testing certs.
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

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
    let mut cfg = make_server_tls_config_base(cert_path, key_path)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Build a `rustls::ServerConfig` that advertises ONLY `http/1.1` via ALPN.
///
/// Use this for the dedicated H1-over-TLS listener (port 3447). The generic
/// `make_server_tls_config` advertises both `h2` and `http/1.1`, so if a
/// gateway's upstream client (e.g. Kong/Tyk/KrakenD Go `net/http` defaults,
/// which offer h2) hits that listener, TLS will negotiate `h2` and then the
/// hyper HTTP/1.1 server bytes-parse will fail — the benchmark silently
/// downgrades to "broken connections" instead of measuring H1-over-TLS
/// throughput. Advertising only `http/1.1` here forces every client to
/// either get `http/1.1` or fail the TLS handshake cleanly.
pub fn make_server_tls_config_h1_only(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<rustls::ServerConfig> {
    let mut cfg = make_server_tls_config_base(cert_path, key_path)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Build a `rustls::ServerConfig` that advertises ONLY `h2` via ALPN.
///
/// Mirrors `make_server_tls_config_h1_only` for the H2-over-TLS listener
/// (port 3443). The generic `make_server_tls_config` advertises `["h2",
/// "http/1.1"]`, which lets an upstream client that negotiates `http/1.1`
/// (or offers no ALPN at all) through the TLS handshake — then hyper's
/// H2-only server rejects the HTTP/1.1 bytes. By advertising only `h2` we
/// force every client to either negotiate `h2` or fail TLS cleanly, so a
/// benchmark never silently measures a broken transport.
pub fn make_server_tls_config_h2_only(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<rustls::ServerConfig> {
    let mut cfg = make_server_tls_config_base(cert_path, key_path)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

fn make_server_tls_config_base(
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

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building server TLS config")
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
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1024));
    transport.stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024)); // 8 MiB
    transport.receive_window(quinn::VarInt::from_u32(32 * 1024 * 1024)); // 32 MiB
    transport.send_window(8 * 1024 * 1024); // 8 MiB
    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

/// Create a `quinn::ClientConfig` that skips server certificate verification.
///
/// Applies optimized QUIC transport settings (8 MiB stream window, 32 MiB
/// connection window, 8 MiB send window) to match the gateway's tuned defaults
/// and ensure the bench client is not the bottleneck.
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
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1024));
    transport.stream_receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024)); // 8 MiB
    transport.receive_window(quinn::VarInt::from_u32(32 * 1024 * 1024)); // 32 MiB
    transport.send_window(8 * 1024 * 1024); // 8 MiB
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
