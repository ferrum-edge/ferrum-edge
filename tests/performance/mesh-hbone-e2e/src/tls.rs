//! TLS server config helpers for the stub HBONE sidecar.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let certs = CertificateDer::pem_reader_iter(f)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing PEM certs")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in {}", path.display()));
    }
    Ok(certs)
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    PrivateKeyDer::from_pem_reader(f).with_context(|| format!("parsing PEM key {}", path.display()))
}

/// Build a `ServerConfig` that requires + verifies a client certificate against
/// `ca_path`. ALPN is `h2` so the gateway's outbound HBONE pool negotiates HTTP/2.
pub fn make_sidecar_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<Arc<ServerConfig>> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let certs = read_certs(cert_path)?;
    let key = read_key(key_path)?;

    let mut roots = RootCertStore::empty();
    for ca in read_certs(ca_path)? {
        roots
            .add(ca)
            .map_err(|e| anyhow!("adding CA to trust store: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow!("building client verifier: {e}"))?;

    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("building sidecar server TLS config")?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

#[allow(dead_code)]
pub fn make_loadgen_client_config(ca_path: &Path) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for ca in read_certs(ca_path)? {
        roots
            .add(ca)
            .map_err(|e| anyhow!("adding CA to trust store: {e}"))?;
    }
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}
