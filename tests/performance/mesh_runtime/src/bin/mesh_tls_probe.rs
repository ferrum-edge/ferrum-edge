//! TLS handshake probe for mesh auth verification.
//!
//! Completes one TLS handshake (ALPN `h2`) against a mesh inbound
//! listener with a given trust bundle and optional client certificate,
//! then requires the server's H2 SETTINGS frame in reply (TLS 1.3
//! client-auth rejection only surfaces after the client Finished),
//! prints one JSON line describing the negotiated parameters, and exits
//! 0 on success / 1 on failure. The harness runs the matrix: valid
//! client cert (must succeed), no client cert (must fail), rogue-CA
//! client cert (must fail).

use std::fs;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    addr: SocketAddr,
    #[arg(long)]
    server_name: String,
    /// PEM trust bundle for verifying the server.
    #[arg(long)]
    ca: PathBuf,
    /// Optional client certificate chain (PEM).
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Optional client private key (PEM PKCS#8).
    #[arg(long)]
    key: Option<PathBuf>,
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    CertificateDer::pem_slice_iter(&pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing certificates")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut roots = rustls::RootCertStore::empty();
    for cert in load_certs(&args.ca)? {
        roots.add(cert).context("adding trust anchor")?;
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut config = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => {
            let certs = load_certs(cert)?;
            let key_pem = fs::read(key).context("reading client key")?;
            let key = PrivateKeyDer::from_pem_slice(&key_pem).context("parsing client key")?;
            builder
                .with_client_auth_cert(certs, key)
                .context("building client auth")?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => anyhow::bail!("--cert and --key must be supplied together"),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];

    let server_name = ServerName::try_from(args.server_name.clone())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(args.addr))
        .await
        .context("connect timed out")??;
    let _ = tcp.set_nodelay(true);
    let mut stream =
        tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
            .await
            .context("handshake timed out")??;
    // TLS 1.3 client authentication is judged after the client's
    // Finished, so a completed client-side handshake alone does not prove
    // the server accepted us. Send the HTTP/2 client preface + an empty
    // SETTINGS frame and require the server's SETTINGS in reply.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const EMPTY_SETTINGS: &[u8] = &[0, 0, 0, 0x4, 0, 0, 0, 0, 0];
    stream.write_all(PREFACE).await.context("writing preface")?;
    stream
        .write_all(EMPTY_SETTINGS)
        .await
        .context("writing SETTINGS")?;
    stream.flush().await.context("flushing preface")?;
    let mut reply = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut reply))
        .await
        .context("server reply timed out")??;
    anyhow::ensure!(n >= 9, "server closed without an H2 reply (n={n})");
    anyhow::ensure!(reply[3] == 0x4, "server reply is not an H2 SETTINGS frame");
    let (_, session) = stream.get_ref();
    let version = session
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".to_string());
    let alpn = session
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default();
    let cipher = session
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_else(|| "unknown".to_string());
    println!("{{\"tls_version\":\"{version}\",\"alpn\":\"{alpn}\",\"cipher\":\"{cipher}\"}}");
    Ok(())
}
