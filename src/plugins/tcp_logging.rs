//! TCP/TLS access logging plugin — batched async log shipping over TCP.
//!
//! Serializes `TransactionSummary` entries as newline-delimited JSON (NDJSON)
//! and sends them to a remote TCP endpoint in batches. Uses
//! `BatchingLogger<LogEntry>` to decouple the proxy hot path from network I/O.
//! Failed batches are retried with configurable delay, and the connection is
//! re-established automatically on failure.
//!
//! Supports both plaintext TCP and TLS-encrypted connections. TLS uses the
//! gateway's global CA bundle (`FERRUM_TLS_CA_BUNDLE_PATH`) and skip-verify
//! (`FERRUM_TLS_NO_VERIFY`) settings, with per-plugin `tls_server_name`
//! override.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, matching the http_logging plugin's behavior.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Duration;

use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, SummaryLogEntry, build_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

#[derive(Clone)]
struct TcpFlushConfig {
    host: String,
    port: u16,
    tls_enabled: bool,
    tls_server_name: Option<String>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<String>,
    connect_timeout: Duration,
}

pub struct TcpLogging {
    logger: BatchingLogger<SummaryLogEntry>,
    endpoint_hostname: String,
}

impl TcpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let host = config["host"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "tcp_logging: 'host' is required — logs will have nowhere to send".to_string()
            })?
            .to_string();

        let port = config["port"]
            .as_u64()
            .ok_or_else(|| "tcp_logging: 'port' is required".to_string())?;
        if port == 0 || port > 65535 {
            return Err(format!(
                "tcp_logging: 'port' must be between 1 and 65535 (got {port})"
            ));
        }
        let port = port as u16;

        let tls_enabled = config["tls"].as_bool().unwrap_or(false);
        let tls_server_name = config["tls_server_name"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let connect_timeout_ms = config["connect_timeout_ms"]
            .as_u64()
            .unwrap_or(5000)
            .max(100);

        let flush_config = TcpFlushConfig {
            host: host.clone(),
            port,
            tls_enabled,
            tls_server_name,
            tls_no_verify: http_client.tls_no_verify(),
            tls_ca_bundle_path: http_client.tls_ca_bundle_path().map(|s| s.to_string()),
            connect_timeout: Duration::from_millis(connect_timeout_ms),
        };
        let writer = Arc::new(Mutex::new(None));
        let logger = BatchingLogger::spawn(
            // Config remains `max_retries`; the shared retry policy counts the
            // initial attempt plus those retries.
            build_batch_config(
                config,
                "tcp_logging",
                BatchConfigDefaults {
                    batch_size_key: "batch_size",
                    batch_size: 50,
                    flush_interval_ms: 1000,
                    min_flush_interval_ms: 100,
                    buffer_capacity: 10000,
                    max_retries: 3,
                    retry_delay_ms: 1000,
                },
            ),
            move |batch| {
                let flush_config = flush_config.clone();
                let writer = Arc::clone(&writer);
                async move { send_batch(&flush_config, &writer, batch).await }
            },
        );

        Ok(Self {
            logger,
            endpoint_hostname: host,
        })
    }
}

#[async_trait]
impl Plugin for TcpLogging {
    fn name(&self) -> &str {
        "tcp_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::TCP_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(summary.into());
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(summary.into());
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }
}

/// Writable TCP connection — either plaintext or TLS-wrapped.
enum TcpWriter {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl TcpWriter {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            TcpWriter::Plain(stream) => stream.write_all(buf).await,
            TcpWriter::Tls(stream) => stream.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TcpWriter::Plain(stream) => stream.flush().await,
            TcpWriter::Tls(stream) => stream.flush().await,
        }
    }
}

async fn connect_tcp(cfg: &TcpFlushConfig) -> Result<TcpWriter, String> {
    let addr = format!("{}:{}", cfg.host, cfg.port);

    let stream = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("TCP logging: connect timeout to {addr}"))?
        .map_err(|e| format!("TCP logging: failed to connect to {addr}: {e}"))?;

    if !cfg.tls_enabled {
        return Ok(TcpWriter::Plain(stream));
    }

    let mut root_store = rustls::RootCertStore::empty();

    if !cfg.tls_no_verify {
        if let Some(ca_path) = &cfg.tls_ca_bundle_path {
            match std::fs::read(ca_path) {
                Ok(ca_pem) => {
                    let certs = rustls_pemfile::certs(&mut &ca_pem[..])
                        .filter_map(|cert| cert.ok())
                        .collect::<Vec<_>>();
                    if certs.is_empty() {
                        return Err(format!(
                            "TCP logging: no valid certificates found in CA bundle {ca_path}"
                        ));
                    }
                    for cert in certs {
                        root_store.add(cert).map_err(|error| {
                            format!("TCP logging: failed to add CA cert from {ca_path}: {error}")
                        })?;
                    }
                }
                Err(error) => {
                    return Err(format!(
                        "TCP logging: failed to read CA bundle {ca_path}: {error}"
                    ));
                }
            }
        } else {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }

    let tls_config = if cfg.tls_no_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name_str = cfg.tls_server_name.as_deref().unwrap_or(&cfg.host);
    let server_name = rustls::pki_types::ServerName::try_from(server_name_str.to_string())
        .map_err(|error| {
            format!("TCP logging: invalid TLS server name '{server_name_str}': {error}")
        })?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("TCP logging: TLS handshake failed with {addr}: {error}"))?;

    Ok(TcpWriter::Tls(Box::new(tls_stream)))
}

/// No-op TLS certificate verifier for `tls_no_verify` mode.
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
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

async fn send_batch(
    cfg: &TcpFlushConfig,
    writer_state: &Mutex<Option<TcpWriter>>,
    batch: Vec<SummaryLogEntry>,
) -> Result<(), String> {
    let mut payload = Vec::with_capacity(batch.len() * 256);
    for entry in &batch {
        if let Ok(json) = serde_json::to_vec(entry) {
            payload.extend_from_slice(&json);
            payload.push(b'\n');
        }
    }

    let mut connection = writer_state
        .lock()
        .map_err(|_| "TCP logging: writer state lock poisoned".to_string())?
        .take();

    if connection.is_none() {
        connection = Some(connect_tcp(cfg).await?);
    }

    let mut keep_connection = true;
    let result = match connection.as_mut() {
        Some(writer) => match writer.write_all(&payload).await {
            Ok(()) => match writer.flush().await {
                Ok(()) => Ok(()),
                Err(error) => {
                    keep_connection = false;
                    Err(format!("TCP logging: flush failed: {error}"))
                }
            },
            Err(error) => {
                keep_connection = false;
                Err(format!("TCP logging: write failed: {error}"))
            }
        },
        None => Err("TCP logging: writer unavailable after reconnect".to_string()),
    };
    if !keep_connection {
        connection = None;
    }

    *writer_state
        .lock()
        .map_err(|_| "TCP logging: writer state lock poisoned".to_string())? = connection;

    result
}
