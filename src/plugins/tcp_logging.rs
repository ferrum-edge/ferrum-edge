//! TCP/TLS access logging plugin — batched async log shipping over TCP.
//!
//! Serializes `TransactionSummary` entries as newline-delimited JSON (NDJSON) and
//! sends them to a remote TCP endpoint in batches. Uses an mpsc channel to decouple
//! the proxy hot path from network I/O: the `log()` hook enqueues the entry
//! (non-blocking), and a background task drains the channel in configurable batch
//! sizes with a flush interval timer. Failed batches are retried with configurable
//! delay, and the connection is re-established automatically on failure.
//!
//! Supports both plaintext TCP and TLS-encrypted connections. TLS uses the
//! gateway's global CA bundle (`FERRUM_TLS_CA_BUNDLE_PATH`) and skip-verify
//! (`FERRUM_TLS_NO_VERIFY`) settings, with per-plugin `tls_server_name` override.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, matching the http_logging plugin's behavior.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;

use super::utils::PluginHttpClient;
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Union type for log entries sent through the batched channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

struct TcpConfig {
    host: String,
    port: u16,
    tls_enabled: bool,
    tls_server_name: Option<String>,
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<String>,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    connect_timeout: Duration,
}

pub struct TcpLogging {
    sender: mpsc::Sender<LogEntry>,
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

        let batch_size = config["batch_size"].as_u64().unwrap_or(50).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(1000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;
        let connect_timeout_ms = config["connect_timeout_ms"]
            .as_u64()
            .unwrap_or(5000)
            .max(100);

        let tcp_config = TcpConfig {
            host: host.clone(),
            port,
            tls_enabled,
            tls_server_name,
            tls_no_verify: http_client.tls_no_verify(),
            tls_ca_bundle_path: http_client.tls_ca_bundle_path().map(|s| s.to_string()),
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries: config["max_retries"].as_u64().unwrap_or(3) as u32,
            retry_delay: Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(1000)),
            connect_timeout: Duration::from_millis(connect_timeout_ms),
        };

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, tcp_config));

        Ok(Self {
            sender,
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
        if self
            .sender
            .try_send(LogEntry::Stream(summary.clone()))
            .is_err()
        {
            warn!("TCP logging buffer full — dropping stream log entry");
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self
            .sender
            .try_send(LogEntry::Http(summary.clone()))
            .is_err()
        {
            warn!("TCP logging buffer full — dropping log entry");
        }
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

async fn connect_tcp(cfg: &TcpConfig) -> Result<TcpWriter, String> {
    let addr = format!("{}:{}", cfg.host, cfg.port);

    let stream = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("TCP logging: connect timeout to {addr}"))?
        .map_err(|e| format!("TCP logging: failed to connect to {addr}: {e}"))?;

    if !cfg.tls_enabled {
        return Ok(TcpWriter::Plain(stream));
    }

    // Build rustls TLS config
    let mut root_store = rustls::RootCertStore::empty();

    if !cfg.tls_no_verify {
        if let Some(ca_path) = &cfg.tls_ca_bundle_path {
            // Custom CA — sole trust anchor (no webpki roots)
            match std::fs::read(ca_path) {
                Ok(ca_pem) => {
                    let certs = rustls_pemfile::certs(&mut &ca_pem[..])
                        .filter_map(|r| r.ok())
                        .collect::<Vec<_>>();
                    if certs.is_empty() {
                        return Err(format!(
                            "TCP logging: no valid certificates found in CA bundle {ca_path}"
                        ));
                    }
                    for cert in certs {
                        root_store.add(cert).map_err(|e| {
                            format!("TCP logging: failed to add CA cert from {ca_path}: {e}")
                        })?;
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "TCP logging: failed to read CA bundle {ca_path}: {e}"
                    ));
                }
            }
        } else {
            // No custom CA — use webpki roots
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

    // Use tls_server_name if provided, otherwise fall back to host
    let server_name_str = cfg.tls_server_name.as_deref().unwrap_or(&cfg.host);
    let server_name = rustls::pki_types::ServerName::try_from(server_name_str.to_string())
        .map_err(|e| format!("TCP logging: invalid TLS server name '{server_name_str}': {e}"))?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("TCP logging: TLS handshake failed with {addr}: {e}"))?;

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

async fn flush_loop(mut receiver: mpsc::Receiver<LogEntry>, cfg: TcpConfig) {
    let mut buffer: Vec<LogEntry> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    // The first tick completes immediately — consume it so the first real
    // flush waits for one full interval.
    timer.tick().await;

    // Persistent connection — reconnected on failure.
    let mut writer: Option<TcpWriter> = None;

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(entry) => {
                        buffer.push(entry);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            writer = send_batch(&cfg, batch, writer).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining entries and exit.
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            let _ = send_batch(&cfg, batch, writer).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    writer = send_batch(&cfg, batch, writer).await;
                }
            }
        }
    }
}

/// Serialize a batch as NDJSON and send over the TCP connection.
///
/// Returns the connection on success (for reuse), or `None` on failure.
/// Re-establishes the connection if `writer` is `None` or the write fails.
async fn send_batch(
    cfg: &TcpConfig,
    batch: Vec<LogEntry>,
    mut writer: Option<TcpWriter>,
) -> Option<TcpWriter> {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();

    // Pre-serialize the batch as NDJSON (newline-delimited JSON).
    let mut payload = Vec::with_capacity(entry_count * 256);
    for entry in &batch {
        if let Ok(json) = serde_json::to_vec(entry) {
            payload.extend_from_slice(&json);
            payload.push(b'\n');
        }
    }

    for attempt in 1..=total_attempts {
        // Ensure we have a connection.
        if writer.is_none() {
            match connect_tcp(cfg).await {
                Ok(w) => writer = Some(w),
                Err(e) => {
                    warn!(
                        "TCP logging: connection failed: {} (attempt {}/{})",
                        e, attempt, total_attempts,
                    );
                    if attempt < total_attempts {
                        tokio::time::sleep(cfg.retry_delay).await;
                    }
                    continue;
                }
            }
        }

        // Write the payload.
        let Some(w) = writer.as_mut() else {
            continue;
        };
        match w.write_all(&payload).await {
            Ok(()) => match w.flush().await {
                Ok(()) => return writer,
                Err(e) => {
                    warn!(
                        "TCP logging: flush failed: {} (attempt {}/{})",
                        e, attempt, total_attempts,
                    );
                    writer = None; // Connection is broken, reconnect next attempt.
                }
            },
            Err(e) => {
                warn!(
                    "TCP logging: write failed: {} (attempt {}/{})",
                    e, attempt, total_attempts,
                );
                writer = None; // Connection is broken, reconnect next attempt.
            }
        }

        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "TCP logging batch discarded after {} attempts ({} entries lost)",
        total_attempts, entry_count,
    );
    None
}
