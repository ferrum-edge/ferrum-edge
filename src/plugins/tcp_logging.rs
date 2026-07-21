//! TCP/TLS access logging plugin — batched async log shipping over TCP.
//!
//! Serializes `TransactionSummary` entries as newline-delimited JSON (NDJSON)
//! and sends them to a remote TCP endpoint in batches. Uses
//! `BatchingLogger<LogEntry>` to decouple the proxy hot path from network I/O.
//! Failed batches are retried with configurable delay, and the connection is
//! re-established automatically on failure.
//!
//! Supports both plaintext TCP and TLS-encrypted connections. TLS uses the
//! gateway's global CA bundle (`FERRUM_TLS_CA_BUNDLE_PATH`), skip-verify
//! (`FERRUM_TLS_NO_VERIFY`), and CRL list (`FERRUM_TLS_CRL_FILE_PATH`) settings,
//! with per-plugin `tls_server_name` override validated at admission.
//! `connect_timeout_ms` covers DNS, TCP connect, and TLS handshake;
//! `write_timeout_ms` bounds each batch write/flush. Unknown config keys are
//! rejected fail-closed. Revoked log-sink certificates are rejected via
//! `WebPkiServerVerifier`'s
//! `allow_unknown_revocation_status() + only_check_end_entity_revocation()`
//! policy, matching the proxy backend / DTLS / frontend mTLS surfaces.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, matching the http_logging plugin's behavior.

use async_trait::async_trait;
use rustls::pki_types::{CertificateRevocationListDer, ServerName};
use serde_json::{Map, Value};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::warn;

use super::utils::log_schema::{
    SchemaCapabilities, SummaryLogEntryView, SummarySchema, resolve_schema,
};
use super::utils::{
    BatchConfig, BatchConfigDefaults, DeferredBatchingLogger, PluginHttpClient, SummaryLogEntry,
    build_batch_config, parse_socket_host, resolve_tcp_endpoint, validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::dns::DnsCache;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::util::unknown_keys::reject_unknown_keys;

const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 60_000;

/// Authoritative closed set of top-level `tcp_logging` configuration keys.
///
/// Constructor admission, OpenAPI `TcpLoggingConfig`, and operator docs must
/// stay in lockstep with this list. Nested `schema` objects remain validated by
/// the shared log-schema compiler and are not flattened here.
pub const TCP_LOGGING_CONFIG_KEYS: &[&str] = &[
    "batch_size",
    "buffer_capacity",
    "connect_timeout_ms",
    "flush_interval_ms",
    "host",
    "max_retries",
    "port",
    "retry_delay_ms",
    "schema",
    "schema_ref",
    "tls",
    "tls_server_name",
    "write_timeout_ms",
];

/// Prebuilt TLS materials for the log sink.
///
/// Built once in `TcpLogging::new` so reconnects reuse the connector and the
/// already-validated rustls `ServerName` instead of re-parsing on every batch.
#[derive(Clone)]
struct TcpTlsRuntime {
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
}

#[derive(Clone)]
struct TcpFlushConfig {
    host: String,
    port: u16,
    /// `Some` when `tls: true`. Absent for plaintext sinks.
    tls: Option<TcpTlsRuntime>,
    /// Bounds DNS resolution, TCP connect, and (when enabled) the TLS handshake.
    connect_timeout: Duration,
    /// Bounds `write_all` + `flush` for one batch send attempt.
    write_timeout: Duration,
    /// Gateway-shared DNS cache for endpoint resolution. Pre-warmed at startup
    /// via `Plugin::warmup_hostnames`, refreshed in the background. `None` only
    /// when the plugin was constructed via the test/fallback `PluginHttpClient`
    /// path that has no cache attached.
    dns_cache: Option<DnsCache>,
    schema: Option<Arc<SummarySchema>>,
}

pub struct TcpLogging {
    batch_config: BatchConfig,
    flush_config: TcpFlushConfig,
    writer: Arc<Mutex<Option<TcpWriter>>>,
    logger: DeferredBatchingLogger<SummaryLogEntry>,
    endpoint_hostname: Option<String>,
}

impl TcpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "tcp_logging: config must be an object; allowed keys: {}",
                TCP_LOGGING_CONFIG_KEYS.join(", ")
            )
        })?;
        reject_unknown_tcp_logging_keys(config_obj)?;

        let raw_host = config
            .get("host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "tcp_logging: 'host' is required — logs will have nowhere to send".to_string()
            })?
            .to_string();
        let socket_host = parse_socket_host("tcp_logging", "host", &raw_host)?;
        socket_host.screen_egress_ip("tcp_logging", "host", http_client.backend_allow_ips())?;
        let host = socket_host.dial_host.clone();

        let port = config
            .get("port")
            .and_then(Value::as_u64)
            .ok_or_else(|| "tcp_logging: 'port' is required and must be an integer".to_string())?;
        if port == 0 || port > 65535 {
            return Err(format!(
                "tcp_logging: 'port' must be between 1 and 65535 (got {port})"
            ));
        }
        let port = port as u16;

        let tls_enabled = optional_bool(config, "tls")?.unwrap_or(false);
        let tls_server_name_override = optional_non_empty_string(config, "tls_server_name")?;
        if !tls_enabled && tls_server_name_override.is_some() {
            return Err(
                "tcp_logging: 'tls_server_name' requires 'tls: true' — refuse plaintext sinks with a TLS identity override"
                    .to_string(),
            );
        }

        let connect_timeout_ms = bounded_timeout_ms(config, "connect_timeout_ms", 5000)?;
        let write_timeout_ms = bounded_timeout_ms(config, "write_timeout_ms", 5000)?;

        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 50,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: 10000,
            max_retries: 3,
            retry_delay_ms: 1000,
        };
        validate_batch_config(config, "tcp_logging", batch_defaults)?;

        let schema = resolve_schema(config, "tcp_logging", SchemaCapabilities::BASE)?;
        // Build the TLS connector and parse the effective server name once on
        // the cold construction path. A bad CA bundle or invalid SNI/IP
        // identity fails admission instead of dropping every batch later.
        let tls = if tls_enabled {
            let connector = build_tls_connector(
                http_client.tls_no_verify(),
                http_client.tls_ca_bundle_path(),
                http_client.tls_crls(),
            )?;
            let server_name_str = tls_server_name_override
                .as_deref()
                .unwrap_or(host.as_str())
                .to_string();
            let server_name = ServerName::try_from(server_name_str.clone()).map_err(|error| {
                format!("tcp_logging: invalid TLS server name '{server_name_str}': {error}")
            })?;
            Some(TcpTlsRuntime {
                connector,
                server_name,
            })
        } else {
            None
        };
        let flush_config = TcpFlushConfig {
            host: host.clone(),
            port,
            tls,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            write_timeout: Duration::from_millis(write_timeout_ms),
            dns_cache: http_client.dns_cache().cloned(),
            schema,
        };

        Ok(Self {
            batch_config: build_batch_config(config, "tcp_logging", batch_defaults),
            flush_config,
            writer: Arc::new(Mutex::new(None)),
            logger: DeferredBatchingLogger::new(),
            endpoint_hostname: socket_host.warmup_hostname,
        })
    }
}

fn reject_unknown_tcp_logging_keys(object: &Map<String, Value>) -> Result<(), String> {
    reject_unknown_keys(object, "config", TCP_LOGGING_CONFIG_KEYS, "tcp_logging: ")
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("tcp_logging: '{key}' must be a boolean")),
        None => Ok(None),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("tcp_logging: '{key}' must be an unsigned integer")),
        None => Ok(None),
    }
}

fn bounded_timeout_ms(config: &Value, key: &str, default_ms: u64) -> Result<u64, String> {
    let value = optional_u64(config, key)?.unwrap_or(default_ms);
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&value) {
        return Err(format!(
            "tcp_logging: '{key}' must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS} milliseconds (got {value})"
        ));
    }
    Ok(value)
}

fn optional_non_empty_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("tcp_logging: '{key}' must be a string"))?;
            if value.is_empty() {
                return Err(format!("tcp_logging: '{key}' must not be empty"));
            }
            if value.trim() != value {
                return Err(format!(
                    "tcp_logging: '{key}' must not contain leading or trailing whitespace"
                ));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
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

    fn start_background_tasks(&self) -> Result<(), String> {
        let flush_config = self.flush_config.clone();
        let writer = Arc::clone(&self.writer);
        // Config remains `max_retries`; the shared retry policy counts the
        // initial attempt plus those retries.
        self.logger
            .start("tcp_logging", self.batch_config, move |batch| {
                let flush_config = flush_config.clone();
                let writer = Arc::clone(&writer);
                async move { send_batch(&flush_config, &writer, batch).await }
            })
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(summary.into());
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(summary.into());
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname.iter().cloned().collect()
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
    // Resolve via the gateway DNS cache so log shipping shares the same
    // pre-warmed / stale-while-revalidate behaviour as the proxy hot path.
    //
    // `connect_timeout_ms` bounds DNS resolution, the plaintext TCP connect,
    // and (when TLS is enabled) the TLS handshake as one establishment budget.
    // A collector that accepts TCP but never completes TLS must not pin the
    // sole batching worker indefinitely — timeout returns through the normal
    // retry/reconnect path so reload can also retire a stuck generation.
    let host_log = cfg.host.clone();
    let port = cfg.port;
    let establish = async {
        let socket_addr =
            resolve_tcp_endpoint(&cfg.host, cfg.port, cfg.dns_cache.as_ref(), "tcp_logging")
                .await?;
        let addr_log = format!("{host_log} ({socket_addr})");
        let stream = TcpStream::connect(socket_addr)
            .await
            .map_err(|e| format!("TCP logging: failed to connect to {addr_log}: {e}"))?;

        let Some(tls) = cfg.tls.as_ref() else {
            return Ok::<TcpWriter, String>(TcpWriter::Plain(stream));
        };

        let tls_stream = tls
            .connector
            .connect(tls.server_name.clone(), stream)
            .await
            .map_err(|error| {
                format!("TCP logging: TLS handshake failed with {addr_log}: {error}")
            })?;
        Ok(TcpWriter::Tls(Box::new(tls_stream)))
    };

    match tokio::time::timeout(cfg.connect_timeout, establish).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "TCP logging: connect timeout to {host_log}:{port} (includes TLS handshake when enabled)"
        )),
    }
}

/// Build the TLS connector for the TCP log sink.
///
/// Performs the synchronous CA-bundle read + PEM parse and the verifier build
/// exactly once, on the cold construction path, so the async flush task never
/// blocks a tokio worker thread re-reading the filesystem on reconnect
/// (finding #74). The result is an `Arc<ClientConfig>`-backed connector that is
/// cheap to clone per reconnect.
fn build_tls_connector(
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<&str>,
    tls_crls: &[CertificateRevocationListDer<'static>],
) -> Result<tokio_rustls::TlsConnector, String> {
    let tls_config = if tls_no_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        if let Some(ca_path) = tls_ca_bundle_path {
            let source = CertSource::parse(ca_path, MaterialKind::CaBundle);
            let ca_material = load_material_blocking(&source, MaterialKind::CaBundle)
                .map_err(|error| format!("TCP logging: failed to load CA bundle: {error}"))?;
            let source_id = ca_material.display_source_id.clone();
            let mut reader = ca_material.bytes.expose_secret();
            let certs = rustls_pemfile::certs(&mut reader)
                .filter_map(|cert| cert.ok())
                .collect::<Vec<_>>();
            if certs.is_empty() {
                return Err(format!(
                    "TCP logging: no valid certificates found in CA bundle {source_id}"
                ));
            }
            for cert in certs {
                root_store.add(cert).map_err(|error| {
                    format!("TCP logging: failed to add CA cert from {source_id}: {error}")
                })?;
            }
        } else {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        // Apply gateway CRL list (`FERRUM_TLS_CRL_FILE_PATH`) so that revoked
        // log-sink certificates are rejected, matching the proxy backend / DTLS
        // / frontend mTLS surfaces. The verifier uses
        // `allow_unknown_revocation_status() + only_check_end_entity_revocation()`
        // (set inside `build_server_verifier_with_crls`).
        let verifier = crate::tls::build_server_verifier_with_crls(root_store, tls_crls)
            .map_err(|error| format!("TCP logging: failed to build TLS verifier: {error}"))?;
        rustls::ClientConfig::builder()
            .with_webpki_verifier(verifier)
            .with_no_client_auth()
    };

    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_config)))
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
    let mut dropped = 0usize;
    let mut first_error: Option<String> = None;
    for entry in &batch {
        let result = match cfg.schema.as_deref() {
            Some(schema) => serde_json::to_vec(&SummaryLogEntryView { entry, schema }),
            None => serde_json::to_vec(entry),
        };
        match result {
            Ok(json) => {
                payload.extend_from_slice(&json);
                payload.push(b'\n');
            }
            Err(error) => {
                // Skip only the bad entry and keep shipping the rest, but
                // surface the loss instead of swallowing it silently (the UDP
                // sink already warns on serialize failure). Aggregate per batch
                // so a recurring bad entry shape cannot flood the logs:
                // `send_batch` runs at most once per flush interval.
                dropped += 1;
                if first_error.is_none() {
                    first_error = Some(error.to_string());
                }
            }
        }
    }
    if let Some(error) = first_error {
        warn!(
            dropped_entries = dropped,
            "tcp_logging: dropped log entries that failed to serialize: {error}"
        );
    }

    let mut connection = writer_state
        .lock()
        .map_err(|_| "TCP logging: writer state lock poisoned".to_string())?
        .take();

    if connection.is_none() {
        connection = Some(connect_tcp(cfg).await?);
    }

    // Delivery is at-least-once: a timeout or I/O error after a partial write
    // discards the socket and returns through the shared retry path. Retries
    // may re-send the full batch; collectors must tolerate duplicates.
    let mut keep_connection = true;
    let result = match connection.as_mut() {
        Some(writer) => {
            let write_and_flush = async {
                writer.write_all(&payload).await?;
                writer.flush().await?;
                Ok::<(), std::io::Error>(())
            };
            match tokio::time::timeout(cfg.write_timeout, write_and_flush).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => {
                    keep_connection = false;
                    Err(format!("TCP logging: write failed: {error}"))
                }
                Err(_) => {
                    keep_connection = false;
                    Err(format!(
                        "TCP logging: write timeout to {}:{} after {}ms",
                        cfg.host,
                        cfg.port,
                        cfg.write_timeout.as_millis()
                    ))
                }
            }
        }
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

#[cfg(test)]
mod tests {
    //! Inline unit tests for the TLS path. The plugin test fixtures live in
    //! `tests/unit/plugins/tcp_logging_tests.rs` (public-API surface); this
    //! module covers the private `connect_tcp` TLS verification path which
    //! tests under `tests/` cannot reach.
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    };
    use rustls::pki_types::pem::PemObject;
    use std::sync::Once;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    static INIT_CRYPTO: Once = Once::new();
    fn ensure_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn must_some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn path_str(path: &std::path::Path) -> &str {
        match path.to_str() {
            Some(value) => value,
            None => panic!("test path should be valid UTF-8: {path:?}"),
        }
    }

    fn generate_ca() -> (Issuer<'static, KeyPair>, String) {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate CA key",
        );
        let mut params = must(
            CertificateParams::new(Vec::<String>::new()),
            "build CA params",
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let cert = must(params.self_signed(&key_pair), "self-sign CA");
        let cert_pem = cert.pem();
        (Issuer::new(params, key_pair), cert_pem)
    }

    fn generate_signed_leaf(
        ca: &Issuer<'static, KeyPair>,
        sans: &[&str],
    ) -> (String, String, SerialNumber) {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate leaf key",
        );
        let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut params = must(CertificateParams::new(san_strings), "build leaf params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Leaf");
        let serial_bytes: Vec<u8> = (1..=20).collect();
        let serial = SerialNumber::from_slice(&serial_bytes);
        params.serial_number = Some(serial.clone());
        let cert = must(params.signed_by(&key_pair, ca), "sign leaf cert");
        (cert.pem(), key_pair.serialize_pem(), serial)
    }

    fn generate_crl_pem(ca: &Issuer<'static, KeyPair>, revoked_serials: &[SerialNumber]) -> String {
        let now = time::OffsetDateTime::now_utc();
        let revoked_certs: Vec<RevokedCertParams> = revoked_serials
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: s.clone(),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let crl = must(params.signed_by(ca), "sign CRL");
        must(crl.pem(), "serialize CRL PEM")
    }

    /// Spawn a one-shot TLS server that completes the handshake (or fails) and
    /// returns the bound port.
    async fn spawn_tls_server(cert_pem: &str, key_pem: &str) -> u16 {
        let cert_chain: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .filter_map(|c| c.ok())
            .collect();
        let key = must_some(
            must(
                rustls_pemfile::private_key(&mut key_pem.as_bytes()),
                "parse private key",
            ),
            "private key should be present",
        );
        let server_config = must(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key),
            "build TLS server config",
        );
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = must(TcpListener::bind("127.0.0.1:0").await, "bind TLS server");
        let port = must(listener.local_addr(), "read TLS server local addr").port();

        tokio::spawn(async move {
            // Accept up to two connections then exit; keeps the test free of
            // long-lived background tasks.
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // The handshake should be rejected client-side when the
                    // leaf is revoked, so we simply attempt accept + drain.
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        let mut buf = [0u8; 64];
                        let _ = tls.read(&mut buf).await;
                    }
                });
            }
        });

        port
    }

    /// Revoking the server cert via the CRL list passed to `PluginHttpClient`
    /// must cause `connect_tcp` to reject the TLS handshake. This proves the
    /// gateway-wide CRL list reaches the logging-sink rustls verifier (the
    /// previous code path used `with_root_certificates(...)` which bypassed
    /// CRL checking entirely).
    #[tokio::test]
    async fn test_tcp_logging_rejects_revoked_server_cert_via_crl() {
        ensure_crypto_provider();

        let (ca_issuer, ca_pem) = generate_ca();
        let (leaf_pem, leaf_key_pem, leaf_serial) =
            generate_signed_leaf(&ca_issuer, &["localhost", "127.0.0.1"]);
        let crl_pem = generate_crl_pem(&ca_issuer, std::slice::from_ref(&leaf_serial));

        // Write CA to a tempfile — `PluginHttpClient` consumes the bundle by path.
        let td = must(tempfile::tempdir(), "create tempdir");
        let ca_path = td.path().join("ca.pem");
        must(std::fs::write(&ca_path, &ca_pem), "write CA PEM");

        // Parse CRL into the in-memory `CrlList` form `PluginHttpClient` expects.
        let crls: Vec<_> =
            rustls::pki_types::CertificateRevocationListDer::pem_slice_iter(crl_pem.as_bytes())
                .filter_map(|c| c.ok())
                .collect();
        assert_eq!(crls.len(), 1, "CRL should parse as exactly one entry");
        let crl_list: crate::tls::CrlList = Arc::new(crls);

        // Spawn the TLS server with the now-revoked leaf and dial it.
        let port = spawn_tls_server(&leaf_pem, &leaf_key_pem).await;

        // Build a plugin HTTP client carrying the gateway CA + CRL.
        let http_client = PluginHttpClient::new(
            &crate::config::PoolConfig::default(),
            crate::dns::DnsCache::new(crate::dns::DnsConfig::default()),
            1000,
            0,
            100,
            false,
            Some(path_str(&ca_path)),
            crl_list.clone(),
            "ferrum",
            crate::config::BackendEgressPolicy::unrestricted(),
            std::sync::Arc::new(Vec::new()),
            0,
        );

        let plugin = TcpLogging::new(
            &serde_json::json!({
                "host": "127.0.0.1",
                "port": port,
                "tls": true,
                "tls_server_name": "localhost",
                "connect_timeout_ms": 2000,
            }),
            http_client,
        );
        let plugin = must(plugin, "tcp_logging config should be valid");
        assert_eq!(plugin.name(), "tcp_logging");

        // Reach into `connect_tcp` directly so the handshake error surfaces
        // synchronously rather than being swallowed by the batching task.
        let tls_connector = must(
            build_tls_connector(false, Some(path_str(&ca_path)), &crl_list),
            "build TLS connector",
        );
        let cfg = TcpFlushConfig {
            host: "127.0.0.1".to_string(),
            port,
            tls: Some(TcpTlsRuntime {
                connector: tls_connector,
                server_name: ServerName::try_from("localhost".to_string())
                    .expect("localhost is a valid server name"),
            }),
            connect_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            dns_cache: None,
            schema: None,
        };
        let result = connect_tcp(&cfg).await;
        let err = match result {
            Ok(_) => {
                panic!("TLS handshake to a revoked server cert must fail when the CRL is applied")
            }
            Err(e) => e,
        };
        assert!(
            err.contains("TLS handshake failed") || err.contains("revoked"),
            "Expected revocation/handshake error, got: {err}"
        );
    }

    /// Sanity counter-test: with an empty CRL list, the same fixture connects.
    /// Pinpoints the previous bug — the leaf was indistinguishable from a valid
    /// cert when CRLs weren't plumbed through.
    #[tokio::test]
    async fn test_tcp_logging_accepts_unrevoked_server_cert_with_empty_crl() {
        ensure_crypto_provider();

        let (ca_issuer, ca_pem) = generate_ca();
        let (leaf_pem, leaf_key_pem, _) =
            generate_signed_leaf(&ca_issuer, &["localhost", "127.0.0.1"]);

        let td = must(tempfile::tempdir(), "create tempdir");
        let ca_path = td.path().join("ca.pem");
        must(std::fs::write(&ca_path, &ca_pem), "write CA PEM");

        let port = spawn_tls_server(&leaf_pem, &leaf_key_pem).await;

        let tls_connector = must(
            build_tls_connector(false, Some(path_str(&ca_path)), &[]),
            "build TLS connector",
        );
        let cfg = TcpFlushConfig {
            host: "127.0.0.1".to_string(),
            port,
            tls: Some(TcpTlsRuntime {
                connector: tls_connector,
                server_name: ServerName::try_from("localhost".to_string())
                    .expect("localhost is a valid server name"),
            }),
            connect_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            dns_cache: None,
            schema: None,
        };
        let result = connect_tcp(&cfg).await;
        assert!(
            result.is_ok(),
            "Empty CRL must allow the unrevoked cert to connect, got: {:?}",
            result.err()
        );
    }

    /// A collector that accepts TCP but never speaks TLS must fail inside
    /// `connect_timeout_ms` rather than pinning the flush worker forever.
    #[tokio::test]
    async fn test_tcp_logging_tls_handshake_honors_connect_timeout() {
        ensure_crypto_provider();

        let listener = must(
            TcpListener::bind("127.0.0.1:0").await,
            "bind silent TLS peer",
        );
        let port = must(listener.local_addr(), "read silent peer addr").port();
        tokio::spawn(async move {
            // Accept and hold the socket open without completing a handshake.
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            // Keep the accepted socket alive until the client times out.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });

        let tls_connector = must(
            build_tls_connector(true, None, &[]),
            "build no-verify connector",
        );
        let cfg = TcpFlushConfig {
            host: "127.0.0.1".to_string(),
            port,
            tls: Some(TcpTlsRuntime {
                connector: tls_connector,
                server_name: ServerName::try_from("localhost".to_string())
                    .expect("localhost is a valid server name"),
            }),
            connect_timeout: Duration::from_millis(200),
            write_timeout: Duration::from_secs(2),
            dns_cache: None,
            schema: None,
        };

        let started = tokio::time::Instant::now();
        let err = match connect_tcp(&cfg).await {
            Ok(_) => panic!("handshake against a silent peer must time out"),
            Err(error) => error,
        };
        let elapsed = started.elapsed();
        assert!(
            err.contains("connect timeout"),
            "expected connect timeout error, got: {err}"
        );
        assert!(
            elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(2),
            "timeout should land near connect_timeout_ms, elapsed={elapsed:?}"
        );
    }

    fn shrink_plain_send_buffer(writer: &mut TcpWriter, bytes: usize) {
        let TcpWriter::Plain(stream) = writer else {
            panic!("expected plaintext writer for send-buffer shrink");
        };
        let sock_ref = socket2::SockRef::from(&*stream);
        must(
            sock_ref.set_send_buffer_size(bytes),
            "shrink SO_SNDBUF so stalled writes block deterministically",
        );
    }

    /// A collector that accepts but never reads must fail the write/flush
    /// budget, discard the writer, and succeed after a healthy reconnect.
    #[tokio::test]
    async fn test_tcp_logging_write_timeout_discards_socket_and_recovers() {
        ensure_crypto_provider();

        let stalled = must(
            TcpListener::bind("127.0.0.1:0").await,
            "bind stalled reader",
        );
        let stalled_port = must(stalled.local_addr(), "read stalled addr").port();
        tokio::spawn(async move {
            let Ok((stream, _)) = stalled.accept().await else {
                return;
            };
            // Keep the receive window tiny so the sender blocks after a small
            // write rather than absorbing megabytes into kernel buffers.
            let sock_ref = socket2::SockRef::from(&stream);
            let _ = sock_ref.set_recv_buffer_size(1024);
            // Do not read — fill the sender's buffers until write times out.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });

        let healthy = must(
            TcpListener::bind("127.0.0.1:0").await,
            "bind healthy reader",
        );
        let healthy_port = must(healthy.local_addr(), "read healthy addr").port();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = healthy.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match stream.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
                if buf.contains(&b'\n') {
                    let _ = tx.send(buf);
                    break;
                }
            }
        });

        let stalled_cfg = TcpFlushConfig {
            host: "127.0.0.1".to_string(),
            port: stalled_port,
            tls: None,
            connect_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_millis(200),
            dns_cache: None,
            schema: None,
        };
        let mut stalled_writer = must(
            connect_tcp(&stalled_cfg).await,
            "connect to stalled collector",
        );
        shrink_plain_send_buffer(&mut stalled_writer, 1024);
        let writer = Mutex::new(Some(stalled_writer));

        // Larger than the shrunk send/recv windows so write_all blocks against
        // a non-reading peer and hits write_timeout_ms.
        let huge = "x".repeat(256 * 1024);
        let batch = vec![SummaryLogEntry::Http(TransactionSummary {
            client_ip: "127.0.0.1".to_string(),
            http_method: "GET".to_string(),
            request_path: format!("/{huge}"),
            response_status_code: 200,
            ..TransactionSummary::default()
        })];

        let started = tokio::time::Instant::now();
        let stalled_err = match send_batch(&stalled_cfg, &writer, batch).await {
            Ok(()) => panic!("write against a non-reading peer must time out"),
            Err(error) => error,
        };
        let elapsed = started.elapsed();
        assert!(
            stalled_err.contains("write timeout"),
            "expected write timeout, got: {stalled_err}"
        );
        assert!(
            elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(3),
            "write timeout should land near write_timeout_ms, elapsed={elapsed:?}"
        );
        assert!(
            writer.lock().expect("writer lock").is_none(),
            "timed-out writer must be discarded before retry/reconnect"
        );

        let healthy_cfg = TcpFlushConfig {
            host: "127.0.0.1".to_string(),
            port: healthy_port,
            tls: None,
            connect_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            dns_cache: None,
            schema: None,
        };
        let small_batch = vec![SummaryLogEntry::Http(TransactionSummary {
            client_ip: "127.0.0.1".to_string(),
            http_method: "GET".to_string(),
            request_path: "/ok".to_string(),
            response_status_code: 200,
            ..TransactionSummary::default()
        })];
        must(
            send_batch(&healthy_cfg, &writer, small_batch).await,
            "healthy collector must accept the reconnecting send",
        );
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("healthy reader should receive a batch")
            .expect("channel open");
        let text = String::from_utf8_lossy(&received);
        assert!(text.contains("\"/ok\""), "unexpected payload: {text}");
    }
}
