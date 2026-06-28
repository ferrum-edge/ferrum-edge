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
//! with per-plugin `tls_server_name` override. Revoked log-sink certificates
//! are rejected via `WebPkiServerVerifier`'s
//! `allow_unknown_revocation_status() + only_check_end_entity_revocation()`
//! policy, matching the proxy backend / DTLS / frontend mTLS surfaces.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, matching the http_logging plugin's behavior.

use async_trait::async_trait;
use rustls::pki_types::CertificateRevocationListDer;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::warn;

use super::utils::log_schema::{SummaryLogEntryView, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, SummaryLogEntry, build_batch_config,
    parse_socket_host, resolve_tcp_endpoint, validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::dns::DnsCache;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

#[derive(Clone)]
struct TcpFlushConfig {
    host: String,
    port: u16,
    tls_server_name: Option<String>,
    /// Prebuilt TLS connector, or `None` when TLS is disabled.
    ///
    /// The CA-bundle read + PEM parse and the `WebPkiServerVerifier` build
    /// (which applies the gateway CRL list, `FERRUM_TLS_CRL_FILE_PATH`, so
    /// revoked log-sink certificates are rejected) all happen once in
    /// `TcpLogging::new` — off the async flush task. Reconnects clone this
    /// cheap `Arc<ClientConfig>`-backed connector instead of re-reading the
    /// filesystem and re-parsing PEM synchronously on a tokio worker thread.
    tls_connector: Option<tokio_rustls::TlsConnector>,
    connect_timeout: Duration,
    /// Gateway-shared DNS cache for endpoint resolution. Pre-warmed at startup
    /// via `Plugin::warmup_hostnames`, refreshed in the background. `None` only
    /// when the plugin was constructed via the test/fallback `PluginHttpClient`
    /// path that has no cache attached.
    dns_cache: Option<DnsCache>,
    schema: Option<Arc<SummarySchema>>,
}

pub struct TcpLogging {
    logger: BatchingLogger<SummaryLogEntry>,
    endpoint_hostname: Option<String>,
}

impl TcpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("tcp_logging: config must be an object".to_string());
        }

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
        let tls_server_name = optional_non_empty_string(config, "tls_server_name")?;

        let connect_timeout_ms = optional_u64(config, "connect_timeout_ms")?
            .unwrap_or(5000)
            .max(100);

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

        let schema = resolve_schema(config, "tcp_logging")?;
        // Build the TLS connector once, here on the cold construction path. The
        // CA bundle is read + PEM-parsed synchronously inside
        // `build_tls_connector`; doing it now (rather than per reconnect inside
        // the async flush task) keeps blocking filesystem I/O off the tokio
        // runtime and surfaces a bad CA bundle at admission time.
        let tls_connector = if tls_enabled {
            Some(build_tls_connector(
                http_client.tls_no_verify(),
                http_client.tls_ca_bundle_path(),
                http_client.tls_crls(),
            )?)
        } else {
            None
        };
        let flush_config = TcpFlushConfig {
            host: host.clone(),
            port,
            tls_server_name,
            tls_connector,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            dns_cache: http_client.dns_cache().cloned(),
            schema,
        };
        let writer = Arc::new(Mutex::new(None));
        let logger = BatchingLogger::spawn(
            // Config remains `max_retries`; the shared retry policy counts the
            // initial attempt plus those retries.
            build_batch_config(config, "tcp_logging", batch_defaults),
            move |batch| {
                let flush_config = flush_config.clone();
                let writer = Arc::clone(&writer);
                async move { send_batch(&flush_config, &writer, batch).await }
            },
        );

        Ok(Self {
            logger,
            endpoint_hostname: socket_host.warmup_hostname,
        })
    }
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

fn optional_non_empty_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("tcp_logging: '{key}' must be a string"))?
                .trim();
            if value.is_empty() {
                return Err(format!("tcp_logging: '{key}' must not be empty"));
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
    // Both the resolve and the TCP connect happen inside `cfg.connect_timeout`:
    // the previous `TcpStream::connect("host:port")` form had the OS DNS
    // lookup implicitly bounded by the connect timeout. Now that we resolve
    // explicitly first, a cold/expired cache or stuck upstream nameserver
    // could otherwise block the batching task well past `connect_timeout_ms`,
    // delaying log delivery and retries — so the timeout wraps the full
    // resolve+connect sequence.
    let host_log = cfg.host.clone();
    let port = cfg.port;
    let resolve_and_connect = async {
        let socket_addr =
            resolve_tcp_endpoint(&cfg.host, cfg.port, cfg.dns_cache.as_ref(), "tcp_logging")
                .await?;
        let addr_log = format!("{host_log} ({socket_addr})");
        let stream = TcpStream::connect(socket_addr)
            .await
            .map_err(|e| format!("TCP logging: failed to connect to {addr_log}: {e}"))?;
        Ok::<(TcpStream, String), String>((stream, addr_log))
    };

    let (stream, addr_log) = tokio::time::timeout(cfg.connect_timeout, resolve_and_connect)
        .await
        .map_err(|_| format!("TCP logging: connect timeout to {host_log}:{port}"))??;

    let Some(connector) = cfg.tls_connector.clone() else {
        return Ok(TcpWriter::Plain(stream));
    };

    let server_name_str = cfg.tls_server_name.as_deref().unwrap_or(&cfg.host);
    let server_name = rustls::pki_types::ServerName::try_from(server_name_str.to_string())
        .map_err(|error| {
            format!("TCP logging: invalid TLS server name '{server_name_str}': {error}")
        })?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("TCP logging: TLS handshake failed with {addr_log}: {error}"))?;

    Ok(TcpWriter::Tls(Box::new(tls_stream)))
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
            let source_id = ca_material.source_id.clone();
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
            tls_server_name: Some("localhost".to_string()),
            tls_connector: Some(tls_connector),
            connect_timeout: Duration::from_secs(2),
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
            tls_server_name: Some("localhost".to_string()),
            tls_connector: Some(tls_connector),
            connect_timeout: Duration::from_secs(2),
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
}
