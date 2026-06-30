//! UDP/DTLS access logging plugin — batched async log shipping over UDP.
//!
//! Serializes `TransactionSummary` and `StreamTransactionSummary` entries and
//! sends them to a remote UDP endpoint in batches. Uses
//! `BatchingLogger<LogEntry>` to decouple the proxy hot path from network I/O.
//!
//! Supports both plain UDP and DTLS-encrypted transport. When `dtls` is
//! enabled, the plugin performs a DTLS handshake on first use and encrypts all
//! log datagrams. DTLS client certificates and CA verification are configurable
//! for mutual TLS environments. The gateway's CRL list
//! (`FERRUM_TLS_CRL_FILE_PATH`) is applied to the DTLS server verifier with
//! `allow_unknown_revocation_status() + only_check_end_entity_revocation()`,
//! matching the proxy backend / DTLS / frontend mTLS surfaces.
//!
//! Each batch is serialized as a JSON array and sent as a single UDP datagram.
//! Operators should size `batch_size` to keep serialized payloads under the
//! network MTU (typically ~1400 bytes for DTLS, ~1472 for plain UDP over
//! Ethernet). Oversized datagrams may be fragmented or dropped.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rustls::pki_types::CertificateRevocationListDer;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::warn;

use super::utils::log_schema::{SummaryLogEntryBatchView, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, SummaryLogEntry,
    UDP_RE_RESOLVE_INTERVAL, bind_connected_udp_socket, build_batch_config, parse_socket_host,
    resolve_udp_endpoint, validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::dns::DnsCache;

#[derive(Clone)]
struct UdpFlushConfig {
    host: String,
    port: u16,
    dtls_enabled: bool,
    dtls_cert_path: Option<String>,
    dtls_key_path: Option<String>,
    dtls_ca_cert_path: Option<String>,
    dtls_no_verify: bool,
    /// Gateway CRL list (`FERRUM_TLS_CRL_FILE_PATH`). Applied to the DTLS
    /// `WebPkiServerVerifier` so that revoked log-sink certificates are
    /// rejected, matching the proxy backend / DTLS / frontend mTLS surfaces.
    /// Empty when no CRL file is configured.
    dtls_crls: Vec<CertificateRevocationListDer<'static>>,
    dns_cache: Option<DnsCache>,
    schema: Option<Arc<SummarySchema>>,
}

struct UdpFlushState {
    sender: Option<UdpSender>,
    current_addr: Option<SocketAddr>,
    last_resolve: Instant,
}

pub struct UdpLogging {
    logger: BatchingLogger<SummaryLogEntry>,
    endpoint_hostname: Option<String>,
}

impl UdpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("udp_logging: config must be an object".to_string());
        }

        let raw_host = config
            .get("host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "udp_logging: 'host' is required".to_string())?
            .to_string();
        let socket_host = parse_socket_host("udp_logging", "host", &raw_host)?;
        socket_host.screen_egress_ip("udp_logging", "host", http_client.backend_allow_ips())?;
        let host = socket_host.dial_host.clone();
        let port = config.get("port").and_then(Value::as_u64).ok_or_else(|| {
            "udp_logging: 'port' is required and must be a positive integer".to_string()
        })?;
        if port == 0 || port > 65535 {
            return Err(format!(
                "udp_logging: 'port' must be between 1 and 65535 (got {port})"
            ));
        }

        let dtls_enabled = optional_bool(config, "dtls")?.unwrap_or(false);
        let dtls_cert_path = optional_non_empty_string(config, "dtls_cert_path")?;
        let dtls_key_path = optional_non_empty_string(config, "dtls_key_path")?;
        let dtls_ca_cert_path = optional_non_empty_string(config, "dtls_ca_cert_path")?;
        let dtls_no_verify = optional_bool(config, "dtls_no_verify")?.unwrap_or(false);

        if dtls_cert_path.is_some() != dtls_key_path.is_some() {
            return Err(
                "udp_logging: 'dtls_cert_path' and 'dtls_key_path' must be provided together"
                    .to_string(),
            );
        }

        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 10,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: 10000,
            max_retries: 1,
            retry_delay_ms: 500,
        };
        validate_batch_config(config, "udp_logging", batch_defaults)?;

        let schema = resolve_schema(config, "udp_logging")?;
        let flush_config = UdpFlushConfig {
            host: host.clone(),
            port: port as u16,
            dtls_enabled,
            dtls_cert_path,
            dtls_key_path,
            dtls_ca_cert_path,
            dtls_no_verify,
            dtls_crls: http_client.tls_crls().to_vec(),
            dns_cache: http_client.dns_cache().cloned(),
            schema,
        };
        let state = Arc::new(Mutex::new(UdpFlushState {
            sender: None,
            current_addr: None,
            last_resolve: Instant::now(),
        }));
        let logger = BatchingLogger::spawn(
            // Config remains `max_retries`; the shared retry policy counts the
            // initial attempt plus those retries.
            build_batch_config(config, "udp_logging", batch_defaults),
            move |batch| {
                let flush_config = flush_config.clone();
                let state = Arc::clone(&state);
                async move { send_batch(&flush_config, &state, batch).await }
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
            .ok_or_else(|| format!("udp_logging: '{key}' must be a boolean")),
        None => Ok(None),
    }
}

fn optional_non_empty_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("udp_logging: '{key}' must be a string"))?
                .trim();
            if value.is_empty() {
                return Err(format!("udp_logging: '{key}' must not be empty"));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

#[async_trait]
impl Plugin for UdpLogging {
    fn name(&self) -> &str {
        "udp_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::UDP_LOGGING
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

/// Sender abstraction to handle both plain UDP and DTLS connections.
enum UdpSender {
    Plain(Arc<UdpSocket>),
    Dtls(Arc<crate::dtls::DtlsConnection>),
}

impl UdpSender {
    async fn send(&self, data: &[u8]) -> Result<(), String> {
        match self {
            UdpSender::Plain(socket) => socket
                .send(data)
                .await
                .map(|_| ())
                .map_err(|e| format!("UDP send error: {e}")),
            UdpSender::Dtls(conn) => conn
                .send(data)
                .await
                .map_err(|e| format!("DTLS send error: {e}")),
        }
    }
}

async fn create_sender(
    cfg: &UdpFlushConfig,
    dns_cache: Option<&DnsCache>,
) -> Result<(UdpSender, SocketAddr), String> {
    let remote_addr = resolve_udp_endpoint(&cfg.host, cfg.port, dns_cache, "udp_logging").await?;
    let sender = build_sender_for_addr(cfg, remote_addr).await?;
    Ok((sender, remote_addr))
}

/// Bind an ephemeral local UDP socket, connect to `remote_addr`, and (if
/// configured) complete a DTLS handshake.
async fn build_sender_for_addr(
    cfg: &UdpFlushConfig,
    remote_addr: SocketAddr,
) -> Result<UdpSender, String> {
    let socket = bind_connected_udp_socket(remote_addr, "udp_logging").await?;

    if cfg.dtls_enabled {
        let certificate =
            if let (Some(cert_path), Some(key_path)) = (&cfg.dtls_cert_path, &cfg.dtls_key_path) {
                crate::dtls::load_dtls_certificate(cert_path, key_path)
                    .map_err(|error| format!("udp_logging: DTLS cert load failed: {error}"))?
            } else {
                crate::dtls::generate_ephemeral_cert_public()
                    .map_err(|error| format!("udp_logging: DTLS ephemeral cert failed: {error}"))?
            };

        let (server_name, server_cert_verifier) = if cfg.dtls_no_verify {
            (None, None)
        } else {
            let root_store = if let Some(ca_path) = &cfg.dtls_ca_cert_path {
                crate::dtls::load_root_store_from_pem(ca_path)
                    .map_err(|error| format!("udp_logging: DTLS CA load failed: {error}"))?
            } else {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                roots
            };
            let server_name = rustls::pki_types::ServerName::try_from(cfg.host.clone())
                .map_err(|_| format!("udp_logging: invalid DTLS server name: {}", cfg.host))?;
            // Apply gateway CRL list (`FERRUM_TLS_CRL_FILE_PATH`) so revoked
            // DTLS log-sink certificates are rejected, matching the proxy
            // backend / DTLS / frontend mTLS surfaces.
            let verifier = crate::tls::build_server_verifier_with_crls(root_store, &cfg.dtls_crls)
                .map_err(|error| format!("udp_logging: DTLS verifier build failed: {error}"))?;
            (
                Some(server_name),
                Some(verifier as Arc<dyn rustls::client::danger::ServerCertVerifier>),
            )
        };

        let params = crate::dtls::BackendDtlsParams {
            config: Arc::new(dimpl::Config::default()),
            certificate,
            server_name,
            server_cert_verifier,
            // The udp_logging plugin doesn't expose a connect timeout config,
            // so preserve the historical 10s budget that this code path used
            // before `BackendDtlsParams.connect_timeout_ms` existed.
            connect_timeout_ms: 10_000,
        };

        let dtls_conn = crate::dtls::DtlsConnection::connect(socket, params)
            .await
            .map_err(|error| format!("udp_logging: DTLS handshake failed: {error}"))?;

        Ok(UdpSender::Dtls(Arc::new(dtls_conn)))
    } else {
        Ok(UdpSender::Plain(Arc::new(socket)))
    }
}

async fn send_batch(
    cfg: &UdpFlushConfig,
    state: &Mutex<UdpFlushState>,
    batch: Vec<SummaryLogEntry>,
) -> Result<(), String> {
    let view = SummaryLogEntryBatchView {
        entries: &batch,
        schema: cfg.schema.as_deref(),
    };
    let payload = match serde_json::to_vec(&view) {
        Ok(payload) => payload,
        Err(error) => {
            warn!("udp_logging: failed to serialize batch: {error}");
            return Ok(());
        }
    };

    let (mut sender, mut current_addr, mut last_resolve) = {
        let mut state = state
            .lock()
            .map_err(|_| "udp_logging: flush state lock poisoned".to_string())?;
        (state.sender.take(), state.current_addr, state.last_resolve)
    };

    if sender.is_none() {
        let (new_sender, new_addr) = create_sender(cfg, cfg.dns_cache.as_ref()).await?;
        last_resolve = Instant::now();
        sender = Some(new_sender);
        current_addr = Some(new_addr);
    }

    // Periodically re-resolve DNS and rebuild the sender when the endpoint
    // address actually changes (DNS rollover, pod reschedule, LB failover).
    // This applies to DTLS too: a connected DTLS association established once
    // at startup would otherwise keep sending to a stale peer forever. The
    // `current_addr != Some(new_addr)` guard ensures a fresh DTLS handshake
    // only runs when the resolved address moved, not on every interval.
    if last_resolve.elapsed() >= UDP_RE_RESOLVE_INTERVAL {
        last_resolve = Instant::now();
        if let Ok(new_addr) =
            resolve_udp_endpoint(&cfg.host, cfg.port, cfg.dns_cache.as_ref(), "udp_logging").await
            && current_addr != Some(new_addr)
            && let Ok(new_sender) = build_sender_for_addr(cfg, new_addr).await
        {
            sender = Some(new_sender);
            current_addr = Some(new_addr);
        }
    }

    let result = match sender.as_ref() {
        Some(sender) => sender.send(&payload).await,
        None => Err("udp_logging: sender unavailable after initialization".to_string()),
    };

    // On send failure, tear down the sender so the next batch's
    // `sender.is_none()` branch forces a fresh resolve + handshake. UDP/DTLS
    // sends frequently succeed at the socket layer even when the peer is gone,
    // so error-triggered teardown is the most robust recovery trigger and also
    // covers plain-UDP socket errors that the periodic re-resolve would miss.
    if result.is_err() {
        sender = None;
        current_addr = None;
    }

    let mut state = state
        .lock()
        .map_err(|_| "udp_logging: flush state lock poisoned".to_string())?;
    state.sender = sender;
    state.current_addr = current_addr;
    state.last_resolve = last_resolve;

    result
}
