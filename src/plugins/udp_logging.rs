//! UDP/DTLS access logging plugin — batched async log shipping over UDP.
//!
//! Serializes `TransactionSummary` and `StreamTransactionSummary` entries and
//! sends them to a remote UDP endpoint in batches. Uses an mpsc channel to
//! decouple the proxy hot path from network I/O: the `log()` hook enqueues
//! the entry (non-blocking), and a background task drains the channel in
//! configurable batch sizes with a flush interval timer.
//!
//! Supports both plain UDP and DTLS-encrypted transport. When `dtls` is
//! enabled, the plugin performs a DTLS handshake at startup and encrypts
//! all log datagrams. DTLS client certificates and CA verification are
//! configurable for mutual TLS environments.
//!
//! Each batch is serialized as a JSON array and sent as a single UDP datagram.
//! Operators should size `batch_size` to keep serialized payloads under the
//! network MTU (typically ~1400 bytes for DTLS, ~1472 for plain UDP over
//! Ethernet). Oversized datagrams may be fragmented or dropped.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::warn;

use super::utils::PluginHttpClient;
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::dns::DnsCache;

/// How often to re-resolve the remote UDP endpoint even if sends succeed.
const RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(60);

/// Union type for log entries sent through the batched channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

pub struct UdpLogging {
    sender: mpsc::Sender<LogEntry>,
    endpoint_hostname: Option<String>,
}

impl UdpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let host = config["host"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "udp_logging: 'host' is required".to_string())?
            .to_string();
        let port = config["port"].as_u64().ok_or_else(|| {
            "udp_logging: 'port' is required and must be a positive integer".to_string()
        })?;
        if port == 0 || port > 65535 {
            return Err(format!(
                "udp_logging: 'port' must be between 1 and 65535 (got {port})"
            ));
        }

        let dtls_enabled = config["dtls"].as_bool().unwrap_or(false);
        let dtls_cert_path = config["dtls_cert_path"].as_str().map(|s| s.to_string());
        let dtls_key_path = config["dtls_key_path"].as_str().map(|s| s.to_string());
        let dtls_ca_cert_path = config["dtls_ca_cert_path"].as_str().map(|s| s.to_string());
        let dtls_no_verify = config["dtls_no_verify"].as_bool().unwrap_or(false);

        // Validate cert/key pairing
        if dtls_cert_path.is_some() != dtls_key_path.is_some() {
            return Err(
                "udp_logging: 'dtls_cert_path' and 'dtls_key_path' must be provided together"
                    .to_string(),
            );
        }

        let batch_size = config["batch_size"].as_u64().unwrap_or(10).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(1000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;
        let max_retries = config["max_retries"].as_u64().unwrap_or(1) as u32;
        let retry_delay = Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(500));

        let endpoint_hostname = Some(host.clone());

        let send_config = UdpSendConfig {
            host,
            port: port as u16,
            dtls_enabled,
            dtls_cert_path,
            dtls_key_path,
            dtls_ca_cert_path,
            dtls_no_verify,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries,
            retry_delay,
        };

        let dns_cache = http_client.dns_cache().cloned();

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, send_config, dns_cache));

        Ok(Self {
            sender,
            endpoint_hostname,
        })
    }
}

struct UdpSendConfig {
    host: String,
    port: u16,
    dtls_enabled: bool,
    dtls_cert_path: Option<String>,
    dtls_key_path: Option<String>,
    dtls_ca_cert_path: Option<String>,
    dtls_no_verify: bool,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
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
        if self
            .sender
            .try_send(LogEntry::Stream(summary.clone()))
            .is_err()
        {
            warn!("UDP logging buffer full — dropping stream log entry");
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self
            .sender
            .try_send(LogEntry::Http(summary.clone()))
            .is_err()
        {
            warn!("UDP logging buffer full — dropping log entry");
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
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

/// Resolve the remote UDP endpoint. Prefers the gateway's shared `DnsCache`
/// (TTL-aware, stale-while-revalidate, background refresh) and falls back to
/// `tokio::net::lookup_host` when no cache is present (tests / fallback).
async fn resolve_endpoint(
    host: &str,
    port: u16,
    dns_cache: Option<&DnsCache>,
) -> Result<SocketAddr, String> {
    if let Some(cache) = dns_cache {
        match cache.resolve(host, None, None).await {
            Ok(ip) => return Ok(SocketAddr::new(ip, port)),
            Err(e) => {
                warn!(
                    "udp_logging: DNS cache resolution failed for '{host}': {e} — falling back to system DNS"
                );
            }
        }
    }
    use tokio::net::lookup_host;
    let addr_str = format!("{host}:{port}");
    lookup_host(&addr_str)
        .await
        .map_err(|e| format!("udp_logging: DNS resolution failed for {addr_str}: {e}"))?
        .next()
        .ok_or_else(|| format!("udp_logging: no addresses resolved for {addr_str}"))
}

async fn create_sender(
    cfg: &UdpSendConfig,
    dns_cache: Option<&DnsCache>,
) -> Result<UdpSender, String> {
    let remote_addr = resolve_endpoint(&cfg.host, cfg.port, dns_cache).await?;

    // Bind to an ephemeral local port — use IPv4 or IPv6 to match the remote
    let bind_addr: SocketAddr = if remote_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("udp_logging: bind failed: {e}"))?;
    socket
        .connect(remote_addr)
        .await
        .map_err(|e| format!("udp_logging: connect to {remote_addr} failed: {e}"))?;

    if cfg.dtls_enabled {
        let certificate =
            if let (Some(cert_path), Some(key_path)) = (&cfg.dtls_cert_path, &cfg.dtls_key_path) {
                crate::dtls::load_dtls_certificate(cert_path, key_path)
                    .map_err(|e| format!("udp_logging: DTLS cert load failed: {e}"))?
            } else {
                crate::dtls::generate_ephemeral_cert_public()
                    .map_err(|e| format!("udp_logging: DTLS ephemeral cert failed: {e}"))?
            };

        let (server_name, server_cert_verifier) = if cfg.dtls_no_verify {
            (None, None)
        } else {
            let root_store = if let Some(ca_path) = &cfg.dtls_ca_cert_path {
                crate::dtls::load_root_store_from_pem(ca_path)
                    .map_err(|e| format!("udp_logging: DTLS CA load failed: {e}"))?
            } else {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                roots
            };
            let server_name = rustls::pki_types::ServerName::try_from(cfg.host.clone())
                .map_err(|_| format!("udp_logging: invalid DTLS server name: {}", cfg.host))?;
            let verifier = crate::tls::build_server_verifier_with_crls(
                root_store,
                &[], // No CRL for logging endpoint
            )
            .map_err(|e| format!("udp_logging: DTLS verifier build failed: {e}"))?;
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
        };

        let dtls_conn = crate::dtls::DtlsConnection::connect(socket, params)
            .await
            .map_err(|e| format!("udp_logging: DTLS handshake failed: {e}"))?;

        Ok(UdpSender::Dtls(Arc::new(dtls_conn)))
    } else {
        Ok(UdpSender::Plain(Arc::new(socket)))
    }
}

async fn flush_loop(
    mut receiver: mpsc::Receiver<LogEntry>,
    cfg: UdpSendConfig,
    dns_cache: Option<DnsCache>,
) {
    // Establish the UDP/DTLS connection. On failure, log and drain the channel.
    let mut sender = match create_sender(&cfg, dns_cache.as_ref()).await {
        Ok(s) => s,
        Err(e) => {
            warn!("udp_logging: failed to create sender, logs will be dropped: {e}");
            while receiver.recv().await.is_some() {}
            return;
        }
    };

    let mut buffer: Vec<LogEntry> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    // The first tick completes immediately — consume it so the first real
    // flush waits for one full interval.
    timer.tick().await;
    // Periodic DNS re-resolution so a changing A/AAAA record propagates
    // without requiring a gateway restart. Plain UDP can re-bind cheaply;
    // DTLS reconnection is expensive, so we only rebuild the sender when
    // the resolved address actually changes (DTLS case handled inside
    // `create_sender`).
    let mut last_resolve = Instant::now();

    loop {
        if last_resolve.elapsed() >= RE_RESOLVE_INTERVAL {
            last_resolve = Instant::now();
            if !cfg.dtls_enabled
                && let Ok(new_sender) = create_sender(&cfg, dns_cache.as_ref()).await
            {
                sender = new_sender;
            }
        }

        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(entry) => {
                        buffer.push(entry);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&cfg, &sender, batch).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining entries and exit.
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&cfg, &sender, batch).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    send_batch(&cfg, &sender, batch).await;
                }
            }
        }
    }
}

async fn send_batch(cfg: &UdpSendConfig, sender: &UdpSender, batch: Vec<LogEntry>) {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();

    let payload = match serde_json::to_vec(&batch) {
        Ok(p) => p,
        Err(e) => {
            warn!("udp_logging: failed to serialize batch: {e}");
            return;
        }
    };

    for attempt in 1..=total_attempts {
        match sender.send(&payload).await {
            Ok(()) => return,
            Err(e) => {
                warn!("UDP logging batch failed: {e} (attempt {attempt}/{total_attempts})",);
            }
        }
        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "UDP logging batch discarded after {total_attempts} attempts ({entry_count} entries lost)",
    );
}
