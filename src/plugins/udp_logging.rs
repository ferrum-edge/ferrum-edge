//! UDP/DTLS access logging plugin — batched async log shipping over UDP.
//!
//! Serializes `TransactionSummary` and `StreamTransactionSummary` entries and
//! sends them to a remote UDP endpoint in batches. Uses
//! `BatchingLogger<LogEntry>` to decouple the proxy hot path from network I/O.
//!
//! Supports both plain UDP and DTLS-encrypted transport. When `dtls` is
//! enabled, the plugin performs a DTLS handshake on first use and encrypts all
//! log datagrams. DTLS client certificates and CA verification are configurable
//! for mutual TLS environments.
//!
//! Each batch is serialized as a JSON array and sent as a single UDP datagram.
//! Operators should size `batch_size` to keep serialized payloads under the
//! network MTU (typically ~1400 bytes for DTLS, ~1472 for plain UDP over
//! Ethernet). Oversized datagrams may be fragmented or dropped.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::warn;

use super::utils::{BatchConfig, BatchingLogger, PluginHttpClient, RetryPolicy};
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

#[derive(Clone)]
struct UdpFlushConfig {
    host: String,
    port: u16,
    dtls_enabled: bool,
    dtls_cert_path: Option<String>,
    dtls_key_path: Option<String>,
    dtls_ca_cert_path: Option<String>,
    dtls_no_verify: bool,
    dns_cache: Option<DnsCache>,
}

struct UdpFlushState {
    sender: Option<UdpSender>,
    current_addr: Option<SocketAddr>,
    last_resolve: Instant,
}

pub struct UdpLogging {
    logger: BatchingLogger<LogEntry>,
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
        let retry_delay = Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(500));

        let flush_config = UdpFlushConfig {
            host: host.clone(),
            port: port as u16,
            dtls_enabled,
            dtls_cert_path,
            dtls_key_path,
            dtls_ca_cert_path,
            dtls_no_verify,
            dns_cache: http_client.dns_cache().cloned(),
        };
        let state = Arc::new(Mutex::new(UdpFlushState {
            sender: None,
            current_addr: None,
            last_resolve: Instant::now(),
        }));
        let logger = BatchingLogger::spawn(
            BatchConfig {
                batch_size,
                flush_interval: Duration::from_millis(flush_interval_ms),
                buffer_capacity,
                retry: RetryPolicy {
                    max_attempts: config["max_retries"].as_u64().unwrap_or(1) as u32 + 1,
                    delay: retry_delay,
                },
                plugin_name: "udp_logging",
            },
            move |batch| {
                let flush_config = flush_config.clone();
                let state = Arc::clone(&state);
                async move { send_batch(&flush_config, &state, batch).await }
            },
        );

        Ok(Self {
            logger,
            endpoint_hostname: Some(host),
        })
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
        self.logger.try_send(LogEntry::Stream(summary.clone()));
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(LogEntry::Http(summary.clone()));
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname
            .as_ref()
            .map(|host| vec![host.clone()])
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
/// and falls back to `tokio::net::lookup_host` when no cache is present.
async fn resolve_endpoint(
    host: &str,
    port: u16,
    dns_cache: Option<&DnsCache>,
) -> Result<SocketAddr, String> {
    if let Some(cache) = dns_cache {
        match cache.resolve(host, None, None).await {
            Ok(ip) => return Ok(SocketAddr::new(ip, port)),
            Err(error) => {
                warn!(
                    "udp_logging: DNS cache resolution failed for '{host}': {error} — falling back to system DNS"
                );
            }
        }
    }

    let addr_str = format!("{host}:{port}");
    tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|error| format!("udp_logging: DNS resolution failed for {addr_str}: {error}"))?
        .next()
        .ok_or_else(|| format!("udp_logging: no addresses resolved for {addr_str}"))
}

async fn create_sender(
    cfg: &UdpFlushConfig,
    dns_cache: Option<&DnsCache>,
) -> Result<(UdpSender, SocketAddr), String> {
    let remote_addr = resolve_endpoint(&cfg.host, cfg.port, dns_cache).await?;
    let sender = build_sender_for_addr(cfg, remote_addr).await?;
    Ok((sender, remote_addr))
}

/// Bind an ephemeral local UDP socket, connect to `remote_addr`, and (if
/// configured) complete a DTLS handshake.
async fn build_sender_for_addr(
    cfg: &UdpFlushConfig,
    remote_addr: SocketAddr,
) -> Result<UdpSender, String> {
    let bind_addr = if remote_addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|error| format!("udp_logging: bind failed: {error}"))?;
    socket
        .connect(remote_addr)
        .await
        .map_err(|error| format!("udp_logging: connect to {remote_addr} failed: {error}"))?;

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
            let verifier = crate::tls::build_server_verifier_with_crls(root_store, &[])
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
    batch: Vec<LogEntry>,
) -> Result<(), String> {
    let payload = match serde_json::to_vec(&batch) {
        Ok(payload) => payload,
        Err(error) => {
            warn!("udp_logging: failed to serialize batch: {error}");
            return Ok(());
        }
    };

    let mut state = state.lock().await;

    if state.sender.is_none() {
        let (sender, current_addr) = create_sender(cfg, cfg.dns_cache.as_ref()).await?;
        state.sender = Some(sender);
        state.current_addr = Some(current_addr);
        state.last_resolve = Instant::now();
    }

    if !cfg.dtls_enabled && state.last_resolve.elapsed() >= RE_RESOLVE_INTERVAL {
        state.last_resolve = Instant::now();
        if let Ok(new_addr) = resolve_endpoint(&cfg.host, cfg.port, cfg.dns_cache.as_ref()).await
            && state.current_addr != Some(new_addr)
            && let Ok(new_sender) = build_sender_for_addr(cfg, new_addr).await
        {
            state.sender = Some(new_sender);
            state.current_addr = Some(new_addr);
        }
    }

    let Some(sender) = state.sender.as_ref() else {
        return Err("udp_logging: sender unavailable after initialization".to_string());
    };
    sender.send(&payload).await
}
