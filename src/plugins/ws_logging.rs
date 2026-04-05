//! WebSocket access logging plugin — batched async log shipping over ws/wss.
//!
//! Serializes `TransactionSummary` entries and sends them to a remote WebSocket
//! endpoint in batches. Uses an mpsc channel to decouple the proxy hot path
//! from network I/O: the `log()` hook enqueues the entry (non-blocking), and
//! a background task drains the channel in configurable batch sizes with a
//! flush interval timer. The WebSocket connection is maintained persistently
//! with automatic reconnection on failure.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type.
//!
//! **TLS**: For `wss://` endpoints, the plugin builds a `rustls::ClientConfig`
//! that follows the gateway's CA trust chain:
//! - Custom CA (`FERRUM_TLS_CA_BUNDLE_PATH`) → sole trust anchor (webpki roots excluded)
//! - No CA configured → webpki/system roots as default fallback
//! - `FERRUM_TLS_NO_VERIFY` → skip server certificate verification

use async_trait::async_trait;
use futures_util::SinkExt;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;
use url::Url;

use super::utils::PluginHttpClient;
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Union type for log entries sent through the batched channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

struct WsConfig {
    endpoint_url: String,
    connector: Option<tokio_tungstenite::Connector>,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    reconnect_delay: Duration,
}

pub struct WsLogging {
    sender: mpsc::Sender<LogEntry>,
    endpoint_hostname: Option<String>,
}

impl WsLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let endpoint_url = config["endpoint_url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "ws_logging: 'endpoint_url' is required — logs will have nowhere to send"
                    .to_string()
            })?
            .to_string();
        let parsed_url = Url::parse(&endpoint_url)
            .map_err(|e| format!("ws_logging: invalid 'endpoint_url': {e}"))?;
        match parsed_url.scheme() {
            "ws" | "wss" => {}
            scheme => {
                return Err(format!(
                    "ws_logging: 'endpoint_url' must use ws:// or wss:// (got '{scheme}')"
                ));
            }
        }
        if parsed_url.host_str().is_none() {
            return Err(
                "ws_logging: 'endpoint_url' must include a hostname or IP address".to_string(),
            );
        }

        // Build TLS connector for wss:// using gateway CA/verify settings.
        let connector = if parsed_url.scheme() == "wss" {
            Some(build_tls_connector(&http_client)?)
        } else {
            None
        };

        let batch_size = config["batch_size"].as_u64().unwrap_or(50).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(1000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;

        let ws_config = WsConfig {
            endpoint_url,
            connector,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries: config["max_retries"].as_u64().unwrap_or(3) as u32,
            retry_delay: Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(1000)),
            reconnect_delay: Duration::from_millis(
                config["reconnect_delay_ms"].as_u64().unwrap_or(5000),
            ),
        };

        let endpoint_hostname = parsed_url.host_str().map(|h| h.to_string());

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, ws_config));

        Ok(Self {
            sender,
            endpoint_hostname,
        })
    }
}

/// Build a `tokio_tungstenite::Connector::Rustls` that follows the gateway's
/// CA trust chain: custom CA → sole anchor, no CA → webpki roots, no-verify →
/// skip verification entirely.
fn build_tls_connector(
    http_client: &PluginHttpClient,
) -> Result<tokio_tungstenite::Connector, String> {
    let tls_no_verify = http_client.tls_no_verify();
    let ca_bundle_path = http_client.tls_ca_bundle_path();

    // Build root certificate store following the gateway's CA trust chain:
    // - Custom CA configured → empty store + only that CA (CA exclusivity)
    // - No CA configured → webpki roots as default fallback
    let mut root_store = if ca_bundle_path.is_some() {
        rustls::RootCertStore::empty()
    } else {
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    };

    if let Some(ca_path) = ca_bundle_path {
        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| format!("ws_logging: failed to read CA bundle '{ca_path}': {e}"))?;
        let mut cursor = std::io::Cursor::new(ca_pem);
        for cert in rustls_pemfile::certs(&mut cursor).flatten() {
            root_store
                .add(cert)
                .map_err(|e| format!("ws_logging: failed to add CA certificate: {e}"))?;
        }
    }

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if tls_no_verify {
        warn!("WebSocket logging TLS certificate verification DISABLED (FERRUM_TLS_NO_VERIFY)");
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(crate::tls::NoVerifier));
    }

    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(
        client_config,
    )))
}

#[async_trait]
impl Plugin for WsLogging {
    fn name(&self) -> &str {
        "ws_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_LOGGING
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
            warn!("WebSocket logging buffer full — dropping stream log entry");
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self
            .sender
            .try_send(LogEntry::Http(summary.clone()))
            .is_err()
        {
            warn!("WebSocket logging buffer full — dropping log entry");
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }
}

/// Background task that maintains a persistent WebSocket connection and
/// flushes batched log entries as JSON text messages.
async fn flush_loop(mut receiver: mpsc::Receiver<LogEntry>, cfg: WsConfig) {
    if cfg.endpoint_url.is_empty() {
        while receiver.recv().await.is_some() {}
        return;
    }

    let mut buffer: Vec<LogEntry> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    timer.tick().await;

    // Lazily connect — the first flush attempt will establish the connection.
    let mut ws_sink: Option<WsSink> = None;

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(entry) => {
                        buffer.push(entry);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            ws_sink = send_batch(&cfg, batch, ws_sink).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining entries and exit.
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            let _ = send_batch(&cfg, batch, ws_sink).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    ws_sink = send_batch(&cfg, batch, ws_sink).await;
                }
            }
        }
    }
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::protocol::Message,
>;

/// Attempt to send a batch over the WebSocket connection. Returns the sink
/// on success, or `None` if the connection was lost and could not be
/// re-established within the retry budget.
async fn send_batch(
    cfg: &WsConfig,
    batch: Vec<LogEntry>,
    mut sink: Option<WsSink>,
) -> Option<WsSink> {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();

    let payload = match serde_json::to_string(&batch) {
        Ok(json) => json,
        Err(e) => {
            warn!("WebSocket logging: failed to serialize batch: {e}");
            return sink;
        }
    };

    for attempt in 1..=total_attempts {
        // Ensure we have a live connection.
        if sink.is_none() {
            sink = connect(cfg).await;
            if sink.is_none() {
                warn!(
                    "WebSocket logging: connection failed (attempt {}/{})",
                    attempt, total_attempts,
                );
                if attempt < total_attempts {
                    tokio::time::sleep(cfg.retry_delay).await;
                }
                continue;
            }
        }

        if let Some(ref mut ws) = sink {
            let msg =
                tokio_tungstenite::tungstenite::protocol::Message::Text(payload.clone().into());
            match ws.send(msg).await {
                Ok(()) => return sink,
                Err(e) => {
                    warn!(
                        "WebSocket logging: send failed: {e} (attempt {}/{})",
                        attempt, total_attempts,
                    );
                    // Connection is broken — drop it and reconnect on next attempt.
                    sink = None;
                    if attempt < total_attempts {
                        tokio::time::sleep(cfg.retry_delay).await;
                    }
                }
            }
        }
    }

    warn!(
        "WebSocket logging batch discarded after {} attempts ({} entries lost)",
        total_attempts, entry_count,
    );
    sink
}

/// Establish a new WebSocket connection to the configured endpoint.
///
/// Uses `connect_async_tls_with_config` with the pre-built TLS connector
/// so that `wss://` connections respect the gateway's CA trust chain and
/// `FERRUM_TLS_NO_VERIFY` setting.
async fn connect(cfg: &WsConfig) -> Option<WsSink> {
    use futures_util::StreamExt;

    match tokio_tungstenite::connect_async_tls_with_config(
        &cfg.endpoint_url,
        None,
        false,
        cfg.connector.clone(),
    )
    .await
    {
        Ok((stream, _response)) => {
            let (sink, _read) = stream.split();
            Some(sink)
        }
        Err(e) => {
            warn!(
                "WebSocket logging: failed to connect to {}: {e} — will retry in {:?}",
                cfg.endpoint_url, cfg.reconnect_delay,
            );
            tokio::time::sleep(cfg.reconnect_delay).await;
            None
        }
    }
}
