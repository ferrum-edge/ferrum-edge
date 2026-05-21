//! WebSocket access logging plugin — batched async log shipping over ws/wss.
//!
//! Serializes `TransactionSummary`, `StreamTransactionSummary`, and WebSocket
//! disconnect entries, then sends them to a remote WebSocket endpoint in batches.
//! Uses an mpsc channel to decouple the proxy hot path from network I/O: hooks
//! enqueue entries non-blocking, and a background task drains the channel in
//! configurable batch sizes with a flush interval timer. The WebSocket
//! connection is maintained persistently with automatic reconnection on failure.
//!
//! **TLS**: For `wss://` endpoints, the plugin builds a `rustls::ClientConfig`
//! that follows the gateway's CA trust chain:
//! - Custom CA (`FERRUM_TLS_CA_BUNDLE_PATH`) → sole trust anchor (webpki roots excluded)
//! - No CA configured → webpki/system roots as default fallback
//! - `FERRUM_TLS_NO_VERIFY` → skip server certificate verification
//! - CRL list (`FERRUM_TLS_CRL_FILE_PATH`) is applied via `WebPkiServerVerifier`
//!   with `allow_unknown_revocation_status() + only_check_end_entity_revocation()`,
//!   so revoked log-sink certificates are rejected. Matches the proxy backend /
//!   DTLS / frontend mTLS surfaces.

use async_trait::async_trait;
use futures_util::SinkExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;
use url::Url;

use super::utils::log_schema::{SchemaView, SummarySchema, resolve_schema};
use super::utils::{BatchConfigDefaults, PluginHttpClient, validate_batch_config};
use super::{
    ALL_PROTOCOLS, Direction, Plugin, ProxyProtocol, StreamTransactionSummary, TransactionSummary,
    WsDisconnectContext,
};

/// Union type for log entries sent through the batched channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
    WebSocket(WsDisconnectLogEntry),
}

// TODO: extend the customizable log schema to WsDisconnectLogEntry.
// Today `schema:` / `schema_ref:` on ws_logging only customize HTTP and
// Stream summaries; WebSocket-disconnect entries fall through with their
// native field set. Tracked under "Per-Plugin Notes" in
// docs/log_schema.md. Implementing this means teaching `SchemaView`
// (or a sibling view) about a third summary kind keyed off the fields
// in this struct, then routing it through `WsBatchView` like the other
// two arms.
#[derive(Clone, serde::Serialize)]
struct WsDisconnectLogEntry {
    event: &'static str,
    namespace: String,
    proxy_id: String,
    proxy_name: Option<String>,
    client_ip: String,
    consumer_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_method: Option<&'static str>,
    backend_target: String,
    protocol: &'static str,
    listen_port: u16,
    duration_ms: f64,
    frames_client_to_backend: u64,
    frames_backend_to_client: u64,
    direction: Option<Direction>,
    io_side: Option<crate::proxy::tcp_proxy::StreamIoSide>,
    error_class: Option<crate::retry::ErrorClass>,
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "crate::plugins::utils::metadata_redaction::serialize_redacted_metadata"
    )]
    metadata: HashMap<String, String>,
}

impl From<&WsDisconnectContext> for WsDisconnectLogEntry {
    fn from(ctx: &WsDisconnectContext) -> Self {
        Self {
            event: "websocket_disconnect",
            namespace: ctx.namespace.clone(),
            proxy_id: ctx.proxy_id.clone(),
            proxy_name: ctx.proxy_name.clone(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.consumer_username.clone(),
            auth_method: ctx.auth_method,
            backend_target: ctx.backend_target.clone(),
            protocol: "websocket",
            listen_port: ctx.listen_port,
            duration_ms: ctx.duration_ms,
            frames_client_to_backend: ctx.frames_client_to_backend,
            frames_backend_to_client: ctx.frames_backend_to_client,
            direction: ctx.direction,
            io_side: ctx.io_side,
            error_class: ctx.error_class,
            metadata: ctx.metadata.clone(),
        }
    }
}

struct WsConfig {
    endpoint_url: String,
    connector: Option<tokio_tungstenite::Connector>,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    reconnect_delay: Duration,
    schema: Option<Arc<SummarySchema>>,
}

/// Serialize-time wrapper: emits the LogEntry slice as a JSON array,
/// applying `schema` to HTTP / Stream entries when its `summary_type`
/// matches. WebSocket disconnect entries keep their native format.
struct WsBatchView<'a> {
    entries: &'a [LogEntry],
    schema: Option<&'a SummarySchema>,
}

impl<'a> serde::Serialize for WsBatchView<'a> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = ser.serialize_seq(Some(self.entries.len()))?;
        for entry in self.entries {
            match (entry, self.schema) {
                (LogEntry::Http(summary), Some(schema)) if schema.applies_to_http() => {
                    seq.serialize_element(&SchemaView { summary, schema })?;
                }
                (LogEntry::Stream(summary), Some(schema)) if schema.applies_to_stream() => {
                    seq.serialize_element(&SchemaView { summary, schema })?;
                }
                _ => seq.serialize_element(entry)?,
            }
        }
        seq.end()
    }
}

pub struct WsLogging {
    sender: mpsc::Sender<LogEntry>,
    endpoint_hostname: Option<String>,
}

impl WsLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ws_logging: config must be a JSON object".to_string());
        }

        let endpoint_url = config
            .get("endpoint_url")
            .and_then(Value::as_str)
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

        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 50,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: 10_000,
            max_retries: 3,
            retry_delay_ms: 1000,
        };
        validate_batch_config(config, "ws_logging", batch_defaults)?;
        if let Some(value) = config.get("reconnect_delay_ms")
            && value.as_u64().is_none()
        {
            return Err("ws_logging: 'reconnect_delay_ms' must be an unsigned integer".to_string());
        }

        let batch_size = optional_usize(config, "batch_size", batch_defaults.batch_size)?.max(1);
        let flush_interval_ms = optional_u64(
            config,
            "flush_interval_ms",
            batch_defaults.flush_interval_ms,
        )?
        .max(batch_defaults.min_flush_interval_ms);
        let buffer_capacity =
            optional_usize(config, "buffer_capacity", batch_defaults.buffer_capacity)?.max(1);
        let max_retries =
            optional_u32_saturating(config, "max_retries", batch_defaults.max_retries)?;
        let retry_delay_ms = optional_u64(config, "retry_delay_ms", batch_defaults.retry_delay_ms)?;
        let reconnect_delay_ms = optional_u64(config, "reconnect_delay_ms", 5000)?;

        let schema = resolve_schema(config, "ws_logging")?;
        let ws_config = WsConfig {
            endpoint_url,
            connector,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries,
            retry_delay: Duration::from_millis(retry_delay_ms),
            reconnect_delay: Duration::from_millis(reconnect_delay_ms),
            schema,
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

fn optional_u64(config: &Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("ws_logging: '{key}' must be an unsigned integer")),
        None => Ok(default),
    }
}

fn optional_usize(config: &Value, key: &str, default: u64) -> Result<usize, String> {
    Ok(optional_u64(config, key, default)?.min(usize::MAX as u64) as usize)
}

fn optional_u32_saturating(config: &Value, key: &str, default: u64) -> Result<u32, String> {
    Ok(optional_u64(config, key, default)?.min(u64::from(u32::MAX)) as u32)
}

/// Build a `tokio_tungstenite::Connector::Rustls` that follows the gateway's
/// CA trust chain: custom CA → sole anchor, no CA → webpki roots, no-verify →
/// skip verification entirely. The gateway's CRL list
/// (`FERRUM_TLS_CRL_FILE_PATH`) is applied via `WebPkiServerVerifier` so that
/// revoked log-sink certificates are rejected, matching the proxy backend /
/// DTLS / frontend mTLS surfaces.
fn build_tls_connector(
    http_client: &PluginHttpClient,
) -> Result<tokio_tungstenite::Connector, String> {
    let tls_no_verify = http_client.tls_no_verify();
    let ca_bundle_path = http_client.tls_ca_bundle_path();
    let crls = http_client.tls_crls();

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

    let mut client_config = if tls_no_verify {
        // No-verify path bypasses CRL checking entirely; warn below on first build.
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        // Apply gateway CRL list via `build_server_verifier_with_crls` (uses
        // `allow_unknown_revocation_status() + only_check_end_entity_revocation()`).
        let verifier = crate::tls::build_server_verifier_with_crls(root_store, crls)
            .map_err(|e| format!("ws_logging: failed to build TLS verifier: {e}"))?;
        rustls::ClientConfig::builder()
            .with_webpki_verifier(verifier)
            .with_no_client_auth()
    };

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

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
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

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        if self
            .sender
            .try_send(LogEntry::WebSocket(WsDisconnectLogEntry::from(ctx)))
            .is_err()
        {
            warn!("WebSocket logging buffer full — dropping WebSocket disconnect log entry");
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
    let mut ws_conn: Option<WsConnection> = None;

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(entry) => {
                        buffer.push(entry);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            ws_conn = send_batch(&cfg, batch, ws_conn).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining entries and exit.
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            let _ = send_batch(&cfg, batch, ws_conn).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    ws_conn = send_batch(&cfg, batch, ws_conn).await;
                }
            }
        }
    }
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::protocol::Message,
>;

/// A live WebSocket connection paired with the abort handle for its
/// drain task. Dropping the connection aborts the drain task so the
/// underlying `WebSocketStream` — held alive by
/// `futures_util::stream::split`'s `BiLock` while either half lives —
/// is released immediately. Without this, a `sink.send(...)` failure
/// that drops only the sink leaves the read half (and the underlying
/// TCP/TLS stream) alive until the peer eventually closes, briefly
/// stacking two drain tasks + two connections during a reconnect.
struct WsConnection {
    sink: WsSink,
    drain: tokio::task::AbortHandle,
}

impl Drop for WsConnection {
    fn drop(&mut self) {
        self.drain.abort();
    }
}

/// Attempt to send a batch over the WebSocket connection. Returns the
/// connection on success, or `None` if the connection was lost and
/// could not be re-established within the retry budget.
async fn send_batch(
    cfg: &WsConfig,
    batch: Vec<LogEntry>,
    mut conn: Option<WsConnection>,
) -> Option<WsConnection> {
    let total_attempts = cfg.max_retries.saturating_add(1);
    let entry_count = batch.len();

    let view = WsBatchView {
        entries: &batch,
        schema: cfg.schema.as_deref(),
    };
    let payload = match serde_json::to_string(&view) {
        Ok(json) => json,
        Err(e) => {
            warn!("WebSocket logging: failed to serialize batch: {e}");
            return conn;
        }
    };

    for attempt in 1..=total_attempts {
        // Ensure we have a live connection.
        if conn.is_none() {
            conn = connect(cfg).await;
            if conn.is_none() {
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

        if let Some(ref mut ws) = conn {
            let msg =
                tokio_tungstenite::tungstenite::protocol::Message::Text(payload.clone().into());
            match ws.sink.send(msg).await {
                Ok(()) => return conn,
                Err(e) => {
                    warn!(
                        "WebSocket logging: send failed: {e} (attempt {}/{})",
                        attempt, total_attempts,
                    );
                    // Connection is broken — dropping `conn` aborts the
                    // drain task so the underlying stream is released
                    // immediately rather than lingering alongside the
                    // reconnect attempt.
                    conn = None;
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
    conn
}

/// Establish a new WebSocket connection to the configured endpoint.
///
/// Uses `connect_async_tls_with_config` with the pre-built TLS connector
/// so that `wss://` connections respect the gateway's CA trust chain and
/// `FERRUM_TLS_NO_VERIFY` setting.
///
/// `tokio_tungstenite` handles WebSocket control frames (Ping / Pong /
/// server-initiated Close) inside its `Stream` impl while the read half
/// is being polled. We don't consume any inbound application messages
/// — log shipping is write-only — but if we just `drop` the read half
/// the server stops getting Pong replies to its Pings, and after the
/// server's ping timeout it tears the connection down. Worse, a
/// server-initiated Close goes unobserved until the next `send` errors
/// out, by which time the kernel receive buffer may have filled. Spawn
/// a small drain task that polls the read side and discards every
/// message; that drives the protocol forward without doing anything
/// with the data. The task's abort handle rides along with the sink in
/// [`WsConnection`] so a sink-side failure tears down both halves in
/// lock-step (see the type's doc-comment for the race it prevents).
async fn connect(cfg: &WsConfig) -> Option<WsConnection> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};

    // ws_logging is intentionally write-only. Keep inbound parsing bounded
    // to control resource usage if the remote endpoint (or path to it) sends
    // unexpected payload data.
    let mut ws_cfg = WebSocketConfig::default();
    ws_cfg.max_message_size = Some(64 << 10);
    ws_cfg.max_frame_size = Some(16 << 10);

    match tokio_tungstenite::connect_async_tls_with_config(
        &cfg.endpoint_url,
        Some(ws_cfg),
        false,
        cfg.connector.clone(),
    )
    .await
    {
        Ok((stream, _response)) => {
            let (sink, mut read) = stream.split();
            // Drain the read half so tungstenite can service Ping/Pong
            // and server-initiated Close frames. Exits cleanly when the
            // peer closes — at that point `sink.send(...)` errors and
            // the main loop reconnects.
            let drain = tokio::spawn(async move {
                while let Some(item) = read.next().await {
                    match item {
                        Ok(Message::Text(_)) | Ok(Message::Binary(_)) => {
                            // Unexpected application data for a write-only
                            // channel: stop draining and let reconnect logic
                            // establish a fresh socket.
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            });
            Some(WsConnection {
                sink,
                drain: drain.abort_handle(),
            })
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
