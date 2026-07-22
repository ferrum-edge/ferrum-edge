//! WebSocket access logging plugin — batched async log shipping over ws/wss.
//!
//! Serializes `TransactionSummary`, `StreamTransactionSummary`, and WebSocket
//! disconnect entries, then sends them to a remote WebSocket endpoint in batches.
//! Uses an mpsc channel to decouple the proxy hot path from network I/O: hooks
//! reserve a queue slot, then take a provisional aggregate byte reservation
//! before any serialization (or disconnect-field cloning), shrink that lease to
//! the exact retained charge after bounded serialization, and enqueue. A
//! background task drains the channel in configurable batch sizes with a flush
//! interval timer. The WebSocket connection is maintained persistently with
//! automatic reconnection on failure; establishment and write/flush progress
//! are bounded by documented timeouts.
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
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tracing::warn;
use url::{Host, Url};

use super::utils::log_schema::view::{
    MetadataNested, emit_timestamp, extract_host_from_url, serialize_schema_metadata,
};
use super::utils::log_schema::{
    DerivedKind, MetadataPolicy, SchemaCapabilities, SchemaSerializable, SchemaView, SummarySchema,
    TimestampFormat, resolve_schema,
};
use super::utils::{
    BatchConfigDefaults, MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, PluginHttpClient,
    validate_batch_config,
};
use super::{
    ALL_PROTOCOLS, Direction, Plugin, ProxyProtocol, StreamTransactionSummary, TransactionSummary,
    WsDisconnectContext,
};
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

/// Default / hard maxima for per-entry serialization and aggregate queued,
/// batch-assembly, and retry bytes.
pub const WS_DEFAULT_MAX_ENTRY_BYTES: usize = 64 * 1024;
pub const WS_MAX_MAX_ENTRY_BYTES: usize = 1024 * 1024;
pub const WS_DEFAULT_BUFFER_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const WS_MAX_BUFFER_MAX_BYTES: usize = 256 * 1024 * 1024;

const WS_MIN_RESOURCE_BYTES: usize = 1024;
const WS_MIN_BUFFER_MAX_BYTES: usize = (WS_MIN_RESOURCE_BYTES + 1) * 2;
const WS_DROP_WARN_EVERY: u64 = 100;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_WRITE_TIMEOUT_MS: u64 = 5_000;
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_RETRY_DELAY_MS: u64 = 60_000;
const MAX_RECONNECT_DELAY_MS: u64 = 60_000;
const MAX_RETRIES: u64 = 10;

/// Pre-serialized log entry admitted under slot + byte budgets.
///
/// Admission takes a provisional lease for the configured per-entry maximum
/// retained charge, then shrinks to the exact charge after bounded
/// serialization. The lease conservatively covers two copies of the entry plus
/// JSON-array framing. One copy is the queued entry; the second is the
/// contiguous batch payload allocated while entries are assembled and converted
/// into an `Arc<str>`. Keeping that reservation with the payload bounds both
/// the transient assembly peak and every retry, even while new records queue.
struct QueuedEntry {
    json: Arc<str>,
    _lease: Arc<WsByteLease>,
}

/// Borrowed disconnect view used only for bounded admission serialization.
/// Holds references into the caller's `WsDisconnectContext` so attacker-shaped
/// strings/metadata are never deep-cloned before the aggregate byte gate.
#[derive(Clone, serde::Serialize)]
struct WsDisconnectLogEntry<'a> {
    event: &'static str,
    namespace: &'a str,
    proxy_id: &'a str,
    proxy_name: Option<&'a str>,
    client_ip: &'a str,
    consumer_username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_method: Option<&'static str>,
    backend_target: &'a str,
    protocol: &'static str,
    listen_port: u16,
    duration_ms: f64,
    frames_client_to_backend: u64,
    frames_backend_to_client: u64,
    bytes_client_to_backend: u64,
    bytes_backend_to_client: u64,
    timestamp_connected: &'a str,
    timestamp_disconnected: &'a str,
    direction: Option<Direction>,
    io_side: Option<crate::proxy::tcp_proxy::StreamIoSide>,
    error_class: Option<crate::retry::ErrorClass>,
    #[serde(
        skip_serializing_if = "borrowed_metadata_is_empty",
        serialize_with = "serialize_borrowed_redacted_metadata"
    )]
    metadata: &'a HashMap<String, String>,
}

fn borrowed_metadata_is_empty(metadata: &&HashMap<String, String>) -> bool {
    metadata.is_empty()
}

fn serialize_borrowed_redacted_metadata<S>(
    metadata: &&HashMap<String, String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    crate::plugins::utils::metadata_redaction::serialize_redacted_metadata(metadata, serializer)
}

impl SchemaSerializable for WsDisconnectLogEntry<'_> {
    fn owns_native(&self, source: &str) -> bool {
        super::utils::log_schema::WS_DISCONNECT_FIELDS
            .iter()
            .any(|f| f.name == source)
    }

    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        match source {
            "event" => map.serialize_entry(out_key, self.event),
            "namespace" => map.serialize_entry(out_key, self.namespace),
            "proxy_id" => map.serialize_entry(out_key, self.proxy_id),
            "proxy_name" => map.serialize_entry(out_key, &self.proxy_name),
            "client_ip" => map.serialize_entry(out_key, self.client_ip),
            "consumer_username" => map.serialize_entry(out_key, &self.consumer_username),
            "auth_method" => match self.auth_method {
                Some(value) => map.serialize_entry(out_key, value),
                None => Ok(()),
            },
            "backend_target" => map.serialize_entry(out_key, self.backend_target),
            "protocol" => map.serialize_entry(out_key, self.protocol),
            "listen_port" => map.serialize_entry(out_key, &self.listen_port),
            "duration_ms" => map.serialize_entry(out_key, &self.duration_ms),
            "frames_client_to_backend" => {
                map.serialize_entry(out_key, &self.frames_client_to_backend)
            }
            "frames_backend_to_client" => {
                map.serialize_entry(out_key, &self.frames_backend_to_client)
            }
            "bytes_client_to_backend" => {
                map.serialize_entry(out_key, &self.bytes_client_to_backend)
            }
            "bytes_backend_to_client" => {
                map.serialize_entry(out_key, &self.bytes_backend_to_client)
            }
            "timestamp_connected" => {
                emit_timestamp(out_key, self.timestamp_connected, ts_format, map)
            }
            "timestamp_disconnected" => {
                emit_timestamp(out_key, self.timestamp_disconnected, ts_format, map)
            }
            "direction" => map.serialize_entry(out_key, &self.direction),
            "io_side" => map.serialize_entry(out_key, &self.io_side),
            "error_class" => map.serialize_entry(out_key, &self.error_class),
            "metadata" => {
                if !self.metadata.is_empty() {
                    map.serialize_entry(out_key, &MetadataNested(self.metadata))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        match kind {
            DerivedKind::StatusClass => map.serialize_entry(out_key, "none")?,
            DerivedKind::BackendHost => {
                let Some(host) = extract_host_from_url(self.backend_target) else {
                    return Ok(false);
                };
                map.serialize_entry(out_key, host)?;
            }
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "websocket_disconnect")?;
            }
            DerivedKind::Outcome => {
                let outcome = if self.error_class.is_some() {
                    "error"
                } else {
                    "ok"
                };
                map.serialize_entry(out_key, outcome)?;
            }
        }
        Ok(true)
    }

    fn serialize_metadata<S>(
        &self,
        policy: &MetadataPolicy,
        emitted: &mut HashSet<String>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: serde::ser::SerializeMap,
    {
        serialize_schema_metadata(self.metadata, policy, emitted, map)
    }
}

impl<'a> From<&'a WsDisconnectContext> for WsDisconnectLogEntry<'a> {
    fn from(ctx: &'a WsDisconnectContext) -> Self {
        Self {
            event: "websocket_disconnect",
            namespace: ctx.namespace.as_str(),
            proxy_id: ctx.proxy_id.as_str(),
            proxy_name: ctx.proxy_name.as_deref(),
            client_ip: ctx.client_ip.as_str(),
            consumer_username: ctx.consumer_username.as_deref(),
            auth_method: ctx.auth_method,
            backend_target: ctx.backend_target.as_str(),
            protocol: "websocket",
            listen_port: ctx.listen_port,
            duration_ms: ctx.duration_ms,
            frames_client_to_backend: ctx.frames_client_to_backend,
            frames_backend_to_client: ctx.frames_backend_to_client,
            bytes_client_to_backend: ctx.bytes_client_to_backend,
            bytes_backend_to_client: ctx.bytes_backend_to_client,
            timestamp_connected: ctx.timestamp_connected.as_str(),
            timestamp_disconnected: ctx.timestamp_disconnected.as_str(),
            direction: ctx.direction,
            io_side: ctx.io_side,
            error_class: ctx.error_class,
            metadata: &ctx.metadata,
        }
    }
}

struct WsConfig {
    /// Full dial URL retained only for connection establishment.
    endpoint_url: String,
    /// Structurally redacted form used in every diagnostic (`scheme://host[:port]/redacted`).
    endpoint_url_for_logs: String,
    connector: Option<tokio_tungstenite::Connector>,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    reconnect_delay: Duration,
    connect_timeout: Duration,
    write_timeout: Duration,
}

struct WsByteLease {
    used_bytes: Arc<AtomicUsize>,
    /// Current retained charge. Atomic so a provisional reservation can shrink
    /// race-safely against `Drop` without temporarily releasing the whole lease.
    bytes: AtomicUsize,
}

impl WsByteLease {
    /// Reduce this lease from its provisional charge to the exact retained
    /// charge. Never releases-and-reacquires; only subtracts the unused delta.
    /// No-op when `new_bytes` is not strictly smaller than the current charge.
    fn shrink_to(&self, new_bytes: usize) {
        let mut current = self.bytes.load(Ordering::Acquire);
        while new_bytes < current {
            match self.bytes.compare_exchange_weak(
                current,
                new_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.used_bytes
                        .fetch_sub(current - new_bytes, Ordering::AcqRel);
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    fn charged_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

impl Drop for WsByteLease {
    fn drop(&mut self) {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        if bytes != 0 {
            self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

struct WsByteBudget {
    used_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    dropped_count: AtomicU64,
}

impl WsByteBudget {
    fn new(max_bytes: usize) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes,
            dropped_count: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn used(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    fn try_acquire(&self, bytes: usize) -> Option<Arc<WsByteLease>> {
        if bytes == 0 {
            return Some(Arc::new(WsByteLease {
                used_bytes: Arc::clone(&self.used_bytes),
                bytes: AtomicUsize::new(0),
            }));
        }
        let reserved = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            });
        if reserved.is_err() {
            self.record_drop("retained-content byte budget exhausted");
            return None;
        }

        Some(Arc::new(WsByteLease {
            used_bytes: Arc::clone(&self.used_bytes),
            bytes: AtomicUsize::new(bytes),
        }))
    }

    fn record_drop(&self, reason: &str) {
        let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(WS_DROP_WARN_EVERY) {
            warn!(
                plugin = "ws_logging",
                "WebSocket logging: dropping entry because {} ({} dropped total; logging every {} drops)",
                reason,
                dropped,
                WS_DROP_WARN_EVERY,
            );
        }
    }
}

/// Conservative retained charge for one admitted entry: queued JSON plus the
/// contiguous reference-counted batch payload, each sized to `serialized_len`,
/// plus two bytes of JSON-array framing budget (`+1` before `*2`). Retries
/// clone only the payload handle.
fn retained_charge_for_serialized_len(serialized_len: usize) -> usize {
    serialized_len.saturating_add(1).saturating_mul(2)
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(4096)),
            max_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "serialized WebSocket logging entry exceeded its byte limit",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct WsLogging {
    sender: mpsc::Sender<QueuedEntry>,
    schema: Option<Arc<SummarySchema>>,
    byte_budget: Arc<WsByteBudget>,
    max_entry_bytes: usize,
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
        if !parsed_url.username().is_empty()
            || parsed_url.password().is_some()
            || endpoint_authority(&endpoint_url).is_some_and(|authority| authority.contains('@'))
        {
            return Err(
                "ws_logging: 'endpoint_url' must not include URL user information".to_string(),
            );
        }
        if !has_non_empty_authority(&endpoint_url) {
            return Err(
                "ws_logging: 'endpoint_url' must include a hostname or IP address".to_string(),
            );
        }
        let endpoint_hostname = endpoint_hostname(&parsed_url)?;
        let endpoint_url_for_logs = redacted_endpoint_url(&parsed_url);

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
        for key in [
            "reconnect_delay_ms",
            "connect_timeout_ms",
            "write_timeout_ms",
            "max_entry_bytes",
            "buffer_max_bytes",
        ] {
            if let Some(value) = config.get(key)
                && value.as_u64().is_none()
            {
                return Err(format!("ws_logging: '{key}' must be an unsigned integer"));
            }
        }

        let batch_size = bounded_u64(
            config,
            "batch_size",
            batch_defaults.batch_size,
            1,
            MAX_BATCH_SIZE as u64,
        )? as usize;
        let flush_interval_ms = bounded_u64(
            config,
            "flush_interval_ms",
            batch_defaults.flush_interval_ms,
            batch_defaults.min_flush_interval_ms,
            u64::MAX,
        )?;
        let buffer_capacity = bounded_u64(
            config,
            "buffer_capacity",
            batch_defaults.buffer_capacity,
            1,
            MAX_BUFFER_CAPACITY as u64,
        )? as usize;
        let max_retries = bounded_u64(
            config,
            "max_retries",
            batch_defaults.max_retries,
            0,
            MAX_RETRIES,
        )? as u32;
        let retry_delay_ms = bounded_u64(
            config,
            "retry_delay_ms",
            batch_defaults.retry_delay_ms,
            1,
            MAX_RETRY_DELAY_MS,
        )?;
        let reconnect_delay_ms = bounded_u64(
            config,
            "reconnect_delay_ms",
            5000,
            1,
            MAX_RECONNECT_DELAY_MS,
        )?;
        let connect_timeout_ms = bounded_u64(
            config,
            "connect_timeout_ms",
            DEFAULT_CONNECT_TIMEOUT_MS,
            MIN_TIMEOUT_MS,
            MAX_RETRY_DELAY_MS,
        )?;
        let write_timeout_ms = bounded_u64(
            config,
            "write_timeout_ms",
            DEFAULT_WRITE_TIMEOUT_MS,
            MIN_TIMEOUT_MS,
            MAX_RETRY_DELAY_MS,
        )?;
        let max_entry_bytes = bounded_u64(
            config,
            "max_entry_bytes",
            WS_DEFAULT_MAX_ENTRY_BYTES as u64,
            WS_MIN_RESOURCE_BYTES as u64,
            WS_MAX_MAX_ENTRY_BYTES as u64,
        )? as usize;
        let buffer_max_bytes = bounded_u64(
            config,
            "buffer_max_bytes",
            WS_DEFAULT_BUFFER_MAX_BYTES as u64,
            WS_MIN_BUFFER_MAX_BYTES as u64,
            WS_MAX_BUFFER_MAX_BYTES as u64,
        )? as usize;
        let minimum_buffer_max_bytes = max_entry_bytes.saturating_add(1).saturating_mul(2);
        if buffer_max_bytes < minimum_buffer_max_bytes {
            return Err(
                "ws_logging: 'buffer_max_bytes' must be at least twice 'max_entry_bytes' plus 2 bytes for conservative queue/batch accounting"
                    .to_string(),
            );
        }

        // ws_logging is the only caller that serializes WebSocket-disconnect
        // entries, so it opts into that field family. Every other logging
        // plugin uses the shared compiler under `SchemaCapabilities::BASE`.
        let schema = resolve_schema(config, "ws_logging", SchemaCapabilities::WS_LOGGING)?;
        let ws_config = WsConfig {
            endpoint_url,
            endpoint_url_for_logs,
            connector,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries,
            retry_delay: Duration::from_millis(retry_delay_ms),
            reconnect_delay: Duration::from_millis(reconnect_delay_ms),
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            write_timeout: Duration::from_millis(write_timeout_ms),
        };

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, ws_config));

        Ok(Self {
            sender,
            schema,
            byte_budget: Arc::new(WsByteBudget::new(buffer_max_bytes)),
            max_entry_bytes,
            endpoint_hostname: Some(endpoint_hostname),
        })
    }

    fn queue_value<T>(&self, value: &T, kind: &str)
    where
        T: serde::Serialize,
    {
        let Ok(permit) = self.sender.try_reserve() else {
            self.byte_budget.record_drop("queue slot exhausted");
            return;
        };
        let Some((json, lease)) =
            serialize_under_byte_budget(&self.byte_budget, self.max_entry_bytes, value, kind)
        else {
            return;
        };
        permit.send(QueuedEntry {
            json,
            _lease: lease,
        });
    }

    fn queue_http(&self, summary: &TransactionSummary) {
        match self.schema.as_deref() {
            Some(schema) if schema.applies_to_http() => {
                self.queue_value(&SchemaView { summary, schema }, "HTTP entry");
            }
            _ => self.queue_value(summary, "HTTP entry"),
        }
    }

    fn queue_stream(&self, summary: &StreamTransactionSummary) {
        match self.schema.as_deref() {
            Some(schema) if schema.applies_to_stream() => {
                self.queue_value(&SchemaView { summary, schema }, "stream entry");
            }
            _ => self.queue_value(summary, "stream entry"),
        }
    }

    fn queue_websocket(&self, ctx: &WsDisconnectContext) {
        // Slot first, then provisional aggregate bytes, then a borrowed
        // disconnect view (no deep clone of attacker-shaped strings/metadata).
        let Ok(permit) = self.sender.try_reserve() else {
            self.byte_budget.record_drop("queue slot exhausted");
            return;
        };
        let provisional = retained_charge_for_serialized_len(self.max_entry_bytes);
        let Some(lease) = self.byte_budget.try_acquire(provisional) else {
            return;
        };
        let entry = WsDisconnectLogEntry::from(ctx);
        let mut writer = BoundedJsonWriter::new(self.max_entry_bytes);
        let serialize_result = match self.schema.as_deref() {
            Some(schema) if schema.applies_to_websocket_disconnect() => serde_json::to_writer(
                &mut writer,
                &SchemaView {
                    summary: &entry,
                    schema,
                },
            ),
            _ => serde_json::to_writer(&mut writer, &entry),
        };
        if let Err(error) = serialize_result {
            if writer.limit_exceeded {
                self.byte_budget
                    .record_drop("serialized entry exceeded max_entry_bytes");
            } else {
                warn!("WebSocket logging: failed to serialize WebSocket disconnect entry: {error}");
            }
            return;
        }
        let retained_bytes = retained_charge_for_serialized_len(writer.bytes.len());
        lease.shrink_to(retained_bytes);
        let json = match String::from_utf8(writer.bytes) {
            Ok(line) => Arc::<str>::from(line),
            Err(error) => {
                warn!(
                    "WebSocket logging: serialized WebSocket disconnect entry was not UTF-8: {error}"
                );
                return;
            }
        };
        permit.send(QueuedEntry {
            json,
            _lease: lease,
        });
    }
}

/// Acquire a provisional max-entry aggregate reservation, serialize under the
/// per-entry bound, then shrink the lease to the exact retained charge.
/// Returns `None` without invoking the serializer when the aggregate gate denies.
fn serialize_under_byte_budget<T>(
    byte_budget: &WsByteBudget,
    max_entry_bytes: usize,
    value: &T,
    kind: &str,
) -> Option<(Arc<str>, Arc<WsByteLease>)>
where
    T: serde::Serialize,
{
    let provisional = retained_charge_for_serialized_len(max_entry_bytes);
    let lease = byte_budget.try_acquire(provisional)?;
    let mut writer = BoundedJsonWriter::new(max_entry_bytes);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.limit_exceeded {
            byte_budget.record_drop("serialized entry exceeded max_entry_bytes");
        } else {
            warn!("WebSocket logging: failed to serialize {kind}: {error}");
        }
        return None;
    }
    let retained_bytes = retained_charge_for_serialized_len(writer.bytes.len());
    lease.shrink_to(retained_bytes);
    match String::from_utf8(writer.bytes) {
        Ok(line) => Some((Arc::<str>::from(line), lease)),
        Err(error) => {
            warn!("WebSocket logging: serialized {kind} was not UTF-8: {error}");
            None
        }
    }
}

fn redacted_endpoint_url(endpoint: &Url) -> String {
    crate::plugins::loki_logging::redacted_endpoint_url(endpoint)
}

fn bounded_u64(
    config: &Value,
    key: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, String> {
    let value = match config.get(key) {
        None => default,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("ws_logging: '{key}' must be an unsigned integer"))?,
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "ws_logging: '{key}' must be between {minimum} and {maximum}"
        ));
    }
    Ok(value)
}

fn endpoint_hostname(parsed_url: &Url) -> Result<String, String> {
    let host = parsed_url.host().ok_or_else(|| {
        "ws_logging: 'endpoint_url' must include a hostname or IP address".to_string()
    })?;

    Ok(match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn has_non_empty_authority(endpoint_url: &str) -> bool {
    endpoint_authority(endpoint_url).is_some_and(|authority| !authority.is_empty())
}

fn endpoint_authority(endpoint_url: &str) -> Option<&str> {
    let (_, after_scheme) = endpoint_url.split_once(':')?;
    let authority_and_path = after_scheme.strip_prefix("//")?;
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());
    Some(&authority_and_path[..authority_end])
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
        let source = CertSource::parse(ca_path, MaterialKind::CaBundle);
        let ca_material = load_material_blocking(&source, MaterialKind::CaBundle)
            .map_err(|e| format!("ws_logging: failed to load CA bundle: {e}"))?;
        let source_id = ca_material.display_source_id.clone();
        let mut cursor = std::io::Cursor::new(ca_material.bytes.expose_secret());
        for cert in rustls_pemfile::certs(&mut cursor).flatten() {
            root_store.add(cert).map_err(|e| {
                format!("ws_logging: failed to add CA certificate from {source_id}: {e}")
            })?;
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
        self.queue_stream(summary);
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.queue_websocket(ctx);
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.queue_http(summary);
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
async fn flush_loop(mut receiver: mpsc::Receiver<QueuedEntry>, cfg: WsConfig) {
    if cfg.endpoint_url.is_empty() {
        while receiver.recv().await.is_some() {}
        return;
    }

    let mut buffer: Vec<QueuedEntry> = Vec::with_capacity(cfg.batch_size);
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

            _ = wait_drain_done(&ws_conn) => {
                // Drain finished (application frame / Close / read error).
                // Invalidate the complete connection so the next send reconnects
                // and control-frame handling is not left abandoned on a stale socket.
                if ws_conn.as_ref().is_some_and(|c| c.drain_finished()) {
                    ws_conn = None;
                }
            }
        }
    }
}

async fn wait_drain_done(conn: &Option<WsConnection>) {
    match conn {
        Some(c) => {
            let mut rx = c.drain_done.clone();
            if *rx.borrow() {
                return;
            }
            let _ = rx.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::protocol::Message,
>;

/// A live WebSocket connection paired with the abort handle for its
/// drain task and a completion signal. Dropping the connection aborts the
/// drain task so the underlying `WebSocketStream` — held alive by
/// `futures_util::stream::split`'s `BiLock` while either half lives —
/// is released immediately. Without this, a `sink.send(...)` failure
/// that drops only the sink leaves the read half (and the underlying
/// TCP/TLS stream) alive until the peer eventually closes, briefly
/// stacking two drain tasks + two connections during a reconnect.
///
/// The plugin is write-only. Unexpected Text/Binary frames, server Close,
/// or read errors mark the connection finished so the flush loop invalidates
/// the complete connection (sink + drain) rather than leaving an unpolled
/// read half while the writer keeps the stale socket selected.
struct WsConnection {
    sink: WsSink,
    drain: tokio::task::AbortHandle,
    drain_done: watch::Receiver<bool>,
}

impl WsConnection {
    fn drain_finished(&self) -> bool {
        *self.drain_done.borrow()
    }
}

impl Drop for WsConnection {
    fn drop(&mut self) {
        self.drain.abort();
    }
}

struct BatchPayload {
    /// Tungstenite's UTF-8 payload wraps ref-counted `Bytes`: construction
    /// consumes the batch `String` without copying, and each retry clones only
    /// the buffer handle rather than the attacker-sized payload.
    json: tokio_tungstenite::tungstenite::Utf8Bytes,
    /// Keep the conservative byte reservations alive for the payload's full
    /// send/retry lifetime after the individual queued JSON allocations drop.
    _leases: Vec<Arc<WsByteLease>>,
}

fn build_batch_payload(entries: Vec<QueuedEntry>) -> BatchPayload {
    let mut total = 2; // `[` `]`
    for (idx, entry) in entries.iter().enumerate() {
        if idx > 0 {
            total += 1;
        }
        total += entry.json.len();
    }
    let mut out = String::with_capacity(total);
    let mut leases = Vec::with_capacity(entries.len());
    out.push('[');
    for (idx, entry) in entries.into_iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&entry.json);
        leases.push(entry._lease);
    }
    out.push(']');
    BatchPayload {
        json: out.into(),
        _leases: leases,
    }
}

/// Attempt to send a batch over the WebSocket connection. Returns the
/// connection on success, or `None` if the connection was lost and
/// could not be re-established within the retry budget.
///
/// The pre-built `Arc<str>` payload is reused across retries so attacker-shaped
/// records are not re-cloned or re-serialized on each attempt. A write timeout
/// or send error invalidates the complete [`WsConnection`] (including its drain
/// task) before retry/reconnect. Delivery is at-least-once: a timeout after
/// partial transport progress may cause the collector to receive a duplicate
/// when the batch is retried on a fresh socket.
async fn send_batch(
    cfg: &WsConfig,
    batch: Vec<QueuedEntry>,
    mut conn: Option<WsConnection>,
) -> Option<WsConnection> {
    let total_attempts = cfg.max_retries.saturating_add(1);
    let entry_count = batch.len();
    let payload = build_batch_payload(batch);

    for attempt in 1..=total_attempts {
        if conn.as_ref().is_some_and(|c| c.drain_finished()) {
            conn = None;
        }

        // Ensure we have a live connection.
        if conn.is_none() {
            conn = connect(cfg).await;
            if conn.is_none() {
                warn!(
                    "WebSocket logging: connection failed to {} (attempt {}/{})",
                    cfg.endpoint_url_for_logs, attempt, total_attempts,
                );
                if attempt < total_attempts {
                    tokio::time::sleep(cfg.retry_delay).await;
                }
                continue;
            }
        }

        if let Some(ref mut ws) = conn {
            let msg = tokio_tungstenite::tungstenite::protocol::Message::Text(payload.json.clone());
            match tokio::time::timeout(cfg.write_timeout, ws.sink.send(msg)).await {
                Ok(Ok(())) => return conn,
                Ok(Err(e)) => {
                    warn!(
                        "WebSocket logging: send failed to {}: {e} (attempt {}/{})",
                        cfg.endpoint_url_for_logs, attempt, total_attempts,
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
                Err(_) => {
                    warn!(
                        "WebSocket logging: write/flush timeout to {} after {:?} (attempt {}/{})",
                        cfg.endpoint_url_for_logs, cfg.write_timeout, attempt, total_attempts,
                    );
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
/// `FERRUM_TLS_NO_VERIFY` setting. The entire establishment path (DNS, TCP,
/// TLS, and WebSocket Upgrade) is bounded by `connect_timeout`.
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
/// with the data. Unexpected Text/Binary frames mark the connection
/// finished so the flush loop invalidates both halves together.
async fn connect(cfg: &WsConfig) -> Option<WsConnection> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};

    // ws_logging is intentionally write-only. Keep inbound parsing bounded
    // to control resource usage if the remote endpoint (or path to it) sends
    // unexpected payload data.
    let mut ws_cfg = WebSocketConfig::default();
    ws_cfg.max_message_size = Some(64 << 10);
    ws_cfg.max_frame_size = Some(16 << 10);

    let connect_fut = tokio_tungstenite::connect_async_tls_with_config(
        &cfg.endpoint_url,
        Some(ws_cfg),
        false,
        cfg.connector.clone(),
    );

    match tokio::time::timeout(cfg.connect_timeout, connect_fut).await {
        Ok(Ok((stream, _response))) => {
            let (sink, mut read) = stream.split();
            let (done_tx, done_rx) = watch::channel(false);
            // Drain the read half so tungstenite can service Ping/Pong
            // and server-initiated Close frames. Mark finished on
            // application data, Close, or read error so the writer cannot
            // keep selecting a read-dead socket.
            let drain = tokio::spawn(async move {
                while let Some(item) = read.next().await {
                    match item {
                        Ok(Message::Text(_)) | Ok(Message::Binary(_)) => {
                            let _ = done_tx.send(true);
                            break;
                        }
                        Ok(Message::Close(_)) => {
                            let _ = done_tx.send(true);
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => {
                            let _ = done_tx.send(true);
                            break;
                        }
                    }
                }
                let _ = done_tx.send(true);
            });
            Some(WsConnection {
                sink,
                drain: drain.abort_handle(),
                drain_done: done_rx,
            })
        }
        Ok(Err(e)) => {
            warn!(
                "WebSocket logging: failed to connect to {}: {e} — will retry in {:?}",
                cfg.endpoint_url_for_logs, cfg.reconnect_delay,
            );
            tokio::time::sleep(cfg.reconnect_delay).await;
            None
        }
        Err(_) => {
            warn!(
                "WebSocket logging: connect timeout to {} after {:?} — will retry in {:?}",
                cfg.endpoint_url_for_logs, cfg.connect_timeout, cfg.reconnect_delay,
            );
            tokio::time::sleep(cfg.reconnect_delay).await;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use serde_json::{Value, json};
    use std::sync::atomic::AtomicBool;
    use std::thread;

    fn disconnect_entry<'a>(metadata: &'a HashMap<String, String>) -> WsDisconnectLogEntry<'a> {
        WsDisconnectLogEntry {
            event: "websocket_disconnect",
            namespace: "ferrum",
            proxy_id: "p1",
            proxy_name: Some("things-ws"),
            client_ip: "10.0.0.1",
            consumer_username: Some("alice"),
            auth_method: None,
            backend_target: "wss://backend.example.com:9000/ws",
            protocol: "websocket",
            listen_port: 8080,
            duration_ms: 42.0,
            frames_client_to_backend: 3,
            frames_backend_to_client: 5,
            bytes_client_to_backend: 128,
            bytes_backend_to_client: 256,
            timestamp_connected: "2026-01-01T00:00:00+00:00",
            timestamp_disconnected: "2026-01-01T00:00:42+00:00",
            direction: None,
            io_side: None,
            error_class: None,
            metadata,
        }
    }

    fn serialize_disconnect(entry: &WsDisconnectLogEntry<'_>, raw_schema: Value) -> Value {
        let schema =
            SummarySchema::compile(&raw_schema, "ws_logging", SchemaCapabilities::WS_LOGGING)
                .unwrap();
        let view = SchemaView {
            summary: entry,
            schema: &schema,
        };
        serde_json::to_value(view).unwrap()
    }

    #[test]
    fn ws_disconnect_flatten_keeps_metadata_named_like_unowned_http_natives() {
        // Round-3 regression: a WebSocket-disconnect entry is serialized through
        // a `summary_type: http` ws_logging schema, whose native specs include
        // HTTP-only fields (`http_method`, `request_path`,
        // `response_status_code`) that `WsDisconnectLogEntry::serialize_native`
        // never emits. Those specs must NOT reserve the flatten output key, so
        // disconnect metadata sharing the name survives under the default
        // `on_collision: skip`.
        let mut metadata = HashMap::new();
        metadata.insert("http_method".to_string(), "GET".to_string());
        metadata.insert("request_path".to_string(), "/live".to_string());
        metadata.insert("response_status_code".to_string(), "101".to_string());
        // A metadata key colliding with a native the disconnect entry DOES own
        // must still yield to the native value.
        metadata.insert("namespace".to_string(), "shadow".to_string());
        let entry = disconnect_entry(&metadata);

        let v = serialize_disconnect(
            &entry,
            json!({
                "summary_type": "http",
                "metadata": { "mode": "flatten", "on_collision": "skip" }
            }),
        );

        assert_eq!(v.get("http_method").and_then(Value::as_str), Some("GET"));
        assert_eq!(v.get("request_path").and_then(Value::as_str), Some("/live"));
        assert_eq!(
            v.get("response_status_code").and_then(Value::as_str),
            Some("101")
        );
        // Owned + emitted native wins; the colliding metadata value is dropped.
        assert_eq!(v.get("namespace").and_then(Value::as_str), Some("ferrum"));
        // The disconnect's own native fields still serialize.
        assert_eq!(
            v.get("event").and_then(Value::as_str),
            Some("websocket_disconnect")
        );
        assert_eq!(
            v.get("bytes_client_to_backend").and_then(Value::as_u64),
            Some(128)
        );
        assert_eq!(
            v.get("timestamp_connected").and_then(Value::as_str),
            Some("2026-01-01T00:00:00+00:00")
        );
    }

    #[test]
    fn redacted_endpoint_strips_path_and_query() {
        let url = Url::parse("wss://collector.example/ingest?token=secret-token").unwrap();
        assert_eq!(
            redacted_endpoint_url(&url),
            "wss://collector.example/redacted"
        );
    }

    #[test]
    fn denied_provisional_reservation_skips_serialization() {
        struct Probe<'a>(&'a AtomicBool);
        impl Serialize for Probe<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.store(true, Ordering::SeqCst);
                serializer.serialize_str("probe")
            }
        }

        let budget = WsByteBudget::new(64);
        let _hold = budget
            .try_acquire(64)
            .expect("fill budget so provisional max-entry charge is denied");
        let ran = AtomicBool::new(false);
        let admitted = serialize_under_byte_budget(&budget, 1024, &Probe(&ran), "probe");
        assert!(
            admitted.is_none(),
            "denied aggregate reservation must fail closed"
        );
        assert!(
            !ran.load(Ordering::SeqCst),
            "serializer must not run when provisional aggregate reservation is denied"
        );
        assert_eq!(budget.used(), 64);
    }

    #[test]
    fn provisional_reservation_shrinks_to_exact_charge_and_releases_on_drop() {
        let budget = WsByteBudget::new(1_048_576);
        let max_entry_bytes = 4096;
        let provisional = retained_charge_for_serialized_len(max_entry_bytes);
        let (json, lease) =
            serialize_under_byte_budget(&budget, max_entry_bytes, &json!({"k":"v"}), "http")
                .expect("admit small entry");
        let exact = retained_charge_for_serialized_len(json.len());
        assert!(
            exact < provisional,
            "exact charge must be below provisional max"
        );
        assert_eq!(lease.charged_bytes(), exact);
        assert_eq!(budget.used(), exact);

        drop(lease);
        assert_eq!(
            budget.used(),
            0,
            "drop must release the shrunk charge exactly"
        );
    }

    #[test]
    fn serialize_error_path_releases_provisional_reservation() {
        struct AlwaysFails;
        impl Serialize for AlwaysFails {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("forced serialize failure"))
            }
        }

        let budget = WsByteBudget::new(1_048_576);
        let admitted = serialize_under_byte_budget(&budget, 1024, &AlwaysFails, "broken");
        assert!(admitted.is_none());
        assert_eq!(
            budget.used(),
            0,
            "failed serialization must release the provisional lease"
        );
    }

    #[test]
    fn byte_budget_cannot_oversubscribe_or_underflow_under_concurrent_shrink() {
        const MAX_BYTES: usize = 10_000;
        let budget = Arc::new(WsByteBudget::new(MAX_BYTES));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let budget = Arc::clone(&budget);
            handles.push(thread::spawn(move || {
                for _ in 0..200 {
                    let Some(lease) = budget.try_acquire(500) else {
                        continue;
                    };
                    assert!(budget.used() <= MAX_BYTES);
                    lease.shrink_to(120);
                    assert_eq!(lease.charged_bytes(), 120);
                    assert!(budget.used() <= MAX_BYTES);
                    drop(lease);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("budget worker");
        }
        assert_eq!(
            budget.used(),
            0,
            "all leases must release without underflow wrap"
        );
    }

    #[test]
    fn shrink_racing_drop_never_underflows_budget() {
        let budget = WsByteBudget::new(1_000);
        let lease = budget.try_acquire(400).expect("lease");
        let lease2 = Arc::clone(&lease);
        let shrinker = thread::spawn(move || {
            lease2.shrink_to(50);
        });
        drop(lease);
        shrinker.join().expect("shrinker");
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn borrowed_disconnect_view_native_and_custom_schema_match_without_metadata_clone() {
        let source = include_str!("ws_logging.rs");
        // concat! keeps the forbidden needle out of the source as one literal so
        // this assertion cannot match itself.
        let owned_metadata_clone = concat!("metadata: ctx.metadata", ".clone()");
        assert!(
            !source.contains(owned_metadata_clone),
            "queue path must not deep-clone disconnect metadata before admission"
        );
        assert!(
            source.contains("metadata: &ctx.metadata"),
            "disconnect view must borrow metadata by reference"
        );

        let mut metadata = HashMap::new();
        metadata.insert("correlation_id".to_string(), "cid-9".to_string());
        metadata.insert("authorization".to_string(), "Bearer secret".to_string());
        let ctx = WsDisconnectContext {
            namespace: "ferrum".to_string(),
            proxy_id: "proxy-ws".to_string(),
            proxy_name: Some("websocket-proxy".to_string()),
            client_ip: "127.0.0.1".to_string(),
            backend_target: "ws://backend.local/chat".to_string(),
            listen_port: 8080,
            duration_ms: 250.0,
            frames_client_to_backend: 3,
            frames_backend_to_client: 4,
            bytes_client_to_backend: 128,
            bytes_backend_to_client: 256,
            timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
            timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
            direction: Some(Direction::ClientToBackend),
            io_side: Some(crate::proxy::tcp_proxy::StreamIoSide::Write),
            error_class: Some(crate::retry::ErrorClass::ConnectionReset),
            consumer_username: Some("alice".to_string()),
            auth_method: Some("jwt_auth"),
            connection_id: 0,
            metadata,
        };
        let entry = WsDisconnectLogEntry::from(&ctx);

        let native = serde_json::to_value(&entry).expect("native serialize");
        assert_eq!(native["event"], "websocket_disconnect");
        assert_eq!(native["bytes_client_to_backend"], 128);
        assert_eq!(native["bytes_backend_to_client"], 256);
        assert_eq!(native["timestamp_connected"], "2026-01-01T00:00:00+00:00");
        assert_eq!(
            native["timestamp_disconnected"],
            "2026-01-01T00:00:01+00:00"
        );
        assert_eq!(native["metadata"]["correlation_id"], "cid-9");
        assert_eq!(native["metadata"]["authorization"], "[REDACTED]");
        // Pointer equality proves the view still aliases the context map.
        assert!(std::ptr::eq(entry.metadata, &ctx.metadata));

        let custom = serialize_disconnect(
            &entry,
            json!({
                "summary_type": "http",
                "rename": { "event": "kind" },
                "derived_fields": [
                    { "name": "record_type", "kind": "summary_kind" },
                    { "name": "outcome", "kind": "outcome" },
                    { "name": "backend_host", "kind": "backend_host" }
                ],
                "metadata": { "mode": "flatten", "prefix": "meta_" }
            }),
        );
        assert_eq!(custom["kind"], "websocket_disconnect");
        assert_eq!(custom["record_type"], "websocket_disconnect");
        assert_eq!(custom["outcome"], "error");
        assert_eq!(custom["backend_host"], "backend.local");
        assert_eq!(custom["meta_correlation_id"], "cid-9");
        assert_eq!(custom["meta_authorization"], "[REDACTED]");
        assert_eq!(custom["bytes_client_to_backend"], 128);
        assert_eq!(custom["timestamp_connected"], "2026-01-01T00:00:00+00:00");
    }
}
