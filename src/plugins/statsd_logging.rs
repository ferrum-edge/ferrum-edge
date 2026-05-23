//! StatsD metrics logging plugin — async metric shipping over UDP.
//!
//! Extracts metrics from `TransactionSummary` and `StreamTransactionSummary`
//! entries and sends them to a StatsD-compatible server (StatsD, Datadog,
//! Telegraf, etc.) over UDP. Uses `BatchingLogger<MetricEntry>` to decouple
//! the proxy hot path from socket I/O.
//!
//! Hostname resolution uses the gateway's shared `DnsCache` (pre-warmed via
//! `warmup_hostnames()`) with TTL, stale-while-revalidate, and background
//! refresh — consistent with all other gateway components.
//!
//! Supports all proxy protocols (HTTP, gRPC, WebSocket, TCP, UDP).

use async_trait::async_trait;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;
use tracing::warn;

use super::utils::log_schema::{SummarySchema, resolve_schema};
use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, SummaryLogEntry,
    UDP_RE_RESOLVE_INTERVAL, bind_connected_udp_socket, build_batch_config, parse_socket_host,
    resolve_udp_endpoint,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::dns::DnsCache;

/// Mapping from a default statsd tag key to its backing native field on
/// [`TransactionSummary`]. Schema `rename` / `omit` consult the native
/// column; tags without a native backing (e.g. `status_class`) are not
/// configurable. Documented in [docs/plugins.md] under `statsd_logging`.
const HTTP_TAG_NATIVE: &[(&str, &str)] = &[
    ("method", "http_method"),
    ("status", "response_status_code"),
    ("proxy", "proxy_id"),
];

const STREAM_TAG_NATIVE: &[(&str, &str)] = &[
    ("protocol", "protocol"),
    ("proxy", "proxy_id"),
    ("cause", "disconnect_cause"),
    ("direction", "disconnect_direction"),
];

/// Emit a `warn!` for any inline `schema:` keys that the statsd
/// emitter does not honor. Only `rename`, `omit`, and `summary_type`
/// have an effect — everything else (`static_fields`, `derived_fields`,
/// `metadata`, `timestamp_format`, `order`) is silently dropped because
/// statsd is line protocol, not JSON. Documenting this in
/// `docs/log_schema.md` isn't enough on its own: operators copying a
/// working JSON-logger schema across to statsd would otherwise have no
/// indication their `static_fields` are being thrown away. The schema
/// itself still constructs (the keys are valid in the abstract); we
/// just point out they will be no-ops here.
///
/// Schema-by-reference (`schema_ref:`) is intentionally not inspected:
/// the named schema is shared across many sinks and warning per
/// referrer would be noisy.
fn warn_on_unsupported_inline_schema_keys(config: &Value) {
    const UNSUPPORTED: &[&str] = &[
        "static_fields",
        "derived_fields",
        "metadata",
        "timestamp_format",
        "order",
    ];
    let Some(inline) = config.get("schema").and_then(Value::as_object) else {
        return;
    };
    let present: Vec<&str> = UNSUPPORTED
        .iter()
        .copied()
        .filter(|k| inline.contains_key(*k))
        .collect();
    if !present.is_empty() {
        warn!(
            "statsd_logging: schema keys {:?} are no-ops for statsd (line protocol, not JSON) — only `rename`, `omit`, and `summary_type` affect statsd output. See docs/log_schema.md.",
            present
        );
    }
}

/// Resolve a statsd tag key honoring the schema's rename rule for the
/// backing native field. Returns `None` when the schema omits the field.
fn resolve_tag_key<'a>(
    schema: Option<&'a SummarySchema>,
    default_key: &'a str,
    mapping: &[(&'static str, &'static str)],
) -> Option<&'a str> {
    let Some(native) = mapping
        .iter()
        .find_map(|(d, n)| (*d == default_key).then_some(*n))
    else {
        // Default key has no native backing — never renameable / omittable
        // through schema; always emit with the default key.
        return Some(default_key);
    };
    let Some(schema) = schema else {
        return Some(default_key);
    };
    if schema.omits_tag(native) {
        return None;
    }
    Some(schema.rename_for_tag(native).unwrap_or(default_key))
}

/// Sanitize a value used in a StatsD tag: strip the delimiters that would break
/// the line protocol (`,`, `|`, `#`, `:`) and trim surrounding whitespace.
/// Replaces disallowed chars with `_` so the tag remains parseable.
fn sanitize_tag_value(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "none".to_string();
    }
    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        match c {
            ',' | '|' | '#' | ':' | '\n' | '\r' => out.push('_'),
            c if c.is_whitespace() => out.push('_'),
            c => out.push(c),
        }
    }
    out
}

type MetricEntry = SummaryLogEntry;

#[derive(Clone)]
struct StatsdFlushConfig {
    hostname: String,
    port: u16,
    prefix: String,
    global_tags: String,
    dns_cache: Option<DnsCache>,
    schema: Option<Arc<SummarySchema>>,
}

struct StatsdFlushState {
    socket: Option<tokio::net::UdpSocket>,
    current_addr: Option<SocketAddr>,
    last_resolve: Instant,
}

pub struct StatsdLogging {
    logger: BatchingLogger<MetricEntry>,
    hostname: Option<String>,
}

impl StatsdLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("statsd_logging: config must be an object".to_string());
        }

        let raw_host = config
            .get("host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "statsd_logging: 'host' is required — metrics will have nowhere to send".to_string()
            })?
            .to_string();
        let socket_host = parse_socket_host("statsd_logging", "host", &raw_host)?;
        let host = socket_host.dial_host.clone();

        let port = match config.get("port") {
            Some(value) => value.as_u64().ok_or_else(|| {
                "statsd_logging: 'port' must be an integer between 1 and 65535".to_string()
            })?,
            None => 8125,
        };
        if port == 0 || port > 65535 {
            return Err(format!(
                "statsd_logging: 'port' must be between 1 and 65535 (got {port})"
            ));
        }

        let ns = http_client.namespace();
        let prefix = match config.get("prefix") {
            Some(value) => {
                let prefix = value
                    .as_str()
                    .ok_or_else(|| "statsd_logging: 'prefix' must be a string".to_string())?
                    .trim();
                if prefix.is_empty() {
                    return Err("statsd_logging: 'prefix' must not be empty".to_string());
                }
                prefix.to_string()
            }
            None => ns.to_string(),
        };
        let global_tags = {
            let mut pairs = Vec::new();
            if let Some(global_tags) = config.get("global_tags") {
                let tags_obj = global_tags
                    .as_object()
                    .ok_or_else(|| "statsd_logging: 'global_tags' must be an object".to_string())?;
                pairs.reserve(tags_obj.len());
                for (key, value) in tags_obj {
                    if key.trim().is_empty() {
                        return Err(
                            "statsd_logging: 'global_tags' keys must not be empty".to_string()
                        );
                    }
                    let value = value.as_str().ok_or_else(|| {
                        format!("statsd_logging: 'global_tags.{key}' must be a string")
                    })?;
                    pairs.push(format!(
                        "{}:{}",
                        sanitize_tag_value(key),
                        sanitize_tag_value(value)
                    ));
                }
            }
            if !pairs.iter().any(|pair| pair.starts_with("namespace:")) {
                pairs.push(format!("namespace:{}", sanitize_tag_value(ns)));
            }
            if pairs.is_empty() {
                String::new()
            } else {
                format!("|#{}", pairs.join(","))
            }
        };

        warn_on_unsupported_inline_schema_keys(config);
        let schema = resolve_schema(config, "statsd_logging")?;
        let flush_config = StatsdFlushConfig {
            hostname: host.clone(),
            port: port as u16,
            prefix,
            global_tags,
            dns_cache: http_client.dns_cache().cloned(),
            schema,
        };
        let state = Arc::new(Mutex::new(StatsdFlushState {
            socket: None,
            current_addr: None,
            last_resolve: Instant::now(),
        }));
        let logger = BatchingLogger::spawn(
            // Config remains `max_retries`; the shared retry policy counts the
            // initial attempt plus those retries.
            build_batch_config(
                config,
                "statsd_logging",
                BatchConfigDefaults {
                    batch_size_key: "max_batch_lines",
                    batch_size: 50,
                    flush_interval_ms: 500,
                    min_flush_interval_ms: 50,
                    buffer_capacity: 10000,
                    max_retries: 0,
                    retry_delay_ms: 0,
                },
            ),
            move |batch| {
                let flush_config = flush_config.clone();
                let state = Arc::clone(&state);
                async move { send_batch(&flush_config, &state, batch).await }
            },
        );

        Ok(Self {
            logger,
            hostname: socket_host.warmup_hostname,
        })
    }
}

#[async_trait]
impl Plugin for StatsdLogging {
    fn name(&self) -> &str {
        "statsd_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::STATSD_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(summary.into());
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(summary.into());
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.hostname.iter().cloned().collect()
    }
}

/// Format HTTP transaction metrics as StatsD line protocol.
fn format_http_metrics(
    summary: &TransactionSummary,
    prefix: &str,
    global_tags: &str,
    schema: Option<&SummarySchema>,
    buf: &mut String,
) {
    use std::fmt::Write;

    // Only consult HTTP schemas for HTTP metrics — a stream-only schema
    // is unrelated.
    let effective_schema = schema.filter(|s| s.applies_to_http());
    let method = sanitize_tag_value(&summary.http_method);
    let status = summary.response_status_code;
    let status_class = format!("{}xx", status / 100);
    let proxy_raw = summary
        .proxy_name
        .as_deref()
        .or(summary.proxy_id.as_deref())
        .unwrap_or("none");
    let proxy_tag = sanitize_tag_value(proxy_raw);

    // Build the trailing `|#k:v,k:v,...` block directly into a reusable
    // String, avoiding the Vec<String> + per-tag format! + join pattern
    // (one small heap allocation per tag → one allocation total).
    let mut builder = TagBlockBuilder::new();
    if let Some(k) = resolve_tag_key(effective_schema, "method", HTTP_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{method}"));
    }
    if let Some(k) = resolve_tag_key(effective_schema, "status", HTTP_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{status}"));
    }
    if let Some(k) = resolve_tag_key(effective_schema, "status_class", HTTP_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{status_class}"));
    }
    if let Some(k) = resolve_tag_key(effective_schema, "proxy", HTTP_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{proxy_tag}"));
    }
    let tags = builder.finish(global_tags);

    let _ = writeln!(buf, "{prefix}.request.count:1|c{tags}");
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_total_ms:{:.2}|ms{tags}",
        summary.latency_total_ms,
    );
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_backend_ttfb_ms:{:.2}|ms{tags}",
        summary.latency_backend_ttfb_ms,
    );
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_gateway_overhead_ms:{:.2}|ms{tags}",
        summary.latency_gateway_overhead_ms,
    );
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_plugin_execution_ms:{:.2}|ms{tags}",
        summary.latency_plugin_execution_ms,
    );
    let _ = writeln!(buf, "{prefix}.request.status.{status_class}:1|c{tags}");
    if summary.client_disconnected {
        let _ = writeln!(buf, "{prefix}.request.client_disconnect:1|c{tags}");
    }
}

/// Format stream transaction metrics as StatsD line protocol.
fn format_stream_metrics(
    summary: &StreamTransactionSummary,
    prefix: &str,
    global_tags: &str,
    schema: Option<&SummarySchema>,
    buf: &mut String,
) {
    use std::fmt::Write;

    let effective_schema = schema.filter(|s| s.applies_to_stream());
    let protocol = sanitize_tag_value(&summary.protocol);
    let proxy_raw = summary.proxy_name.as_deref().unwrap_or(&summary.proxy_id);
    let proxy_tag = sanitize_tag_value(proxy_raw);
    let has_error = if summary.connection_error.is_some() {
        "true"
    } else {
        "false"
    };

    let cause_tag = match summary.disconnect_cause {
        Some(crate::plugins::DisconnectCause::IdleTimeout) => "idle_timeout",
        Some(crate::plugins::DisconnectCause::RecvError) => "recv_error",
        Some(crate::plugins::DisconnectCause::BackendError) => "backend_error",
        Some(crate::plugins::DisconnectCause::GracefulShutdown) => "graceful_shutdown",
        None => "unknown",
    };
    let direction_tag = match summary.disconnect_direction {
        Some(crate::plugins::Direction::ClientToBackend) => "client_to_backend",
        Some(crate::plugins::Direction::BackendToClient) => "backend_to_client",
        Some(crate::plugins::Direction::Unknown) => "unknown",
        None => "unknown",
    };

    let mut builder = TagBlockBuilder::new();
    if let Some(k) = resolve_tag_key(effective_schema, "protocol", STREAM_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{protocol}"));
    }
    if let Some(k) = resolve_tag_key(effective_schema, "proxy", STREAM_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{proxy_tag}"));
    }
    if let Some(k) = resolve_tag_key(effective_schema, "error", STREAM_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{has_error}"));
    }
    if let Some(k) = resolve_tag_key(effective_schema, "cause", STREAM_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{cause_tag}"));
    }
    if let Some(k) = resolve_tag_key(effective_schema, "direction", STREAM_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{direction_tag}"));
    }
    let tags = builder.finish(global_tags);

    let _ = writeln!(buf, "{prefix}.stream.count:1|c{tags}");
    let _ = writeln!(
        buf,
        "{prefix}.stream.duration_ms:{:.2}|ms{tags}",
        summary.duration_ms,
    );
    let _ = writeln!(
        buf,
        "{prefix}.stream.bytes_sent:{}|g{tags}",
        summary.bytes_sent
    );
    let _ = writeln!(
        buf,
        "{prefix}.stream.bytes_received:{}|g{tags}",
        summary.bytes_received,
    );
    let _ = writeln!(buf, "{prefix}.stream.disconnect:1|c{tags}");
}

/// Single-allocation builder for the trailing `|#k:v,k:v,…` block.
///
/// Replaces the prior `Vec<String> + per-tag format! + join` pattern,
/// which allocated once per tag plus once for the joined string. Tags are
/// written directly into one growing `String` via `fmt::Write`, so the
/// total allocation count is bounded by `String`'s growth strategy —
/// effectively one allocation per call site (the buffer reservation),
/// regardless of tag count.
struct TagBlockBuilder {
    out: String,
    has_entries: bool,
}

impl TagBlockBuilder {
    fn new() -> Self {
        Self {
            out: String::new(),
            has_entries: false,
        }
    }

    fn push(&mut self, key: &str, value: std::fmt::Arguments<'_>) -> std::fmt::Result {
        use std::fmt::Write;
        if !self.has_entries {
            self.out.push_str("|#");
            self.has_entries = true;
        } else {
            self.out.push(',');
        }
        write!(self.out, "{key}:")?;
        self.out.write_fmt(value)
    }

    fn finish(mut self, global_tags: &str) -> String {
        if global_tags.is_empty() {
            return self.out;
        }
        // `global_tags` begins with "|#"; skip those when we already have
        // an open block.
        let stripped = &global_tags[2..];
        if !self.has_entries {
            self.out.push_str("|#");
        } else if !stripped.is_empty() {
            self.out.push(',');
        }
        self.out.push_str(stripped);
        self.out
    }
}

async fn send_batch(
    cfg: &StatsdFlushConfig,
    state: &Mutex<StatsdFlushState>,
    batch: Vec<MetricEntry>,
) -> Result<(), String> {
    let mut payload = String::with_capacity(batch.len() * 128);
    for entry in &batch {
        match entry {
            MetricEntry::Http(summary) => {
                format_http_metrics(
                    summary,
                    &cfg.prefix,
                    &cfg.global_tags,
                    cfg.schema.as_deref(),
                    &mut payload,
                );
            }
            MetricEntry::Stream(summary) => {
                format_stream_metrics(
                    summary,
                    &cfg.prefix,
                    &cfg.global_tags,
                    cfg.schema.as_deref(),
                    &mut payload,
                );
            }
        }
    }

    if payload.is_empty() {
        return Ok(());
    }

    let (mut socket, mut current_addr, mut last_resolve) = {
        let mut state = state
            .lock()
            .map_err(|_| "statsd_logging: flush state lock poisoned".to_string())?;
        (state.socket.take(), state.current_addr, state.last_resolve)
    };

    if socket.is_none() {
        let resolved_addr = resolve_udp_endpoint(
            &cfg.hostname,
            cfg.port,
            cfg.dns_cache.as_ref(),
            "statsd_logging",
        )
        .await?;
        let new_socket = bind_connected_udp_socket(resolved_addr, "statsd_logging").await?;
        current_addr = Some(resolved_addr);
        socket = Some(new_socket);
        last_resolve = Instant::now();
    }

    if last_resolve.elapsed() >= UDP_RE_RESOLVE_INTERVAL {
        last_resolve = Instant::now();
        if let Ok(new_addr) = resolve_udp_endpoint(
            &cfg.hostname,
            cfg.port,
            cfg.dns_cache.as_ref(),
            "statsd_logging",
        )
        .await
            && current_addr != Some(new_addr)
            && let Ok(new_socket) = bind_connected_udp_socket(new_addr, "statsd_logging").await
        {
            current_addr = Some(new_addr);
            socket = Some(new_socket);
        }
    }

    let result = if let Some(socket) = socket.as_ref() {
        const MAX_UDP_PAYLOAD: usize = 1472;
        if payload.len() <= MAX_UDP_PAYLOAD {
            socket
                .send(payload.as_bytes())
                .await
                .map(|_| ())
                .map_err(|error| format!("statsd_logging: failed to send metrics: {error}"))
        } else {
            let mut chunk = String::with_capacity(MAX_UDP_PAYLOAD);
            for line in payload.lines() {
                if !chunk.is_empty() && chunk.len() + line.len() + 1 > MAX_UDP_PAYLOAD {
                    socket.send(chunk.as_bytes()).await.map_err(|error| {
                        format!("statsd_logging: failed to send metrics chunk: {error}")
                    })?;
                    chunk.clear();
                }
                if !chunk.is_empty() {
                    chunk.push('\n');
                }
                chunk.push_str(line);
            }
            if !chunk.is_empty() {
                socket.send(chunk.as_bytes()).await.map_err(|error| {
                    format!("statsd_logging: failed to send metrics chunk: {error}")
                })?;
            }
            Ok(())
        }
    } else {
        Err("statsd_logging: UDP socket unavailable after initialization".to_string())
    };

    let mut state = state
        .lock()
        .map_err(|_| "statsd_logging: flush state lock poisoned".to_string())?;
    state.socket = socket;
    state.current_addr = current_addr;
    state.last_resolve = last_resolve;

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_tag_value_replaces_delimiters() {
        assert_eq!(sanitize_tag_value("foo,bar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo|bar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo#bar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo:bar"), "foo_bar");
    }

    #[test]
    fn sanitize_tag_value_replaces_whitespace_and_newlines() {
        assert_eq!(sanitize_tag_value("foo bar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo\nbar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo\r\nbar"), "foo__bar");
    }

    #[test]
    fn sanitize_tag_value_preserves_normal_chars() {
        assert_eq!(sanitize_tag_value("my-proxy_01.abc"), "my-proxy_01.abc");
    }

    #[test]
    fn sanitize_tag_value_empty_becomes_none() {
        assert_eq!(sanitize_tag_value(""), "none");
        assert_eq!(sanitize_tag_value("   "), "none");
    }

    #[test]
    fn sanitize_tag_value_mixed_attack_string() {
        assert_eq!(sanitize_tag_value("evil,|#:proxy"), "evil____proxy");
    }
}
