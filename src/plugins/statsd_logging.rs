//! StatsD metrics logging plugin — async metric shipping over UDP.
//!
//! Extracts metrics from `TransactionSummary`, `StreamTransactionSummary`, and
//! `WsDisconnectContext` entries and sends them to a StatsD-compatible server
//! (StatsD, Datadog, Telegraf, etc.) over UDP. Uses `BatchingLogger<MetricEntry>`
//! to decouple the proxy hot path from socket I/O.
//!
//! Hostname resolution uses the gateway's shared `DnsCache` (pre-warmed via
//! `warmup_hostnames()`) with TTL, stale-while-revalidate, and background
//! refresh — consistent with all other gateway components.
//!
//! Supports all proxy protocols (HTTP, gRPC, WebSocket, TCP, UDP).

use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;
use tracing::warn;

use super::utils::log_schema::{SchemaCapabilities, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, UDP_RE_RESOLVE_INTERVAL,
    bind_connected_udp_socket, build_batch_config, parse_socket_host, resolve_udp_endpoint,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary, WsDisconnectContext};
use crate::config::types::MAX_NAMESPACE_LENGTH;
use crate::dns::DnsCache;

/// Authoritative closed set of top-level `statsd_logging` configuration keys.
///
/// Constructor admission, OpenAPI `StatsdLoggingConfig`, and operator docs must
/// stay in lockstep with this list. Nested maps that are intentionally open
/// (`global_tags` string values; inline `schema` shape validated by the shared
/// log-schema compiler) are not flattened into this set — only the outer
/// property names are closed.
pub const STATSD_LOGGING_CONFIG_KEYS: &[&str] = &[
    "buffer_capacity",
    "flush_interval_ms",
    "global_tags",
    "host",
    "max_batch_lines",
    "max_retries",
    "port",
    "prefix",
    "retry_delay_ms",
    "schema",
    "schema_ref",
];

/// Conservative UDP payload ceiling shared by IPv4 (1472) and IPv6 (1452)
/// under a 1500-byte MTU before extension headers / overlay overhead.
/// Every `UdpSocket::send` payload is kept at or below this bound.
pub const MAX_UDP_PAYLOAD: usize = 1452;

/// Upper bound on a sanitized metric-name prefix after line-protocol scrubbing.
pub const MAX_PREFIX_LEN: usize = 256;

/// Upper bound on the encoded `global_tags` payload (the text after `|#`).
pub const MAX_GLOBAL_TAGS_ENCODED_LEN: usize = 400;

/// Upper bound on a single sanitized tag key.
pub const MAX_TAG_KEY_LEN: usize = 64;

/// Upper bound on the length of a single sanitized request-derived tag value.
const MAX_TAG_VALUE_LEN: usize = 64;

/// Namespace tag values preserve the full validated Ferrum namespace identity
/// (up to [`MAX_NAMESPACE_LENGTH`]) so distinct tenants cannot collide through
/// silent truncation.
const MAX_NAMESPACE_TAG_VALUE_LEN: usize = MAX_NAMESPACE_LENGTH;

/// Runtime-owned DogStatsD tag keys that operators and schemas must not
/// override or collide with. Compared case-insensitively at admission.
const RESERVED_TAG_KEYS: &[&str] = &[
    "namespace",
    "method",
    "status",
    "status_class",
    "proxy",
    "protocol",
    "error",
    "cause",
    "direction",
    "body_outcome",
    "body_error",
    "result",
    "io_side",
    "error_class",
];

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

const WS_TAG_NATIVE: &[(&str, &str)] = &[("proxy", "proxy_id")];

fn reject_unknown_config_keys(config: &serde_json::Map<String, Value>) -> Result<(), String> {
    let mut unknown: Vec<&str> = config
        .keys()
        .filter(|key| !STATSD_LOGGING_CONFIG_KEYS.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "statsd_logging: unknown configuration key(s): {}; allowed keys: {}",
        unknown.join(", "),
        STATSD_LOGGING_CONFIG_KEYS.join(", ")
    ))
}

/// Emit a `warn!` for any inline `schema:` keys that the statsd
/// emitter does not honor. Only `rename`, `omit`, and `summary_type`
/// have an effect — everything else (`static_fields`, `derived_fields`,
/// `metadata`, `timestamp_format`, `order`) is silently dropped because
/// statsd is line protocol, not JSON.
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

fn is_reserved_tag_key(key: &str) -> bool {
    RESERVED_TAG_KEYS
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(key))
}

/// Validate a configured StatsD tag key against a portable grammar.
///
/// Configured keys (global_tags / schema rename targets) are rejected rather
/// than rewritten so operators cannot accidentally inject line-protocol
/// delimiters or control characters into every datagram.
pub fn validate_tag_key(key: &str) -> Result<&str, String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("statsd_logging: tag keys must not be empty".to_string());
    }
    if trimmed != key {
        return Err(format!(
            "statsd_logging: tag key '{key}' must not contain leading or trailing whitespace"
        ));
    }
    if trimmed.len() > MAX_TAG_KEY_LEN {
        return Err(format!(
            "statsd_logging: tag key exceeds maximum length of {MAX_TAG_KEY_LEN} bytes"
        ));
    }
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return Err("statsd_logging: tag keys must not be empty".to_string());
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!(
            "statsd_logging: tag key '{trimmed}' must start with an ASCII letter or underscore"
        ));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
            return Err(format!(
                "statsd_logging: tag key '{trimmed}' contains characters outside [A-Za-z0-9_.-]"
            ));
        }
    }
    Ok(trimmed)
}

fn validate_reserved_tag_key(key: &str, context: &str) -> Result<(), String> {
    if is_reserved_tag_key(key) {
        return Err(format!(
            "statsd_logging: {context} tag key '{key}' is reserved and cannot be overridden \
             (reserved: {})",
            RESERVED_TAG_KEYS.join(", ")
        ));
    }
    Ok(())
}

/// Sanitize a value used in a StatsD tag: strip the delimiters that would break
/// the line protocol (`,`, `|`, `#`, `:`), every Unicode control character, and
/// whitespace. Replaces disallowed chars with `_` so the tag remains parseable,
/// and caps the result at `max_len` bytes (on a char boundary).
fn sanitize_tag_value_with_cap(input: &str, max_len: usize) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "none".to_string();
    }
    let mut out = String::with_capacity(trimmed.len().min(max_len));
    for c in trimmed.chars() {
        // Stop before exceeding the cap; never split a multi-byte char.
        if out.len() + c.len_utf8() > max_len {
            break;
        }
        match c {
            ',' | '|' | '#' | ':' | '\n' | '\r' => out.push('_'),
            c if c.is_control() || c.is_whitespace() => out.push('_'),
            c => out.push(c),
        }
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out
    }
}

/// Sanitize a request-derived tag value (proxy name, protocol, …).
pub fn sanitize_tag_value(input: &str) -> String {
    sanitize_tag_value_with_cap(input, MAX_TAG_VALUE_LEN)
}

/// Sanitize the authoritative namespace tag without collapsing distinct
/// Ferrum namespaces that share a 64-byte prefix.
pub fn sanitize_namespace_tag_value(input: &str) -> String {
    let sanitized = sanitize_tag_value_with_cap(input, MAX_NAMESPACE_TAG_VALUE_LEN);
    // Defense-in-depth: if sanitization would lose trailing uniqueness for an
    // over-long input, append a stable short hash of the original bytes.
    if input.trim().len() > MAX_NAMESPACE_TAG_VALUE_LEN {
        let digest = Sha256::digest(input.trim().as_bytes());
        let hash = hex::encode(&digest[..8]);
        let keep = MAX_NAMESPACE_TAG_VALUE_LEN.saturating_sub(hash.len() + 1);
        let mut prefix = sanitize_tag_value_with_cap(input, keep);
        prefix.push('_');
        prefix.push_str(&hash);
        return prefix;
    }
    sanitized
}

/// Sanitize a StatsD metric-name prefix so every emitted metric name is
/// line-protocol-safe. The prefix is interpolated raw into each line
/// (`"{prefix}.request.count:1|c{tags}"`), so a prefix containing the
/// metric-name/value delimiter (`:`), the tag delimiters (`|`, `#`, `,`), a
/// newline, or other control/whitespace chars would corrupt the line.
/// Disallowed chars are replaced with `_`. Returns `None` when the prefix is
/// empty (or whitespace-only) after trimming.
pub fn sanitize_metric_name(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        match c {
            ',' | '|' | '#' | ':' | '\n' | '\r' => out.push('_'),
            c if c.is_control() || c.is_whitespace() => out.push('_'),
            c => out.push(c),
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Canonical HTTP methods emitted verbatim as the `method` tag. Any other
/// method token collapses to [`OTHER_METHOD`] so a hostile client cannot drive
/// unbounded `method` tag cardinality.
const KNOWN_HTTP_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

const OTHER_METHOD: &str = "other";

/// Map a request method to a bounded `method` tag value.
pub fn bounded_method_tag(method: &str) -> &'static str {
    KNOWN_HTTP_METHODS
        .iter()
        .find(|known| **known == method)
        .copied()
        .unwrap_or(OTHER_METHOD)
}

fn validate_statsd_schema_keys(schema: Option<&SummarySchema>) -> Result<HashSet<String>, String> {
    let mut seen = HashSet::new();
    let mut runtime_keys: HashSet<String> = RESERVED_TAG_KEYS
        .iter()
        .map(|key| key.to_ascii_lowercase())
        .collect();
    let mappings = [
        ("http", HTTP_TAG_NATIVE, &["method", "status", "proxy"][..]),
        (
            "stream",
            STREAM_TAG_NATIVE,
            &["protocol", "proxy", "error", "cause", "direction"][..],
        ),
        ("websocket", WS_TAG_NATIVE, &["proxy"][..]),
    ];

    for (family, mapping, defaults) in mappings {
        let effective_schema = schema.filter(|s| match family {
            "http" | "websocket" => s.applies_to_http(),
            "stream" => s.applies_to_stream(),
            _ => false,
        });
        for default_key in defaults {
            let Some(key) = resolve_tag_key(effective_schema, default_key, mapping) else {
                continue;
            };
            let validated = validate_tag_key(key).map_err(|err| {
                format!("{err} (schema rename target for {family} tag '{default_key}')")
            })?;
            if validated != *default_key && is_reserved_tag_key(validated) {
                return Err(format!(
                    "statsd_logging: schema rename target '{validated}' for {family} tag \
                     '{default_key}' collides with a reserved runtime tag"
                ));
            }
            let dedupe = format!("{family}:{}", validated.to_ascii_lowercase());
            if !seen.insert(dedupe) {
                return Err(format!(
                    "statsd_logging: schema produces duplicate {family} tag key '{validated}'"
                ));
            }
            runtime_keys.insert(validated.to_ascii_lowercase());
        }
    }
    Ok(runtime_keys)
}

fn build_global_tags(
    config: &Value,
    namespace: &str,
    runtime_tag_keys: &HashSet<String>,
) -> Result<String, String> {
    let mut pairs = Vec::new();
    let mut seen_keys = HashSet::new();

    if let Some(global_tags) = config.get("global_tags") {
        let tags_obj = global_tags
            .as_object()
            .ok_or_else(|| "statsd_logging: 'global_tags' must be an object".to_string())?;
        pairs.reserve(tags_obj.len() + 1);
        for (key, value) in tags_obj {
            let validated = validate_tag_key(key)?;
            validate_reserved_tag_key(validated, "global_tags")?;
            let dedupe = validated.to_ascii_lowercase();
            if runtime_tag_keys.contains(&dedupe) {
                return Err(format!(
                    "statsd_logging: global_tags key '{validated}' collides with a schema-owned \
                     runtime tag"
                ));
            }
            if !seen_keys.insert(dedupe) {
                return Err(format!(
                    "statsd_logging: duplicate global_tags key '{validated}' after normalization"
                ));
            }
            let value = value
                .as_str()
                .ok_or_else(|| format!("statsd_logging: 'global_tags.{key}' must be a string"))?;
            pairs.push(format!("{validated}:{}", sanitize_tag_value(value)));
        }
    }

    // Authoritative gateway namespace is always appended and never overridable.
    pairs.push(format!(
        "namespace:{}",
        sanitize_namespace_tag_value(namespace)
    ));

    let encoded = pairs.join(",");
    if encoded.len() > MAX_GLOBAL_TAGS_ENCODED_LEN {
        return Err(format!(
            "statsd_logging: encoded global_tags (+ namespace) exceed maximum length of \
             {MAX_GLOBAL_TAGS_ENCODED_LEN} bytes (got {})",
            encoded.len()
        ));
    }

    if encoded.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("|#{encoded}"))
    }
}

/// True when `value` is a finite, non-negative timer sample that may be emitted.
pub fn is_valid_timer_sample(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

/// Classify terminal HTTP body completion for StatsD tags/counters.
///
/// - `complete`: body finished successfully (`body_completed`)
/// - `incomplete`: streamed/body failure or client disconnect before completion
/// - `none`: no streamed body outcome applies (e.g. buffered reject with defaults)
pub fn http_body_outcome(summary: &TransactionSummary) -> &'static str {
    if summary.body_completed {
        return "complete";
    }
    if summary.body_error_class.is_some()
        || summary.client_disconnected
        || (summary.response_streamed && !summary.body_completed)
    {
        return "incomplete";
    }
    "none"
}

#[derive(Clone)]
enum MetricEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
    WebSocket(WsDisconnectContext),
}

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
        let Some(config_object) = config.as_object() else {
            return Err(format!(
                "statsd_logging: config must be an object; allowed keys: {}",
                STATSD_LOGGING_CONFIG_KEYS.join(", ")
            ));
        };
        reject_unknown_config_keys(config_object)?;

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
        socket_host.screen_egress_ip("statsd_logging", "host", http_client.backend_allow_ips())?;
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
        // The prefix is interpolated raw into every metric line, so it must be
        // line-protocol-safe. Sanitize both an explicit `prefix` and the
        // namespace-derived fallback (a namespace can contain characters that
        // are legal there but not in a StatsD metric name).
        let prefix = match config.get("prefix") {
            Some(value) => {
                let raw = value
                    .as_str()
                    .ok_or_else(|| "statsd_logging: 'prefix' must be a string".to_string())?;
                sanitize_metric_name(raw)
                    .ok_or_else(|| "statsd_logging: 'prefix' must not be empty".to_string())?
            }
            None => sanitize_metric_name(ns).ok_or_else(|| {
                "statsd_logging: namespace used as the metric prefix must not be empty".to_string()
            })?,
        };
        if prefix.len() > MAX_PREFIX_LEN {
            return Err(format!(
                "statsd_logging: 'prefix' exceeds maximum length of {MAX_PREFIX_LEN} bytes \
                 after sanitization (got {})",
                prefix.len()
            ));
        }

        warn_on_unsupported_inline_schema_keys(config);
        let schema = resolve_schema(config, "statsd_logging", SchemaCapabilities::BASE)?;
        let runtime_tag_keys = validate_statsd_schema_keys(schema.as_deref())?;
        let global_tags = build_global_tags(config, ns, &runtime_tag_keys)?;

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
        // Mirror/shadow summaries are internal backend probes, not client
        // traffic — match prometheus_metrics and exclude them from request
        // families (issue #2553).
        if summary.mirror {
            return;
        }
        self.logger.try_send(MetricEntry::Http(summary.clone()));
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(MetricEntry::Stream(summary.clone()));
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.logger.try_send(MetricEntry::WebSocket(ctx.clone()));
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.hostname.iter().cloned().collect()
    }
}

fn write_timer(buf: &mut String, prefix: &str, metric: &str, value: f64, tags: &str) {
    use std::fmt::Write;
    if is_valid_timer_sample(value) {
        let _ = writeln!(buf, "{prefix}.{metric}:{value:.2}|ms{tags}");
    }
}

/// Format HTTP transaction metrics as StatsD line protocol.
pub fn format_http_metrics(
    summary: &TransactionSummary,
    prefix: &str,
    global_tags: &str,
    schema: Option<&SummarySchema>,
    buf: &mut String,
) {
    use std::fmt::Write;

    if summary.mirror {
        return;
    }

    // Only consult HTTP schemas for HTTP metrics — a stream-only schema
    // is unrelated.
    let effective_schema = schema.filter(|s| s.applies_to_http());
    let method = bounded_method_tag(&summary.http_method);
    let status = summary.response_status_code;
    let status_class = format!("{}xx", status / 100);
    let proxy_raw = summary
        .proxy_name
        .as_deref()
        .or(summary.proxy_id.as_deref())
        .unwrap_or("none");
    let proxy_tag = sanitize_tag_value(proxy_raw);
    let body_outcome = http_body_outcome(summary);
    let body_error = summary
        .body_error_class
        .as_ref()
        .map(crate::retry::ErrorClass::as_str)
        .unwrap_or("none");

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
    let _ = builder.push("body_outcome", format_args!("{body_outcome}"));
    let _ = builder.push("body_error", format_args!("{body_error}"));
    let tags = builder.finish(global_tags);

    let _ = writeln!(buf, "{prefix}.request.count:1|c{tags}");
    write_timer(
        buf,
        prefix,
        "request.latency_total_ms",
        summary.latency_total_ms,
        &tags,
    );
    // `-1.0` is the shared no-backend sentinel — omit rather than sample.
    write_timer(
        buf,
        prefix,
        "request.latency_backend_ttfb_ms",
        summary.latency_backend_ttfb_ms,
        &tags,
    );
    write_timer(
        buf,
        prefix,
        "request.latency_gateway_overhead_ms",
        summary.latency_gateway_overhead_ms,
        &tags,
    );
    write_timer(
        buf,
        prefix,
        "request.latency_plugin_execution_ms",
        summary.latency_plugin_execution_ms,
        &tags,
    );
    let _ = writeln!(buf, "{prefix}.request.status.{status_class}:1|c{tags}");
    if summary.client_disconnected {
        let _ = writeln!(buf, "{prefix}.request.client_disconnect:1|c{tags}");
    }
    if body_outcome == "incomplete" {
        let _ = writeln!(buf, "{prefix}.request.body_incomplete:1|c{tags}");
    }
}

/// Format stream transaction metrics as StatsD line protocol.
pub fn format_stream_metrics(
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
    write_timer(
        buf,
        prefix,
        "stream.duration_ms",
        summary.duration_ms,
        &tags,
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

fn ws_direction_tag(direction: Option<crate::plugins::Direction>) -> &'static str {
    match direction {
        Some(crate::plugins::Direction::ClientToBackend) => "client_to_backend",
        Some(crate::plugins::Direction::BackendToClient) => "backend_to_client",
        Some(crate::plugins::Direction::Unknown) | None => "unknown",
    }
}

fn ws_io_side_tag(side: Option<crate::proxy::tcp_proxy::StreamIoSide>) -> &'static str {
    match side {
        Some(crate::proxy::tcp_proxy::StreamIoSide::Read) => "read",
        Some(crate::proxy::tcp_proxy::StreamIoSide::Write) => "write",
        None => "unknown",
    }
}

/// Format WebSocket session-completion metrics as StatsD line protocol.
///
/// Emitted once from `on_ws_disconnect`. The HTTP upgrade handshake still
/// produces a separate short-lived `request.*` series; these `websocket.*`
/// families cover the upgraded session only.
pub fn format_ws_metrics(
    ctx: &WsDisconnectContext,
    prefix: &str,
    global_tags: &str,
    schema: Option<&SummarySchema>,
    buf: &mut String,
) {
    use std::fmt::Write;

    let effective_schema = schema.filter(|s| s.applies_to_websocket_disconnect());
    let proxy_raw = ctx.proxy_name.as_deref().unwrap_or(&ctx.proxy_id);
    let proxy_tag = sanitize_tag_value(proxy_raw);
    let result = if ctx.error_class.is_some() {
        "error"
    } else {
        "success"
    };
    let direction = ws_direction_tag(ctx.direction);
    let io_side = ws_io_side_tag(ctx.io_side);
    let error_class = ctx
        .error_class
        .as_ref()
        .map(crate::retry::ErrorClass::as_str)
        .unwrap_or("none");

    let mut builder = TagBlockBuilder::new();
    if let Some(k) = resolve_tag_key(effective_schema, "proxy", WS_TAG_NATIVE) {
        let _ = builder.push(k, format_args!("{proxy_tag}"));
    }
    let _ = builder.push("result", format_args!("{result}"));
    let _ = builder.push("direction", format_args!("{direction}"));
    let _ = builder.push("io_side", format_args!("{io_side}"));
    let _ = builder.push("error_class", format_args!("{error_class}"));
    let tags = builder.finish(global_tags);

    let _ = writeln!(buf, "{prefix}.websocket.session.count:1|c{tags}");
    write_timer(
        buf,
        prefix,
        "websocket.session.duration_ms",
        ctx.duration_ms,
        &tags,
    );
    let _ = writeln!(
        buf,
        "{prefix}.websocket.bytes_client_to_backend:{}|g{tags}",
        ctx.bytes_client_to_backend
    );
    let _ = writeln!(
        buf,
        "{prefix}.websocket.bytes_backend_to_client:{}|g{tags}",
        ctx.bytes_backend_to_client
    );
    let _ = writeln!(
        buf,
        "{prefix}.websocket.frames_client_to_backend:{}|g{tags}",
        ctx.frames_client_to_backend
    );
    let _ = writeln!(
        buf,
        "{prefix}.websocket.frames_backend_to_client:{}|g{tags}",
        ctx.frames_backend_to_client
    );
}

/// Pack newline-delimited StatsD lines into UDP datagrams that each stay at
/// or below `max_payload`. Individual lines larger than the ceiling are
/// dropped (never fragmented mid-line) and counted in the returned drop tally.
pub fn pack_udp_datagrams(payload: &str, max_payload: usize) -> (Vec<String>, usize) {
    let mut datagrams = Vec::new();
    let mut chunk = String::with_capacity(max_payload.min(payload.len()));
    let mut dropped = 0usize;

    for line in payload.lines() {
        if line.is_empty() {
            continue;
        }
        if line.len() > max_payload {
            dropped = dropped.saturating_add(1);
            warn!(
                line_len = line.len(),
                max_payload, "statsd_logging: dropping metric line exceeding UDP payload ceiling"
            );
            continue;
        }
        if !chunk.is_empty() && chunk.len() + line.len() + 1 > max_payload {
            datagrams.push(std::mem::take(&mut chunk));
            chunk = String::with_capacity(max_payload);
        }
        if !chunk.is_empty() {
            chunk.push('\n');
        }
        chunk.push_str(line);
    }
    if !chunk.is_empty() {
        datagrams.push(chunk);
    }
    (datagrams, dropped)
}

/// Single-allocation builder for the trailing `|#k:v,k:v,…` block.
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
            MetricEntry::WebSocket(ctx) => {
                format_ws_metrics(
                    ctx,
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
        let (datagrams, _dropped) = pack_udp_datagrams(&payload, MAX_UDP_PAYLOAD);
        let mut send_result = Ok(());
        for datagram in datagrams {
            debug_assert!(datagram.len() <= MAX_UDP_PAYLOAD);
            if let Err(error) = socket.send(datagram.as_bytes()).await {
                send_result = Err(format!("statsd_logging: failed to send metrics: {error}"));
                break;
            }
        }
        send_result
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
    fn sanitize_tag_value_replaces_whitespace_newlines_and_controls() {
        assert_eq!(sanitize_tag_value("foo bar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo\nbar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo\r\nbar"), "foo__bar");
        assert_eq!(sanitize_tag_value("foo\0bar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo\x1bbar"), "foo_bar");
        assert_eq!(sanitize_tag_value("foo\x07bar"), "foo_bar");
        // Unicode Cc control (NEXT LINE / NEL).
        assert_eq!(sanitize_tag_value("foo\u{0085}bar"), "foo_bar");
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

    #[test]
    fn sanitize_tag_value_caps_length() {
        let long = "a".repeat(500);
        let out = sanitize_tag_value(&long);
        assert_eq!(out.len(), MAX_TAG_VALUE_LEN);
        assert!(out.bytes().all(|b| b == b'a'));
    }

    #[test]
    fn sanitize_namespace_tag_preserves_long_identity() {
        let ns = format!("{}{}", "a".repeat(64), "unique-suffix-tenant-b");
        let out = sanitize_namespace_tag_value(&ns);
        assert!(out.contains("unique-suffix-tenant-b"), "got: {out}");
        assert_ne!(
            sanitize_namespace_tag_value(&format!(
                "{}{}",
                "a".repeat(64),
                "unique-suffix-tenant-a"
            )),
            out
        );
    }

    #[test]
    fn sanitize_metric_name_replaces_line_protocol_delimiters() {
        assert_eq!(sanitize_metric_name("foo:bar").as_deref(), Some("foo_bar"));
        assert_eq!(sanitize_metric_name("foo|bar").as_deref(), Some("foo_bar"));
        assert_eq!(sanitize_metric_name("foo#bar").as_deref(), Some("foo_bar"));
        assert_eq!(sanitize_metric_name("foo,bar").as_deref(), Some("foo_bar"));
    }

    #[test]
    fn sanitize_metric_name_rejects_a_line_injection_prefix() {
        assert_eq!(
            sanitize_metric_name("p:1|c\nevil.metric").as_deref(),
            Some("p_1_c_evil.metric")
        );
    }

    #[test]
    fn sanitize_metric_name_empty_is_none() {
        assert_eq!(sanitize_metric_name(""), None);
        assert_eq!(sanitize_metric_name("   "), None);
    }

    #[test]
    fn validate_tag_key_rejects_injection() {
        assert!(validate_tag_key("method\nrogue").is_err());
        assert!(validate_tag_key("a:b").is_err());
        assert!(validate_tag_key("a|b").is_err());
        assert!(validate_tag_key(" method").is_err());
        assert!(validate_tag_key("method ").is_err());
        assert!(validate_tag_key("ok_tag").is_ok());
    }

    #[test]
    fn pack_udp_datagrams_enforces_ceiling() {
        let ok = "a".repeat(MAX_UDP_PAYLOAD);
        let (dgrams, dropped) = pack_udp_datagrams(&ok, MAX_UDP_PAYLOAD);
        assert_eq!(dropped, 0);
        assert_eq!(dgrams.len(), 1);
        assert_eq!(dgrams[0].len(), MAX_UDP_PAYLOAD);

        let over = "b".repeat(MAX_UDP_PAYLOAD + 1);
        let (dgrams, dropped) = pack_udp_datagrams(&over, MAX_UDP_PAYLOAD);
        assert_eq!(dropped, 1);
        assert!(dgrams.is_empty());

        let under = "c".repeat(MAX_UDP_PAYLOAD - 1);
        let (dgrams, dropped) = pack_udp_datagrams(&under, MAX_UDP_PAYLOAD);
        assert_eq!(dropped, 0);
        assert_eq!(dgrams[0].len(), MAX_UDP_PAYLOAD - 1);
    }

    #[test]
    fn pack_udp_datagrams_keeps_valid_siblings_when_one_line_is_oversized() {
        let payload = format!("short:1|c\n{}\nother:1|c", "x".repeat(MAX_UDP_PAYLOAD + 8));
        let (dgrams, dropped) = pack_udp_datagrams(&payload, MAX_UDP_PAYLOAD);
        assert_eq!(dropped, 1);
        let joined = dgrams.join("\n");
        assert!(joined.contains("short:1|c"));
        assert!(joined.contains("other:1|c"));
        assert!(dgrams.iter().all(|d| d.len() <= MAX_UDP_PAYLOAD));
    }

    #[test]
    fn format_http_metrics_skips_mirror_and_negative_ttfb() {
        let mut summary = http_summary("GET");
        summary.mirror = true;
        let mut buf = String::new();
        format_http_metrics(&summary, "ferrum", "", None, &mut buf);
        assert!(buf.is_empty(), "mirror must emit nothing: {buf}");

        let mut summary = http_summary("GET");
        summary.latency_backend_ttfb_ms = -1.0;
        summary.latency_total_ms = 12.0;
        let mut buf = String::new();
        format_http_metrics(&summary, "ferrum", "", None, &mut buf);
        assert!(buf.contains("ferrum.request.count:1|c"), "got: {buf}");
        assert!(
            !buf.contains("latency_backend_ttfb_ms"),
            "sentinel must be omitted: {buf}"
        );
        assert!(buf.contains("latency_total_ms:12.00|ms"), "got: {buf}");
    }

    #[test]
    fn format_http_metrics_marks_terminal_body_failure() {
        let mut summary = http_summary("GET");
        summary.response_status_code = 200;
        summary.response_streamed = true;
        summary.body_completed = false;
        summary.body_error_class = Some(crate::retry::ErrorClass::ConnectionReset);
        let mut buf = String::new();
        format_http_metrics(&summary, "ferrum", "", None, &mut buf);
        assert!(buf.contains("status:200"), "got: {buf}");
        assert!(buf.contains("status_class:2xx"), "got: {buf}");
        assert!(buf.contains("body_outcome:incomplete"), "got: {buf}");
        assert!(buf.contains("body_error:connection_reset"), "got: {buf}");
        assert!(
            buf.contains("ferrum.request.body_incomplete:1|c"),
            "got: {buf}"
        );
    }

    #[test]
    fn format_ws_metrics_emits_session_families() {
        let ctx = WsDisconnectContext {
            namespace: "ferrum".to_string(),
            proxy_id: "ws-1".to_string(),
            proxy_name: Some("WS".to_string()),
            client_ip: "127.0.0.1".to_string(),
            backend_target: "http://127.0.0.1:9000/".to_string(),
            listen_port: 8080,
            duration_ms: 1500.0,
            frames_client_to_backend: 3,
            frames_backend_to_client: 4,
            bytes_client_to_backend: 30,
            bytes_backend_to_client: 40,
            timestamp_connected: "2026-01-01T00:00:00+00:00".to_string(),
            timestamp_disconnected: "2026-01-01T00:00:01+00:00".to_string(),
            direction: None,
            io_side: None,
            error_class: None,
            consumer_username: None,
            auth_method: None,
            connection_id: 0,
            metadata: Default::default(),
        };
        let mut buf = String::new();
        format_ws_metrics(&ctx, "ferrum", "", None, &mut buf);
        assert!(buf.contains("ferrum.websocket.session.count:1|c"), "{buf}");
        assert!(
            buf.contains("ferrum.websocket.session.duration_ms:1500.00|ms"),
            "{buf}"
        );
        assert!(
            buf.contains("ferrum.websocket.bytes_client_to_backend:30|g"),
            "{buf}"
        );
        assert!(
            buf.contains("ferrum.websocket.frames_backend_to_client:4|g"),
            "{buf}"
        );
        assert!(buf.contains("result:success"), "{buf}");
    }

    #[tokio::test]
    async fn statsd_prefix_with_delimiters_constructs_sanitized() {
        let cfg = serde_json::json!({ "host": "127.0.0.1", "prefix": "ev:il|p\n" });
        assert!(StatsdLogging::new(&cfg, PluginHttpClient::default()).is_ok());
    }

    #[tokio::test]
    async fn statsd_rejects_reserved_global_tag_override() {
        let cfg = serde_json::json!({
            "host": "127.0.0.1",
            "global_tags": { "namespace": "victim" }
        });
        match StatsdLogging::new(&cfg, PluginHttpClient::default()) {
            Ok(_) => panic!("reserved namespace global tag must be rejected"),
            Err(err) => assert!(err.contains("reserved"), "got: {err}"),
        }
    }

    #[tokio::test]
    async fn statsd_rejects_schema_rename_line_injection() {
        let cfg = serde_json::json!({
            "host": "127.0.0.1",
            "schema": {
                "summary_type": "http",
                "rename": { "http_method": "method\nrogue.metric:1|c\nx" }
            }
        });
        match StatsdLogging::new(&cfg, PluginHttpClient::default()) {
            Ok(_) => panic!("injecting rename target must be rejected"),
            Err(err) => assert!(
                err.contains("tag key") || err.contains("characters"),
                "got: {err}"
            ),
        }
    }

    #[tokio::test]
    async fn statsd_rejects_schema_ref_rename_line_injection() {
        // Advisory coverage for named `schema_ref` reuse: an unsafe rename that
        // compiles under the shared log-schema registry must still be rejected
        // by statsd admission. Serialized via lock_for_tests to avoid
        // process-global registry races with other tests.
        use crate::plugins::utils::log_schema::{SchemaCapabilities, SummarySchema, registry};
        use std::sync::Arc;

        let _g = registry::lock_for_tests();
        registry::reset_for_tests();
        registry::begin_reload().expect("reload bracket opens");
        let raw = serde_json::json!({
            "summary_type": "http",
            "rename": { "http_method": "method\nrogue.metric:1|c\nx" }
        });
        let compiled = SummarySchema::compile(
            &raw,
            "transaction_log_schema[statsd_inject]",
            SchemaCapabilities::BASE,
        )
        .expect("named schema compiles under shared log-schema rules");
        registry::register_named("statsd_inject", Arc::new(raw), compiled)
            .expect("register named schema");
        registry::commit_reload().expect("reload bracket commits");

        let cfg = serde_json::json!({
            "host": "127.0.0.1",
            "schema_ref": "statsd_inject"
        });
        match StatsdLogging::new(&cfg, PluginHttpClient::default()) {
            Ok(_) => panic!("schema_ref injecting rename must be rejected"),
            Err(err) => assert!(
                err.contains("tag key") || err.contains("characters"),
                "got: {err}"
            ),
        }
    }

    #[test]
    fn format_http_metrics_bounds_method_tag() {
        let summary = http_summary("EVILMETHODabcdefghijklmnop");
        let mut buf = String::new();
        format_http_metrics(&summary, "ferrum", "", None, &mut buf);
        assert!(buf.contains("method:other"), "got: {buf}");
        assert!(!buf.contains("EVILMETHOD"), "got: {buf}");
    }

    fn http_summary(method: &str) -> TransactionSummary {
        TransactionSummary {
            http_method: method.to_string(),
            response_status_code: 200,
            body_completed: true,
            latency_backend_ttfb_ms: 10.0,
            latency_total_ms: 12.0,
            latency_gateway_overhead_ms: 1.0,
            latency_plugin_execution_ms: 1.0,
            ..TransactionSummary::default()
        }
    }
}
