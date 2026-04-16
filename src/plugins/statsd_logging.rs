//! StatsD metrics logging plugin — async metric shipping over UDP.
//!
//! Extracts metrics from `TransactionSummary` and `StreamTransactionSummary`
//! entries and sends them to a StatsD-compatible server (StatsD, Datadog,
//! Telegraf, etc.) over UDP. Uses an mpsc channel to decouple the proxy hot
//! path from socket I/O: the `log()` hook enqueues the entry (non-blocking),
//! and a background task formats and sends metrics in batches.
//!
//! Hostname resolution uses the gateway's shared `DnsCache` (pre-warmed via
//! `warmup_hostnames()`) with TTL, stale-while-revalidate, and background
//! refresh — consistent with all other gateway components.
//!
//! Supports all proxy protocols (HTTP, gRPC, WebSocket, TCP, UDP).

use async_trait::async_trait;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::warn;

use super::utils::PluginHttpClient;
use super::{Plugin, StreamTransactionSummary, TransactionSummary};
use crate::dns::DnsCache;

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

/// Union type for entries sent through the channel.
#[derive(Clone)]
enum MetricEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

struct StatsdConfig {
    hostname: String,
    port: u16,
    prefix: String,
    global_tags: String,
    flush_interval: Duration,
    max_batch_lines: usize,
}

pub struct StatsdLogging {
    sender: mpsc::Sender<MetricEntry>,
    hostname: String,
}

impl StatsdLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let host = config["host"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "statsd_logging: 'host' is required — metrics will have nowhere to send".to_string()
            })?
            .to_string();

        let port = config["port"].as_u64().unwrap_or(8125);
        if port == 0 || port > 65535 {
            return Err(format!(
                "statsd_logging: 'port' must be between 1 and 65535 (got {port})"
            ));
        }

        let ns = http_client.namespace();
        let prefix = config["prefix"].as_str().unwrap_or(ns).to_string();

        // Build a global tags suffix string (DogStatsD/Datadog extension).
        // Config: {"global_tags": {"env": "prod", "region": "us-east-1"}}
        // When namespace is non-default and not already present in global_tags,
        // inject a namespace tag automatically for metric isolation.
        let global_tags = {
            let mut pairs: Vec<String> = if let Some(tags_obj) = config["global_tags"].as_object() {
                tags_obj
                    .iter()
                    .map(|(k, v)| {
                        let val = v.as_str().unwrap_or("");
                        format!("{k}:{val}")
                    })
                    .collect()
            } else {
                Vec::new()
            };
            // Auto-inject namespace tag when non-default.
            if ns != crate::config::types::DEFAULT_NAMESPACE
                && !pairs.iter().any(|p| p.starts_with("namespace:"))
            {
                pairs.push(format!("namespace:{ns}"));
            }
            if pairs.is_empty() {
                String::new()
            } else {
                format!("|#{}", pairs.join(","))
            }
        };

        let flush_interval_ms = config["flush_interval_ms"].as_u64().unwrap_or(500).max(50);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;
        let max_batch_lines = config["max_batch_lines"].as_u64().unwrap_or(50).max(1) as usize;

        let statsd_config = StatsdConfig {
            hostname: host.clone(),
            port: port as u16,
            prefix,
            global_tags,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_batch_lines,
        };

        let dns_cache = http_client.dns_cache().cloned();

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, statsd_config, dns_cache));

        Ok(Self {
            sender,
            hostname: host,
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
        if self
            .sender
            .try_send(MetricEntry::Http(summary.clone()))
            .is_err()
        {
            warn!("StatsD logging buffer full — dropping log entry");
        }
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if self
            .sender
            .try_send(MetricEntry::Stream(summary.clone()))
            .is_err()
        {
            warn!("StatsD logging buffer full — dropping stream log entry");
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.hostname.clone()]
    }
}

/// Format HTTP transaction metrics as StatsD line protocol.
fn format_http_metrics(
    summary: &TransactionSummary,
    prefix: &str,
    global_tags: &str,
    buf: &mut String,
) {
    // Per-request tags: method, status, proxy. Operator-controlled values
    // (proxy name/id) are sanitized so that delimiters in the name don't
    // corrupt downstream parsing.
    let method = sanitize_tag_value(&summary.http_method);
    let status = summary.response_status_code;
    let status_class = format!("{}xx", status / 100);
    let proxy_raw = summary
        .matched_proxy_name
        .as_deref()
        .or(summary.matched_proxy_id.as_deref())
        .unwrap_or("none");
    let proxy_tag = sanitize_tag_value(proxy_raw);

    let tags = format!(
        "|#method:{method},status:{status},status_class:{status_class},proxy:{proxy_tag}{extra}",
        extra = if global_tags.is_empty() {
            String::new()
        } else {
            // global_tags already starts with "|#", strip the "|#" and prepend ","
            format!(",{}", &global_tags[2..])
        }
    );

    // Counter: request count
    use std::fmt::Write;
    let _ = writeln!(buf, "{prefix}.request.count:1|c{tags}");

    // Timer: total latency (ms)
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_total_ms:{:.2}|ms{tags}",
        summary.latency_total_ms,
    );

    // Timer: backend TTFB (ms)
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_backend_ttfb_ms:{:.2}|ms{tags}",
        summary.latency_backend_ttfb_ms,
    );

    // Timer: gateway overhead (ms)
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_gateway_overhead_ms:{:.2}|ms{tags}",
        summary.latency_gateway_overhead_ms,
    );

    // Timer: plugin execution (ms)
    let _ = writeln!(
        buf,
        "{prefix}.request.latency_plugin_execution_ms:{:.2}|ms{tags}",
        summary.latency_plugin_execution_ms,
    );

    // Counter: status code bucket
    let _ = writeln!(buf, "{prefix}.request.status.{status_class}:1|c{tags}");
}

/// Format stream transaction metrics as StatsD line protocol.
fn format_stream_metrics(
    summary: &StreamTransactionSummary,
    prefix: &str,
    global_tags: &str,
    buf: &mut String,
) {
    let protocol = sanitize_tag_value(&summary.protocol);
    let proxy_raw = summary.proxy_name.as_deref().unwrap_or(&summary.proxy_id);
    let proxy_tag = sanitize_tag_value(proxy_raw);
    let has_error = if summary.connection_error.is_some() {
        "true"
    } else {
        "false"
    };

    let tags = format!(
        "|#protocol:{protocol},proxy:{proxy_tag},error:{has_error}{extra}",
        extra = if global_tags.is_empty() {
            String::new()
        } else {
            format!(",{}", &global_tags[2..])
        }
    );

    use std::fmt::Write;

    // Counter: stream connection count
    let _ = writeln!(buf, "{prefix}.stream.count:1|c{tags}");

    // Timer: stream duration (ms)
    let _ = writeln!(
        buf,
        "{prefix}.stream.duration_ms:{:.2}|ms{tags}",
        summary.duration_ms,
    );

    // Gauge: bytes sent/received
    let _ = writeln!(
        buf,
        "{prefix}.stream.bytes_sent:{}|g{tags}",
        summary.bytes_sent,
    );
    let _ = writeln!(
        buf,
        "{prefix}.stream.bytes_received:{}|g{tags}",
        summary.bytes_received,
    );
}

/// Resolve the StatsD hostname to an IP address. Uses the gateway's DNS cache
/// when available (pre-warmed, TTL-aware, stale-while-revalidate). Falls back
/// to `tokio::net::lookup_host` when no cache is present (tests / fallback).
async fn resolve_host(
    hostname: &str,
    port: u16,
    dns_cache: &Option<DnsCache>,
) -> Option<SocketAddr> {
    if let Some(cache) = dns_cache {
        match cache.resolve(hostname, None, None).await {
            Ok(ip) => return Some(SocketAddr::new(ip, port)),
            Err(e) => {
                warn!(
                    "statsd_logging: DNS cache resolution failed for '{hostname}': {e} — falling back to system DNS"
                );
            }
        }
    }

    // Fallback: direct lookup (tests or when DNS cache is unavailable).
    let addr_str = format!("{hostname}:{port}");
    match tokio::net::lookup_host(&addr_str).await {
        Ok(mut addrs) => addrs.next(),
        Err(e) => {
            warn!("statsd_logging: failed to resolve '{addr_str}': {e}");
            None
        }
    }
}

/// Bind a UDP socket whose address family matches the resolved endpoint.
async fn bind_and_connect(addr: SocketAddr) -> Option<UdpSocket> {
    let bind_addr = if addr.ip() == IpAddr::from([0u8; 16]) || addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("statsd_logging: failed to bind UDP socket: {e}");
            return None;
        }
    };
    if let Err(e) = socket.connect(addr).await {
        warn!("statsd_logging: failed to connect UDP socket to {addr}: {e}");
        return None;
    }
    Some(socket)
}

/// How often to re-resolve the StatsD hostname even when sends succeed. DNS is
/// also re-checked opportunistically on send failures.
const RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(60);

async fn flush_loop(
    mut receiver: mpsc::Receiver<MetricEntry>,
    cfg: StatsdConfig,
    dns_cache: Option<DnsCache>,
) {
    // Initial resolve. If it fails we still drain the channel so producers
    // don't backpressure the hot path — metrics are dropped until the DNS
    // situation improves on restart.
    let mut current_addr = match resolve_host(&cfg.hostname, cfg.port, &dns_cache).await {
        Some(addr) => addr,
        None => {
            warn!(
                "statsd_logging: could not resolve '{}:{}' — metrics will be lost",
                cfg.hostname, cfg.port
            );
            while receiver.recv().await.is_some() {}
            return;
        }
    };
    let mut socket = match bind_and_connect(current_addr).await {
        Some(s) => s,
        None => {
            while receiver.recv().await.is_some() {}
            return;
        }
    };
    let mut last_resolve = Instant::now();

    let mut buffer: Vec<MetricEntry> = Vec::with_capacity(cfg.max_batch_lines);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    timer.tick().await; // consume immediate first tick

    loop {
        // Opportunistic re-resolve. Stale DNS is the main reason StatsD
        // traffic silently goes into a black hole; 60s is a compromise
        // between reactivity and resolver load.
        if last_resolve.elapsed() >= RE_RESOLVE_INTERVAL
            && let Some(new_addr) = resolve_host(&cfg.hostname, cfg.port, &dns_cache).await
            && new_addr != current_addr
            && let Some(new_sock) = bind_and_connect(new_addr).await
        {
            current_addr = new_addr;
            socket = new_sock;
            last_resolve = Instant::now();
        } else if last_resolve.elapsed() >= RE_RESOLVE_INTERVAL {
            last_resolve = Instant::now();
        }

        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(entry) => {
                        buffer.push(entry);
                        if buffer.len() >= cfg.max_batch_lines {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&socket, &cfg, batch).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining entries and exit.
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&socket, &cfg, batch).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    send_batch(&socket, &cfg, batch).await;
                }
            }
        }
    }
}

async fn send_batch(socket: &UdpSocket, cfg: &StatsdConfig, batch: Vec<MetricEntry>) {
    let mut payload = String::with_capacity(batch.len() * 128);
    for entry in &batch {
        match entry {
            MetricEntry::Http(summary) => {
                format_http_metrics(summary, &cfg.prefix, &cfg.global_tags, &mut payload);
            }
            MetricEntry::Stream(summary) => {
                format_stream_metrics(summary, &cfg.prefix, &cfg.global_tags, &mut payload);
            }
        }
    }

    if payload.is_empty() {
        return;
    }

    // StatsD servers accept newline-delimited metrics in a single UDP packet.
    // Max safe UDP payload is ~1472 bytes (MTU 1500 - IP/UDP headers).
    // Split into chunks if payload exceeds that.
    const MAX_UDP_PAYLOAD: usize = 1472;

    if payload.len() <= MAX_UDP_PAYLOAD {
        if let Err(e) = socket.send(payload.as_bytes()).await {
            warn!("statsd_logging: failed to send metrics: {e}");
        }
    } else {
        // Split on newline boundaries, packing as many lines per packet as fit.
        let mut chunk = String::with_capacity(MAX_UDP_PAYLOAD);
        for line in payload.lines() {
            // +1 for the newline we'll re-add
            if !chunk.is_empty() && chunk.len() + line.len() + 1 > MAX_UDP_PAYLOAD {
                if let Err(e) = socket.send(chunk.as_bytes()).await {
                    warn!("statsd_logging: failed to send metrics chunk: {e}");
                }
                chunk.clear();
            }
            if !chunk.is_empty() {
                chunk.push('\n');
            }
            chunk.push_str(line);
        }
        if !chunk.is_empty()
            && let Err(e) = socket.send(chunk.as_bytes()).await
        {
            warn!("statsd_logging: failed to send metrics chunk: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_tag_value_replaces_delimiters() {
        // StatsD/DogStatsD tag delimiters must not survive in tag values.
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
        // The motivating case: an operator-controlled proxy name that
        // contains several delimiters should be fully neutralized.
        assert_eq!(
            sanitize_tag_value("evil,|#:proxy"),
            "evil____proxy",
            "delimiter injection must not survive sanitization"
        );
    }
}
