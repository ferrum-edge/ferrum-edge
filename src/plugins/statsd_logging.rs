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

use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, SummaryLogEntry,
    UDP_RE_RESOLVE_INTERVAL, bind_connected_udp_socket, build_batch_config, resolve_udp_endpoint,
};
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

type MetricEntry = SummaryLogEntry;

#[derive(Clone)]
struct StatsdFlushConfig {
    hostname: String,
    port: u16,
    prefix: String,
    global_tags: String,
    dns_cache: Option<DnsCache>,
}

struct StatsdFlushState {
    socket: Option<tokio::net::UdpSocket>,
    current_addr: Option<SocketAddr>,
    last_resolve: Instant,
}

pub struct StatsdLogging {
    logger: BatchingLogger<MetricEntry>,
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
        let global_tags = {
            let mut pairs: Vec<String> = if let Some(tags_obj) = config["global_tags"].as_object() {
                tags_obj
                    .iter()
                    .map(|(key, value)| format!("{key}:{}", value.as_str().unwrap_or("")))
                    .collect()
            } else {
                Vec::new()
            };
            if ns != crate::config::types::DEFAULT_NAMESPACE
                && !pairs.iter().any(|pair| pair.starts_with("namespace:"))
            {
                pairs.push(format!("namespace:{ns}"));
            }
            if pairs.is_empty() {
                String::new()
            } else {
                format!("|#{}", pairs.join(","))
            }
        };

        let flush_config = StatsdFlushConfig {
            hostname: host.clone(),
            port: port as u16,
            prefix,
            global_tags,
            dns_cache: http_client.dns_cache().cloned(),
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
        self.logger.try_send(summary.into());
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(summary.into());
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
            format!(",{}", &global_tags[2..])
        }
    );

    use std::fmt::Write;
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

    let tags = format!(
        "|#protocol:{protocol},proxy:{proxy_tag},error:{has_error},cause:{cause_tag},direction:{direction_tag}{extra}",
        extra = if global_tags.is_empty() {
            String::new()
        } else {
            format!(",{}", &global_tags[2..])
        }
    );

    use std::fmt::Write;
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

async fn send_batch(
    cfg: &StatsdFlushConfig,
    state: &Mutex<StatsdFlushState>,
    batch: Vec<MetricEntry>,
) -> Result<(), String> {
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
