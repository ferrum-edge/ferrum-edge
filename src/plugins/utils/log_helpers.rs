use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use url::{Host, Url};

use super::response_body::{BoundedReadError, measure_response_body_bounded};
use super::{
    BatchConfig, MAX_BATCH_FLUSH_INTERVAL_MS, MAX_BATCH_RETRIES, MAX_BATCH_RETRY_DELAY_MS,
    MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, RetryPolicy,
};

/// Hard cap on acknowledgement bodies drained from HTTP log sinks.
///
/// Sink ACKs are typically tiny; this bound exists only so a misbehaving
/// collector cannot stream an unbounded body into the flush worker. Chunks are
/// counted and discarded — never buffered or logged. Matches the notification
/// dispatch drain and Loki's delivery path.
pub const HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Maximum time spent draining one sink response body after headers arrive.
///
/// Separate from the plugin HTTP client's overall request timeout so a stalled
/// acknowledgement cannot pin a flush worker for the full request budget.
pub const HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Result of a bounded, discard-only drain of an HTTP batch-response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBatchDrainOutcome {
    /// Body reached EOF within the byte cap.
    Complete(u64),
    /// Advertised `Content-Length` or streamed total exceeded the hard cap.
    LimitExceeded,
    /// Drain did not finish before [`HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT`].
    Timeout,
    /// Underlying byte stream failed (truncated/malformed framing, reset, etc.).
    TransportFailure,
}

impl HttpBatchDrainOutcome {
    pub fn diagnostic(self) -> &'static str {
        match self {
            Self::Complete(_) => "response body drained",
            Self::LimitExceeded => "response body exceeded the drain limit",
            Self::Timeout => "response body drain timed out",
            Self::TransportFailure => "response body drain had a transport failure",
        }
    }
}

/// Discard a sink response body under the shared hard cap and drain timeout.
///
/// Used by [`handle_http_batch_response`] and by Loki's delivery classifier so
/// every HTTP log sink shares one keep-alive-safe drain contract.
///
/// After a complete EOF drain the reqwest/hyper client returns the socket to
/// its idle pool asynchronously. Log-sink flush workers (especially
/// `batch_size = 1`) may start the next POST on the same task immediately;
/// yielding once after EOF lets that pool reclaim run before the next
/// checkout. This is cold-path sink I/O only — it does not change status,
/// retry, cap, or timeout semantics.
pub async fn drain_http_batch_response_body(response: reqwest::Response) -> HttpBatchDrainOutcome {
    if response
        .content_length()
        .is_some_and(|length| length > HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES as u64)
    {
        return HttpBatchDrainOutcome::LimitExceeded;
    }
    match tokio::time::timeout(
        HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT,
        measure_response_body_bounded(response, HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES),
    )
    .await
    {
        Err(_) => HttpBatchDrainOutcome::Timeout,
        Ok(Ok(bytes)) => {
            // Response (and its pooled connection) were dropped when the
            // measure future completed; give the idle-pool reclaim a turn
            // before the caller issues another request on this client.
            tokio::task::yield_now().await;
            HttpBatchDrainOutcome::Complete(bytes)
        }
        Ok(Err(BoundedReadError::LimitExceeded { .. })) => HttpBatchDrainOutcome::LimitExceeded,
        Ok(Err(BoundedReadError::Stream(_))) => HttpBatchDrainOutcome::TransportFailure,
    }
}

/// Sink-specific defaults and minima for shared batch admission.
///
/// Maxima for batch size, buffer capacity, retries, and retry delay are shared
/// constants ([`MAX_BATCH_SIZE`], [`MAX_BUFFER_CAPACITY`],
/// [`MAX_BATCH_FLUSH_INTERVAL_MS`], [`MAX_BATCH_RETRIES`], and
/// [`MAX_BATCH_RETRY_DELAY_MS`]) so validation and builder cannot drift.
#[derive(Clone, Copy)]
pub struct BatchConfigDefaults {
    pub batch_size_key: &'static str,
    pub batch_size: u64,
    pub flush_interval_ms: u64,
    pub min_flush_interval_ms: u64,
    pub buffer_capacity: u64,
    pub max_retries: u64,
    pub retry_delay_ms: u64,
    /// Minimum admitted `retry_delay_ms` when the field is present.
    ///
    /// StatsD (and other sinks that default delay to `0`) use `0`. Loki / WS
    /// require at least `1` so a configured delay cannot silently become a
    /// busy-loop.
    pub min_retry_delay_ms: u64,
}

/// Admit one optional unsigned integer config field.
///
/// Absent keys resolve to `default`. Present keys must be JSON unsigned
/// integers inside `[minimum, maximum]` — wrong scalar types and out-of-range
/// values are rejected with field-specific errors (no silent clamp/replace).
fn admit_batch_u64(
    config: &Value,
    plugin_name: &'static str,
    key: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, String> {
    match config.get(key) {
        None => Ok(default),
        Some(value) => {
            let Some(parsed) = value.as_u64() else {
                return Err(format!(
                    "{plugin_name}: '{key}' must be an unsigned integer"
                ));
            };
            if !(minimum..=maximum).contains(&parsed) {
                return Err(format!(
                    "{plugin_name}: '{key}' must be between {minimum} and {maximum}"
                ));
            }
            Ok(parsed)
        }
    }
}

/// Resolve shared batch fields using the same bounds as [`validate_batch_config`].
fn admit_batch_fields(
    config: &Value,
    plugin_name: &'static str,
    defaults: BatchConfigDefaults,
) -> Result<(usize, u64, usize, u64, u64), String> {
    let batch_size = admit_batch_u64(
        config,
        plugin_name,
        defaults.batch_size_key,
        defaults.batch_size,
        1,
        MAX_BATCH_SIZE as u64,
    )? as usize;
    let flush_interval_ms = admit_batch_u64(
        config,
        plugin_name,
        "flush_interval_ms",
        defaults.flush_interval_ms,
        defaults.min_flush_interval_ms,
        MAX_BATCH_FLUSH_INTERVAL_MS,
    )?;
    let buffer_capacity = admit_batch_u64(
        config,
        plugin_name,
        "buffer_capacity",
        defaults.buffer_capacity,
        1,
        MAX_BUFFER_CAPACITY as u64,
    )? as usize;
    let max_retries = admit_batch_u64(
        config,
        plugin_name,
        "max_retries",
        defaults.max_retries,
        0,
        MAX_BATCH_RETRIES,
    )?;
    let retry_delay_ms = admit_batch_u64(
        config,
        plugin_name,
        "retry_delay_ms",
        defaults.retry_delay_ms,
        defaults.min_retry_delay_ms,
        MAX_BATCH_RETRY_DELAY_MS,
    )?;
    Ok((
        batch_size,
        flush_interval_ms,
        buffer_capacity,
        max_retries,
        retry_delay_ms,
    ))
}

/// Build a [`BatchConfig`] from plugin JSON using the shared admission contract.
///
/// Callers that already ran [`validate_batch_config`] still go through the same
/// resolver so builder and validator cannot drift. Invalid present values are
/// errors — never silently clamped or replaced with defaults.
pub fn build_batch_config(
    config: &Value,
    plugin_name: &'static str,
    defaults: BatchConfigDefaults,
) -> Result<BatchConfig, String> {
    let (batch_size, flush_interval_ms, buffer_capacity, max_retries, retry_delay_ms) =
        admit_batch_fields(config, plugin_name, defaults)?;

    Ok(BatchConfig {
        batch_size,
        flush_interval: Duration::from_millis(flush_interval_ms),
        buffer_capacity,
        // Plugin config remains `max_retries`; RetryPolicy stores total
        // attempts, so add the initial try here. These loggers use a constant
        // inter-attempt delay (no backoff/jitter), so build a fixed policy.
        retry: RetryPolicy::fixed(
            max_retries.saturating_add(1) as u32,
            Duration::from_millis(retry_delay_ms),
        ),
        plugin_name,
    })
}

/// Authoritative type + range admission for shared batching fields.
///
/// Rejects wrong scalar types and every numeric value outside the sink's
/// documented minima/maxima (including values the historical builder would have
/// silently clamped). Sink-specific keys and minima come from `defaults`;
/// shared maxima are [`MAX_BATCH_SIZE`], [`MAX_BUFFER_CAPACITY`],
/// [`MAX_BATCH_FLUSH_INTERVAL_MS`], [`MAX_BATCH_RETRIES`], and
/// [`MAX_BATCH_RETRY_DELAY_MS`].
pub fn validate_batch_config(
    config: &Value,
    plugin_name: &'static str,
    defaults: BatchConfigDefaults,
) -> Result<(), String> {
    admit_batch_fields(config, plugin_name, defaults).map(|_| ())
}

pub fn parse_http_endpoint(
    config: &Value,
    plugin_name: &'static str,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(String, String), String> {
    let endpoint_url = config["endpoint_url"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("{plugin_name}: 'endpoint_url' is required — logs will have nowhere to send")
        })?
        .to_string();

    let parsed_url = Url::parse(&endpoint_url)
        .map_err(|error| format!("{plugin_name}: invalid 'endpoint_url': {error}"))?;

    match parsed_url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "{plugin_name}: 'endpoint_url' must use http:// or https:// (got '{scheme}')"
            ));
        }
    }

    if !has_non_empty_authority(&endpoint_url) {
        return Err(format!(
            "{plugin_name}: 'endpoint_url' must include a hostname or IP address"
        ));
    }

    let host = parsed_url.host().ok_or_else(|| {
        format!("{plugin_name}: 'endpoint_url' must include a hostname or IP address")
    })?;
    let hostname = match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };

    screen_endpoint_ip_policy(plugin_name, &host, backend_allow_ips)?;

    Ok((endpoint_url, hostname))
}

/// SSRF / internal-address screening for a configured log-sink `endpoint_url`,
/// using the gateway's outbound IP policy (`FERRUM_BACKEND_ALLOW_IPS`).
///
/// Logger sinks POST `TransactionSummary` / `StreamTransactionSummary` batches
/// (client IPs, consumer/auth metadata) plus any operator `custom_headers`
/// (which may carry the sink's bearer token) on every flush, so a mistyped or
/// copy-pasted endpoint that points at an internal address — loopback,
/// link-local / cloud-metadata (`169.254.0.0/16`, `fe80::/10`), unique-local
/// (`fc00::/7`), or RFC1918 — can exfiltrate that data to an unintended host.
///
/// This mirrors how the gateway screens every other outbound connection: a
/// **literal-IP** endpoint host is checked with the same
/// [`BackendEgressPolicy`](crate::config::BackendEgressPolicy) used by the
/// proxy's `DnsCacheResolver`. Under the default policy, loopback and RFC1918
/// sinks are still allowed (a local agent or in-cluster collector reached by IP
/// is a legitimate common case), but cloud-metadata / link-local / multicast /
/// unspecified targets are rejected by the dangerous-range baseline; operators
/// who set `FERRUM_BACKEND_ALLOW_IPS=public` get private egress forbidden here
/// too, closing the SSRF gap consistently across the gateway.
///
/// Only literal-IP hosts are screened here. A `Host::Domain` can still resolve
/// to an internal address, but construction-time validation cannot know that;
/// at send time the shared `PluginHttpClient`'s `DnsCacheResolver` applies the
/// same policy to the resolved IP.
fn screen_endpoint_ip_policy(
    plugin_name: &'static str,
    host: &Host<&str>,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    let ip = match host {
        Host::Ipv4(address) => std::net::IpAddr::V4(*address),
        Host::Ipv6(address) => std::net::IpAddr::V6(*address),
        // Domain hosts are resolved (and IP-policy screened) at send time.
        Host::Domain(_) => return Ok(()),
    };

    match backend_allow_ips.deny_reason(&ip) {
        None => Ok(()),
        Some(reason) => Err(format!(
            "{plugin_name}: 'endpoint_url' address {ip} is blocked by the backend egress \
             policy ({reason}); refusing to send log data there. Adjust \
             FERRUM_BACKEND_ALLOW_IPS / FERRUM_BACKEND_ALLOW_CIDRS or point the sink at an \
             allowed address."
        )),
    }
}

/// Screen the literal-IP host of a parsed config URL against the backend egress
/// policy, for plugins that build a dedicated client or parse their own URL
/// rather than dialing through the policy-screened shared client (e.g.
/// `api_chargeback_sink` ClickHouse, `spec_expose`). Hostnames are screened at
/// resolution time by the DNS cache; `field` names the config key for the
/// error message.
pub fn screen_url_host_egress(
    plugin_name: &str,
    field: &str,
    url: &Url,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    let ip = match url.host() {
        Some(Host::Ipv4(address)) => std::net::IpAddr::V4(address),
        Some(Host::Ipv6(address)) => std::net::IpAddr::V6(address),
        // Domain / no host → screened at resolution time by the DNS cache.
        _ => return Ok(()),
    };
    match backend_allow_ips.deny_reason(&ip) {
        None => Ok(()),
        Some(reason) => Err(format!(
            "{plugin_name}: '{field}' address {ip} is blocked by the backend egress policy \
             ({reason}); adjust FERRUM_BACKEND_ALLOW_IPS / FERRUM_BACKEND_ALLOW_CIDRS or point \
             it at an allowed address."
        )),
    }
}

pub fn parse_custom_headers(
    config: &Value,
    plugin_name: &'static str,
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let mut custom_headers = Vec::new();
    let Some(custom_headers_value) = config.get("custom_headers") else {
        return Ok(custom_headers);
    };

    let map = custom_headers_value
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: 'custom_headers' must be an object"))?;
    for (key, value) in map {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: custom_headers['{key}'] must be a string"))?;
        let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
            format!("{plugin_name}: invalid custom_headers name '{key}': {error}")
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|error| {
            format!("{plugin_name}: invalid custom_headers value for '{key}': {error}")
        })?;
        custom_headers.retain(|(existing, _)| *existing != header_name);
        custom_headers.push((header_name, header_value));
    }

    Ok(custom_headers)
}

fn has_non_empty_authority(endpoint_url: &str) -> bool {
    let Some((_, after_scheme)) = endpoint_url.split_once(':') else {
        return false;
    };
    let Some(authority_and_path) = after_scheme.strip_prefix("//") else {
        return false;
    };
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());

    authority_end > 0
}

/// Classify an HTTP batch-delivery response after a bounded body drain.
///
/// Status semantics are unchanged from the historical helper:
/// - 2xx succeeds (drain is best-effort so a committed ACK is never retried)
/// - non-408/429 4xx discards without retry
/// - 408/429/5xx (and other non-success statuses) remain retryable
///
/// Every `Ok(response)` path asynchronously drains/discards the body under
/// [`HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES`] and
/// [`HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT`] so HTTP/1.1 keep-alive connections can
/// be reused. Peer-controlled body bytes are never logged or retained.
pub async fn handle_http_batch_response(
    plugin_label: &str,
    entry_count: usize,
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<(), String> {
    match result {
        Ok(response) => {
            let status = response.status();
            let drain = drain_http_batch_response_body(response).await;
            classify_http_batch_response(plugin_label, entry_count, status, drain)
        }
        Err(error) => Err(format!("{plugin_label} batch failed: {error}")),
    }
}

fn classify_http_batch_response(
    plugin_label: &str,
    entry_count: usize,
    status: reqwest::StatusCode,
    drain: HttpBatchDrainOutcome,
) -> Result<(), String> {
    if status.is_success() {
        if !matches!(drain, HttpBatchDrainOutcome::Complete(_)) {
            tracing::warn!(
                "{plugin_label}: successful batch response drain incomplete ({}); connection may not be reused",
                drain.diagnostic(),
            );
        }
        return Ok(());
    }

    if status.is_client_error()
        && status != reqwest::StatusCode::REQUEST_TIMEOUT
        && status != reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        tracing::warn!(
            "{plugin_label} batch discarded due to {} response ({} entries lost); {}",
            status,
            entry_count,
            drain.diagnostic(),
        );
        return Ok(());
    }

    Err(format!(
        "{plugin_label} batch failed with status {status}; {}",
        drain.diagnostic()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::config::{BackendAllowIps, BackendEgressPolicy};

    // Screen with the SSRF-hardening policy (forbid private egress).
    fn parse_public(url: &str) -> Result<(String, String), String> {
        parse_http_endpoint(
            &json!({ "endpoint_url": url }),
            "http_logging",
            &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
        )
    }

    // Screen with a fully-unrestricted policy (no mode filter, no baseline).
    fn parse_both(url: &str) -> Result<(String, String), String> {
        parse_http_endpoint(
            &json!({ "endpoint_url": url }),
            "http_logging",
            &BackendEgressPolicy::unrestricted(),
        )
    }

    #[test]
    fn parse_http_endpoint_accepts_public_host_and_ip() {
        let (url, host) = parse_public("https://logs.example.com/ingest").expect("public host ok");
        assert_eq!(url, "https://logs.example.com/ingest");
        assert_eq!(host, "logs.example.com");

        let (_, host) = parse_public("http://93.184.216.34:8080").expect("public IP ok");
        assert_eq!(host, "93.184.216.34");
    }

    #[test]
    fn parse_http_endpoint_public_policy_rejects_loopback_ip() {
        let err = parse_public("http://127.0.0.1:9000/ingest").expect_err("loopback must reject");
        assert!(
            err.contains("blocked by the backend egress policy"),
            "got: {err}"
        );
        assert!(err.contains("public"), "got: {err}");
    }

    #[test]
    fn parse_http_endpoint_public_policy_rejects_cloud_metadata_ip() {
        // 169.254.169.254 is the classic cloud-metadata SSRF target.
        let err = parse_public("http://169.254.169.254/latest/meta-data/")
            .expect_err("link-local / metadata must reject");
        assert!(
            err.contains("blocked by the backend egress policy"),
            "got: {err}"
        );
        assert!(err.contains("169.254.169.254"), "got: {err}");
    }

    #[test]
    fn parse_http_endpoint_public_policy_rejects_rfc1918_and_ipv6_internal() {
        assert!(parse_public("http://10.0.0.5/log").is_err());
        assert!(parse_public("http://192.168.1.10:514").is_err());
        assert!(parse_public("https://172.16.4.4").is_err());
        // IPv6 loopback and unique-local.
        assert!(parse_public("http://[::1]:9000").is_err());
        assert!(parse_public("http://[fc00::1]/log").is_err());
        // IPv6 link-local.
        assert!(parse_public("http://[fe80::1]/log").is_err());
    }

    #[test]
    fn parse_http_endpoint_unrestricted_policy_allows_any_sink() {
        // A fully-unrestricted policy (mode `both`, baseline off) allows every
        // address, including the local-sink case (a local agent / sidecar
        // reached by loopback or RFC1918 IP) and even cloud-metadata. NOTE: the
        // *production* default keeps the dangerous-range baseline ON, so
        // 169.254.169.254 is rejected by default — see the config unit tests.
        let (url, host) = parse_both("http://127.0.0.1:9000/ingest").expect("loopback allowed");
        assert_eq!(url, "http://127.0.0.1:9000/ingest");
        assert_eq!(host, "127.0.0.1");
        assert!(parse_both("http://10.0.0.5/log").is_ok());
        assert!(parse_both("http://169.254.169.254/").is_ok());
    }

    #[test]
    fn parse_http_endpoint_private_policy_rejects_public_ip() {
        // `Private` is the mirror case: a public endpoint is blocked.
        let err = parse_http_endpoint(
            &json!({ "endpoint_url": "https://93.184.216.34/ingest" }),
            "http_logging",
            &BackendEgressPolicy::from_allow_ips(BackendAllowIps::Private),
        )
        .expect_err("public IP must reject under Private policy");
        assert!(
            err.contains("blocked by the backend egress policy"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_http_endpoint_domain_is_not_screened_at_construction() {
        // A domain that *resolves* internally cannot be screened here; that is
        // handled at send time by the DnsCache IP policy. `localhost` is a
        // domain host, so even the strict `Public` policy passes it through at
        // config time.
        let (_, host) = parse_public("http://localhost:9000/ingest").expect("domain host ok");
        assert_eq!(host, "localhost");
    }

    #[test]
    fn parse_http_endpoint_still_enforces_scheme_and_authority() {
        assert!(parse_public("ftp://logs.example.com").is_err());
        assert!(parse_public("https:///no-host").is_err());
        // Scheme/authority checks run regardless of IP policy.
        assert!(parse_both("ftp://logs.example.com").is_err());
    }
}
