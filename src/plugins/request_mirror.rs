//! Request Mirror Plugin
//!
//! Duplicates live proxy traffic to a secondary destination for shadow testing,
//! validation, or migration checks without affecting client responses. Mirrored
//! requests are fire-and-forget — the gateway does not wait for the mirror
//! target's response and never propagates mirror failures to the client.
//!
//! Similar to APISIX's `proxy-mirror` plugin.
//!
//! ## How it works
//!
//! During the `before_proxy` phase (after all request transforms), the plugin
//! captures the request method, path, query string, headers, and optionally the
//! body, then spawns an async task to replay the request against the configured
//! mirror destination. The main request proceeds immediately — mirror latency
//! has zero impact on client response time.
//!
//! Outbound mirror headers cross the same canonical secondary-request boundary
//! as primary backend dispatch (Connection-listed hop-by-hop, Trailer, framing,
//! Ferrum request-only markers, and proxy-owned `X-Forwarded-*`). Client `Host`
//! is omitted so authority comes from the mirror URL; native gRPC content-types
//! re-synthesise `te: trailers`. The mirror request-target prefers the original
//! raw query (after the same auth credential strips the primary backend uses)
//! so duplicate keys, order, flags, `+`, percent escapes, and encoded bytes
//! match the primary contract.
//!
//! The mirror request uses the gateway's shared `PluginHttpClient`, which means
//! it inherits the gateway's DNS cache, connection pool keepalive, and TLS
//! settings (CA bundle, skip-verify).
//!
//! ## Mirror response logging
//!
//! The spawned task captures mirror response metadata (status code, response
//! size, latency) and writes it to a `tokio::sync::watch` channel. Transaction
//! logging consumes that channel from a separate detached task, so all logging
//! plugins receive mirror metadata without delaying the client response.
//!
//! Mirror timeout defaults to the proxy's `backend_read_timeout_ms`, ensuring
//! shadow requests respect the same timeout budget as the real backend call.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "mirror_host": "mirror.example.com",
//!   "mirror_port": 8080,
//!   "mirror_protocol": "https",
//!   "mirror_path": "/shadow",
//!   "percentage": 100.0,
//!   "mirror_request_body": true,
//!   "max_response_body_bytes": 1048576
//! }
//! ```
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `mirror_host` | string | **(required)** | Hostname or IP of the mirror target |
//! | `mirror_port` | u16 | 80 (http) / 443 (https) | Port of the mirror target |
//! | `mirror_protocol` | string | `"http"` | `"http"` or `"https"` |
//! | `mirror_path` | string | (none) | Override the request path for the mirror. When unset, the backend-effective authorized path is used if backend-path policy is active; otherwise the original request path is used |
//! | `percentage` | f64 | `100.0` | Percentage of requests to mirror (0.0–100.0) |
//! | `mirror_request_body` | bool | `true` | Whether to include the request body in the mirror request |
//! | `max_response_body_bytes` | u64 | `1048576` (1 MiB) | Cap on bytes read from a mirror response when sizing it (only consulted when the response has no `content-length`). Streaming aborts as soon as the limit is crossed; mirror task discards the bytes after sizing. |
//! | `max_in_flight` | u64 | `256` | Maximum concurrent detached mirror tasks per plugin instance (minimum 1). Requests that arrive while every permit is in use are still served normally but are not mirrored — saturation drops the new mirror attempt without affecting the primary request. |

use async_trait::async_trait;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;
use url::{Host, form_urlencoded};

use super::utils::response_body::{
    BoundedReadError, measure_response_body_bounded, parse_max_response_body_bytes,
};
use super::{MirrorResponseMeta, Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::proxy::headers::{
    SecondaryRequestHostPolicy, filter_secondary_request_headers,
    synthesize_grpc_te_trailers_if_needed,
};

/// Default cap on the size of mirror response bodies the gateway is willing
/// to read. The body is discarded — only its length is reported in mirror
/// metadata — so 1 MiB is plenty for the size-derivation use case while still
/// protecting against a misbehaving mirror endpoint streaming an unbounded
/// response over a fire-and-forget task.
const DEFAULT_MIRROR_MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_IN_FLIGHT_MIRRORS: usize = 256;
const LOAD_TESTING_TRIGGER_HEADER: &str = "x-loadtesting-key";
const LOAD_TESTING_FANOUT_HEADER: &str = "x-loadtesting-fanout";

fn strip_query_params(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

pub struct RequestMirror {
    http_client: PluginHttpClient,
    mirror_host: String,
    mirror_port: u16,
    mirror_protocol: String,
    mirror_path: Option<String>,
    percentage: f64,
    mirror_request_body: bool,
    /// Maximum number of bytes to read from the mirror response when deriving
    /// `mirror_response_size_bytes`. The body is discarded after measurement,
    /// so this only bounds memory usage for fire-and-forget mirror tasks
    /// against misbehaving sinks. Used only when the mirror response has no
    /// `content-length` header (the CL fast path doesn't read the body).
    max_response_body_bytes: usize,
    mirror_hostname: Option<String>,
    /// Monotonic counter for deterministic percentage sampling without rand.
    /// Every Nth request is mirrored based on the percentage threshold.
    request_counter: AtomicU64,
    /// Bounds concurrent mirror tasks to prevent unbounded background work.
    mirror_in_flight: Arc<tokio::sync::Semaphore>,
}

impl RequestMirror {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("request_mirror: config must be an object".to_string());
        }

        let raw_mirror_host = optional_string(config, "mirror_host")?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "request_mirror: 'mirror_host' is required".to_string())?
            .to_ascii_lowercase();
        let (mirror_host, mirror_hostname) = parse_mirror_host(&raw_mirror_host)?;

        let mirror_protocol = optional_string(config, "mirror_protocol")?
            .unwrap_or_else(|| "http".to_string())
            .to_ascii_lowercase();

        if mirror_protocol != "http" && mirror_protocol != "https" {
            return Err(format!(
                "request_mirror: 'mirror_protocol' must be 'http' or 'https' (got '{}')",
                mirror_protocol
            ));
        }

        let default_port: u16 = if mirror_protocol == "https" { 443 } else { 80 };
        let mirror_port = optional_u64(config, "mirror_port")?
            .map(|p| {
                if p == 0 || p > 65535 {
                    Err(format!(
                        "request_mirror: 'mirror_port' must be 1–65535 (got {})",
                        p
                    ))
                } else {
                    Ok(p as u16)
                }
            })
            .transpose()?
            .unwrap_or(default_port);

        let mirror_path = optional_string(config, "mirror_path")?.filter(|s| !s.is_empty());
        if let Some(path) = &mirror_path
            && !path.starts_with('/')
        {
            return Err("request_mirror: 'mirror_path' must start with '/'".to_string());
        }

        let percentage = optional_f64(config, "percentage")?.unwrap_or(100.0);
        if !(0.0..=100.0).contains(&percentage) {
            return Err(format!(
                "request_mirror: 'percentage' must be 0.0–100.0 (got {})",
                percentage
            ));
        }

        let mirror_request_body = optional_bool(config, "mirror_request_body")?.unwrap_or(true);

        let max_in_flight = optional_u64(config, "max_in_flight")?
            .map(|v| {
                if v == 0 {
                    Err("request_mirror: 'max_in_flight' must be >= 1".to_string())
                } else {
                    usize::try_from(v).map_err(|_| {
                        "request_mirror: 'max_in_flight' is too large for this platform".to_string()
                    })
                }
            })
            .transpose()?
            .unwrap_or(DEFAULT_MAX_IN_FLIGHT_MIRRORS);

        let max_response_body_bytes = parse_max_response_body_bytes(
            config,
            "request_mirror",
            "max_response_body_bytes",
            DEFAULT_MIRROR_MAX_RESPONSE_BODY_BYTES,
        )?;

        Ok(Self {
            http_client,
            mirror_host,
            mirror_port,
            mirror_protocol,
            mirror_path,
            percentage,
            mirror_request_body,
            max_response_body_bytes,
            mirror_hostname,
            request_counter: AtomicU64::new(0),
            mirror_in_flight: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
        })
    }

    /// Build the full mirror URL from the configured or gateway-selected path.
    ///
    /// Prefer the effective raw query string (original wire query after the same
    /// auth credential strips primary dispatch applies) so duplicate keys,
    /// ordering, flags, empty values, `+`, percent escapes, and non-ASCII
    /// encoded bytes survive. Fall back to the materialised `query_params` map
    /// only when no raw query is available (tests / already-decoded contexts).
    fn build_mirror_url(
        &self,
        original_path: &str,
        raw_query: Option<&str>,
        query_params: &HashMap<String, String>,
    ) -> String {
        let path = self.mirror_path.as_deref().unwrap_or(original_path);

        let mut url = String::with_capacity(
            self.mirror_protocol.len() + 3 + self.mirror_host.len() + 1 + 5 + path.len(),
        );
        url.push_str(&self.mirror_protocol);
        url.push_str("://");
        url.push_str(&self.mirror_host);
        url.push(':');
        let _ = write!(&mut url, "{}", self.mirror_port);
        url.push_str(path);

        if let Some(query) = raw_query {
            // `Some("")` is authoritative: an auth strip may have removed the
            // entire raw query, so falling back to the materialised map here
            // would reintroduce the credential.
            if !query.is_empty() {
                url.push('?');
                url.push_str(query);
            }
        } else if !query_params.is_empty() {
            url.push('?');
            let encoded: String = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query_params.iter())
                .finish();
            url.push_str(&encoded);
        }

        url
    }

    /// Should this request be mirrored (percentage sampling)?
    ///
    /// Uses a monotonic counter for deterministic sampling without external RNG.
    /// For a percentage of N%, every request where `(counter % 1000) < (N * 10)`
    /// is mirrored. This gives 0.1% granularity and even distribution.
    fn should_mirror(&self) -> bool {
        if self.percentage >= 100.0 {
            return true;
        }
        if self.percentage <= 0.0 {
            return false;
        }
        let count = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let threshold = (self.percentage * 10.0) as u64; // 0.1% granularity
        (count % 1000) < threshold
    }
}

fn parse_mirror_host(raw_host: &str) -> Result<(String, Option<String>), String> {
    let host = raw_host.trim();
    if host.is_empty() {
        return Err("request_mirror: 'mirror_host' is required".to_string());
    }
    if host
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
        || host.contains("://")
        || host.contains(['/', '?', '#', '@'])
    {
        return Err(
            "request_mirror: 'mirror_host' must be a hostname or IP address without scheme, path, query, fragment, or credentials"
                .to_string(),
        );
    }

    let bracketed = host.starts_with('[') || host.ends_with(']');
    let host_for_ip = if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        inner
    } else {
        host
    };

    if let Ok(ip) = host_for_ip.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(ip) => (ip.to_string(), None),
            std::net::IpAddr::V6(ip) => (format!("[{ip}]"), None),
        });
    }

    if bracketed || host.contains(':') {
        return Err(
            "request_mirror: 'mirror_host' must not include brackets or a port unless it is an IPv6 literal"
                .to_string(),
        );
    }

    match Host::parse(host) {
        Ok(Host::Domain(domain)) if !domain.is_empty() => {
            let hostname = domain.to_ascii_lowercase();
            Ok((hostname.clone(), Some(hostname)))
        }
        _ => {
            Err("request_mirror: 'mirror_host' must be a valid hostname or IP address".to_string())
        }
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a boolean")),
    }
}

fn optional_f64(config: &Value, key: &str) -> Result<Option<f64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| format!("request_mirror: '{key}' must be a number")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a number")),
    }
}

fn optional_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("request_mirror: '{key}' must be a string")),
    }
}

fn optional_u64(config: &Value, key: &str) -> Result<Option<u64>, String> {
    match config.get(key) {
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("request_mirror: '{key}' must be an unsigned integer")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "request_mirror: '{key}' must be an unsigned integer"
        )),
    }
}

#[async_trait]
impl Plugin for RequestMirror {
    fn name(&self) -> &str {
        "request_mirror"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_MIRROR
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.mirror_request_body
    }

    fn should_buffer_request_body(&self, _ctx: &RequestContext) -> bool {
        self.mirror_request_body
    }

    fn needs_request_body_bytes(&self) -> bool {
        self.mirror_request_body
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.mirror_hostname.iter().cloned().collect()
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx
            .metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str)
            == Some("true")
        {
            return PluginResult::Continue;
        }
        if !self.should_mirror() {
            return PluginResult::Continue;
        }

        // When backend-path policy is active, mirror the exact path that passed
        // final authorization. Falling back to the ordinary client path keeps
        // the established behavior for proxies without that policy boundary.
        let mirror_path = ctx.authorized_backend_path().unwrap_or(&ctx.path);
        // Match primary backend query construction: start from the retained raw
        // query, then apply auth credential strips marked on the context.
        // Decoded `request_transformer` query-map mutations are intentionally
        // not re-serialized here — primary dispatch likewise keeps the raw
        // (auth-stripped) wire query.
        let query_map_was_transformed = ctx
            .metadata
            .contains_key(crate::proxy::QUERY_PARAMS_TRANSFORMED_METADATA_KEY);
        let effective_query = match ctx.raw_query_string() {
            Some(raw) => Some(crate::proxy::query_string_after_plugin_strips(ctx, raw)),
            // Query-transformer map mutations are intentionally not serialized
            // by primary dispatch. Preserve that contract even when the client
            // supplied no original query, while retaining the legacy map
            // fallback for synthetic/test contexts with no transform marker.
            None if query_map_was_transformed => Some(Cow::Borrowed("")),
            None => None,
        };
        let mirror_url =
            self.build_mirror_url(mirror_path, effective_query.as_deref(), &ctx.query_params);
        let method = ctx.method.clone();

        // Mirror destinations are an egress boundary just like the primary
        // backend. Apply the canonical secondary-request sanitizer (hop-by-hop,
        // Connection-listed, framing, proxy-owned forwarding identity, Host
        // strip) before any mirror-specific exclusions.
        let mut mirror_headers = filter_secondary_request_headers(
            headers,
            SecondaryRequestHostPolicy::Strip,
            &[LOAD_TESTING_TRIGGER_HEADER, LOAD_TESTING_FANOUT_HEADER],
        );
        // gRPC mirrors need `te: trailers` after the generic strip removes `te`.
        synthesize_grpc_te_trailers_if_needed(&mut mirror_headers);

        // Apply the operator-configured baggage strip
        // (`FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`) so mesh-internal identity
        // claims like `source.principal` don't leak to mirror analytics /
        // auditing services that the operator considers off-mesh.
        self.http_client
            .strip_egress_baggage_in_vec(&mut mirror_headers);

        // Strip query params before ANY logging of the mirror URL — it is built
        // from the original request's query string and can carry secrets
        // (`?access_token=`, `?api_key=`, `?sig=`). Computed here, before the
        // permit-exhaustion drop path, so every log site uses the stripped form
        // (the full `mirror_url` is still used for the actual mirror request).
        let mirror_url_for_log = strip_query_params(&mirror_url).to_string();

        let permit = match self.mirror_in_flight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(
                    "request_mirror: dropping mirror request for {} {} because max_in_flight limit was reached",
                    method, mirror_url_for_log
                );
                return PluginResult::Continue;
            }
        };

        // Capture request body if configured and available.
        // Uses the binary-safe `request_body_bytes` field (preserves non-UTF-8
        // payloads like gRPC protobuf), falling back to the UTF-8 metadata key.
        let body_bytes: Option<Vec<u8>> = if self.mirror_request_body {
            ctx.request_body_bytes
                .as_ref()
                .map(|b| b.to_vec())
                .or_else(|| {
                    ctx.metadata
                        .get("request_body")
                        .map(|b| b.as_bytes().to_vec())
                })
        } else {
            None
        };

        let mirror_timeout = ctx.matched_proxy.as_ref().and_then(|p| {
            if p.backend_read_timeout_ms > 0 {
                Some(Duration::from_millis(p.backend_read_timeout_ms))
            } else {
                None
            }
        });

        // Create a watch channel for the spawned task to send mirror response
        // metadata back. Transaction logging consumes it from another detached
        // task after the primary summary is available.
        let (tx, rx) = tokio::sync::watch::channel(None);
        ctx.mirror_result_rx = Some(rx);

        let http_client = self.http_client.clone();
        let max_response_body_bytes = self.max_response_body_bytes;

        // Fire-and-forget: spawn an async task to send the mirror request.
        // The main request proceeds immediately — mirror latency has zero
        // impact on client response time.
        tokio::spawn(async move {
            let _permit = permit;
            let start = std::time::Instant::now();

            let mut req_builder = match method.as_str() {
                "GET" => http_client.get().get(&mirror_url),
                "POST" => http_client.get().post(&mirror_url),
                "PUT" => http_client.get().put(&mirror_url),
                "DELETE" => http_client.get().delete(&mirror_url),
                "PATCH" => http_client.get().patch(&mirror_url),
                "HEAD" => http_client.get().head(&mirror_url),
                _ => http_client.get().request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                    &mirror_url,
                ),
            };

            if let Some(t) = mirror_timeout {
                req_builder = req_builder.timeout(t);
            }

            // Forward sanitized headers from the original (transformed) request.
            // The canonical secondary-request filter already removed hop-by-hop,
            // Connection-listed, framing, proxy-owned forwarding, Host, and the
            // reserved load-testing controls.
            for (key, value) in &mirror_headers {
                req_builder = req_builder.header(key.as_str(), value.as_str());
            }

            if let Some(body) = body_bytes {
                req_builder = req_builder.body(body);
            }

            // Route through `execute_redacted` so the mirror URL used in logs
            // and the returned error string is the query-stripped
            // `mirror_url_for_log`, never the full `mirror_url`. The full URL is
            // built from the original request's query params and can carry
            // credentials (`?access_token=...`, `?api_key=...`, `?sig=...`); a
            // raw `reqwest::Error` renders the full request URL in its Display
            // output, so stringifying it into `mirror_error` would leak those
            // secrets to every logging sink. `execute_redacted` reduces the
            // transport error to an `ErrorClass` plus the stripped URL.
            let (status_code, response_size, error_msg) = match http_client
                .execute_redacted(req_builder, "request_mirror", &mirror_url_for_log)
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Derive response size from content-length when available (avoids
                    // reading the body). When absent, the body would otherwise be
                    // unbounded — a misbehaving mirror sink could exhaust gateway
                    // memory in a fire-and-forget task. Stream and bound by
                    // `max_response_body_bytes`, discarding the bytes after sizing.
                    let size = match resp.content_length() {
                        Some(cl) => Some(cl),
                        None => match measure_response_body_bounded(resp, max_response_body_bytes)
                            .await
                        {
                            Ok(n) => Some(n),
                            Err(BoundedReadError::LimitExceeded { read_so_far, .. }) => {
                                warn!(
                                    "request_mirror: response from {} truncated at {} bytes \
                                         (max_response_body_bytes = {})",
                                    mirror_url_for_log, read_so_far, max_response_body_bytes
                                );
                                Some(read_so_far as u64)
                            }
                            Err(BoundedReadError::Stream(_)) => None,
                        },
                    };
                    (Some(status), size, None)
                }
                Err(err) => {
                    // `err` is already sanitized by `execute_redacted`
                    // (ErrorClass + stripped URL); it never contains the query
                    // string. Use the same string for the log line and the
                    // structured `mirror_error` field.
                    warn!(
                        "request_mirror: failed to mirror {} {} → {}",
                        method, mirror_url_for_log, err
                    );
                    (None, None, Some(err))
                }
            };

            let elapsed = start.elapsed();

            let meta = MirrorResponseMeta {
                mirror_target_url: mirror_url_for_log,
                mirror_response_status_code: status_code,
                mirror_response_size_bytes: response_size,
                mirror_latency_ms: elapsed.as_secs_f64() * 1000.0,
                mirror_error: error_msg,
            };

            // Send to the watch channel. If the receiver was dropped (request
            // completed and logged before mirror finished), the send fails
            // silently — this is expected for the fire-and-forget pattern.
            let _ = tx.send(Some(meta));
        });

        PluginResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestMirror, parse_mirror_host, strip_query_params};
    use crate::plugins::PluginHttpClient;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn strip_query_params_removes_sensitive_query_data() {
        assert_eq!(
            strip_query_params("https://mirror.example.com:8443/path?token=secret&sig=abc"),
            "https://mirror.example.com:8443/path"
        );
        assert_eq!(
            strip_query_params("https://mirror.example.com:8443/path"),
            "https://mirror.example.com:8443/path"
        );
    }

    #[test]
    fn parse_mirror_host_brackets_ipv6_for_url_authority() {
        assert_eq!(
            parse_mirror_host("2001:db8::10").unwrap(),
            ("[2001:db8::10]".to_string(), None)
        );
        assert_eq!(
            parse_mirror_host("[2001:db8::10]").unwrap(),
            ("[2001:db8::10]".to_string(), None)
        );
    }

    #[test]
    fn build_mirror_url_uses_bracketed_ipv6_authority() {
        let plugin = RequestMirror::new(
            &json!({
                "mirror_host": "2001:db8::10",
                "mirror_port": 8443,
                "mirror_protocol": "https"
            }),
            PluginHttpClient::default(),
        )
        .unwrap();
        let mut query_params = HashMap::new();
        query_params.insert("page".to_string(), "1".to_string());

        assert_eq!(
            plugin.build_mirror_url("/shadow", None, &query_params),
            "https://[2001:db8::10]:8443/shadow?page=1"
        );
        assert_eq!(
            plugin.build_mirror_url("/shadow", Some("tag=red&tag=blue&q=a+b"), &query_params),
            "https://[2001:db8::10]:8443/shadow?tag=red&tag=blue&q=a+b"
        );
    }

    #[test]
    fn build_mirror_url_preserves_raw_query_edge_cases_byte_for_byte() {
        let plugin = RequestMirror::new(
            &json!({ "mirror_host": "mirror.example", "mirror_port": 8080 }),
            PluginHttpClient::default(),
        )
        .unwrap();
        let collapsed = HashMap::from([("tag".to_string(), "only-one".to_string())]);
        for raw in [
            "tag=red&tag=blue",
            "b=1&a=2",
            "flag",
            "empty=",
            "q=a+b",
            "path=%2Froot&k=a%26b",
            "key=a%2Fb",
            "name=%E2%9C%93&q=%C3%A9",
            "tag=red&tag=blue&q=a+b&flag&empty=&path=%2Froot&key=a%2Fb&name=%E2%9C%93",
        ] {
            let url = plugin.build_mirror_url("/api", Some(raw), &collapsed);
            assert!(
                url.ends_with(&format!("?{raw}")),
                "raw query must be preserved exactly: got {url}"
            );
            assert!(
                !url.contains("only-one"),
                "lossy query map must not replace raw query: {url}"
            );
        }
    }
}
