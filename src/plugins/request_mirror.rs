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
//! The mirror request uses the gateway's shared `PluginHttpClient`, which means
//! it inherits the gateway's DNS cache, connection pool keepalive, and TLS
//! settings (CA bundle, skip-verify).
//!
//! ## Mirror response logging
//!
//! The spawned task captures mirror response metadata (status code, response
//! size, latency) and writes it to a `tokio::sync::watch` channel. The proxy
//! handler collects the result before building `TransactionSummary`, so all
//! logging plugins (stdout, http_logging, prometheus, transaction_debugger)
//! receive mirror metadata in the `mirror` field automatically.
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
//!   "mirror_request_body": true
//! }
//! ```
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `mirror_host` | string | **(required)** | Hostname or IP of the mirror target |
//! | `mirror_port` | u16 | 80 (http) / 443 (https) | Port of the mirror target |
//! | `mirror_protocol` | string | `"http"` | `"http"` or `"https"` |
//! | `mirror_path` | string | (none) | Override the request path for the mirror. When unset, the original request path is used |
//! | `percentage` | f64 | `100.0` | Percentage of requests to mirror (0.0–100.0) |
//! | `mirror_request_body` | bool | `true` | Whether to include the request body in the mirror request |

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;
use url::form_urlencoded;

use super::{MirrorResponseMeta, Plugin, PluginHttpClient, PluginResult, RequestContext};

pub struct RequestMirror {
    http_client: PluginHttpClient,
    mirror_host: String,
    mirror_port: u16,
    mirror_protocol: String,
    mirror_path: Option<String>,
    percentage: f64,
    mirror_request_body: bool,
    mirror_hostname: String,
    /// Monotonic counter for deterministic percentage sampling without rand.
    /// Every Nth request is mirrored based on the percentage threshold.
    request_counter: AtomicU64,
}

impl RequestMirror {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let mirror_host = config["mirror_host"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "request_mirror: 'mirror_host' is required".to_string())?
            .to_ascii_lowercase();

        let mirror_protocol = config["mirror_protocol"]
            .as_str()
            .unwrap_or("http")
            .to_ascii_lowercase();

        if mirror_protocol != "http" && mirror_protocol != "https" {
            return Err(format!(
                "request_mirror: 'mirror_protocol' must be 'http' or 'https' (got '{}')",
                mirror_protocol
            ));
        }

        let default_port: u16 = if mirror_protocol == "https" { 443 } else { 80 };
        let mirror_port = config["mirror_port"]
            .as_u64()
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

        let mirror_path = config["mirror_path"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from);

        let percentage = config["percentage"].as_f64().unwrap_or(100.0);
        if !(0.0..=100.0).contains(&percentage) {
            return Err(format!(
                "request_mirror: 'percentage' must be 0.0–100.0 (got {})",
                percentage
            ));
        }

        let mirror_request_body = config["mirror_request_body"].as_bool().unwrap_or(true);

        let mirror_hostname = mirror_host.clone();

        Ok(Self {
            http_client,
            mirror_host,
            mirror_port,
            mirror_protocol,
            mirror_path,
            percentage,
            mirror_request_body,
            mirror_hostname,
            request_counter: AtomicU64::new(0),
        })
    }

    /// Build the full mirror URL from the config and original request path/query.
    fn build_mirror_url(
        &self,
        original_path: &str,
        query_params: &HashMap<String, String>,
    ) -> String {
        let path = self.mirror_path.as_deref().unwrap_or(original_path);

        let mut url = format!(
            "{}://{}:{}{}",
            self.mirror_protocol, self.mirror_host, self.mirror_port, path
        );

        if !query_params.is_empty() {
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
        vec![self.mirror_hostname.clone()]
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.should_mirror() {
            return PluginResult::Continue;
        }

        let mirror_url = self.build_mirror_url(&ctx.path, &ctx.query_params);
        let method = ctx.method.clone();

        // Collect headers for the mirror request. Use the proxy headers (post-transform)
        // which reflect any modifications from upstream plugins like request_transformer.
        let mirror_headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

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

        let mirror_timeout = ctx
            .matched_proxy
            .as_ref()
            .map(|p| {
                if p.backend_read_timeout_ms > 0 {
                    Duration::from_millis(p.backend_read_timeout_ms)
                } else {
                    Duration::from_secs(60)
                }
            })
            .unwrap_or(Duration::from_secs(60));

        // Create a watch channel for the spawned task to send mirror response
        // metadata back. The proxy handler collects the result via
        // `ctx.collect_mirror_result()` before building TransactionSummary.
        let (tx, rx) = tokio::sync::watch::channel(None);
        ctx.mirror_result_rx = Some(rx);

        let http_client = self.http_client.clone();
        let mirror_url_for_log = mirror_url.clone();

        // Fire-and-forget: spawn an async task to send the mirror request.
        // The main request proceeds immediately — mirror latency has zero
        // impact on client response time.
        tokio::spawn(async move {
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

            // Override the client-level timeout with the proxy's backend timeout.
            req_builder = req_builder.timeout(mirror_timeout);

            // Forward all headers from the original (transformed) request
            for (key, value) in &mirror_headers {
                // Skip hop-by-hop and connection-specific headers
                match key.as_str() {
                    "host"
                    | "connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "te"
                    | "upgrade"
                    | "proxy-authorization"
                    | "proxy-connection" => continue,
                    _ => {
                        req_builder = req_builder.header(key.as_str(), value.as_str());
                    }
                }
            }

            if let Some(body) = body_bytes {
                req_builder = req_builder.body(body);
            }

            let (status_code, response_size, error_msg) =
                match http_client.execute(req_builder, "request_mirror").await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        // Derive response size from content-length when available (avoids
                        // reading the body). Fall back to consuming the body bytes.
                        let size = match resp.content_length() {
                            Some(cl) => Some(cl),
                            None => resp.bytes().await.ok().map(|b| b.len() as u64),
                        };
                        (Some(status), size, None)
                    }
                    Err(err) => {
                        warn!(
                            "request_mirror: failed to mirror {} {} → {}",
                            method, mirror_url_for_log, err
                        );
                        (None, None, Some(err.to_string()))
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
