//! Load Testing Plugin
//!
//! Enables on-demand load testing of a proxy's backend by sending concurrent
//! requests through the gateway's own proxy listener. Triggered when a request
//! includes an `X-Loadtesting-Key` header matching the configured secret key.
//!
//! ## How it works
//!
//! When a matching key is received in `before_proxy`, the plugin spawns a
//! background load test that sends concurrent requests back through the
//! gateway's local listener (`127.0.0.1:{gateway_port}`). Because synthetic
//! requests omit the `X-Loadtesting-Key` header, they flow through the full
//! proxy pipeline (routing, auth, rate limiting, backend dispatch, logging)
//! without re-triggering the load test — the gateway's native transaction
//! logging captures every synthetic request automatically.
//!
//! The triggering request itself proceeds normally through the proxy pipeline
//! and is not blocked by the load test.
//!
//! ## Multi-node fan-out
//!
//! When `gateway_addresses` is configured, the plugin forwards the trigger
//! request (WITH the `X-Loadtesting-Key` header) to each remote gateway node
//! as a fire-and-forget call. Each remote node's `load_testing` plugin
//! instance picks up the key and starts its own independent local load test.
//! This way, a single trigger request fans out to all nodes and each node
//! tests its own backend connections locally.
//!
//! ## HTTPS loopback
//!
//! For deployments that disable the HTTP listener and only expose HTTPS,
//! set `gateway_tls: true` to send synthetic requests to the HTTPS port.
//! Since the gateway's frontend TLS cert is typically issued for an external
//! domain (not `127.0.0.1`), `gateway_tls_no_verify` (default `true` when
//! `gateway_tls` is enabled) skips certificate verification for the loopback
//! connection only. This does NOT affect the backend TLS path — the proxy
//! pipeline's backend connection uses the normal CA trust chain regardless.
//!
//! ## Caveats
//!
//! - **Auth forwarding**: Synthetic requests forward the triggering request's
//!   headers (minus `X-Loadtesting-Key` and hop-by-hop headers). For auth
//!   schemes with short-lived tokens (e.g., HMAC with timestamps), tokens may
//!   expire during long-duration tests.
//! - **Rate limiting**: Synthetic requests pass through rate limiting plugins
//!   on the proxy. High `concurrent_clients` values may trigger rate limits.
//!   This is realistic (tests the full pipeline) but may reduce effective
//!   throughput if rate limits are tight.
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "key": "my-secret-load-test-key",
//!   "concurrent_clients": 10,
//!   "duration_seconds": 30,
//!   "ramp": false,
//!   "gateway_port": 8443,
//!   "gateway_tls": true,
//!   "gateway_tls_no_verify": true,
//!   "gateway_addresses": ["https://node2:8443", "https://node3:8443"]
//! }
//! ```
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `key` | string | **(required)** | Value that `X-Loadtesting-Key` must match to trigger |
//! | `concurrent_clients` | u64 | **(required)** | Number of concurrent virtual clients (1–10,000) |
//! | `duration_seconds` | u64 | **(required)** | How long the test runs (1–3,600) |
//! | `ramp` | bool | `false` | When true, clients start gradually over the duration instead of all at once |
//! | `gateway_port` | u16 | `FERRUM_PROXY_HTTP_PORT` (or `FERRUM_PROXY_HTTPS_PORT` when `gateway_tls`) or 8000/8443 | Local gateway port for synthetic requests |
//! | `gateway_tls` | bool | `false` | Use HTTPS for local loopback synthetic requests |
//! | `gateway_tls_no_verify` | bool | `true` when `gateway_tls` is enabled | Skip TLS certificate verification for loopback connections (the gateway cert typically won't match `127.0.0.1`) |
//! | `request_timeout_ms` | u64 | `30000` | Per-request timeout in milliseconds. Prevents workers from hanging on streaming/long-lived responses (SSE, long-poll). Must be > 0 |
//! | `gateway_addresses` | string[] | (none) | Remote gateway URLs to fan out the trigger to. Each receives the original request WITH the key header so it starts its own local load test |

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::info;
use url::form_urlencoded;

use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::dns::DnsCacheResolver;

pub struct LoadTesting {
    /// Shared plugin HTTP client — used for fan-out trigger requests to remote
    /// nodes (respects global gateway TLS settings for inter-node communication).
    http_client: PluginHttpClient,
    /// Dedicated reqwest client for local synthetic load test requests. When
    /// `gateway_tls_no_verify` is true, this client skips TLS cert verification
    /// so loopback HTTPS works even when the gateway cert doesn't cover `127.0.0.1`.
    load_test_client: reqwest::Client,
    key: String,
    concurrent_clients: u32,
    duration_seconds: u64,
    ramp: bool,
    /// Local base URL for synthetic requests (e.g., `http://127.0.0.1:8000`
    /// or `https://127.0.0.1:8443`).
    gateway_base_url: String,
    /// Remote gateway URLs for multi-node fan-out. Each receives the trigger
    /// request WITH the key header to start its own local load test.
    gateway_addresses: Vec<String>,
    is_running: Arc<AtomicBool>,
}

impl LoadTesting {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let key = config["key"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "load_testing: 'key' is required and must be a non-empty string".to_string()
            })?
            .to_string();

        let concurrent_clients = config["concurrent_clients"]
            .as_u64()
            .ok_or_else(|| "load_testing: 'concurrent_clients' is required".to_string())?;
        if concurrent_clients == 0 || concurrent_clients > 10_000 {
            return Err(format!(
                "load_testing: 'concurrent_clients' must be 1–10000 (got {})",
                concurrent_clients
            ));
        }

        let duration_seconds = config["duration_seconds"]
            .as_u64()
            .ok_or_else(|| "load_testing: 'duration_seconds' is required".to_string())?;
        if duration_seconds == 0 || duration_seconds > 3600 {
            return Err(format!(
                "load_testing: 'duration_seconds' must be 1–3600 (got {})",
                duration_seconds
            ));
        }

        let ramp = config["ramp"].as_bool().unwrap_or(false);

        let request_timeout_ms = config["request_timeout_ms"].as_u64().unwrap_or(30_000);
        if request_timeout_ms == 0 {
            return Err("load_testing: 'request_timeout_ms' must be greater than 0".to_string());
        }

        let gateway_tls = config["gateway_tls"].as_bool().unwrap_or(false);

        // Default to true when TLS is enabled — the gateway cert won't match 127.0.0.1
        let gateway_tls_no_verify = config["gateway_tls_no_verify"]
            .as_bool()
            .unwrap_or(gateway_tls);

        // Determine local gateway port with smart env-var defaults
        let default_env_var = if gateway_tls {
            "FERRUM_PROXY_HTTPS_PORT"
        } else {
            "FERRUM_PROXY_HTTP_PORT"
        };
        let default_port: u16 = if gateway_tls { 8443 } else { 8000 };

        let gateway_port = config["gateway_port"]
            .as_u64()
            .map(|p| {
                if p == 0 || p > 65535 {
                    Err(format!(
                        "load_testing: 'gateway_port' must be 1–65535 (got {})",
                        p
                    ))
                } else {
                    Ok(p as u16)
                }
            })
            .transpose()?
            .unwrap_or_else(|| {
                std::env::var(default_env_var)
                    .ok()
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(default_port)
            });

        let scheme = if gateway_tls { "https" } else { "http" };
        let gateway_base_url = format!("{}://127.0.0.1:{}", scheme, gateway_port);

        // Build dedicated reqwest client for load test traffic, with optional
        // TLS no-verify scoped only to this client (not the global gateway).
        // The timeout prevents workers from hanging on streaming/long-lived
        // responses (SSE, long-poll) that never complete.
        //
        // Local synthetic requests target `127.0.0.1` (no DNS lookup needed),
        // but `gateway_addresses` fan-out is handled by the shared
        // `PluginHttpClient` rather than this client. We still install the
        // gateway's `DnsCache` resolver here so this builder honours the
        // project-wide invariant ("every reqwest::Client::builder must use the
        // shared cache") and stays correct if a future change repurposes this
        // client for hostname targets.
        let mut load_test_builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(gateway_tls_no_verify)
            .timeout(Duration::from_millis(request_timeout_ms));
        if let Some(dns_cache) = http_client.dns_cache() {
            load_test_builder =
                load_test_builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())));
        }
        let load_test_client = load_test_builder
            .build()
            .map_err(|e| format!("load_testing: failed to build HTTP client: {}", e))?;

        // Parse optional remote gateway addresses for multi-node fan-out
        let gateway_addresses = if let Some(addresses) = config["gateway_addresses"].as_array() {
            if addresses.is_empty() {
                return Err(
                    "load_testing: 'gateway_addresses' must not be empty when provided".to_string(),
                );
            }
            let mut urls = Vec::with_capacity(addresses.len());
            for addr in addresses {
                let url = addr.as_str().ok_or_else(|| {
                    "load_testing: each 'gateway_addresses' entry must be a string".to_string()
                })?;
                if url.is_empty() {
                    return Err(
                        "load_testing: 'gateway_addresses' entries must not be empty".to_string(),
                    );
                }
                urls.push(url.trim_end_matches('/').to_string());
            }
            urls
        } else {
            Vec::new()
        };

        Ok(Self {
            http_client,
            load_test_client,
            key,
            concurrent_clients: concurrent_clients as u32,
            duration_seconds,
            ramp,
            gateway_base_url,
            gateway_addresses,
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[async_trait]
impl Plugin for LoadTesting {
    fn name(&self) -> &str {
        "load_testing"
    }

    fn priority(&self) -> u16 {
        super::priority::LOAD_TESTING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only trigger when the key header matches
        let key_matches = headers
            .get("x-loadtesting-key")
            .map(|k| k == &self.key)
            .unwrap_or(false);

        if !key_matches {
            return PluginResult::Continue;
        }

        // Prevent concurrent load tests on the same proxy
        if self
            .is_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            tracing::warn!("load_testing: test already in progress, ignoring trigger");
            return PluginResult::Continue;
        }

        let proxy_name = ctx
            .matched_proxy
            .as_ref()
            .and_then(|p| p.name.as_deref())
            .unwrap_or("unknown")
            .to_string();

        let path = ctx.path.clone();
        let query_params = ctx.query_params.clone();
        let method = ctx.method.clone();

        // Headers for synthetic load test requests: forward everything except
        // the load test key (prevents recursion) and hop-by-hop headers.
        // Keeping "host" is intentional — it ensures the gateway routes
        // synthetic requests to the correct proxy when host-based routing is
        // configured.
        let synthetic_headers: Vec<(String, String)> = headers
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    "x-loadtesting-key"
                        | "connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "te"
                        | "upgrade"
                        | "proxy-authorization"
                        | "proxy-connection"
                )
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Headers for fan-out trigger requests: same as original but KEEP the
        // key so remote nodes trigger their own load tests.
        let fanout_headers: Vec<(String, String)> = headers
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    "connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "te"
                        | "upgrade"
                        | "proxy-authorization"
                        | "proxy-connection"
                )
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let concurrent_clients = self.concurrent_clients;
        let duration = Duration::from_secs(self.duration_seconds);
        let duration_secs = self.duration_seconds;
        let ramp = self.ramp;
        let gateway_base_url = self.gateway_base_url.clone();
        let load_test_client = self.load_test_client.clone();
        let is_running = Arc::clone(&self.is_running);

        // Fan out trigger to remote gateway nodes (fire-and-forget).
        // Each remote node receives the full request WITH the key header,
        // so its load_testing plugin triggers an independent local load test.
        if !self.gateway_addresses.is_empty() {
            for addr in &self.gateway_addresses {
                let fanout_url = build_url(addr, &path, &query_params);
                let fanout_method = method.clone();
                let fanout_hdrs = fanout_headers.clone();
                let client = self.http_client.clone();
                let addr_log = addr.clone();

                tokio::spawn(async move {
                    let req =
                        build_request(client.get(), &fanout_method, &fanout_url, &fanout_hdrs);
                    if let Err(e) = req.send().await {
                        tracing::warn!(
                            remote = %addr_log,
                            error = %e,
                            "load_testing: failed to fan out trigger to remote node"
                        );
                    }
                });
            }
        }

        info!(
            proxy = %proxy_name,
            concurrent_clients = concurrent_clients,
            duration_seconds = duration_secs,
            ramp = ramp,
            "load_testing: starting load test"
        );

        tokio::spawn(async move {
            let start = Instant::now();
            let deadline = start + duration;

            let mut handles = Vec::with_capacity(concurrent_clients as usize);

            for i in 0..concurrent_clients {
                let ramp_delay = if ramp {
                    // Stagger client starts evenly across the test duration.
                    // Client 0 starts immediately, client N-1 starts at
                    // duration * (N-1)/N.
                    duration * i / concurrent_clients
                } else {
                    Duration::ZERO
                };

                let client = load_test_client.clone();
                let base_url = gateway_base_url.clone();
                let path = path.clone();
                let query_params = query_params.clone();
                let method = method.clone();
                let req_headers = synthetic_headers.clone();

                let handle = tokio::spawn(async move {
                    if !ramp_delay.is_zero() {
                        tokio::time::sleep(ramp_delay).await;
                    }

                    let mut request_count: u64 = 0;

                    while Instant::now() < deadline {
                        let url = build_url(&base_url, &path, &query_params);
                        let req = build_request(&client, &method, &url, &req_headers);

                        // Send request and consume response body to completion
                        if let Ok(resp) = req.send().await {
                            let _ = resp.bytes().await;
                        }

                        request_count += 1;
                    }

                    request_count
                });

                handles.push(handle);
            }

            let mut total_requests: u64 = 0;
            for handle in handles {
                if let Ok(count) = handle.await {
                    total_requests += count;
                }
            }

            let elapsed = start.elapsed();
            let rps = if elapsed.as_secs_f64() > 0.0 {
                total_requests as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

            info!(
                proxy = %proxy_name,
                total_requests = total_requests,
                elapsed_seconds = %format_args!("{:.2}", elapsed.as_secs_f64()),
                requests_per_second = %format_args!("{:.1}", rps),
                "load_testing: load test finished"
            );

            is_running.store(false, Ordering::Release);
        });

        PluginResult::Continue
    }
}

/// Build a full URL from a base URL, path, and query parameters.
fn build_url(base: &str, path: &str, query_params: &HashMap<String, String>) -> String {
    let mut url = format!("{}{}", base, path);
    if !query_params.is_empty() {
        url.push('?');
        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query_params.iter())
            .finish();
        url.push_str(&encoded);
    }
    url
}

/// Build a reqwest `RequestBuilder` with the given method, URL, and headers.
fn build_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        "HEAD" => client.head(url),
        _ => client.request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
            url,
        ),
    };

    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }

    req
}
