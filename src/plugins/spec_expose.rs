//! Spec Expose plugin — serves API specifications (OpenAPI, WSDL, WADL) on a
//! `/specz` sub-path of each proxy's listen path.
//!
//! When a `GET` request arrives at `{listen_path}/specz`, the plugin fetches
//! the specification document from the configured `spec_url` and returns it to
//! the caller with the upstream's `Content-Type` preserved. The `/specz`
//! endpoint is unauthenticated — it short-circuits before the authentication
//! phase so consumers can discover API contracts without credentials.
//!
//! Only compatible with prefix-based `listen_path` proxies (not regex, not
//! host-only or port-only routing) and HTTP protocol types.
//!
//!
//! # Configuration
//!
//! ```json
//! {
//!   "spec_url": "https://internal-service/docs/openapi.yaml",
//!   "content_type": "application/yaml",    // optional override
//!   "tls_no_verify": false                 // optional, skip TLS verification
//! }
//! ```

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::dns::DnsCacheResolver;

use super::{Plugin, PluginResult, RequestContext};

/// Spec Expose plugin — serves API spec documents on `{listen_path}/specz`.
pub struct SpecExpose {
    spec_url: String,
    content_type_override: Option<String>,
    http_client: reqwest::Client,
}

impl SpecExpose {
    pub fn new(
        config: &Value,
        plugin_http_client: super::PluginHttpClient,
    ) -> Result<Self, String> {
        let spec_url = config["spec_url"]
            .as_str()
            .filter(|s| !s.is_empty() && *s != "default")
            .ok_or_else(|| {
                "spec_expose: 'spec_url' is required and must be a non-empty URL string".to_string()
            })?
            .to_string();

        // Validate URL format
        url::Url::parse(&spec_url)
            .map_err(|e| format!("spec_expose: 'spec_url' is not a valid URL: {e}"))?;

        let content_type_override = config["content_type"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let tls_no_verify = config["tls_no_verify"]
            .as_bool()
            .unwrap_or(plugin_http_client.tls_no_verify());

        // Build a dedicated reqwest client for spec fetching.
        // We use a separate client so we can honour the per-plugin tls_no_verify
        // setting independently of the shared plugin HTTP client, but we still
        // wire the gateway's shared DNS cache for consistent resolution + TTL.
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(tls_no_verify);

        if let Some(dns_cache) = plugin_http_client.dns_cache() {
            builder = builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())));
        }

        // Load custom CA bundle when not skipping verification.
        if !tls_no_verify && let Some(ca_path) = plugin_http_client.tls_ca_bundle_path() {
            match std::fs::read(ca_path) {
                Ok(ca_pem) => match reqwest::Certificate::from_pem(&ca_pem) {
                    Ok(cert) => {
                        builder = builder
                            .tls_built_in_root_certs(false)
                            .add_root_certificate(cert);
                    }
                    Err(e) => {
                        tracing::warn!("spec_expose: failed to parse CA bundle at {ca_path}: {e}");
                    }
                },
                Err(e) => {
                    tracing::warn!("spec_expose: failed to read CA bundle at {ca_path}: {e}");
                }
            }
        }

        let http_client = builder
            .build()
            .map_err(|e| format!("spec_expose: failed to build HTTP client: {e}"))?;

        Ok(Self {
            spec_url,
            content_type_override,
            http_client,
        })
    }

    /// Check whether the request path is exactly `{listen_path}/specz`.
    pub fn is_specz_request(path: &str, listen_path: &str) -> bool {
        // For root listen_path "/", the specz path is "/specz"
        if listen_path == "/" {
            return path == "/specz";
        }
        // For other listen paths like "/api/v1", check for "/api/v1/specz"
        if let Some(remainder) = path.strip_prefix(listen_path) {
            remainder == "/specz"
        } else {
            false
        }
    }
}

#[async_trait]
impl Plugin for SpecExpose {
    fn name(&self) -> &str {
        "spec_expose"
    }

    fn priority(&self) -> u16 {
        super::priority::SPEC_EXPOSE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        if let Ok(url) = url::Url::parse(&self.spec_url)
            && let Some(host) = url.host_str()
        {
            return vec![host.to_string()];
        }
        Vec::new()
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Only intercept GET requests
        if ctx.method != "GET" {
            return PluginResult::Continue;
        }

        // Need a matched proxy with a prefix listen_path (not regex)
        let proxy = match ctx.matched_proxy.as_ref() {
            Some(p) => p,
            None => return PluginResult::Continue,
        };

        // Skip regex listen paths (prefixed with ~)
        if proxy.listen_path.starts_with('~') {
            return PluginResult::Continue;
        }

        if !Self::is_specz_request(&ctx.path, &proxy.listen_path) {
            return PluginResult::Continue;
        }

        // Fetch the spec document from the configured URL
        let response = match self.http_client.get(&self.spec_url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(
                    spec_url = %self.spec_url,
                    error = %e,
                    "spec_expose: failed to fetch spec document"
                );
                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                return PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"Failed to fetch API specification from upstream","detail":"{}"}}"#,
                        e.to_string().replace('"', "\\\"")
                    ),
                    headers,
                };
            }
        };

        if !response.status().is_success() {
            let status = response.status().as_u16();
            tracing::warn!(
                spec_url = %self.spec_url,
                upstream_status = status,
                "spec_expose: upstream returned non-success status"
            );
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            return PluginResult::Reject {
                status_code: 502,
                body: format!(r#"{{"error":"Upstream spec endpoint returned status {status}"}}"#),
                headers,
            };
        }

        // Determine content-type: plugin override > upstream response > default
        let content_type = self
            .content_type_override
            .clone()
            .or_else(|| {
                response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());

        match response.bytes().await {
            Ok(body) => {
                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), content_type);
                PluginResult::RejectBinary {
                    status_code: 200,
                    body,
                    headers,
                }
            }
            Err(e) => {
                tracing::warn!(
                    spec_url = %self.spec_url,
                    error = %e,
                    "spec_expose: failed to read spec response body"
                );
                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                PluginResult::Reject {
                    status_code: 502,
                    body: format!(
                        r#"{{"error":"Failed to read API specification response body","detail":"{}"}}"#,
                        e.to_string().replace('"', "\\\"")
                    ),
                    headers,
                }
            }
        }
    }
}
