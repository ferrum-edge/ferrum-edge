//! Consul service discovery via HTTP API.
//!
//! Polls Consul's health API endpoint to discover healthy service instances
//! and converts them into upstream targets. Supports blocking queries for
//! efficient change detection.
//!
//! Uses the gateway's shared `PluginHttpClient` (via its underlying
//! `reqwest::Client`) so that Consul API calls inherit the gateway's
//! connection pool settings, DNS cache, trust store, and
//! `FERRUM_TLS_NO_VERIFY` setting.

use crate::config::types::UpstreamTarget;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

/// Consul service discoverer.
///
/// Queries Consul's `/v1/health/service/:service` endpoint to discover
/// service instances and converts them into `UpstreamTarget` entries.
pub struct ConsulDiscoverer {
    client: reqwest::Client,
    address: String,
    service_name: String,
    datacenter: Option<String>,
    tag: Option<String>,
    healthy_only: bool,
    token: Option<String>,
    default_weight: u32,
    /// Last Consul index for blocking queries.
    last_index: AtomicU64,
}

impl ConsulDiscoverer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: reqwest::Client,
        address: String,
        service_name: String,
        datacenter: Option<String>,
        tag: Option<String>,
        healthy_only: bool,
        token: Option<String>,
        default_weight: u32,
    ) -> Self {
        Self {
            client,
            address: address.trim_end_matches('/').to_string(),
            service_name,
            datacenter,
            tag,
            healthy_only,
            token,
            default_weight,
            last_index: AtomicU64::new(0),
        }
    }

    fn build_url(&self) -> String {
        let mut url = format!("{}/v1/health/service/{}", self.address, self.service_name);

        let mut params = Vec::new();
        if self.healthy_only {
            params.push("passing=true".to_string());
        }
        if let Some(ref dc) = self.datacenter {
            params.push(format!("dc={}", dc));
        }
        if let Some(ref tag) = self.tag {
            params.push(format!("tag={}", tag));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        url
    }
}

#[async_trait::async_trait]
impl super::ServiceDiscoverer for ConsulDiscoverer {
    async fn discover(&self) -> Result<Vec<UpstreamTarget>, anyhow::Error> {
        let url = self.build_url();

        let mut request = self.client.get(&url);

        // Add ACL token if configured
        if let Some(ref token) = self.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await?;

        // Track the Consul index for blocking queries
        if let Some(index) = response
            .headers()
            .get("X-Consul-Index")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            self.last_index.store(index, Ordering::Relaxed);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = match response.text().await {
                Ok(t) => t,
                Err(e) => format!("<failed to read response body: {}>", e),
            };
            anyhow::bail!(
                "Consul API returned {}: {}",
                status,
                body.chars().take(200).collect::<String>()
            );
        }

        let body: Vec<serde_json::Value> = response.json().await?;
        let mut targets = Vec::new();

        for entry in &body {
            let service = match entry.get("Service") {
                Some(s) => s,
                None => continue,
            };

            let address = service
                .get("Address")
                .and_then(|a| a.as_str())
                .unwrap_or("");

            // Fall back to Node address if Service address is empty
            let address = if address.is_empty() {
                entry
                    .get("Node")
                    .and_then(|n| n.get("Address"))
                    .and_then(|a| a.as_str())
                    .unwrap_or("")
            } else {
                address
            };

            if address.is_empty() {
                continue;
            }

            let port = service.get("Port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;

            if port == 0 {
                continue;
            }

            // Use Consul service weights if available
            let weight = service
                .get("Weights")
                .and_then(|w| w.get("Passing"))
                .and_then(|p| p.as_u64())
                .map(|w| w as u32)
                .unwrap_or(self.default_weight);

            // Extract service tags as target tags
            let mut tags = HashMap::new();
            if let Some(service_tags) = service.get("Tags").and_then(|t| t.as_array()) {
                for (i, tag) in service_tags.iter().enumerate() {
                    if let Some(tag_str) = tag.as_str() {
                        tags.insert(format!("consul_tag_{}", i), tag_str.to_string());
                    }
                }
            }

            targets.push(UpstreamTarget {
                host: address.to_string(),
                port,
                weight,
                tags,
            });
        }

        debug!(
            "Consul discovery: found {} targets for service {}",
            targets.len(),
            self.service_name
        );

        Ok(targets)
    }

    fn provider_name(&self) -> &str {
        "consul"
    }
}
