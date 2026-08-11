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
//!
//! The blocking-query cursor (`X-Consul-Index`) is returned as a pending
//! [`super::DiscoveryCursorCommit`] and must be committed by the discovery
//! manager only after shared target admission and successful publication.
//! Failed status, malformed bodies, rejected snapshots, and publication
//! failures retain the previously committed cursor.

use crate::config::types::UpstreamTarget;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

use super::http_body::{DiscoveryBodyRole, collect_discovery_response_body};
use super::{DiscoveryCursorCommit, DiscoverySnapshot};

/// Characters that must be percent-encoded in a URL path segment (RFC 3986 §3.3).
/// Encodes everything except unreserved chars and sub-delims that are safe in path segments.
const PATH_SEGMENT_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'@')
    .add(b'{')
    .add(b'}')
    .add(b'<')
    .add(b'>')
    .add(b'^')
    .add(b'`')
    .add(b'|');

/// Characters that must be percent-encoded in a URL query parameter value.
const QUERY_VALUE_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'=')
    .add(b'{')
    .add(b'}')
    .add(b'<')
    .add(b'>')
    .add(b'^')
    .add(b'`')
    .add(b'|');

/// Maximum accepted `X-Consul-Index` header value length (decimal digits of u64).
const MAX_CONSUL_INDEX_HEADER_LEN: usize = 20;

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
    /// Last Consul index for blocking queries. Advanced only via committed
    /// [`DiscoveryCursorCommit`] handles after snapshot admission.
    last_index: Arc<AtomicU64>,
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
            last_index: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Currently committed blocking-query index (`0` means non-blocking).
    ///
    /// External unit tests observe cursor advancement through
    /// `ferrum_edge::_test_support::consul_blocking_query_index_for_test`.
    #[allow(dead_code)] // reached via `_test_support` from the external test crate
    #[doc(hidden)]
    pub(crate) fn blocking_query_index(&self) -> u64 {
        self.last_index.load(Ordering::Relaxed)
    }

    fn build_url(&self) -> String {
        use std::fmt::Write;

        let encoded_service =
            utf8_percent_encode(&self.service_name, PATH_SEGMENT_ENCODE).to_string();
        let mut url = format!("{}/v1/health/service/{}", self.address, encoded_service);

        let mut params = Vec::new();
        if self.healthy_only {
            params.push("passing=true".to_string());
        }
        if let Some(ref dc) = self.datacenter {
            let encoded = utf8_percent_encode(dc, QUERY_VALUE_ENCODE);
            params.push(format!("dc={}", encoded));
        }
        if let Some(ref tag) = self.tag {
            let encoded = utf8_percent_encode(tag, QUERY_VALUE_ENCODE);
            params.push(format!("tag={}", encoded));
        }

        // Use blocking query if we have a previous index
        let last = self.last_index.load(Ordering::Relaxed);
        if last > 0 {
            let mut param = String::new();
            write!(param, "index={}", last).ok();
            params.push(param);
            params.push("wait=30s".to_string());
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        url
    }
}

/// Parse `X-Consul-Index` with a bounded length check. Malformed or oversized
/// values fail closed (no candidate cursor) without logging header contents.
pub(crate) fn parse_consul_index_header(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers.get("X-Consul-Index")?;
    let value = raw.to_str().ok()?;
    if value.is_empty() || value.len() > MAX_CONSUL_INDEX_HEADER_LEN {
        return None;
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[async_trait::async_trait]
impl super::ServiceDiscoverer for ConsulDiscoverer {
    async fn discover(&self) -> Result<DiscoverySnapshot, anyhow::Error> {
        let url = self.build_url();

        let mut request = self.client.get(&url);

        // Add ACL token if configured
        if let Some(ref token) = self.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await?;

        // Candidate index for this response only — never mutate `last_index`
        // here. The manager commits after shared admission + publication.
        let candidate_index = parse_consul_index_header(response.headers());

        if !response.status().is_success() {
            // Fail closed without surfacing response bodies (may contain
            // secrets). Drain under the tighter error-body ceiling, then emit
            // fixed ACL remediation for 401/403 only.
            let status = response.status().as_u16();
            let _ = collect_discovery_response_body(response, DiscoveryBodyRole::Error).await;
            if matches!(status, 401 | 403) {
                anyhow::bail!(
                    "Consul API returned status {status}; check Consul ACL token policy (service:read on the discovered service)"
                );
            }
            anyhow::bail!("Consul API returned status {status}");
        }

        // Distinguish transport/read failures from malformed JSON without
        // logging body bytes, URLs, tokens, or unredacted error strings.
        let body_bytes = collect_discovery_response_body(response, DiscoveryBodyRole::Success)
            .await
            .map_err(|e| e.as_anyhow("Consul"))?;
        let body: Vec<serde_json::Value> = serde_json::from_slice(body_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("Consul API returned malformed JSON"))?;
        // Release the shared body-budget permit before target construction.
        drop(body_bytes);
        let provider_item_count = body.len();
        let mut targets = Vec::new();
        let mut missing_service = 0usize;
        let mut missing_address = 0usize;
        let mut missing_port = 0usize;

        for entry in &body {
            let service = match entry.get("Service") {
                Some(s) => s,
                None => {
                    missing_service += 1;
                    continue;
                }
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
                missing_address += 1;
                continue;
            }

            let port = service.get("Port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;

            if port == 0 {
                missing_port += 1;
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
                service_port_policy_key: None,
                weight,
                tags,
                locality: None,
                path: None,
            });
        }

        debug!(
            "Consul discovery: found {} targets for service {}",
            targets.len(),
            self.service_name
        );
        if targets.is_empty() && provider_item_count > 0 {
            // Admission emits the operator-facing rejection warn; keep detail here
            // at debug to avoid duplicate warnings for the same rejection.
            debug!(
                service = %self.service_name,
                records = provider_item_count,
                missing_service,
                missing_address,
                missing_port,
                "Consul discovery produced zero valid targets from provider payload"
            );
        }

        let snapshot = if let Some(index) = candidate_index {
            DiscoverySnapshot::with_atomic_cursor(
                targets,
                provider_item_count,
                DiscoveryCursorCommit::new(Arc::clone(&self.last_index), index),
            )
        } else {
            DiscoverySnapshot::with_atomic_targets(targets, provider_item_count)
        };

        Ok(snapshot)
    }

    fn provider_name(&self) -> &str {
        "consul"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn make_discoverer(
        address: &str,
        service_name: &str,
        datacenter: Option<&str>,
        tag: Option<&str>,
        healthy_only: bool,
    ) -> ConsulDiscoverer {
        ConsulDiscoverer {
            client: reqwest::Client::new(),
            address: address.trim_end_matches('/').to_string(),
            service_name: service_name.to_string(),
            datacenter: datacenter.map(|s| s.to_string()),
            tag: tag.map(|s| s.to_string()),
            healthy_only,
            token: None,
            default_weight: 1,
            last_index: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn build_url_basic() {
        let d = make_discoverer("http://consul:8500", "my-api", None, None, false);
        assert_eq!(d.build_url(), "http://consul:8500/v1/health/service/my-api");
    }

    #[test]
    fn build_url_healthy_only() {
        let d = make_discoverer("http://consul:8500", "my-api", None, None, true);
        assert_eq!(
            d.build_url(),
            "http://consul:8500/v1/health/service/my-api?passing=true"
        );
    }

    #[test]
    fn build_url_with_datacenter_and_tag() {
        let d = make_discoverer(
            "http://consul:8500",
            "my-api",
            Some("us-east-1"),
            Some("v2"),
            true,
        );
        let url = d.build_url();
        assert!(url.contains("passing=true"));
        assert!(url.contains("dc=us-east-1"));
        assert!(url.contains("tag=v2"));
    }

    #[test]
    fn build_url_encodes_service_name_with_special_chars() {
        let d = make_discoverer("http://consul:8500", "my service/v2", None, None, false);
        let url = d.build_url();
        // Spaces and slashes should be encoded in path
        assert!(url.contains("my%20service%2Fv2"));
        assert!(!url.contains("my service"));
    }

    #[test]
    fn build_url_encodes_datacenter_with_special_chars() {
        let d = make_discoverer(
            "http://consul:8500",
            "api",
            Some("dc with spaces"),
            None,
            false,
        );
        let url = d.build_url();
        assert!(url.contains("dc=dc%20with%20spaces"));
    }

    #[test]
    fn build_url_encodes_tag_with_ampersand() {
        let d = make_discoverer(
            "http://consul:8500",
            "api",
            None,
            Some("key=value&other"),
            false,
        );
        let url = d.build_url();
        assert!(url.contains("tag=key%3Dvalue%26other"));
    }

    #[test]
    fn build_url_includes_blocking_query_when_index_set() {
        let d = make_discoverer("http://consul:8500", "api", None, None, false);
        d.last_index.store(42, Ordering::Relaxed);
        let url = d.build_url();
        assert!(url.contains("index=42"));
        assert!(url.contains("wait=30s"));
    }

    #[test]
    fn build_url_no_blocking_query_when_index_zero() {
        let d = make_discoverer("http://consul:8500", "api", None, None, false);
        let url = d.build_url();
        assert!(!url.contains("index="));
        assert!(!url.contains("wait="));
    }

    #[test]
    fn build_url_trailing_slash_trimmed() {
        let d = make_discoverer("http://consul:8500/", "api", None, None, false);
        assert_eq!(d.build_url(), "http://consul:8500/v1/health/service/api");
    }

    #[test]
    fn build_url_all_options() {
        let d = make_discoverer(
            "http://consul:8500",
            "my-api",
            Some("dc1"),
            Some("prod"),
            true,
        );
        d.last_index.store(99, Ordering::Relaxed);
        let url = d.build_url();
        assert!(url.starts_with("http://consul:8500/v1/health/service/my-api?"));
        assert!(url.contains("passing=true"));
        assert!(url.contains("dc=dc1"));
        assert!(url.contains("tag=prod"));
        assert!(url.contains("index=99"));
        assert!(url.contains("wait=30s"));
    }
}
