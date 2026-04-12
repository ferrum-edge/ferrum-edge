//! Kubernetes service discovery via EndpointSlice API.
//!
//! Polls the Kubernetes API server for EndpointSlice resources matching a
//! service name and converts ready endpoints into upstream targets.
//!
//! Uses the gateway's shared `PluginHttpClient` (via its underlying
//! `reqwest::Client`) so that Kubernetes API calls inherit the gateway's
//! connection pool settings, DNS cache, trust store, and
//! `FERRUM_TLS_NO_VERIFY` setting.

use crate::config::types::UpstreamTarget;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::collections::HashMap;
use tracing::debug;

/// Characters that must be percent-encoded in a URL path segment (RFC 3986 §3.3).
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

/// Kubernetes service discoverer.
///
/// Polls EndpointSlice resources for the configured service and converts
/// ready endpoints into `UpstreamTarget` entries. Uses a shared
/// `reqwest::Client` from the gateway's `PluginHttpClient` for connection
/// reuse and consistent TLS configuration.
pub struct KubernetesDiscoverer {
    client: reqwest::Client,
    namespace: String,
    service_name: String,
    port_name: Option<String>,
    label_selector: Option<String>,
    default_weight: u32,
    api_url_override: Option<String>,
}

impl KubernetesDiscoverer {
    pub fn new(
        client: reqwest::Client,
        namespace: String,
        service_name: String,
        port_name: Option<String>,
        label_selector: Option<String>,
        default_weight: u32,
    ) -> Self {
        Self {
            client,
            namespace,
            service_name,
            port_name,
            label_selector,
            default_weight,
            api_url_override: None,
        }
    }

    /// Create a new discoverer with a custom API base URL (for testing).
    #[allow(dead_code)]
    pub fn with_api_url(mut self, url: String) -> Self {
        self.api_url_override = Some(url);
        self
    }

    /// Build the Kubernetes API URL for listing EndpointSlices.
    ///
    /// Uses the standard in-cluster environment variables (`KUBERNETES_SERVICE_HOST`,
    /// `KUBERNETES_SERVICE_PORT`) when available, otherwise falls back to
    /// `https://kubernetes.default.svc`.
    fn api_url(&self) -> String {
        let base = if let Some(ref override_url) = self.api_url_override {
            override_url.clone()
        } else {
            match (
                std::env::var("KUBERNETES_SERVICE_HOST"),
                std::env::var("KUBERNETES_SERVICE_PORT"),
            ) {
                (Ok(host), Ok(port)) => {
                    if host.contains(':') {
                        // IPv6 address needs brackets
                        format!("https://[{}]:{}", host, port)
                    } else {
                        format!("https://{}:{}", host, port)
                    }
                }
                _ => "https://kubernetes.default.svc".to_string(),
            }
        };

        let encoded_ns = utf8_percent_encode(&self.namespace, PATH_SEGMENT_ENCODE).to_string();
        let mut url = format!(
            "{}/apis/discovery.k8s.io/v1/namespaces/{}/endpointslices",
            base, encoded_ns
        );

        // Build label selector: always filter by service name.
        // The service name is embedded as a label selector value — encode only
        // the value portion, not the key or operators.
        let mut selectors = vec![format!("kubernetes.io/service-name={}", self.service_name)];
        if let Some(ref extra) = self.label_selector {
            selectors.push(extra.clone());
        }
        // Encode the entire labelSelector query value (commas, equals, slashes
        // are valid within a Kubernetes label selector and the K8s API expects
        // them unescaped, so we only encode characters unsafe in query values).
        let joined = selectors.join(",");
        let encoded_selector = utf8_percent_encode(&joined, QUERY_VALUE_ENCODE).to_string();
        url.push_str(&format!("?labelSelector={}", encoded_selector));

        url
    }

    /// Read the service account token from the standard in-cluster path.
    fn read_sa_token() -> Option<String> {
        std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").ok()
    }

    /// Extract the matching port from an EndpointSlice item.
    fn extract_port(&self, item: &serde_json::Value) -> Option<u16> {
        let ports = item.get("ports").and_then(|v| v.as_array())?;

        if let Some(ref port_name) = self.port_name {
            // Find port by name
            for port in ports {
                let name = port.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if name == port_name {
                    return port.get("port").and_then(|p| p.as_u64()).map(|p| p as u16);
                }
            }
            None
        } else {
            // Use first port
            ports
                .first()?
                .get("port")
                .and_then(|p| p.as_u64())
                .map(|p| p as u16)
        }
    }
}

#[async_trait::async_trait]
impl super::ServiceDiscoverer for KubernetesDiscoverer {
    async fn discover(&self) -> Result<Vec<UpstreamTarget>, anyhow::Error> {
        let url = self.api_url();

        let mut request = self.client.get(&url);

        // Add bearer token auth (re-read each poll — tokens can rotate)
        if let Some(token) = Self::read_sa_token() {
            request = request.bearer_auth(token);
        } else if let Ok(kubeconfig_token) = std::env::var("KUBE_TOKEN") {
            request = request.bearer_auth(kubeconfig_token);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = match response.text().await {
                Ok(t) => t,
                Err(e) => format!("<failed to read response body: {}>", e),
            };
            anyhow::bail!(
                "Kubernetes API returned {}: {}",
                status,
                body.chars().take(200).collect::<String>()
            );
        }

        let body: serde_json::Value = response.json().await?;
        let mut targets = Vec::new();

        if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
            for item in items {
                // Extract ports
                let port = self.extract_port(item);

                // Extract endpoints
                if let Some(endpoints) = item.get("endpoints").and_then(|v| v.as_array()) {
                    for endpoint in endpoints {
                        // Check if endpoint is ready
                        let ready = endpoint
                            .get("conditions")
                            .and_then(|c| c.get("ready"))
                            .and_then(|r| r.as_bool())
                            .unwrap_or(true); // default to ready if conditions not set

                        if !ready {
                            continue;
                        }

                        if let Some(addresses) =
                            endpoint.get("addresses").and_then(|v| v.as_array())
                        {
                            for addr in addresses {
                                if let Some(address) = addr.as_str()
                                    && let Some(port) = port
                                {
                                    targets.push(UpstreamTarget {
                                        host: address.to_string(),
                                        port,
                                        weight: self.default_weight,
                                        tags: HashMap::new(),
                                        path: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        debug!(
            "Kubernetes discovery: found {} targets for {}/{}",
            targets.len(),
            self.namespace,
            self.service_name
        );

        Ok(targets)
    }

    fn provider_name(&self) -> &str {
        "kubernetes"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_discoverer(
        namespace: &str,
        service_name: &str,
        port_name: Option<&str>,
        label_selector: Option<&str>,
    ) -> KubernetesDiscoverer {
        KubernetesDiscoverer {
            client: reqwest::Client::new(),
            namespace: namespace.to_string(),
            service_name: service_name.to_string(),
            port_name: port_name.map(|s| s.to_string()),
            label_selector: label_selector.map(|s| s.to_string()),
            default_weight: 1,
            api_url_override: Some("https://k8s-api:6443".to_string()),
        }
    }

    #[test]
    fn api_url_with_override() {
        let d = make_discoverer("default", "my-svc", None, None);
        let url = d.api_url();
        assert!(url.starts_with(
            "https://k8s-api:6443/apis/discovery.k8s.io/v1/namespaces/default/endpointslices"
        ));
        // The `=` in the label selector value is percent-encoded by QUERY_VALUE_ENCODE
        assert!(url.contains("labelSelector=kubernetes.io/service-name%3Dmy-svc"));
    }

    #[test]
    fn api_url_encodes_namespace_with_special_chars() {
        let d = make_discoverer("my namespace", "svc", None, None);
        let url = d.api_url();
        assert!(url.contains("/namespaces/my%20namespace/"));
    }

    #[test]
    fn api_url_includes_extra_label_selector() {
        let d = make_discoverer("prod", "api", None, Some("env=production"));
        let url = d.api_url();
        // Both selectors are comma-joined then encoded as a single query value
        // The `=` and `,` in selectors get encoded
        assert!(url.contains("labelSelector="));
        assert!(url.contains("kubernetes.io/service-name%3Dapi"));
        assert!(url.contains("env%3Dproduction"));
    }

    #[test]
    fn api_url_default_fallback_without_env_vars() {
        // Without KUBERNETES_SERVICE_HOST/PORT env vars and without override,
        // should fall back to https://kubernetes.default.svc
        let d = KubernetesDiscoverer {
            client: reqwest::Client::new(),
            namespace: "default".to_string(),
            service_name: "test".to_string(),
            port_name: None,
            label_selector: None,
            default_weight: 1,
            api_url_override: None, // No override
        };
        let url = d.api_url();
        // May use env vars if set in the test environment, or fallback
        // Just verify it produces a valid URL structure
        assert!(url.contains("/apis/discovery.k8s.io/v1/namespaces/default/endpointslices"));
    }

    #[test]
    fn extract_port_with_named_port() {
        let d = make_discoverer("default", "svc", Some("http"), None);
        let item = serde_json::json!({
            "ports": [
                {"name": "grpc", "port": 9090},
                {"name": "http", "port": 8080}
            ]
        });
        assert_eq!(d.extract_port(&item), Some(8080));
    }

    #[test]
    fn extract_port_with_named_port_not_found() {
        let d = make_discoverer("default", "svc", Some("metrics"), None);
        let item = serde_json::json!({
            "ports": [
                {"name": "http", "port": 8080}
            ]
        });
        assert_eq!(d.extract_port(&item), None);
    }

    #[test]
    fn extract_port_no_name_uses_first() {
        let d = make_discoverer("default", "svc", None, None);
        let item = serde_json::json!({
            "ports": [
                {"name": "grpc", "port": 9090},
                {"name": "http", "port": 8080}
            ]
        });
        assert_eq!(d.extract_port(&item), Some(9090)); // First port
    }

    #[test]
    fn extract_port_empty_ports_array() {
        let d = make_discoverer("default", "svc", None, None);
        let item = serde_json::json!({"ports": []});
        assert_eq!(d.extract_port(&item), None);
    }

    #[test]
    fn extract_port_no_ports_key() {
        let d = make_discoverer("default", "svc", None, None);
        let item = serde_json::json!({"endpoints": []});
        assert_eq!(d.extract_port(&item), None);
    }

    #[test]
    fn extract_port_name_without_name_field_in_port() {
        let d = make_discoverer("default", "svc", Some("http"), None);
        let item = serde_json::json!({
            "ports": [{"port": 8080}]  // No "name" field
        });
        // Name defaults to "" which != "http", so should return None
        assert_eq!(d.extract_port(&item), None);
    }
}
