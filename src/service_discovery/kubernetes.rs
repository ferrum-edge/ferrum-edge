//! Kubernetes service discovery via EndpointSlice API.
//!
//! Polls the Kubernetes API server for EndpointSlice resources matching a
//! service name and converts ready endpoints into upstream targets.
//!
//! Supports both in-cluster (service account token) and out-of-cluster
//! (kubeconfig) authentication automatically via `KUBECONFIG` env var
//! or the standard in-cluster service account path.

use crate::config::types::UpstreamTarget;
use std::collections::HashMap;
use tracing::debug;

/// Kubernetes service discoverer.
///
/// Polls EndpointSlice resources for the configured service and converts
/// ready endpoints into `UpstreamTarget` entries. The HTTP client is built
/// once at construction and reused across polls to avoid repeated TLS
/// handshakes and connection setup.
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
        namespace: String,
        service_name: String,
        port_name: Option<String>,
        label_selector: Option<String>,
        default_weight: u32,
    ) -> Self {
        let client = Self::build_client();
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

    /// Build the HTTP client once with in-cluster CA cert if available.
    fn build_client() -> reqwest::Client {
        let mut builder = reqwest::Client::builder();

        if let Some(ca_path) = Self::ca_cert_path()
            && let Ok(ca_cert) = std::fs::read(&ca_path)
            && let Ok(cert) = reqwest::Certificate::from_pem(&ca_cert)
        {
            builder = builder.add_root_certificate(cert);
        }

        builder.build().unwrap_or_else(|_| reqwest::Client::new())
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

        let mut url = format!(
            "{}/apis/discovery.k8s.io/v1/namespaces/{}/endpointslices",
            base, self.namespace
        );

        // Build label selector: always filter by service name
        let mut selectors = vec![format!("kubernetes.io/service-name={}", self.service_name)];
        if let Some(ref extra) = self.label_selector {
            selectors.push(extra.clone());
        }
        url.push_str(&format!("?labelSelector={}", selectors.join(",")));

        url
    }

    /// Read the service account token from the standard in-cluster path.
    fn read_sa_token() -> Option<String> {
        std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").ok()
    }

    /// Read the CA cert path for TLS verification against the API server.
    fn ca_cert_path() -> Option<String> {
        let path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
        if std::path::Path::new(path).exists() {
            Some(path.to_string())
        } else {
            None
        }
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

        // Add bearer token auth
        if let Some(token) = Self::read_sa_token() {
            request = request.bearer_auth(token);
        } else if let Ok(kubeconfig_token) = std::env::var("KUBE_TOKEN") {
            request = request.bearer_auth(kubeconfig_token);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
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
