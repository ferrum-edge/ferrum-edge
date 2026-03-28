//! DNS-SD service discovery using SRV records.
//!
//! Queries DNS SRV records for a service name and converts the results
//! into upstream targets. Reuses the gateway's existing DnsCache resolver
//! so that custom nameservers and DNS configuration are respected.

use crate::config::types::UpstreamTarget;
use crate::dns::DnsCache;
use std::collections::HashMap;

/// DNS-SD service discoverer.
///
/// Resolves SRV records for the configured service name and converts
/// each SRV record into an `UpstreamTarget`.
pub struct DnsSdDiscoverer {
    dns_cache: DnsCache,
    service_name: String,
    default_weight: u32,
}

impl DnsSdDiscoverer {
    pub fn new(dns_cache: DnsCache, service_name: String, default_weight: u32) -> Self {
        Self {
            dns_cache,
            service_name,
            default_weight,
        }
    }
}

#[async_trait::async_trait]
impl super::ServiceDiscoverer for DnsSdDiscoverer {
    async fn discover(&self) -> Result<Vec<UpstreamTarget>, anyhow::Error> {
        let srv_results = self.dns_cache.resolve_srv(&self.service_name).await?;

        let targets: Vec<UpstreamTarget> = srv_results
            .into_iter()
            .map(|(host, port, weight)| UpstreamTarget {
                host,
                port,
                weight: if weight > 0 {
                    weight as u32
                } else {
                    self.default_weight
                },
                tags: HashMap::new(),
                path: None,
            })
            .collect();

        Ok(targets)
    }

    fn provider_name(&self) -> &str {
        "dns_sd"
    }
}
