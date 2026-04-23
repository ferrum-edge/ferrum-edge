//! Backend capability registry keyed by deduplicated backend target identity.
//!
//! The request hot path consults this registry to decide whether plain HTTPS
//! traffic should use the native HTTP/3 pool, the direct HTTP/2 pool, or the
//! generic reqwest path. Capabilities are learned at startup and refreshed by
//! a background task so protocol discovery stays out of the hot proxy path.

use dashmap::DashMap;
use std::fmt::Write;
use std::sync::Arc;

use crate::config::types::{BackendScheme, Proxy, UpstreamTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSupport {
    Unknown,
    Supported,
    Unsupported,
}

impl ProtocolSupport {
    #[inline]
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainHttpCapabilities {
    pub h1: ProtocolSupport,
    pub h2_tls: ProtocolSupport,
    pub h3: ProtocolSupport,
}

impl Default for PlainHttpCapabilities {
    fn default() -> Self {
        Self {
            h1: ProtocolSupport::Unknown,
            h2_tls: ProtocolSupport::Unknown,
            h3: ProtocolSupport::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcTransportCapabilities {
    pub h2_tls: ProtocolSupport,
    pub h2c: ProtocolSupport,
}

impl Default for GrpcTransportCapabilities {
    fn default() -> Self {
        Self {
            h2_tls: ProtocolSupport::Unknown,
            h2c: ProtocolSupport::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketTransport {
    Ws,
    Wss,
}

#[derive(Debug, Clone)]
pub struct BackendCapabilityRecord {
    #[allow(dead_code)]
    pub scheme: BackendScheme,
    pub plain_http: PlainHttpCapabilities,
    pub grpc_transport: GrpcTransportCapabilities,
    #[allow(dead_code)]
    pub websocket_transport: WebSocketTransport,
    pub last_probe_at_unix_secs: u64,
    pub last_probe_error: Option<String>,
}

impl BackendCapabilityRecord {
    pub fn for_scheme(scheme: BackendScheme) -> Self {
        Self {
            scheme,
            plain_http: PlainHttpCapabilities::default(),
            grpc_transport: GrpcTransportCapabilities::default(),
            websocket_transport: match scheme {
                BackendScheme::Https => WebSocketTransport::Wss,
                _ => WebSocketTransport::Ws,
            },
            last_probe_at_unix_secs: now_unix_secs(),
            last_probe_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendCapabilityProbeTarget {
    pub key: String,
    pub host: String,
    pub port: u16,
    pub proxy: Proxy,
}

impl BackendCapabilityProbeTarget {
    pub fn from_proxy(proxy: &Proxy, target: Option<&UpstreamTarget>) -> Self {
        let mut target_proxy = proxy.clone();
        if let Some(target) = target {
            target_proxy.backend_host = target.host.clone();
            target_proxy.backend_port = target.port;
        }

        let key = capability_key(&target_proxy);
        Self {
            key,
            host: target_proxy.backend_host.clone(),
            port: target_proxy.backend_port,
            proxy: target_proxy,
        }
    }

    #[inline]
    pub fn scheme(&self) -> BackendScheme {
        self.proxy.backend_scheme.unwrap_or(BackendScheme::Https)
    }
}

#[derive(Debug, Default)]
pub struct BackendCapabilityRegistry {
    entries: DashMap<String, Arc<BackendCapabilityRecord>>,
}

impl BackendCapabilityRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub fn get(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
    ) -> Option<Arc<BackendCapabilityRecord>> {
        let key = capability_key_for_proxy_target(proxy, target);
        self.entries.get(&key).map(|entry| entry.value().clone())
    }

    pub fn upsert(&self, key: String, record: BackendCapabilityRecord) {
        self.entries
            .entry(key)
            .and_modify(|entry| *entry = Arc::new(record.clone()))
            .or_insert_with(|| Arc::new(record));
    }

    pub fn retain_keys(&self, active_keys: &std::collections::HashSet<String>) {
        self.entries.retain(|key, _| active_keys.contains(key));
    }
}

pub fn capability_key_for_proxy_target(proxy: &Proxy, target: Option<&UpstreamTarget>) -> String {
    let mut target_proxy = proxy.clone();
    if let Some(target) = target {
        target_proxy.backend_host = target.host.clone();
        target_proxy.backend_port = target.port;
    }
    capability_key(&target_proxy)
}

pub fn capability_key(proxy: &Proxy) -> String {
    let scheme = proxy.backend_scheme.unwrap_or(BackendScheme::Https);
    let mut key = String::with_capacity(196);
    let _ = write!(
        key,
        "{}|{}|{}|{}|",
        scheme.to_scheme_str(),
        proxy.backend_host,
        proxy.backend_port,
        proxy.dns_override.as_deref().unwrap_or_default(),
    );
    key.push_str(
        proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .unwrap_or_default(),
    );
    key.push('|');
    key.push_str(
        proxy
            .resolved_tls
            .client_cert_path
            .as_deref()
            .unwrap_or_default(),
    );
    key.push('|');
    key.push_str(
        proxy
            .resolved_tls
            .client_key_path
            .as_deref()
            .unwrap_or_default(),
    );
    key.push('|');
    key.push(if proxy.resolved_tls.verify_server_cert {
        '1'
    } else {
        '0'
    });
    key
}

#[inline]
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub type SharedBackendCapabilityRegistry = Arc<BackendCapabilityRegistry>;
