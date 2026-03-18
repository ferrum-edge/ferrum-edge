//! Ferrum Gateway - A high-performance API Gateway and Reverse Proxy built in Rust

pub mod admin;
pub mod config;
pub mod connection_pool;
pub mod consumer_index;
pub mod dns;
pub mod grpc;
pub mod http3;
pub mod modes;
pub mod plugin_cache;
pub mod plugins;
pub mod proxy;
pub mod router_cache;
pub mod tls;

pub use config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
pub use consumer_index::ConsumerIndex;
pub use plugin_cache::PluginCache;
pub use proxy::{build_backend_url, find_matching_proxy};
pub use router_cache::RouterCache;
