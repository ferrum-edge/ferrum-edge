//! Ferrum Gateway - A high-performance API Gateway and Reverse Proxy built in Rust

pub mod admin;
pub mod circuit_breaker;
pub mod config;
pub mod config_delta;
pub mod connection_pool;
pub mod consumer_index;
#[path = "../custom_plugins/mod.rs"]
pub mod custom_plugins;
pub mod dns;
pub mod dtls;
pub mod grpc;
pub mod health_check;
pub mod http3;
pub mod load_balancer;
pub mod modes;
pub mod plugin_cache;
pub mod plugins;
pub mod proxy;
pub mod retry;
pub mod router_cache;
pub mod tls;

pub use config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
pub use consumer_index::ConsumerIndex;
pub use load_balancer::LoadBalancerCache;
pub use plugin_cache::PluginCache;
pub use proxy::build_backend_url;
pub use router_cache::{RouteMatch, RouterCache};
