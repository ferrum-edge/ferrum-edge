//! Ferrum Edge — A high-performance edge proxy built in Rust.
//!
//! This crate re-exports the public API surface used by integration tests,
//! functional tests, and custom plugins. The binary entry point is in `main.rs`;
//! this `lib.rs` simply makes internal modules accessible to external test crates
//! without duplicating module declarations.

/// The Ferrum Edge binary/crate version (sourced from Cargo.toml at compile time).
pub const FERRUM_VERSION: &str = env!("CARGO_PKG_VERSION");

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
pub mod secrets;
pub mod service_discovery;
pub mod startup;
pub mod tls;

pub use config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
pub use consumer_index::ConsumerIndex;
pub use load_balancer::LoadBalancerCache;
pub use plugin_cache::PluginCache;
pub use proxy::{build_backend_url, build_backend_url_with_target};
pub use router_cache::{RouteMatch, RouterCache};
