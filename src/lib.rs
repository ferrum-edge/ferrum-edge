//! Ferrum Gateway - A high-performance API Gateway and Reverse Proxy built in Rust

pub mod admin;
pub mod config;
pub mod connection_pool;
pub mod dns;
pub mod grpc;
pub mod modes;
pub mod plugins;
pub mod proxy;
pub mod tls;

pub use config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
pub use proxy::{build_backend_url, find_matching_proxy};
