//! Shared functional-test infrastructure.
//!
//! This module consolidates the subprocess-harness, echo-server, and config-builder
//! patterns that were previously copy-pasted across 19+ functional test files. It is
//! intentionally additive: it introduces shared abstractions alongside the
//! existing per-test harnesses, which can migrate incrementally.
//!
//! # Modules
//!
//! - [`gateway_harness`] — [`TestGateway`] spawns the `ferrum-edge` binary as a
//!   subprocess with a retry-on-port-race loop (see CLAUDE.md "Functional test
//!   port allocation — MUST use retry pattern"). Provides a fluent builder for
//!   mode, env vars, JWT, and health-check tuning, plus `Drop` cleanup.
//! - [`echo_servers`] — HTTP/TCP/UDP echo spawners that return pre-bound
//!   listeners. Eliminates the bind-drop-rebind race documented in CLAUDE.md
//!   ("Backend/echo server ports should be held, not dropped").
//! - [`config_builder`] — Fluent JSON/YAML builders for `GatewayConfig`,
//!   `Proxy`, `Consumer`, `Upstream`, `PluginConfig`. Writes to the harness's
//!   temp dir; returns `serde_json::Value` so the same bodies can drive the
//!   admin API or file-mode YAML.
//!
//! # Usage
//!
//! ```ignore
//! use crate::common::{TestGateway, spawn_http_echo, ProxyBuilder};
//!
//! #[tokio::test]
//! #[ignore]
//! async fn my_test() {
//!     let echo = spawn_http_echo().await;
//!     let gw = TestGateway::builder()
//!         .mode_database_sqlite()
//!         .spawn()
//!         .await
//!         .expect("spawn gateway");
//!
//!     let client = reqwest::Client::new();
//!     let proxy = ProxyBuilder::new("echo")
//!         .listen_path("/echo")
//!         .backend("127.0.0.1", echo.port)
//!         .build();
//!     client
//!         .post(gw.admin_url("/proxies"))
//!         .header("Authorization", gw.auth_header())
//!         .json(&proxy)
//!         .send()
//!         .await
//!         .unwrap();
//! }
//! ```
//!
//! The module is `#![allow(dead_code, unused_imports)]` because individual
//! tests consume only the subset of helpers they need (same pattern as
//! `functional/namespace_helpers.rs`). `unused_imports` covers the pub
//! re-exports below, which stay warning-clean while the migration is in
//! progress — once callers in later PRs import them, the allow is a no-op.
#![allow(dead_code, unused_imports)]

pub mod backend_availability;
pub mod config_builder;
pub mod echo_servers;
pub mod gateway_harness;
pub mod hmac_helpers;
pub mod protocol_managed_response_headers;

pub use backend_availability::{
    IsolatedSqlDatabase, continue_if_backend_available, continue_if_tls_fixture_available,
    db_backends_required, db_tls_required, ensure_shared_sql_containers_resumed,
    host_port_from_db_url, mysql_test_url, postgres_test_url, provision_isolated_sql_database,
    tcp_endpoint_reachable,
};
pub use config_builder::{
    ConsumerBuilder, GatewayConfigBuilder, PluginConfigBuilder, ProxyBuilder, UpstreamBuilder,
    write_yaml_value,
};
pub use echo_servers::{
    EchoServer, spawn_http_echo, spawn_http_flapping, spawn_http_identifying,
    spawn_http_slow_identifying, spawn_http_status, spawn_tcp_echo, spawn_udp_echo,
};
pub use gateway_harness::{
    DbType, GatewayMode, TestGateway, TestGatewayBuilder, configure_coverage_gateway_command,
    ensure_gateway_built, ephemeral_port, explicit_test_binary, probe_gateway_identity,
    scrub_gateway_capture_for_diagnostics, shutdown_gateway_child,
};
pub use hmac_helpers::{
    empty_digest_header, generate_hmac_signature, generate_hmac_signature_with_digest,
    generate_hmac_signature_with_query, hmac_authority_from_url,
};
