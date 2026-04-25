//! Functional Tests
//!
//! End-to-end tests that spawn the actual ferrum-edge binary and exercise
//! the full system. These tests are marked with #[ignore] and must be run
//! explicitly since they require the binary to be compiled first.
//!
//! Tests:
//!   - functional_cp_dp_test: CP/DP mode with gRPC, database TLS config
//!   - functional_database_test: Database mode with SQLite, Admin API, proxy routing
//!   - functional_db_outage_test: DB outage resilience (proxy+plugins continue, admin reads/writes)
//!   - functional_db_tls_test: Database TLS (PostgreSQL/MySQL/SQLite) connectivity + CRUD
//!   - functional_db_upstream_test: Upstream management via database mode
//!   - functional_file_mode_test: File mode with YAML config, SIGHUP reload
//!   - functional_grpc_test: gRPC reverse proxy
//!   - functional_load_balancer_test: Load balancing algorithms
//!   - functional_load_stress_test: Load & stress (10k proxies, 30k plugins, mixed auth/payloads, admin mutations)
//!   - functional_mtls_test: TLS/mTLS security (frontend mTLS, backend CA verification, gateway-as-mTLS-client, admin mTLS)
//!   - functional_scale_perf_test: Scale performance (0→30k proxies with auth+ACL, throughput degradation)
//!   - functional_tcp_proxy_test: Raw TCP stream proxying
//!   - functional_udp_proxy_test: UDP datagram proxying
//!   - functional_websocket_test: WebSocket proxying
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture

mod common;
mod functional;
mod scaffolding;
mod scenarios;
