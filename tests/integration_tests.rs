//! Integration Tests
//!
//! Tests that verify interactions between multiple modules.
//! These tests may use in-process servers, mock certificates, or database connections
//! but do not spawn the gateway binary.
//!
//! Categories:
//!   - backend_mtls: Backend mutual TLS with client certificates
//!   - connection_pool: Connection pooling with real connections
//!   - cp_dp_grpc: Control Plane / Data Plane gRPC communication
//!   - http3: HTTP/3 flow (client → gateway → backend)
//!   - websocket_gateway: WebSocket gateway routing
//!
//! Run with: cargo test --test integration_tests

// Process-wide tracing interest floor shared by every thread-local log
// capture in this binary (see tests/support/diagnostic_interest.rs).
#[allow(dead_code, unused_imports, unused_macros)]
#[path = "support/diagnostic_interest.rs"]
pub(crate) mod diagnostic_test_interest;

mod common;
mod integration;
mod scaffolding;
