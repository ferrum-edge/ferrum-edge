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

mod common;
mod integration;
mod scaffolding;
