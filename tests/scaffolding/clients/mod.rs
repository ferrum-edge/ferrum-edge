//! Typed clients for driving [`super::harness::GatewayHarness`]-powered tests.
//!
//! Phase 1 only ships HTTP/1.1. H2/H3/gRPC/WebSocket clients arrive in
//! later phases.

pub mod http1;

pub use http1::{ClientResponse, Http1Client};
