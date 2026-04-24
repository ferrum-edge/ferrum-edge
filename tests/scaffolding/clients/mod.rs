//! Typed clients for driving [`super::harness::GatewayHarness`]-powered tests.
//!
//! Phase 1 ships HTTP/1.1. Phase 4 adds UDP and DTLS. H2/H3/gRPC/WebSocket
//! clients arrive in later phases (owned by the Phase 2/3 agents).

pub mod dtls;
pub mod http1;
pub mod udp;

pub use dtls::DtlsClient;
pub use http1::{ClientResponse, Http1Client};
pub use udp::UdpClient;
