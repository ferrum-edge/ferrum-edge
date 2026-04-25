//! Typed clients for driving [`super::harness::GatewayHarness`]-powered tests.
//!
//! - [`http1`] — `reqwest` wired for HTTP/1.1.
//! - [`http2`] — `reqwest` configured for H2 (via ALPN on TLS, or h2c prior
//!   knowledge).
//! - [`grpc`] — raw `h2`-crate gRPC client. No codegen; tests supply bytes.
//! - [`http3`] — Phase 3 QUIC + HTTP/3 client (uses `quinn` + `h3`).
//! - [`udp`] / [`dtls`] — Phase 4 raw-UDP and DTLS clients.

pub mod dtls;
pub mod grpc;
pub mod http1;
pub mod http2;
pub mod http3;
pub mod udp;

pub use dtls::DtlsClient;
pub use grpc::{GrpcClient, GrpcResponse};
pub use http1::{ClientResponse, Http1Client};
pub use http2::Http2Client;
pub use http3::{Http3Client, Http3Response};
pub use udp::UdpClient;
