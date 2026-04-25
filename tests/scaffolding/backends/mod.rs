//! Scripted backends used by [`super::harness::GatewayHarness`] tests.
//!
//! Each submodule provides a server that accepts a deterministic script of
//! wire-level steps, so tests can reproduce specific failure modes
//! (connection refused, TLS cert expired, body truncated mid-stream, H2
//! stream reset mid-response, gRPC trailers missing, etc.) without reaching
//! for `std::process::Command` or brittle timing.
//!
//! - [`tcp`] — raw TCP
//! - [`tls`] — TLS-terminating wrapper around TCP (includes ALPN scripting)
//! - [`http1`] — HTTP/1.1-aware wrapper around TCP (parses requests, knows
//!   how to split responses)
//! - [`http2`] — HTTP/2 (h2 crate server) for frame-level scripting: GOAWAY,
//!   RST_STREAM, flow-control stalls, etc.
//! - [`grpc`] — gRPC framing on top of [`http2`]: length-prefixed messages,
//!   `grpc-status` trailers, missing-trailer fallbacks.
//! - [`udp`] — raw UDP (per-datagram script; Phase 4)
//! - [`dtls`] — DTLS-terminating wrapper around UDP (Phase 4)
//! - [`http3`] — Phase 3 QUIC + HTTP/3 scripted backend (QUIC-level refusal
//!   + H3-level steps)
//! - [`quic_refuser`] — helper fixture: UDP socket that accepts the first
//!   datagram and immediately CONNECTION_CLOSEs. Simulates "backend used to
//!   speak H3 but stopped".
//! - [`tls_no_quic`] — TCP+TLS helper that advertises `h2` + `http/1.1`
//!   with no QUIC listener on the same port (fixture for "initial
//!   capability probe classifies H3 as Unsupported").

pub mod dtls;
pub mod grpc;
pub mod http1;
pub mod http2;
pub mod http3;
pub mod quic_refuser;
pub mod tcp;
pub mod tls;
pub mod tls_no_quic;
pub mod udp;

pub use dtls::{DtlsConfig, ScriptedDtlsBackend};
pub use grpc::{GrpcStep, MatchRpc, ScriptedGrpcBackend, ScriptedGrpcBackendBuilder};
pub use http1::{HttpStep, Request as Http1Request, RequestMatcher, ScriptedHttp1Backend};
pub use http2::{
    ConnectionSettings, H2Step, MatchHeaders, ReceivedStream, ScriptedH2Backend,
    ScriptedH2BackendBuilder,
};
pub use http3::{H3RecordedRequest, H3Step, H3TlsConfig, ScriptedH3Backend};
pub use quic_refuser::QuicRefuser;
pub use tcp::{ExecutionMode, ScriptedTcpBackend, TcpStep};
pub use tls::{ScriptedTlsBackend, TlsConfig};
pub use tls_no_quic::{tls_backend_without_quic, tls_backend_without_quic_with_ok_response};
pub use udp::{DatagramMatcher, RecordedDatagram, ScriptedUdpBackend, UdpStep};
