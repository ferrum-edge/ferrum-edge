//! Scripted backends used by [`super::harness::GatewayHarness`] tests.
//!
//! Each submodule provides a server that accepts a deterministic script of
//! wire-level steps, so tests can reproduce specific failure modes
//! (connection refused, TLS cert expired, body truncated mid-stream, etc.)
//! without reaching for `std::process::Command` or brittle timing.
//!
//! - [`tcp`] — raw TCP
//! - [`tls`] — TLS-terminating wrapper around TCP (includes ALPN scripting)
//! - [`http1`] — HTTP/1.1-aware wrapper around TCP (parses requests, knows
//!   how to split responses)
//! - [`udp`] — raw UDP (per-datagram script; added in Phase 4)
//! - [`dtls`] — DTLS-terminating wrapper around UDP (Phase 4)

pub mod dtls;
pub mod http1;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use dtls::{DtlsConfig, ScriptedDtlsBackend};
pub use http1::{HttpStep, Request as Http1Request, RequestMatcher, ScriptedHttp1Backend};
pub use tcp::{ExecutionMode, ScriptedTcpBackend, TcpStep};
pub use tls::{ScriptedTlsBackend, TlsConfig};
pub use udp::{DatagramMatcher, RecordedDatagram, ScriptedUdpBackend, UdpStep};
