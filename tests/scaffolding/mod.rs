//! Scripted-backend test framework (Phase 1).
//!
//! This crate-internal module provides reusable scaffolding for writing
//! failure-mode tests against the ferrum-edge gateway. Tests get:
//!
//! - [`ports::reserve_port`] — a port held by a live `TcpListener` (no
//!   drop-rebind race).
//! - [`certs::TestCa`] — a self-signed test CA with `valid` / `expired` /
//!   `not_yet_valid` / `wrong_san` / `self_signed` leaf-cert presets.
//! - [`backends::ScriptedTcpBackend`] — TCP server replaying a script of
//!   [`backends::TcpStep`]s.
//! - [`backends::ScriptedTlsBackend`] — TLS-terminating wrapper, with
//!   ALPN scripting for H2 ALPN-fallback tests.
//! - [`backends::ScriptedHttp1Backend`] — HTTP/1.1-aware server with
//!   [`backends::HttpStep`]s covering normal and pathological responses.
//! - [`harness::GatewayHarness`] — high-level builder that spawns
//!   ferrum-edge, wires up admin JWT, exposes `http_client` / `metrics` /
//!   `health` / `reload`.
//! - [`clients::Http1Client`] — a `reqwest`-backed client tuned for the
//!   harness (insecure TLS, short timeout, buffered response).
//!
//! Phase 1 acceptance tests live under `tests/functional/scripted_backend/`
//! (binary mode) and `tests/integration/scripted_backend/` (in-process
//! smoke tests).
//!
//! # Canonical usage
//!
//! ```ignore
//! use crate::scaffolding::*;
//!
//! let reservation = ports::reserve_port().await?;
//! let port = reservation.port;
//! let _backend = backends::ScriptedTcpBackend::builder(reservation.into_listener())
//!     .step(backends::TcpStep::RefuseNextConnect)
//!     .spawn()?;
//!
//! let yaml = file_mode_yaml_for_backend(port);
//! let harness = harness::GatewayHarness::builder().file_config(yaml).spawn().await?;
//!
//! let client = harness.http_client()?;
//! let resp = client.get(&harness.proxy_url("/api/x")).await?;
//! assert_eq!(resp.status, reqwest::StatusCode::BAD_GATEWAY);
//! ```
//!
//! See the `scripted_backend_*` test files for complete examples.

#![allow(dead_code, unused_imports)] // Phase-1 scaffolding: individual tests use subsets.

pub mod backends;
pub mod certs;
pub mod clients;
pub mod harness;
pub mod network;
pub mod ports;

// Curated re-exports so a test's imports fit on one line.
pub use backends::{
    ConnectionSettings, DatagramMatcher, DtlsConfig, ExecutionMode, GrpcStep, H2Step,
    H3RecordedRequest, H3Step, H3TlsConfig, Http1Request, HttpStep, MatchHeaders, MatchRpc,
    QuicRefuser, ReceivedStream, RecordedDatagram, RequestMatcher, ScriptedDtlsBackend,
    ScriptedGrpcBackend, ScriptedH2Backend, ScriptedH3Backend, ScriptedHttp1Backend,
    ScriptedTcpBackend, ScriptedTlsBackend, ScriptedUdpBackend, TcpStep, TlsConfig,
    UdpSocketReservation, UdpStep, tls_backend_without_quic,
    tls_backend_without_quic_with_ok_response,
};
pub use certs::TestCa;
pub use clients::{
    ClientResponse, DtlsClient, GrpcClient, GrpcResponse, Http1Client, Http2Client, Http3Client,
    Http3Response, UdpClient,
};
pub use harness::{GatewayHarness, GatewayHarnessBuilder, HarnessMode};
pub use network::{
    BandwidthLimitedStream, DelayedStream, NetworkProfile, NetworkSimProxy, NetworkSimProxyBuilder,
    TruncatedStream,
};
pub use ports::{
    PortReservation, UdpPortReservation, reserve_port, reserve_port_pair, reserve_udp_port,
    unbound_port, unbound_udp_port,
};

// Small helpers that several acceptance tests reuse.

use serde_json::Value;

/// Build a minimal file-mode YAML config that points one HTTP proxy at a
/// plain HTTP backend on `127.0.0.1:<port>`, with a listen path of `/api`.
/// Use this as the default config for acceptance tests that don't exercise
/// the config-reload path.
pub fn file_mode_yaml_for_backend(port: u16) -> String {
    file_mode_yaml_for_backend_with(port, Value::Null)
}

/// Build file-mode YAML for an HTTPS backend on `127.0.0.1:<port>`.
/// `backend_read_timeout_ms` defaults to 5000 — callers can override via
/// [`file_mode_yaml_for_backend_with`].
pub fn file_mode_yaml_for_https_backend(port: u16) -> String {
    file_mode_yaml_for_backend_with(
        port,
        serde_json::json!({
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_tls_verify_server_cert": false,
        }),
    )
}

/// Build file-mode YAML with explicit overrides. `overrides` is merged
/// into the default proxy body so tests can tweak a single field (e.g.,
/// `backend_read_timeout_ms`) without rebuilding the whole config.
///
/// `overrides` may be [`Value::Null`] if the defaults are enough.
pub fn file_mode_yaml_for_backend_with(port: u16, overrides: Value) -> String {
    let mut proxy = serde_json::json!({
        "id": "scripted",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
    });
    if let (Some(proxy_obj), Some(overrides_obj)) = (proxy.as_object_mut(), overrides.as_object()) {
        for (k, v) in overrides_obj {
            proxy_obj.insert(k.clone(), v.clone());
        }
    }
    // The file-mode loader is strict — every top-level collection must be
    // present, even if empty. Otherwise startup fails with "missing field
    // `consumers`".
    let config = serde_json::json!({
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    to_yaml(&config)
}

fn to_yaml(value: &Value) -> String {
    serde_yaml::to_string(value).expect("serialize yaml")
}
