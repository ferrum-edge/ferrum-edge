//! Phase-6 demo: cross-protocol matrix scenarios driven by the
//! [`gateway_matrix!`] macro.
//!
//! Each `gateway_matrix! { ... }` invocation expands into one
//! `#[tokio::test] #[ignore]` per `(frontend, backend)` combination
//! NOT in the supplied skip list. The scenario closure runs once per
//! combination and is responsible for spawning the backend +
//! gateway, firing the request, and asserting the response.
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_matrix \
//!       -- --ignored --nocapture
//!
//! See `tests/scaffolding/matrix.rs` for the macro internals and the
//! [`crate::scaffolding::matrix::FrontendKind`] /
//! [`crate::scaffolding::matrix::BackendKind`] kind enums.
//!
//! ## Demo coverage
//!
//! The two scenarios below intentionally restrict to the demo-supported
//! frontend / backend kinds (H1, H2, Grpc / H1, H2, Grpc, Tcp). The
//! H3, WS, and UDP variants compile but are reserved for future
//! scenarios — extending those kinds requires wiring the additional
//! client / spawn helpers in `matrix.rs`.

#![allow(clippy::bool_assert_comparison)]

// Macros — `gateway_matrix!` is `#[macro_export]`ed at the test-crate
// root; `crate::gateway_matrix!` reaches it through `tests/functional`.
//
// `BackendKind` and `FrontendKind` are referenced by the macro
// expansion via `$crate::scaffolding::matrix::*`, so we don't import
// them here, but we still bring the kind types into scope for the
// scenario closures below.
use crate::gateway_matrix;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::matrix::{BackendKind, FrontendKind};

// ────────────────────────────────────────────────────────────────────────────
// Scenario 1 — backend refuses the connection.
// ────────────────────────────────────────────────────────────────────────────
//
// For every supported (frontend, backend) combination, point the
// gateway at a backend that accepts then immediately drops every TCP
// connection (`TcpStep::RefuseNextConnect`). The gateway must
// surface the failure as 502 / UNAVAILABLE depending on the frontend.
//
// Generated tests (after skips):
//
//   backend_refuses_returns_502__h1_to_h1
//   backend_refuses_returns_502__h1_to_h2
//   backend_refuses_returns_502__h1_to_grpc
//   backend_refuses_returns_502__h1_to_tcp
//   backend_refuses_returns_502__h2_to_h1
//   backend_refuses_returns_502__h2_to_h2
//   backend_refuses_returns_502__h2_to_grpc
//   backend_refuses_returns_502__h2_to_tcp
//   backend_refuses_returns_502__grpc_to_grpc
//
// Cross-protocol skips: gRPC clients can only target gRPC backends
// in the demo (the gateway routes by content-type and a non-gRPC
// backend would respond with a regular HTTP body that the gRPC
// client would surface as UNKNOWN(2) — distinct error class from
// the "refuse-connect" path we want to assert on).
gateway_matrix! {
    name = backend_refuses_returns_502,
    frontend = [H1, H2, Grpc],
    backend = [H1, H2, Grpc, Tcp],
    skip = [
        // gRPC frontend × non-gRPC backend: the gateway returns the
        // backend's HTTP response verbatim, which a gRPC client
        // surfaces via `effective_grpc_status` as UNKNOWN(2). That's
        // a different signal than UNAVAILABLE-on-refused-connect, so
        // skip these to keep the assertion clean.
        (Grpc, H1),
        (Grpc, H2),
        (Grpc, Tcp),
    ],
    scenario = |frontend: FrontendKind, backend: BackendKind| async move {
        let backend_handle = backend.spawn_refuse_connect().await?;
        let yaml = backend.file_mode_yaml(backend_handle.port());
        let harness = GatewayHarness::builder()
            .file_config(yaml)
            .log_level("info")
            .spawn()
            .await?;

        let response = frontend.send_get(&harness, backend.request_path()).await?;
        // The gateway translates connect-class failures to HTTP 502.
        // The frontend's assert_status maps that to grpc UNAVAILABLE
        // for a gRPC client — see matrix.rs.
        frontend.assert_status(&response, 502);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    },
}

// ────────────────────────────────────────────────────────────────────────────
// Scenario 2 — backend accepts then resets the connection.
// ────────────────────────────────────────────────────────────────────────────
//
// Similar shape to Scenario 1 but the backend accepts the TCP
// handshake then immediately RST's the socket
// (`TcpStep::Reset` — `SO_LINGER=0` then drop). Distinct error
// class from "refuse" — exercises the gateway's "request error"
// classifier rather than its "connect error" classifier.
//
// Generated tests (after skips):
//
//   backend_accepts_then_rst_returns_502__h1_to_h1
//   backend_accepts_then_rst_returns_502__h1_to_h2
//   backend_accepts_then_rst_returns_502__h1_to_grpc
//   backend_accepts_then_rst_returns_502__h1_to_tcp
//   backend_accepts_then_rst_returns_502__h2_to_h1
//   backend_accepts_then_rst_returns_502__h2_to_h2
//   backend_accepts_then_rst_returns_502__h2_to_grpc
//   backend_accepts_then_rst_returns_502__h2_to_tcp
//   backend_accepts_then_rst_returns_502__grpc_to_grpc
gateway_matrix! {
    name = backend_accepts_then_rst_returns_502,
    frontend = [H1, H2, Grpc],
    backend = [H1, H2, Grpc, Tcp],
    skip = [
        (Grpc, H1),
        (Grpc, H2),
        (Grpc, Tcp),
    ],
    scenario = |frontend: FrontendKind, backend: BackendKind| async move {
        let backend_handle = backend.spawn_accept_then_rst().await?;
        let yaml = backend.file_mode_yaml(backend_handle.port());
        let harness = GatewayHarness::builder()
            .file_config(yaml)
            .log_level("info")
            .spawn()
            .await?;

        let response = frontend.send_get(&harness, backend.request_path()).await?;
        frontend.assert_status(&response, 502);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    },
}
