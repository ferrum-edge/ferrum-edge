//! `gateway_matrix!` — generate one `#[tokio::test]` per
//! `(frontend, backend)` protocol combination so a single scenario can
//! exercise the gateway against the full cross-protocol surface in one
//! place.
//!
//! ## Why a macro
//!
//! Cross-protocol scenarios share their gateway shape, scripted-backend
//! shape, and assertion text but differ on:
//!
//! - **Frontend client** — how the test actually issues the request
//!   (reqwest H1, reqwest H2, raw `h2` for gRPC, `h3` for QUIC).
//! - **Backend script** — what the scripted backend speaks (TCP / H2 /
//!   H3 / gRPC).
//! - **Skip list** — combinations that don't make protocol sense
//!   (gRPC frontend can't talk to a non-H2 backend; WebSocket-over-H3
//!   isn't deployed; etc.).
//!
//! Writing one `#[tokio::test]` per combination is the right "shape"
//! for the test runner (one test name per combination, isolated
//! failures, clean parallelism) — but copy/paste means a 30-test
//! matrix balloons into hundreds of LOC. The macro expands one
//! invocation into N test functions.
//!
//! ## Canonical invocation
//!
//! ```ignore
//! gateway_matrix! {
//!     name = backend_refuses_returns_502,
//!     frontend = [H1, H2, Grpc],
//!     backend  = [H1, H2, Grpc],
//!     skip     = [(Grpc, H1)],
//!     scenario = |frontend, backend| async move {
//!         let backend_handle = backend.spawn_refuse_connect().await?;
//!         let yaml = backend.file_mode_yaml(backend_handle.port());
//!         let harness = GatewayHarness::builder()
//!             .file_config(yaml)
//!             .spawn().await?;
//!         let response = frontend.send_get(&harness, backend.request_path()).await?;
//!         frontend.assert_status(&response, 502);
//!         Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
//!     }
//! }
//! ```
//!
//! Each generated test has the function name
//! `{name}__{frontend}_to_{backend}` (e.g.
//! `backend_refuses_returns_502__h1_to_h2`). Skipped combinations are
//! not generated.
//!
//! ## Type-safety
//!
//! The closure receives typed kind values
//! ([`FrontendKind`]/[`BackendKind`]) so the implementation can match
//! on them at runtime. Helper methods (`spawn_refuse_connect`,
//! `send_get`, `assert_status`, etc.) live on the kind structs and
//! drive whichever client/backend the kind represents — the scenario
//! closure stays at the abstraction of "exercise an HTTP-like
//! interaction" rather than recreating the dispatch per combination.
//!
//! Adding a new combination to a future scenario:
//!
//! 1. Add the variant to [`FrontendKind`] / [`BackendKind`] (if not
//!    already present).
//! 2. Implement whichever helper methods the scenario needs on the new
//!    variant.
//! 3. Cite the variant in the matrix's `frontend = [...]` /
//!    `backend = [...]` list.
//!
//! See `tests/functional/scripted_backend_matrix_tests.rs` for the
//! demo invocations.

#![allow(dead_code, unused_imports)] // Macro consumers pick subsets.

use std::time::Duration;

use bytes::Bytes;
use reqwest::StatusCode;

use super::backends::{
    GrpcStep, H2Step, HttpStep, MatchHeaders, MatchRpc, RequestMatcher, ScriptedGrpcBackend,
    ScriptedH2Backend, ScriptedHttp1Backend, ScriptedTcpBackend, TcpStep,
};
use super::clients::{ClientResponse, GrpcClient, GrpcResponse, Http1Client, Http2Client};
use super::harness::GatewayHarness;
use super::ports::{PortReservation, reserve_port};

// ────────────────────────────────────────────────────────────────────────────
// Kinds
// ────────────────────────────────────────────────────────────────────────────

/// Frontend (client-side) protocol the matrix iterates over.
///
/// Variants represent the wire-level protocol the *client* speaks
/// when talking to the gateway. The matrix demo works over plaintext
/// to keep harness setup simple — TLS-frontend variants like H3
/// require additional cert plumbing and are reserved for future
/// matrix scenarios.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontendKind {
    /// HTTP/1.1 client (reqwest, plaintext).
    H1,
    /// HTTP/2 client over h2c (reqwest with prior knowledge,
    /// plaintext).
    H2,
    /// HTTP/3 client (QUIC + h3). Reserved — not used by the demo
    /// matrix tests; helper methods panic to surface unimplemented
    /// matrix entries early.
    H3,
    /// WebSocket client. Reserved — same caveat as `H3`.
    WS,
    /// gRPC client over h2c (raw `h2` crate, plaintext).
    Grpc,
}

impl FrontendKind {
    /// A short snake-case label used as the per-test suffix.
    pub fn label(self) -> &'static str {
        match self {
            FrontendKind::H1 => "h1",
            FrontendKind::H2 => "h2",
            FrontendKind::H3 => "h3",
            FrontendKind::WS => "ws",
            FrontendKind::Grpc => "grpc",
        }
    }

    /// Human-readable name. Used for `panic!()` / debug strings.
    pub fn name(self) -> &'static str {
        match self {
            FrontendKind::H1 => "HTTP/1.1",
            FrontendKind::H2 => "HTTP/2 (h2c)",
            FrontendKind::H3 => "HTTP/3 (QUIC)",
            FrontendKind::WS => "WebSocket",
            FrontendKind::Grpc => "gRPC (h2c)",
        }
    }

    /// Whether this frontend is supported by the demo helpers (i.e.,
    /// the scenarios in `scripted_backend_matrix_tests.rs`). Returning
    /// `false` here causes the helper methods below to panic if the
    /// scenario actually invokes them — that's a useful loud failure
    /// for accidentally-included reserved variants.
    pub fn is_demo_supported(self) -> bool {
        matches!(
            self,
            FrontendKind::H1 | FrontendKind::H2 | FrontendKind::Grpc
        )
    }

    /// Issue a `GET <path>` against the gateway, return a unified
    /// status + body shape. The implementation picks the matching
    /// client per variant.
    ///
    /// Panics for reserved variants (H3, WS) — those are not part of
    /// the Phase 6 demo. Adding them is straightforward: implement
    /// `Http3Client` / WebSocket-client integration paths and remove
    /// the panic.
    pub async fn send_get(
        self,
        harness: &GatewayHarness,
        path: &str,
    ) -> Result<MatrixResponse, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            FrontendKind::H1 => {
                let client = Http1Client::insecure()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
                let url = harness.proxy_url(path);
                let resp = client
                    .get(&url)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                Ok(MatrixResponse::Http(resp))
            }
            FrontendKind::H2 => {
                let client = Http2Client::h2c_prior_knowledge()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
                let url = harness.proxy_url(path);
                let resp = client
                    .get(&url)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                Ok(MatrixResponse::Http(resp))
            }
            FrontendKind::Grpc => {
                let target = harness
                    .proxy_base_url()
                    .trim_start_matches("http://")
                    .trim_start_matches("https://");
                let client = GrpcClient::h2c(target);
                let resp = client.unary(path, Bytes::new()).await?;
                Ok(MatrixResponse::Grpc(resp))
            }
            FrontendKind::H3 | FrontendKind::WS => {
                panic!(
                    "FrontendKind::{:?} is reserved for future matrix scenarios; \
                     the Phase 6 demo only exercises H1/H2/Grpc frontends",
                    self
                );
            }
        }
    }

    /// Assert that the response indicates a backend-side failure that
    /// the gateway translated to `expected_http`. For HTTP frontends
    /// this is a direct status check; for gRPC the helper applies the
    /// canonical HTTP-to-gRPC mapping (see
    /// [`GrpcResponse::effective_grpc_status`]) so the same caller
    /// test works across protocols.
    pub fn assert_status(self, response: &MatrixResponse, expected_http: u16) {
        match (self, response) {
            (FrontendKind::H1, MatrixResponse::Http(r))
            | (FrontendKind::H2, MatrixResponse::Http(r)) => {
                assert_eq!(
                    r.status.as_u16(),
                    expected_http,
                    "[{frontend}] expected HTTP {expected_http}, got {actual} body={body:?}",
                    frontend = self.label(),
                    actual = r.status,
                    body = r.body_text()
                );
            }
            (FrontendKind::Grpc, MatrixResponse::Grpc(r)) => {
                let expected_grpc = http_to_grpc_status(expected_http);
                let actual = r.effective_grpc_status();
                assert_eq!(
                    actual,
                    expected_grpc,
                    "[grpc] expected effective grpc-status {expected_grpc} (HTTP {expected_http}), \
                     got {actual} (http_status={http}, stream_error={err:?})",
                    http = r.http_status,
                    err = r.stream_error
                );
            }
            (kind, _) => panic!(
                "FrontendKind::{:?} cannot consume the supplied MatrixResponse",
                kind
            ),
        }
    }
}

/// Backend protocol the matrix iterates over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    /// HTTP/1.1 backend (scripted via [`ScriptedHttp1Backend`] /
    /// [`ScriptedTcpBackend`]).
    H1,
    /// HTTP/2 backend over h2c (scripted via [`ScriptedH2Backend`]).
    H2,
    /// HTTP/3 (QUIC) backend. Reserved — see [`FrontendKind::H3`].
    H3,
    /// gRPC backend over h2c (scripted via [`ScriptedGrpcBackend`]).
    Grpc,
    /// Raw TCP backend (scripted via [`ScriptedTcpBackend`]).
    Tcp,
    /// Raw UDP backend. Reserved — the matrix demo doesn't pair UDP
    /// backends with HTTP frontends.
    Udp,
}

impl BackendKind {
    pub fn label(self) -> &'static str {
        match self {
            BackendKind::H1 => "h1",
            BackendKind::H2 => "h2",
            BackendKind::H3 => "h3",
            BackendKind::Grpc => "grpc",
            BackendKind::Tcp => "tcp",
            BackendKind::Udp => "udp",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            BackendKind::H1 => "HTTP/1.1",
            BackendKind::H2 => "HTTP/2 (h2c)",
            BackendKind::H3 => "HTTP/3 (QUIC)",
            BackendKind::Grpc => "gRPC (h2c)",
            BackendKind::Tcp => "raw TCP",
            BackendKind::Udp => "raw UDP",
        }
    }

    /// Whether the demo helpers can spawn a "refusing" backend of
    /// this kind (used by the demo matrix tests in
    /// `scripted_backend_matrix_tests.rs`).
    pub fn is_demo_supported(self) -> bool {
        matches!(
            self,
            BackendKind::H1 | BackendKind::H2 | BackendKind::Grpc | BackendKind::Tcp
        )
    }

    /// Spawn a backend of this kind that refuses every accepted
    /// connection (one-shot per accept — `RefuseNextConnect`-class
    /// behavior). Returns the running backend handle wrapped so the
    /// caller doesn't need to know the concrete type.
    ///
    /// Panics for reserved variants.
    pub async fn spawn_refuse_connect(
        self,
    ) -> Result<MatrixBackend, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            BackendKind::H1 | BackendKind::Tcp | BackendKind::H2 | BackendKind::Grpc => {
                // For "connection refused" semantics every HTTP-family
                // backend collapses to "accept the TCP, then drop"
                // — the gateway's pool sees the same observable
                // signal regardless of upper-layer protocol.
                let reservation = reserve_port().await?;
                let port = reservation.port;
                let backend = ScriptedTcpBackend::builder(reservation.into_listener())
                    .step(TcpStep::RefuseNextConnect)
                    .spawn()?;
                Ok(MatrixBackend::new_tcp(port, backend))
            }
            BackendKind::H3 | BackendKind::Udp => {
                panic!(
                    "BackendKind::{:?} is reserved for future matrix scenarios; \
                     the Phase 6 demo only exercises H1/H2/Grpc/Tcp backends",
                    self
                );
            }
        }
    }

    /// Spawn a backend that accepts the connection and immediately
    /// resets it (`SO_LINGER=0`). Same observability for all the
    /// HTTP-family backends — the gateway sees ECONNRESET on its
    /// next read/write.
    pub async fn spawn_accept_then_rst(
        self,
    ) -> Result<MatrixBackend, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            BackendKind::H1 | BackendKind::Tcp | BackendKind::H2 | BackendKind::Grpc => {
                let reservation = reserve_port().await?;
                let port = reservation.port;
                let backend = ScriptedTcpBackend::builder(reservation.into_listener())
                    .step(TcpStep::Reset)
                    .spawn()?;
                Ok(MatrixBackend::new_tcp(port, backend))
            }
            BackendKind::H3 | BackendKind::Udp => {
                panic!(
                    "BackendKind::{:?} is reserved for future matrix scenarios; \
                     the Phase 6 demo only exercises H1/H2/Grpc/Tcp backends",
                    self
                );
            }
        }
    }

    /// Build a file-mode YAML config that points one HTTP proxy at
    /// `127.0.0.1:port` over the protocol shape this backend kind
    /// expects. Used in the demo matrix scenarios as the
    /// `harness.file_config(...)` payload.
    pub fn file_mode_yaml(self, port: u16) -> String {
        let listen_path = self.listen_path();
        let backend_scheme = match self {
            BackendKind::H1 | BackendKind::Tcp | BackendKind::H2 | BackendKind::Grpc => "http",
            BackendKind::H3 | BackendKind::Udp => panic!(
                "BackendKind::{:?} not yet wired into matrix file_mode_yaml",
                self
            ),
        };
        let proxy = serde_json::json!({
            "id": format!("matrix-{}", self.label()),
            "listen_path": listen_path,
            "backend_scheme": backend_scheme,
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
        });
        let config = serde_json::json!({
            "proxies": [proxy],
            "consumers": [],
            "upstreams": [],
            "plugin_configs": [],
        });
        serde_yaml::to_string(&config).expect("serialize matrix yaml")
    }

    /// The proxy `listen_path` baked into [`Self::file_mode_yaml`].
    pub fn listen_path(self) -> &'static str {
        match self {
            BackendKind::H1 | BackendKind::Tcp | BackendKind::H2 => "/api",
            BackendKind::Grpc => "/grpc",
            BackendKind::H3 | BackendKind::Udp => panic!(
                "BackendKind::{:?} not yet wired into matrix listen_path",
                self
            ),
        }
    }

    /// The path the demo scenarios use to drive a request through the
    /// gateway. Mirrors [`Self::listen_path`] plus a per-protocol
    /// suffix (e.g. gRPC needs a method name) so the gateway routes
    /// correctly.
    pub fn request_path(self) -> &'static str {
        match self {
            BackendKind::H1 | BackendKind::Tcp | BackendKind::H2 => "/api/x",
            BackendKind::Grpc => "/grpc/svc.Echo/Method",
            BackendKind::H3 | BackendKind::Udp => panic!(
                "BackendKind::{:?} not yet wired into matrix request_path",
                self
            ),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Response + backend wrappers
// ────────────────────────────────────────────────────────────────────────────

/// Response wrapper that hides the concrete client type from the
/// scenario closure. Contains a `ClientResponse` (HTTP) or a
/// `GrpcResponse` and exposes both via accessors so the closure can
/// pick whichever shape it needs.
#[derive(Debug)]
pub enum MatrixResponse {
    /// HTTP/1 or HTTP/2 response.
    Http(ClientResponse),
    /// gRPC response (over h2c). The buffered shape exposes
    /// HTTP status + grpc-status + body.
    Grpc(GrpcResponse),
}

impl MatrixResponse {
    /// HTTP status code if this is an HTTP response. For gRPC, returns
    /// the underlying HTTP status (0 means "no HTTP response received"
    /// — see [`GrpcResponse::http_status`]).
    pub fn http_status(&self) -> u16 {
        match self {
            MatrixResponse::Http(r) => r.status.as_u16(),
            MatrixResponse::Grpc(r) => r.http_status,
        }
    }

    /// Whether the response indicates a 5xx-class gateway error. For
    /// gRPC, true when the effective grpc-status is
    /// UNAVAILABLE/INTERNAL/UNKNOWN — the canonical mapping for
    /// backend-side connection failures.
    pub fn is_gateway_error(&self) -> bool {
        match self {
            MatrixResponse::Http(r) => r.status.is_server_error(),
            MatrixResponse::Grpc(r) => {
                let s = r.effective_grpc_status();
                s == 14 || s == 13 || s == 2 // UNAVAILABLE, INTERNAL, UNKNOWN
            }
        }
    }
}

/// Backend handle returned by the spawn helpers. Holds the running
/// backend so the matrix scenario can drop it at the end of the test
/// without leaking. Generic over backend type via this struct + an
/// internal handle enum.
pub struct MatrixBackend {
    /// Port the backend is listening on.
    port: u16,
    /// The actual scripted backend (kept alive until drop).
    _backend: BackendHandle,
}

#[allow(dead_code)]
enum BackendHandle {
    Tcp(ScriptedTcpBackend),
    Http1(ScriptedHttp1Backend),
    H2(ScriptedH2Backend),
    Grpc(ScriptedGrpcBackend),
}

impl MatrixBackend {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn new_tcp(port: u16, backend: ScriptedTcpBackend) -> Self {
        Self {
            port,
            _backend: BackendHandle::Tcp(backend),
        }
    }

    pub(crate) fn new_http1(port: u16, backend: ScriptedHttp1Backend) -> Self {
        Self {
            port,
            _backend: BackendHandle::Http1(backend),
        }
    }

    pub(crate) fn new_h2(port: u16, backend: ScriptedH2Backend) -> Self {
        Self {
            port,
            _backend: BackendHandle::H2(backend),
        }
    }

    pub(crate) fn new_grpc(port: u16, backend: ScriptedGrpcBackend) -> Self {
        Self {
            port,
            _backend: BackendHandle::Grpc(backend),
        }
    }
}

impl std::fmt::Debug for MatrixBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixBackend")
            .field("port", &self.port)
            .finish()
    }
}

/// Helper to convert an HTTP-status assertion to its gRPC equivalent
/// per the canonical mapping doc.
fn http_to_grpc_status(http: u16) -> u32 {
    match http {
        200 => 0,
        400 => 13,
        401 => 16,
        403 => 7,
        404 => 12,
        429 | 502 | 503 | 504 => 14,
        _ => 2,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// gateway_matrix! macro
// ────────────────────────────────────────────────────────────────────────────

/// Generate one `#[tokio::test] #[ignore]` per `(frontend, backend)`
/// combination NOT in `skip`.
///
/// See module docs for the canonical invocation. The expansion shape
/// per combination is roughly:
///
/// ```ignore
/// #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
/// #[ignore]
/// async fn {name}__{frontend}_to_{backend}() {
///     // Macro-level skip filter: scenario only runs if the pair
///     // is not in the skip list.
///     if matrix_pair_is_skipped(...) { return; }
///     scenario(FrontendKind::{frontend}, BackendKind::{backend}).await?
/// }
/// ```
///
/// Each generated test is `#[ignore]` so it follows the
/// functional-test convention (`cargo test --ignored`).
///
/// ## Skip mechanics
///
/// `macro_rules!` cannot compare two metavariables for equality, so
/// the skip filter happens at *function body* time: every combination
/// gets a generated function, but skipped functions short-circuit on
/// entry without spawning a backend. Skipped tests show as
/// near-instant passes in `cargo test --list` (or `--show-skipped`).
///
/// This was a design tradeoff vs hand-rolling a tt-muncher comparison
/// — the runtime gate is ~10 lines, completely deterministic across
/// rustc versions, and the per-skipped-test overhead (a single
/// matches!) is negligible. Tests that show up but aren't intended
/// to run still expose any compile-time regression in the matrix
/// closure (which IS what the macro is for).
///
/// If a future scenario has a skip list that's too noisy in
/// `cargo test` output, the macro can be extended to take a
/// `skip_strict = true` mode that emits a compile-time test-skip via
/// `#[cfg(any())]` per pair instead. Keeping the simpler form for now.
#[macro_export]
macro_rules! gateway_matrix {
    // Variant 1 — with skip list. We capture the back list and skip
    // list as `tt` groups so they don't try to align with the front
    // iteration; the per-front macro then re-iterates over backs
    // independently.
    (
        name = $name:ident,
        frontend = [ $($front:ident),+ $(,)? ],
        backend  = $backs:tt,
        skip = $skip:tt,
        scenario = $scenario:expr $(,)?
    ) => {
        $(
            $crate::__gateway_matrix_one_front! {
                name = $name,
                scenario = $scenario,
                skip = $skip,
                front = $front,
                backs = $backs,
            }
        )+
    };
    // Variant 2 — no skip list (defaults to empty parens).
    (
        name = $name:ident,
        frontend = [ $($front:ident),+ $(,)? ],
        backend  = $backs:tt,
        scenario = $scenario:expr $(,)?
    ) => {
        $(
            $crate::__gateway_matrix_one_front! {
                name = $name,
                scenario = $scenario,
                skip = (),
                front = $front,
                backs = $backs,
            }
        )+
    };
}

/// For one front, walk every back and emit a test.
///
/// `backs` is a `tt` group like `[H1, H2, Grpc, Tcp]`; the macro
/// reparses it to extract the `:ident` list. By isolating this
/// reparse inside its own arm we avoid trying to align the back
/// list's iteration count with anything else (notably the outer
/// front list and the skip list).
#[doc(hidden)]
#[macro_export]
macro_rules! __gateway_matrix_one_front {
    (
        name = $name:ident,
        scenario = $scenario:expr,
        skip = $skip:tt,
        front = $front:ident,
        backs = [ $($back:ident),+ $(,)? ],
    ) => {
        $(
            $crate::__gateway_matrix_test! {
                name = $name,
                scenario = $scenario,
                front = $front,
                back  = $back,
                skip  = $skip,
            }
        )+
    };
}

/// Innermost: emit the actual `#[tokio::test]`. Uses `paste::paste!`
/// to concatenate the test-name idents at macro-expansion time.
///
/// The skip filter is implemented as a runtime `matches!` against
/// the supplied skip list (see module docs §"Skip mechanics" for why
/// we picked runtime-gating over a tt-muncher).
///
/// Two arms — one for `skip = [ ... ]` (bracketed, the form the
/// user types in `gateway_matrix!`) and one for `skip = ()` (empty
/// parens — the variant-2 default for "no skip list"). Both shapes
/// are flatten-equivalent; we accept both so the inner forwarding
/// chain doesn't need to normalise to one.
#[doc(hidden)]
#[macro_export]
macro_rules! __gateway_matrix_test {
    // Bracketed (or empty bracketed) skip list — the user-facing form.
    (
        name = $name:ident,
        scenario = $scenario:expr,
        front = $front:ident,
        back  = $back:ident,
        skip  = [ $( ($skip_front:ident, $skip_back:ident) ),* $(,)? ],
    ) => {
        $crate::__gateway_matrix_test_emit! {
            name = $name,
            scenario = $scenario,
            front = $front,
            back  = $back,
            skip_pairs = ( $( ($skip_front, $skip_back) ),* ),
        }
    };
    // Parenthesised skip list — used when variant 2 (no skip) forwards `()`.
    (
        name = $name:ident,
        scenario = $scenario:expr,
        front = $front:ident,
        back  = $back:ident,
        skip  = ( $( ($skip_front:ident, $skip_back:ident) ),* $(,)? ),
    ) => {
        $crate::__gateway_matrix_test_emit! {
            name = $name,
            scenario = $scenario,
            front = $front,
            back  = $back,
            skip_pairs = ( $( ($skip_front, $skip_back) ),* ),
        }
    };
}

/// Common emit step: take the normalised skip pairs and produce the
/// final `#[tokio::test]`. Split out so both arms above don't
/// duplicate the body.
#[doc(hidden)]
#[macro_export]
macro_rules! __gateway_matrix_test_emit {
    (
        name = $name:ident,
        scenario = $scenario:expr,
        front = $front:ident,
        back  = $back:ident,
        skip_pairs = ( $( ($skip_front:ident, $skip_back:ident) ),* $(,)? ),
    ) => {
        ::paste::paste! {
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            #[ignore]
            // Generated names use a double-underscore separator
            // (`name__front_to_back`) so a reader scanning
            // `cargo test` output can spot the matrix invocation
            // they belong to; rustc's snake_case lint flags `__` as
            // non-canonical so we silence it for the generated fn.
            #[allow(non_snake_case)]
            async fn [< $name __ $front:lower _to_ $back:lower >]() {
                let f = $crate::scaffolding::matrix::FrontendKind::$front;
                let b = $crate::scaffolding::matrix::BackendKind::$back;
                // Runtime skip filter — see macro docstring.
                let skipped = false $(
                    || (
                        f == $crate::scaffolding::matrix::FrontendKind::$skip_front
                        && b == $crate::scaffolding::matrix::BackendKind::$skip_back
                    )
                )*;
                if skipped {
                    eprintln!(
                        "[gateway_matrix] {}: ({:?} → {:?}) skipped",
                        stringify!($name), f, b
                    );
                    return;
                }
                let scenario = $scenario;
                let result = scenario(f, b).await;
                if let Err(e) = result {
                    panic!(
                        "matrix scenario {} ({} → {}) failed: {}",
                        stringify!($name),
                        stringify!($front),
                        stringify!($back),
                        e
                    );
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_label_round_trip() {
        for &k in &[
            FrontendKind::H1,
            FrontendKind::H2,
            FrontendKind::H3,
            FrontendKind::WS,
            FrontendKind::Grpc,
        ] {
            assert!(!k.label().is_empty());
            assert!(!k.name().is_empty());
        }
    }

    #[test]
    fn backend_label_round_trip() {
        for &k in &[
            BackendKind::H1,
            BackendKind::H2,
            BackendKind::H3,
            BackendKind::Grpc,
            BackendKind::Tcp,
            BackendKind::Udp,
        ] {
            assert!(!k.label().is_empty());
            assert!(!k.name().is_empty());
        }
    }

    #[test]
    fn http_to_grpc_status_canonical_mapping() {
        // Spot-check: the mapping doc's table entries.
        assert_eq!(http_to_grpc_status(200), 0);
        assert_eq!(http_to_grpc_status(400), 13);
        assert_eq!(http_to_grpc_status(401), 16);
        assert_eq!(http_to_grpc_status(403), 7);
        assert_eq!(http_to_grpc_status(404), 12);
        assert_eq!(http_to_grpc_status(429), 14);
        assert_eq!(http_to_grpc_status(502), 14);
        assert_eq!(http_to_grpc_status(503), 14);
        assert_eq!(http_to_grpc_status(504), 14);
        assert_eq!(http_to_grpc_status(418), 2);
    }

    #[test]
    fn yaml_files_are_per_backend_kind() {
        let h1 = BackendKind::H1.file_mode_yaml(8000);
        assert!(h1.contains("listen_path: /api"), "got {h1}");
        assert!(h1.contains("backend_port: 8000"), "got {h1}");

        let grpc = BackendKind::Grpc.file_mode_yaml(8001);
        assert!(grpc.contains("listen_path: /grpc"), "got {grpc}");
        assert!(grpc.contains("backend_port: 8001"), "got {grpc}");
    }

    #[test]
    fn demo_supported_kinds_match_documented_set() {
        // Catches drift if a future PR widens the demo support
        // without updating either side of the contract.
        let supported_fronts: Vec<FrontendKind> = [
            FrontendKind::H1,
            FrontendKind::H2,
            FrontendKind::H3,
            FrontendKind::WS,
            FrontendKind::Grpc,
        ]
        .into_iter()
        .filter(|f| f.is_demo_supported())
        .collect();
        assert_eq!(
            supported_fronts,
            vec![FrontendKind::H1, FrontendKind::H2, FrontendKind::Grpc]
        );

        let supported_backs: Vec<BackendKind> = [
            BackendKind::H1,
            BackendKind::H2,
            BackendKind::H3,
            BackendKind::Grpc,
            BackendKind::Tcp,
            BackendKind::Udp,
        ]
        .into_iter()
        .filter(|b| b.is_demo_supported())
        .collect();
        assert_eq!(
            supported_backs,
            vec![
                BackendKind::H1,
                BackendKind::H2,
                BackendKind::Grpc,
                BackendKind::Tcp
            ]
        );
    }
}
