//! `ScriptedGrpcBackend` — gRPC-aware wrapper around
//! [`super::http2::ScriptedH2Backend`].
//!
//! Adds the wire-level pieces that differentiate gRPC from plain HTTP/2:
//!
//! - **Length-prefixed messages**: each gRPC DATA payload is a 5-byte
//!   header (1 compressed-flag byte + 4-byte big-endian length) followed
//!   by the serialized message.
//! - **Trailers**: gRPC uses HTTP/2 trailers for `grpc-status` + optional
//!   `grpc-message`. Status 0 is success; anything else is an error.
//! - **`:path`-based routing**: `ExpectRpc` matches on the `:path`
//!   pseudo-header (the gRPC method in canonical form
//!   `/pkg.Service/Method`).
//!
//! The goal is to let a test write:
//!
//! ```ignore
//! let backend = ScriptedGrpcBackend::builder(listener)
//!     .step(GrpcStep::AcceptRpc(MatchRpc::method("/ferrum.Echo/Ping")))
//!     .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
//!     .step(GrpcStep::RespondStatus {
//!         code: 0,
//!         message: "",
//!     })
//!     .spawn_plain()?;
//! ```
//!
//! and get a backend that answers one Ping RPC. No `.proto`, no tonic
//! server, no protobuf encoding — the test supplies whatever byte payload
//! it wants.
//!
//! See [`GrpcStep`] for the full step set.

use super::http2::{
    ConnectionSettings, H2Step, MatchHeaders, ReceivedStream, ScriptedH2Backend,
    ScriptedH2BackendBuilder,
};
use bytes::{BufMut, Bytes, BytesMut};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// A matcher over a gRPC RPC's `:path` / headers.
#[derive(Clone)]
pub struct MatchRpc(Arc<dyn Fn(&ReceivedStream) -> bool + Send + Sync>);

impl std::fmt::Debug for MatchRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchRpc").finish()
    }
}

impl MatchRpc {
    /// Match any RPC.
    pub fn any() -> Self {
        Self(Arc::new(|_| true))
    }

    /// Match the canonical gRPC path `/pkg.Service/Method`.
    pub fn method(path: &'static str) -> Self {
        Self(Arc::new(move |s: &ReceivedStream| s.path == path))
    }

    /// Match on a custom closure.
    pub fn custom<F>(f: F) -> Self
    where
        F: Fn(&ReceivedStream) -> bool + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }
}

/// A single deterministic gRPC script instruction.
#[derive(Clone, Debug)]
pub enum GrpcStep {
    /// Accept an RPC (the next incoming H2 stream) and match its `:path`
    /// against `matcher`. Internally emits an
    /// [`super::http2::H2Step::ExpectHeaders`] with the matcher adapted,
    /// followed by `DrainRequestBody` (gRPC unary requests always have a
    /// body). A mismatch increments `matcher_mismatches`; the script
    /// continues.
    AcceptRpc(MatchRpc),
    /// Send response headers for the current RPC. Default
    /// `content-type: application/grpc`. Callers may add/replace via
    /// [`Self::RespondHeadersOverride`].
    SendInitialHeaders,
    /// Send response headers with an explicit header list. Use when a test
    /// needs to exercise non-default content-type (e.g. `application/grpc+proto`)
    /// or omit `content-type` entirely.
    SendInitialHeadersOverride(Vec<(&'static str, String)>),
    /// Send a gRPC length-prefixed message as the next DATA frame. The
    /// 5-byte gRPC header is prepended for you (flag=0, big-endian length).
    RespondMessage(Bytes),
    /// Send the gRPC status trailer (`grpc-status: <code>` and
    /// `grpc-message: <message>` when non-empty). Implicitly closes the
    /// stream.
    RespondStatus { code: u8, message: &'static str },
    /// Send response headers + an optional payload, then close the stream
    /// WITHOUT any `grpc-status` trailer. Exercises the gateway's
    /// "missing trailers" INTERNAL fallback.
    ///
    /// The body may be empty, in which case the stream is closed via an
    /// `end_stream=true` DATA with no payload.
    OmitTrailers { body: Option<Bytes> },
    /// Send response headers, then sleep for `duration` without sending
    /// any DATA frames. Pair with `backend_read_timeout_ms` on the gateway
    /// side to exercise read-timeout classification.
    StallAfterHeaders(Duration),
    /// Send response headers, then close the underlying TCP connection
    /// (no DATA, no trailers, no GOAWAY). Models a backend that crashes
    /// mid-stream.
    CloseAfterHeaders,
    /// Send a GOAWAY with `error_code`, then close.
    SendGoaway { error_code: u32 },
    /// Send RST_STREAM on the current stream with `error_code`.
    SendRstStream { error_code: u32 },
}

/// Fluent builder for [`ScriptedGrpcBackend`].
pub struct ScriptedGrpcBackendBuilder {
    h2_builder: ScriptedH2BackendBuilder,
}

impl ScriptedGrpcBackendBuilder {
    /// Start a builder over a plain TCP listener (h2c). Use this when the
    /// gateway routes to the scripted backend via `backend_scheme: http`
    /// (the gRPC pool will perform an h2c handshake rather than TLS).
    pub fn plain(listener: TcpListener) -> Self {
        Self {
            h2_builder: ScriptedH2BackendBuilder::plain(listener),
        }
    }

    /// Start a builder over a TLS-terminated listener with ALPN `h2`. Use
    /// when the gateway routes via `backend_scheme: https`.
    pub fn tls(listener: TcpListener, cert_pem: &str, key_pem: &str) -> std::io::Result<Self> {
        let inner = ScriptedH2BackendBuilder::tls(listener, cert_pem, key_pem)?;
        Ok(Self { h2_builder: inner })
    }

    /// Append a gRPC step. Translates into one or more
    /// [`super::http2::H2Step`]s under the hood.
    pub fn step(self, step: GrpcStep) -> Self {
        let Self { mut h2_builder } = self;
        for h2 in lower_grpc_step(step) {
            h2_builder = h2_builder.step(h2);
        }
        Self { h2_builder }
    }

    /// Append multiple gRPC steps.
    pub fn steps(mut self, steps: impl IntoIterator<Item = GrpcStep>) -> Self {
        for s in steps {
            self = self.step(s);
        }
        self
    }

    /// Override pre-handshake H2 settings (window sizes, max concurrent
    /// streams).
    pub fn with_settings(mut self, settings: ConnectionSettings) -> Self {
        self.h2_builder = self.h2_builder.with_settings(settings);
        self
    }

    /// Spawn the backend.
    pub fn spawn(self) -> std::io::Result<ScriptedGrpcBackend> {
        let inner = self.h2_builder.spawn()?;
        Ok(ScriptedGrpcBackend { inner })
    }
}

/// A running scripted gRPC backend. Drop shuts it down.
///
/// Observability surface delegates to the underlying
/// [`ScriptedH2Backend`]; gRPC-level metadata (method path, grpc-status
/// seen) is available through `received_streams()`.
pub struct ScriptedGrpcBackend {
    inner: ScriptedH2Backend,
}

impl ScriptedGrpcBackend {
    /// Builder for plain h2c.
    pub fn builder_plain(listener: TcpListener) -> ScriptedGrpcBackendBuilder {
        ScriptedGrpcBackendBuilder::plain(listener)
    }

    /// Builder for h2 over TLS.
    pub fn builder_tls(
        listener: TcpListener,
        cert_pem: &str,
        key_pem: &str,
    ) -> std::io::Result<ScriptedGrpcBackendBuilder> {
        ScriptedGrpcBackendBuilder::tls(listener, cert_pem, key_pem)
    }

    /// Port the backend is listening on.
    pub fn port(&self) -> u16 {
        self.inner.port
    }

    /// Raw TCP accepts.
    pub fn accepted_connections(&self) -> u32 {
        self.inner.accepted_connections()
    }

    /// Completed H2 handshakes.
    pub fn handshakes_completed(&self) -> u32 {
        self.inner.handshakes_completed()
    }

    /// Every RPC observed by `AcceptRpc`, in arrival order.
    pub async fn received_streams(&self) -> Vec<ReceivedStream> {
        self.inner.received_streams().await
    }

    /// Count of RPCs accepted.
    pub fn received_stream_count(&self) -> u32 {
        self.inner.received_stream_count()
    }

    /// Count of `AcceptRpc` matchers that returned `false`. See
    /// [`Self::assert_no_matcher_mismatches`].
    pub fn matcher_mismatches(&self) -> u32 {
        self.inner.matcher_mismatches()
    }

    /// Panic if any matcher mismatched.
    pub async fn assert_no_matcher_mismatches(&self) {
        self.inner.assert_no_matcher_mismatches().await
    }

    /// Non-empty after a script step failed to execute.
    pub async fn step_errors(&self) -> Vec<String> {
        self.inner.step_errors().await
    }

    /// Panic if any step failed.
    pub async fn assert_no_step_errors(&self) {
        self.inner.assert_no_step_errors().await
    }

    /// Signal shutdown + abort.
    pub fn shutdown(&mut self) {
        self.inner.shutdown();
    }
}

impl Drop for ScriptedGrpcBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Lower one gRPC step into the corresponding H2 steps that drive the
/// scripted H2 backend.
fn lower_grpc_step(step: GrpcStep) -> Vec<H2Step> {
    match step {
        GrpcStep::AcceptRpc(matcher) => {
            // Adapt MatchRpc → MatchHeaders so the H2 backend can use it.
            let match_headers = MatchHeaders::custom(move |s| (matcher.0)(s));
            vec![
                H2Step::ExpectHeaders(match_headers),
                H2Step::DrainRequestBody,
            ]
        }
        GrpcStep::SendInitialHeaders => vec![H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ])],
        GrpcStep::SendInitialHeadersOverride(headers) => vec![H2Step::RespondHeaders(headers)],
        GrpcStep::RespondMessage(body) => {
            // gRPC frame: 1 byte compressed flag + 4 bytes BE length +
            // message bytes.
            let mut buf = BytesMut::with_capacity(body.len() + 5);
            buf.put_u8(0);
            buf.put_u32(body.len() as u32);
            buf.extend_from_slice(&body);
            vec![H2Step::RespondData {
                data: buf.freeze(),
                end_stream: false,
            }]
        }
        GrpcStep::RespondStatus { code, message } => {
            let mut trailers = vec![("grpc-status", code.to_string())];
            if !message.is_empty() {
                trailers.push(("grpc-message", message.to_string()));
            }
            vec![H2Step::RespondTrailers(trailers)]
        }
        GrpcStep::OmitTrailers { body } => {
            let headers = H2Step::RespondHeaders(vec![
                (":status", "200".into()),
                ("content-type", "application/grpc".into()),
            ]);
            let data = match body {
                Some(payload) => {
                    let mut buf = BytesMut::with_capacity(payload.len() + 5);
                    buf.put_u8(0);
                    buf.put_u32(payload.len() as u32);
                    buf.extend_from_slice(&payload);
                    H2Step::RespondData {
                        data: buf.freeze(),
                        end_stream: true,
                    }
                }
                None => H2Step::RespondData {
                    data: Bytes::new(),
                    end_stream: true,
                },
            };
            vec![headers, data]
        }
        GrpcStep::StallAfterHeaders(d) => vec![
            H2Step::RespondHeaders(vec![
                (":status", "200".into()),
                ("content-type", "application/grpc".into()),
            ]),
            H2Step::Sleep(d),
        ],
        GrpcStep::CloseAfterHeaders => vec![
            H2Step::RespondHeaders(vec![
                (":status", "200".into()),
                ("content-type", "application/grpc".into()),
            ]),
            H2Step::DropConnection,
        ],
        GrpcStep::SendGoaway { error_code } => vec![H2Step::SendGoawayAndClose { error_code }],
        GrpcStep::SendRstStream { error_code } => vec![H2Step::SendRstStream { error_code }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_port;
    use bytes::Bytes;
    use h2::client as h2_client;
    use http::Request as HttpRequest;
    use tokio::net::TcpStream;

    /// Happy-path: a backend answers a Unary RPC with a well-formed gRPC
    /// message and a zero grpc-status.
    #[tokio::test]
    async fn grpc_unary_happy_path_over_h2c() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
            .step(GrpcStep::AcceptRpc(MatchRpc::method("/ferrum.Echo/Ping")))
            .step(GrpcStep::SendInitialHeaders)
            .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
            .step(GrpcStep::RespondStatus {
                code: 0,
                message: "",
            })
            .spawn()
            .expect("spawn");

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let (mut send_req, connection) = h2_client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(connection);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("http://127.0.0.1:{port}/ferrum.Echo/Ping"))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .expect("req");
        let (response_fut, mut req_body) = send_req.send_request(req, false).expect("send_request");
        // Send a dummy gRPC message (5-byte header + empty body, or body).
        let mut buf = BytesMut::with_capacity(5);
        buf.put_u8(0);
        buf.put_u32(0);
        req_body.send_data(buf.freeze(), true).expect("send body");
        let response = response_fut.await.expect("response");
        assert_eq!(response.status().as_u16(), 200);
        let (_, mut body) = response.into_parts();
        let mut data = Vec::new();
        while let Some(frame) = body.data().await {
            let chunk = frame.expect("chunk");
            let _ = body.flow_control().release_capacity(chunk.len());
            data.extend_from_slice(&chunk);
        }
        // Parse the 5-byte gRPC header.
        assert_eq!(data[0], 0);
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        assert_eq!(&data[5..5 + len], b"pong");
        let trailers = body
            .trailers()
            .await
            .expect("trailers ok")
            .expect("trailers present");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(backend.received_stream_count(), 1);
        backend.assert_no_matcher_mismatches().await;
    }

    /// Regression test: `OmitTrailers` produces a DATA frame with
    /// end_stream=true and NO `grpc-status` header. Clients must observe
    /// the missing-trailer case.
    #[tokio::test]
    async fn grpc_omit_trailers_closes_stream_without_grpc_status() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
            .step(GrpcStep::AcceptRpc(MatchRpc::any()))
            .step(GrpcStep::OmitTrailers {
                body: Some(Bytes::from_static(b"partial")),
            })
            .spawn()
            .expect("spawn");

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let (mut send_req, connection) = h2_client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(connection);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("http://127.0.0.1:{port}/x"))
            .header("content-type", "application/grpc")
            .body(())
            .expect("req");
        let (response_fut, _) = send_req.send_request(req, true).expect("send_request");
        let response = response_fut.await.expect("response");
        let (_parts, mut body) = response.into_parts();
        let mut got = Vec::new();
        while let Some(frame) = body.data().await {
            let chunk = frame.expect("chunk");
            let _ = body.flow_control().release_capacity(chunk.len());
            got.extend_from_slice(&chunk);
        }
        // Expected bytes: 5-byte gRPC header + b"partial".
        assert!(got.ends_with(b"partial"));
        // Trailers are absent.
        let trailers = body.trailers().await.expect("trailers call ok");
        assert!(trailers.is_none(), "expected no trailers, got {trailers:?}");
    }
}
